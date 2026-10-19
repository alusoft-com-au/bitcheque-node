//! Block storage and chain selection. Every valid-looking block is appended to one file and read
//! back by offset, so memory holds headers and state, not blocks. The main chain is the known
//! branch with the most work. A reorg rebuilds state from the latest snapshot (taken every
//! SNAP_EVERY blocks into `<data>.snap`) along the new branch; a node also starts from that
//! snapshot instead of replaying the whole chain.
use std::collections::{HashMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use crate::block::{next_bits, relieved_bits, Block, Blocks, Chain, Header, HostBlocks};
use crate::params::Params;
use crate::state::State;
use crate::tx::{Tx, R, W};
use crate::u256::U256;

pub enum Accepted { Extended, Reorged(Vec<Tx>), Side, Known }

pub const SNAP_EVERY: u32 = 1000;   // blocks between state snapshots
const SIDE_CAP: usize = 2000;       // side blocks kept in memory (older ones stay in the file)
const SNAP_MAGIC: &[u8; 4] = b"BCS1";

struct Snap { height: u32, tip: [u8; 32], state: State, index: Vec<u8> }

pub struct Store {
    pub chain: Chain,
    pub side: HashMap<[u8; 32], (Block, Option<(u64, u32)>)>,
    side_order: VecDeque<[u8; 32]>,
    index: HashMap<[u8; 32], u32>, // main-chain hash -> height
    file: Option<File>,
    file_len: u64,
    path: Option<PathBuf>,
    genesis: Block,
    snap: Option<Snap>,
    host_snap: Option<(u32, fn(&[u8]))>, // a host-backed store: snapshot every so many blocks, handed to this
}

/// Work of one block as u128: 2^128 / (target>>128 + 1). Deterministic, monotone in difficulty.
pub fn work(bits: u32) -> u128 {
    let t = U256::from_compact(bits);
    let hi = ((t.0[3] as u128) << 64) | t.0[2] as u128;
    u128::MAX / (hi + 1)
}

/// Records of the data file: (offset of the block bytes, length, block), and where the last complete
/// record ends. A truncated last record (a crash while writing) is ignored.
fn records(raw: &[u8]) -> (Vec<(u64, u32, Block)>, usize) {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 4 <= raw.len() {
        let len = u32::from_le_bytes(raw[i..i + 4].try_into().unwrap()) as usize;
        if i + 4 + len > raw.len() { eprintln!("data file: truncated last record ignored"); break; }
        if let Ok(b) = Block::decode(&raw[i + 4..i + 4 + len]) { out.push(((i + 4) as u64, len as u32, b)); }
        i += 4 + len;
    }
    let end = i.min(raw.len());
    (out, end)
}

impl Store {
    pub fn open(p: Params, genesis: &Block, path: Option<&Path>) -> std::io::Result<Store> {
        let chain = Chain::new(p, genesis).map_err(std::io::Error::other)?;
        let mut s = Store { chain, side: HashMap::new(), side_order: VecDeque::new(), index: HashMap::new(), file: None, file_len: 0,
                            path: path.map(Path::to_path_buf), genesis: genesis.clone(), snap: None, host_snap: None };
        s.index.insert(genesis.header.hash(), 0);
        if let Some(path) = path {
            s.chain.blocks = Blocks::File { path: path.to_path_buf(), genesis: genesis.clone(), at: vec![(0, 0)] };
            let mut raw = Vec::new();
            if path.exists() { File::open(path)?.read_to_end(&mut raw)?; }
            let (recs, end) = records(&raw);
            if end < raw.len() {
                // cut the partial record off, or blocks appended after it would be unreadable on the next start
                OpenOptions::new().write(true).open(path)?.set_len(end as u64)?;
                raw.truncate(end);
            }
            s.file_len = raw.len() as u64;
            // fast start: the snapshot's chain is trusted by hash, blocks after it are validated
            let mut done = vec![false; recs.len()];
            if let Some(snap) = s.read_snapshot() {
                let by_hash: HashMap<[u8; 32], usize> = recs.iter().enumerate().map(|(i, r)| (r.2.header.hash(), i)).collect();
                let mut path_idx = Vec::new();
                let mut h = snap.tip;
                while h != genesis.header.hash() { match by_hash.get(&h) { Some(&i) => { path_idx.push(i); h = recs[i].2.header.prev; } None => break } }
                let root_ok = path_idx.first().is_some_and(|&i| recs[i].2.header.state_root == snap.state.root() && snap.state.height == snap.height);
                if h == genesis.header.hash() && path_idx.len() as u32 == snap.height && root_ok {
                    path_idx.reverse();
                    for (k, &i) in path_idx.iter().enumerate() {
                        let (off, len, b) = &recs[i];
                        s.chain.headers.push(b.header.clone()); s.chain.hashes.push(b.header.hash()); s.chain.blocks.push(b, Some((*off, *len)));
                        s.index.insert(b.header.hash(), k as u32 + 1); done[i] = true;
                    }
                    s.chain.state = snap.state.clone();
                    let _ = s.chain.decode_index(&mut R::new(&snap.index));
                    eprintln!("snapshot at height {} loaded", snap.height);
                    s.snap = Some(snap);
                }
            }
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(u32::MAX, |d| d.as_secs() as u32);
            for (i, (off, len, b)) in recs.iter().enumerate() { if !done[i] { let _ = s.accept_inner(b, now, Some((*off, *len))); } }
            if s.chain.height() == 0 && !recs.is_empty() && !recs.iter().any(|r| r.2.header.prev == genesis.header.hash()) {
                eprintln!("warning: {} holds {} blocks, but none builds on this network's genesis block: it belongs to another network or genesis. Starting from block 0.", path.display(), recs.len());
            }
            s.file = Some(OpenOptions::new().create(true).append(true).open(path)?);
        }
        Ok(s)
    }
    /// A store whose blocks a host keeps (see `HostBlocks`). `snap` and `headers` (block 1 onwards,
    /// 112 bytes each) restore the chain at the snapshot's height when they agree with each other; the
    /// host then feeds in the blocks it stored after that. New snapshots go to `sink` every `every` blocks.
    pub fn open_host(p: Params, genesis: &Block, io: HostBlocks, snap: Option<&[u8]>, headers: &[u8], every: u32, sink: fn(&[u8])) -> Result<Store, &'static str> {
        let mut s = Store::open(p, genesis, None).map_err(|_| "genesis")?;
        s.chain.blocks = Blocks::Host { genesis: genesis.clone(), n: 1, io };
        s.host_snap = Some((every.max(1), sink));
        let Some(snap) = snap.and_then(decode_snap) else { return Ok(s) };
        let k = snap.height as usize;
        if snap.height == 0 || headers.len() < k * 112 { return Ok(s); }
        let mut hs = Vec::with_capacity(k);
        let mut prev = genesis.header.hash();
        for c in headers[..k * 112].chunks(112) {
            let h = Header::decode(c.try_into().unwrap());
            if h.prev != prev { return Ok(s); }
            prev = h.hash(); hs.push(h);
        }
        // the snapshot must be of this very chain: its tip, and the state root that block committed to
        if prev != snap.tip || hs[k - 1].state_root != snap.state.root() || snap.state.height != snap.height { return Ok(s); }
        for (i, h) in hs.into_iter().enumerate() { s.index.insert(h.hash(), i as u32 + 1); s.chain.hashes.push(h.hash()); s.chain.headers.push(h); }
        s.chain.blocks = Blocks::Host { genesis: genesis.clone(), n: k + 1, io };
        s.chain.state = snap.state.clone();
        s.chain.decode_index(&mut R::new(&snap.index))?;
        s.snap = Some(snap);
        Ok(s)
    }
    pub fn accept(&mut self, b: &Block, now: u32) -> Result<Accepted, &'static str> { self.accept_inner(b, now, None) }

    /// `loc`: the block's place in the file when loading; None means "new block, append it".
    fn accept_inner(&mut self, b: &Block, now: u32, loc: Option<(u64, u32)>) -> Result<Accepted, &'static str> {
        let h = b.header.hash();
        if self.index.contains_key(&h) || self.side.contains_key(&h) { return Ok(Accepted::Known); }
        if !b.header.meets_target() { return Err("pow"); }
        if b.header.prev != self.chain.tip() && !self.index.contains_key(&b.header.prev) && !self.side.contains_key(&b.header.prev) { return Err("prev unknown"); }
        if b.header.prev != self.chain.tip() { self.check_side_header(&b.header, now)?; }
        let fresh = loc.is_none() && self.file.is_some();
        let loc = match loc { Some(l) => Some(l), None => self.persist(b)? };
        let r = if b.header.prev == self.chain.tip() {
            if let Err(e) = self.chain.add_at(b, now, loc) { if fresh { self.unpersist(loc); } return Err(e); }
            self.index.insert(h, self.chain.height());
            self.maybe_snapshot();
            Accepted::Extended
        } else {
            self.remember_side(h, b.clone(), loc);
            let branch = self.branch(h);
            let Some(&fork) = branch.first().and_then(|x| self.index.get(&x.0.header.prev)) else { return Err("branch root unknown") };
            let new_work: u128 = branch.iter().map(|x| work(x.0.header.bits)).sum();
            let old_work: u128 = self.chain.headers[fork as usize + 1..].iter().map(|x| work(x.bits)).sum();
            if new_work > old_work { Accepted::Reorged(self.reorg(fork, branch, now)?) } else { Accepted::Side }
        };
        Ok(r)
    }
    /// Append a block to the data file. Ok(None) for a node without a file. A failed write is cut
    /// back off, so offsets stay right.
    fn persist(&mut self, b: &Block) -> Result<Option<(u64, u32)>, &'static str> {
        let Some(f) = self.file.as_mut() else { return Ok(None) };
        let e = b.encode();
        if f.write_all(&(e.len() as u32).to_le_bytes()).and_then(|_| f.write_all(&e)).is_err() {
            let _ = f.set_len(self.file_len);
            return Err("disk write failed");
        }
        let loc = (self.file_len + 4, e.len() as u32);
        self.file_len += 4 + e.len() as u64;
        Ok(Some(loc))
    }
    /// Remove the block just appended (it failed validation), so junk does not pile up on disk.
    fn unpersist(&mut self, loc: Option<(u64, u32)>) {
        let (Some(f), Some((off, len))) = (self.file.as_mut(), loc) else { return };
        if off + len as u64 == self.file_len && f.set_len(off - 4).is_ok() { self.file_len = off - 4; }
    }
    /// Header checks for a block off the main chain, in the context of its own ancestors: the right
    /// difficulty, a time after their median and not too far ahead. Without this, side blocks at a
    /// trivial difficulty would cost nothing to make.
    fn check_side_header(&self, h: &Header, now: u32) -> Result<(), &'static str> {
        let p = &self.chain.params;
        let mut anc: Vec<Header> = Vec::new();
        let mut prev = h.prev;
        while let Some((b, _)) = self.side.get(&prev) { anc.push(b.header.clone()); prev = b.header.prev; }
        let Some(&fork) = self.index.get(&prev) else { return Err("branch root unknown") };
        let need = p.lwma_window + 11;
        let from = (fork as usize + 1).saturating_sub(need.saturating_sub(anc.len()));
        let mut ctx: Vec<Header> = self.chain.headers[from..=fork as usize].to_vec();
        ctx.extend(anc.into_iter().rev());
        let mut t: Vec<u32> = ctx.iter().rev().take(11).map(|x| x.time).collect();
        t.sort_unstable();
        if h.time <= t[t.len() / 2] || h.time > now.saturating_add(p.max_future_seconds) { return Err("time"); }
        if h.bits != next_bits(p, &ctx) && h.bits != relieved_bits(p, &ctx, h.time) { return Err("bits"); }
        Ok(())
    }
    fn remember_side(&mut self, h: [u8; 32], b: Block, loc: Option<(u64, u32)>) {
        self.side.insert(h, (b, loc)); self.side_order.push_back(h);
        while self.side.len() > SIDE_CAP { if let Some(old) = self.side_order.pop_front() { self.side.remove(&old); } }
    }
    /// Side blocks from the fork point down to `tip`, oldest first.
    fn branch(&self, tip: [u8; 32]) -> Vec<(Block, Option<(u64, u32)>)> {
        let mut v = Vec::new();
        let mut h = tip;
        while let Some((b, loc)) = self.side.get(&h) { h = b.header.prev; v.push((b.clone(), *loc)); }
        v.reverse();
        v
    }
    /// Rebuild along main[..=fork] + branch, starting from the snapshot when it is below the fork.
    /// Returns txs of the abandoned blocks.
    fn reorg(&mut self, fork: u32, branch: Vec<(Block, Option<(u64, u32)>)>, now: u32) -> Result<Vec<Tx>, &'static str> {
        let mut c = Chain::new(self.chain.params.clone(), &self.genesis)?;
        c.blocks = self.chain.blocks.empty_like();
        let mut from = 1u32;
        if let Some(snap) = &self.snap { if snap.height <= fork && self.chain.hashes.get(snap.height as usize) == Some(&snap.tip) {
            for h in 1..=snap.height as usize { c.headers.push(self.chain.headers[h].clone()); c.hashes.push(self.chain.hashes[h]); }
            c.blocks = self.chain.blocks.prefix(snap.height as usize + 1);
            c.state = snap.state.clone(); let _ = c.decode_index(&mut R::new(&snap.index));
            from = snap.height + 1;
        } }
        for h in from..=fork { let b = self.chain.blocks.get(h as usize).ok_or("block missing")?; c.add_at(&b, now, self.chain.blocks.loc(h as usize))?; }
        for (i, (b, loc)) in branch.iter().enumerate() {
            if let Err(e) = c.add_at(b, now, *loc) { for (x, _) in &branch[i..] { self.side.remove(&x.header.hash()); } return Err(e); }
        }
        let mut abandoned = Vec::new();
        for h in (fork + 1..=self.chain.height()).rev() {
            if let Some(b) = self.chain.blocks.get(h as usize) {
                abandoned.splice(0..0, b.txs[1..].iter().cloned());
                let hash = b.header.hash(); self.index.remove(&hash); let loc = self.chain.blocks.loc(h as usize); self.remember_side(hash, b, loc);
            }
        }
        for (k, (b, _)) in branch.iter().enumerate() { let h = b.header.hash(); self.side.remove(&h); self.index.insert(h, fork + 1 + k as u32); }
        self.chain = c;
        // the snapshot was of a block we just abandoned: forget it (the next one is taken as usual)
        if self.snap.as_ref().is_some_and(|sn| sn.height > fork) {
            self.snap = None;
            if let Some(p) = self.snap_path() { let _ = std::fs::remove_file(p); }
            // a host restarts from its snapshot each time it wakes: replace it now, not at the next multiple
            if self.host_snap.is_some() { self.take_snapshot(); }
        }
        Ok(abandoned)
    }

    // ---- snapshots ----
    fn snap_path(&self) -> Option<PathBuf> { self.path.as_ref().map(|p| p.with_extension("snap")) }
    fn maybe_snapshot(&mut self) {
        let h = self.chain.height();
        let every = self.host_snap.map_or(SNAP_EVERY, |(e, _)| e);
        if h != 0 && h % every == 0 { self.take_snapshot(); }
    }
    fn take_snapshot(&mut self) {
        let h = self.chain.height();
        let path = self.snap_path();
        if path.is_none() && self.host_snap.is_none() { return; }
        let snap = Snap { height: h, tip: self.chain.tip(), state: self.chain.state.clone(), index: self.chain.encode_index() };
        let mut w = W(Vec::new());
        w.0.extend_from_slice(SNAP_MAGIC); w.u32(snap.height); w.0.extend_from_slice(&snap.tip); w.bytes(&snap.state.encode()); w.bytes(&snap.index);
        if let Some(path) = path {
            let tmp = path.with_extension("snap.tmp");
            if std::fs::write(&tmp, &w.0).and_then(|_| std::fs::rename(&tmp, &path)).is_ok() { self.snap = Some(snap); }
        } else if let Some((_, sink)) = self.host_snap { sink(&w.0); self.snap = Some(snap); }
    }
    fn read_snapshot(&self) -> Option<Snap> { decode_snap(&std::fs::read(self.snap_path()?).ok()?) }
}

fn decode_snap(raw: &[u8]) -> Option<Snap> {
    if raw.len() < 40 || &raw[..4] != SNAP_MAGIC { return None; }
    let mut r = R::new(&raw[4..]);
    let height = r.u32().ok()?;
    let tip: [u8; 32] = r.take(32).ok()?.try_into().ok()?;
    let state = State::decode(&mut R::new(&r.bytes().ok()?)).ok()?;
    let index = r.bytes().ok()?;
    Some(Snap { height, tip, state, index })
}

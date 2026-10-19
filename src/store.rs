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

/// Reorged: the abandoned blocks' transactions, and the fork height (blocks above it are the new branch).
pub enum Accepted { Extended, Reorged(Vec<Tx>, u32), Side, Known }

pub const SNAP_EVERY: u32 = 1000;   // blocks between state snapshots
/// Headers a host-backed store keeps in memory: enough for the rules (60 blocks back) and for reorgs up to about
/// a day and a half deep, and well above the host's snapshot interval; memory stays flat however long the chain.
pub const HOST_KEEP: usize = 2000;
const SIDE_CAP: usize = 2000;       // side blocks kept in memory
const SIDE_BYTES: usize = 32 << 20; // ...and their bytes (a host-backed store keeps less: HOST_SIDE_BYTES)
const HOST_SIDE_BYTES: usize = 8 << 20;
const SNAP_MAGIC: &[u8; 4] = b"BCS1";

struct Snap { height: u32, tip: [u8; 32], state: State, index: Vec<u8> }

pub struct Store {
    pub chain: Chain,
    // blocks off the main chain, in memory only: a new side block is written to the file only once a reorg makes it
    // main (abandoned main blocks keep their place in the file), so blocks nobody builds on never pile up on disk
    pub side: HashMap<[u8; 32], (Block, Option<(u64, u32)>)>,
    side_order: VecDeque<[u8; 32]>,
    side_bytes: usize, side_cap: usize,
    index: HashMap<[u8; 32], u32>, // main-chain hash -> height (with a header window, only heights still in it)
    file: Option<File>,
    file_len: u64,
    path: Option<PathBuf>,
    genesis: Block,
    snaps: Vec<Snap>,   // oldest first: every snapshot within max_reorg of the tip, and the newest one below that, so a reorg up to max_reorg deep starts from one
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
        let mut s = Store { chain, side: HashMap::new(), side_order: VecDeque::new(), side_bytes: 0, side_cap: SIDE_BYTES, index: HashMap::new(), file: None, file_len: 0,
                            path: path.map(Path::to_path_buf), genesis: genesis.clone(), snaps: Vec::new(), host_snap: None };
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
            let mut snaps = s.read_snapshot();
            if let Some(snap) = snaps.pop() {
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
                    snaps.push(snap);
                    s.snaps = snaps;
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
    /// A store whose blocks a host keeps (see `HostBlocks`). `snap` and `headers` (112 bytes each, the
    /// most recent ones up to the snapshot's height: block 1 onwards, or just the last HOST_KEEP) restore the
    /// chain at the snapshot's height when they agree with each other; the host then feeds in the blocks it
    /// stored after that. New snapshots go to `sink` every `every` blocks. Only HOST_KEEP headers stay in memory.
    pub fn open_host(p: Params, genesis: &Block, io: HostBlocks, snap: Option<&[u8]>, headers: &[u8], every: u32, sink: fn(&[u8])) -> Result<Store, &'static str> {
        let mut s = Store::open(p, genesis, None).map_err(|_| "genesis")?;
        s.chain.blocks = Blocks::Host { genesis: genesis.clone(), n: 1, io };
        s.chain.keep = Some(HOST_KEEP);
        s.host_snap = Some((every.max(1), sink));
        s.side_cap = HOST_SIDE_BYTES;
        let mut snaps = snap.map(decode_snap).unwrap_or_default();
        let Some(snap) = snaps.pop() else { return Ok(s) };
        let k = snap.height as usize;
        let n = (headers.len() / 112).min(k);
        if snap.height == 0 || n == 0 || headers.len() != n * 112 { return Ok(s); }
        // the headers must link up, end at the snapshot's tip, and that block must commit to the snapshot's state.
        // All of them back to block 1 also link to genesis; a tail is trusted to (it is the host's own record).
        let hs: Vec<Header> = headers.chunks(112).map(|c| Header::decode(c.try_into().unwrap())).collect();
        let mut prev = if n == k { genesis.header.hash() } else { hs[0].prev };
        for h in &hs { if h.prev != prev { return Ok(s); } prev = h.hash(); }
        if prev != snap.tip || hs[n - 1].state_root != snap.state.root() || snap.state.height != snap.height { return Ok(s); }
        let first = (k - n + 1) as u32;
        if n < k { s.chain.headers.clear(); s.chain.hashes.clear(); s.index.clear(); s.chain.base = first; }
        for (i, h) in hs.into_iter().enumerate() { s.index.insert(h.hash(), first + i as u32); s.chain.hashes.push(h.hash()); s.chain.headers.push(h); }
        s.chain.blocks = Blocks::Host { genesis: genesis.clone(), n: k + 1, io };
        s.chain.state = snap.state.clone();
        s.chain.decode_index(&mut R::new(&snap.index))?;
        snaps.push(snap);
        s.snaps = snaps;
        Ok(s)
    }
    pub fn accept(&mut self, b: &Block, now: u32) -> Result<Accepted, &'static str> { self.accept_inner(b, now, None) }

    /// `loc`: the block's place in the file when loading; None means "new block, append it".
    fn accept_inner(&mut self, b: &Block, now: u32, loc: Option<(u64, u32)>) -> Result<Accepted, &'static str> {
        let h = b.header.hash();
        if self.index.contains_key(&h) || self.side.contains_key(&h) { return Ok(Accepted::Known); }
        let p = &self.chain.params;
        // a target easier than any block may have is invalid wherever the block would go (and cheap to fake)
        if U256::from_compact(b.header.bits) > U256::from_compact(p.min_bits.max(p.initial_bits)) { return Err("bits"); }
        if !b.header.meets_target() { return Err("pow"); }
        if b.encode().len() > p.max_block_bytes { return Err("block too large"); }
        if b.header.prev != self.chain.tip() && !self.index.contains_key(&b.header.prev) && !self.side.contains_key(&b.header.prev) { return Err("prev unknown"); }
        if b.header.prev != self.chain.tip() {
            // everything a side block can be checked for without the state at its fork: its header in the context of its
            // own branch, its transactions' root and its coinbase. Its transactions are checked if it ever becomes main.
            let height = self.check_side_header(&b.header, now)?;
            if b.header.tx_root != crate::block::tx_root(&b.txs) { return Err("tx root"); }
            if !matches!(b.txs.first(), Some(Tx::Coinbase { height: ch, .. }) if *ch == height) || b.txs[1..].iter().any(|t| matches!(t, Tx::Coinbase { .. })) { return Err("coinbase"); }
        }
        let main = b.header.prev == self.chain.tip();
        let fresh = loc.is_none() && self.file.is_some() && main;
        let loc = match loc { Some(l) => Some(l), None if main => self.persist(b)?, None => None };
        let r = if main {
            if let Err(e) = self.chain.add_at(b, now, loc) { if fresh { self.unpersist(loc); } return Err(e); }
            self.index.insert(h, self.chain.height());
            self.prune_index();
            self.maybe_snapshot();
            Accepted::Extended
        } else {
            self.remember_side(h, b.clone(), loc);
            let branch = self.branch(h);
            let Some(&fork) = branch.first().and_then(|x| self.index.get(&x.0.header.prev)) else { return Err("branch root unknown") };
            if fork < self.chain.base { return Err("reorg too deep"); }
            let new_work: u128 = branch.iter().map(|x| work(x.0.header.bits)).sum();
            let old_work: u128 = self.chain.headers_from(fork + 1).iter().map(|x| work(x.bits)).sum();
            // a fork deeper than max_reorg wins only with twice the work: blocks that deep are settled for everyday
            // purposes, yet a node that ended up on a wrong branch (say, synced from a liar first) still finds its way back
            let deep = self.chain.height().saturating_sub(fork) > self.chain.params.max_reorg;
            if new_work > old_work && (!deep || new_work / 2 > old_work) { Accepted::Reorged(self.reorg(fork, branch, now)?, fork) } else { Accepted::Side }
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
    /// difficulty, a time after their median and not too far ahead, from a fork still in the header window. Without
    /// this, side blocks at a trivial difficulty would cost nothing to make. Returns the block's height.
    fn check_side_header(&self, h: &Header, now: u32) -> Result<u32, &'static str> {
        let p = &self.chain.params;
        let mut anc: Vec<Header> = Vec::new();
        let mut prev = h.prev;
        while let Some((b, _)) = self.side.get(&prev) { anc.push(b.header.clone()); prev = b.header.prev; }
        let Some(&fork) = self.index.get(&prev) else { return Err("branch root unknown") };
        if fork < self.chain.base { return Err("reorg too deep"); }
        let height = fork + anc.len() as u32 + 1;
        let need = p.lwma_window + 11;
        let from = ((fork as usize + 1).saturating_sub(need.saturating_sub(anc.len())) as u32).max(self.chain.base);
        let mut ctx: Vec<Header> = self.chain.headers_from(from).iter().take((fork + 1).saturating_sub(from) as usize).cloned().collect();
        ctx.extend(anc.into_iter().rev());
        let mut t: Vec<u32> = ctx.iter().rev().take(11).map(|x| x.time).collect();
        t.sort_unstable();
        if h.time <= t[t.len() / 2] || h.time > now.saturating_add(p.max_future_seconds) { return Err("time"); }
        if h.bits != next_bits(p, &ctx) && h.bits != relieved_bits(p, &ctx, h.time) { return Err("bits"); }
        Ok(height)
    }
    /// Keep a side block, evicting the oldest others past the caps, but never one of its own ancestors: a long branch
    /// being built must keep every block back to its fork, or it could never be followed.
    fn remember_side(&mut self, h: [u8; 32], b: Block, loc: Option<(u64, u32)>) {
        self.side_bytes += b.encode().len();
        if let Some((old, _)) = self.side.insert(h, (b, loc)) { self.side_bytes -= old.encode().len(); } else { self.side_order.push_back(h); }
        if self.side.len() <= SIDE_CAP && self.side_bytes <= self.side_cap { return; }
        let mut keep = std::collections::HashSet::new();
        let mut x = h;
        while let Some((b, _)) = self.side.get(&x) { keep.insert(x); x = b.header.prev; }
        let mut kept = VecDeque::new();
        while self.side.len() > SIDE_CAP || self.side_bytes > self.side_cap {
            let Some(old) = self.side_order.pop_front() else { break };
            if keep.contains(&old) { kept.push_back(old); } else { self.forget_side(&old); }
        }
        while let Some(k) = kept.pop_back() { self.side_order.push_front(k); }
    }
    fn forget_side(&mut self, h: &[u8; 32]) {
        if let Some((b, _)) = self.side.remove(h) { self.side_bytes -= b.encode().len(); self.side_order.retain(|x| x != h); }
    }
    /// Side blocks from the fork point down to `tip`, oldest first.
    fn branch(&self, tip: [u8; 32]) -> Vec<(Block, Option<(u64, u32)>)> {
        let mut v = Vec::new();
        let mut h = tip;
        while let Some((b, loc)) = self.side.get(&h) { h = b.header.prev; v.push((b.clone(), *loc)); }
        v.reverse();
        v
    }
    /// Rebuild along main[..=fork] + branch, starting from the newest snapshot at or below the fork. The replay keeps
    /// no blocks (`Blocks::Count`): only once the whole branch has proved valid are its blocks stored (a host's
    /// storage is overwritten from fork + 1 up). Returns txs of the abandoned blocks.
    fn reorg(&mut self, fork: u32, branch: Vec<(Block, Option<(u64, u32)>)>, now: u32) -> Result<Vec<Tx>, &'static str> {
        let mut c = Chain::new(self.chain.params.clone(), &self.genesis)?;
        c.blocks = Blocks::Count(1);
        c.keep = self.chain.keep;
        let mut from = 1u32;
        // start from a snapshot below the fork whose header is still in memory and commits to it; otherwise replay from block 1
        let usable = |sn: &&Snap| sn.height <= fork && self.chain.hash_at(sn.height) == Some(sn.tip) && self.chain.header_at(sn.height).is_some_and(|h| h.state_root == sn.state.root());
        if let Some(snap) = self.snaps.iter().rev().find(usable) {
            let n = (snap.height - self.chain.base) as usize + 1;
            c.headers = self.chain.headers[..n].to_vec(); c.hashes = self.chain.hashes[..n].to_vec(); c.base = self.chain.base;
            c.blocks = Blocks::Count(snap.height as usize + 1);
            c.state = snap.state.clone(); let _ = c.decode_index(&mut R::new(&snap.index));
            from = snap.height + 1;
        }
        for h in from..=fork { let b = self.chain.blocks.get(h as usize).ok_or("block missing")?; c.add(&b, now)?; }
        for (i, (b, _)) in branch.iter().enumerate() {
            if let Err(e) = c.add(b, now) { for (x, _) in &branch[i..] { self.forget_side(&x.header.hash()); } return Err(e); }
        }
        // valid: read the abandoned blocks before their heights are overwritten, then store the branch
        let mut abandoned = Vec::new();
        let mut old = Vec::new();
        for h in (fork + 1..=self.chain.height()).rev() {
            let b = self.chain.blocks.get(h as usize).ok_or("block missing")?;   // nothing has changed yet: give up cleanly
            abandoned.splice(0..0, b.txs[1..].iter().cloned());
            old.push((b.header.hash(), b, self.chain.blocks.loc(h as usize)));
        }
        let mut blocks = self.chain.blocks.prefix(fork as usize + 1);
        for (b, loc) in &branch { let loc = match loc { Some(l) => Some(*l), None => self.persist(b)? }; blocks.push(b, loc); }
        c.blocks = blocks;
        for (hash, b, loc) in old { self.index.remove(&hash); self.remember_side(hash, b, loc); }
        for (k, (b, _)) in branch.iter().enumerate() { let h = b.header.hash(); self.forget_side(&h); self.index.insert(h, fork + 1 + k as u32); }
        self.chain = c;
        self.prune_index();
        // a snapshot of a block just abandoned is forgotten (the next one is taken as usual)
        if self.snaps.iter().any(|sn| sn.height > fork) {
            self.snaps.retain(|sn| sn.height <= fork);
            // a host restarts from its latest snapshot each time it wakes: take one at the new tip now, not at the next multiple
            if self.host_snap.is_some() { self.take_snapshot(); } else { self.write_snapshots(); }
        }
        Ok(abandoned)
    }

    /// With a header window, forget the hashes of main-chain blocks that left it.
    fn prune_index(&mut self) {
        let base = self.chain.base;
        if base > 0 && self.index.len() > self.chain.headers.len() + 64 { self.index.retain(|_, h| *h >= base); }
    }

    // ---- snapshots ----
    fn snap_path(&self) -> Option<PathBuf> { self.path.as_ref().map(|p| p.with_extension("snap")) }
    fn maybe_snapshot(&mut self) {
        let h = self.chain.height();
        let every = self.host_snap.map_or(SNAP_EVERY, |(e, _)| e);
        if h != 0 && h % every == 0 { self.take_snapshot(); }
    }
    fn take_snapshot(&mut self) {
        if self.path.is_none() && self.host_snap.is_none() { return; }
        let h = self.chain.height();
        self.snaps.retain(|sn| sn.height < h);
        self.snaps.push(Snap { height: h, tip: self.chain.tip(), state: self.chain.state.clone(), index: self.chain.encode_index() });
        // keep every snapshot a reorg of up to max_reorg could need: those above tip - max_reorg, and the newest at or below it
        let floor = h.saturating_sub(self.chain.params.max_reorg);
        if let Some(i) = self.snaps.iter().rposition(|sn| sn.height <= floor) { self.snaps.drain(..i); }
        self.write_snapshots();
    }
    /// The latest snapshot, then each older one as one more field, newest first: a reader that wants only the latest stops early.
    fn write_snapshots(&mut self) {
        let Some(last) = self.snaps.last() else {
            if let Some(p) = self.snap_path() { let _ = std::fs::remove_file(p); }
            return;
        };
        let mut w = W(encode_snap(last));
        for sn in self.snaps.iter().rev().skip(1) { w.bytes(&encode_snap(sn)); }
        if let Some(path) = self.snap_path() {
            let tmp = path.with_extension("snap.tmp");
            let _ = std::fs::write(&tmp, &w.0).and_then(|_| std::fs::rename(&tmp, &path));
        } else if let Some((_, sink)) = self.host_snap { sink(&w.0); }
    }
    fn read_snapshot(&self) -> Vec<Snap> { std::fs::read(self.snap_path().unwrap_or_default()).map(|r| decode_snap(&r)).unwrap_or_default() }
}

fn encode_snap(snap: &Snap) -> Vec<u8> {
    let mut w = W(Vec::new());
    w.0.extend_from_slice(SNAP_MAGIC); w.u32(snap.height); w.0.extend_from_slice(&snap.tip); w.bytes(&snap.state.encode()); w.bytes(&snap.index);
    w.0
}
/// The snapshots in a snapshot file, oldest first.
fn decode_snap(raw: &[u8]) -> Vec<Snap> {
    let one = |raw: &[u8]| -> Option<(Snap, usize)> {
        if raw.len() < 40 || &raw[..4] != SNAP_MAGIC { return None; }
        let mut r = R::new(&raw[4..]);
        let height = r.u32().ok()?;
        let tip: [u8; 32] = r.take(32).ok()?.try_into().ok()?;
        let state = State::decode(&mut R::new(&r.bytes().ok()?)).ok()?;
        let index = r.bytes().ok()?;
        Some((Snap { height, tip, state, index }, 4 + r.i))
    };
    let Some((last, used)) = one(raw) else { return Vec::new() };
    let mut r = R::new(&raw[used..]);
    let mut out = vec![last];
    while let Some(o) = r.bytes().ok().and_then(|b| one(&b)).map(|x| x.0) { if o.height >= out.last().unwrap().height { break; } out.push(o); }
    out.reverse();
    out
}

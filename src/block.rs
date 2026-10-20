//! Headers, proof-of-work, LWMA difficulty, block validation and the chain (DESIGN.md §1, §12).
use crate::crypto::sha256d;
use crate::params::Params;
use crate::state::{Event, State};
use crate::tx::AccountId;
use std::collections::{HashMap, VecDeque};
use crate::tx::{Tx, R, W};
use crate::u256::U256;

#[derive(Clone, Debug, PartialEq)]
pub struct Header { pub version: u32, pub prev: [u8; 32], pub tx_root: [u8; 32], pub state_root: [u8; 32], pub time: u32, pub bits: u32, pub nonce: u32 }

impl Header {
    pub fn encode(&self) -> [u8; 112] {
        let mut b = [0u8; 112];
        b[..4].copy_from_slice(&self.version.to_le_bytes()); b[4..36].copy_from_slice(&self.prev);
        b[36..68].copy_from_slice(&self.tx_root); b[68..100].copy_from_slice(&self.state_root);
        b[100..104].copy_from_slice(&self.time.to_le_bytes()); b[104..108].copy_from_slice(&self.bits.to_le_bytes());
        b[108..].copy_from_slice(&self.nonce.to_le_bytes());
        b
    }
    pub fn decode(b: &[u8; 112]) -> Header {
        let g = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
        Header { version: g(0), prev: b[4..36].try_into().unwrap(), tx_root: b[36..68].try_into().unwrap(),
                 state_root: b[68..100].try_into().unwrap(), time: g(100), bits: g(104), nonce: g(108) }
    }
    pub fn hash(&self) -> [u8; 32] { sha256d(&self.encode()) }
    pub fn meets_target(&self) -> bool { U256::from_le_bytes(&self.hash()) < U256::from_compact(self.bits) }
    /// Search nonces until the header meets its target.
    pub fn mine(&mut self) { while !self.meets_target() { self.nonce = self.nonce.wrapping_add(1); } }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Block { pub header: Header, pub txs: Vec<Tx> }

impl Block {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = self.header.encode().to_vec();
        v.extend_from_slice(&(self.txs.len() as u32).to_le_bytes());
        for t in &self.txs { let e = t.encode(); v.extend_from_slice(&(e.len() as u32).to_le_bytes()); v.extend_from_slice(&e); }
        v
    }
    pub fn decode(b: &[u8]) -> Result<Block, &'static str> {
        if b.len() < 116 { return Err("truncated"); }
        let header = Header::decode(b[..112].try_into().unwrap());
        let mut r = R::new(b); r.i = 112;
        let n = r.u32()?; let mut txs = Vec::new();
        for _ in 0..n { let e = r.bytes()?; txs.push(Tx::decode(&mut R::new(&e))?); }
        if r.i != b.len() { return Err("trailing bytes"); }   // one block, one encoding
        Ok(Block { header, txs })
    }
}

/// Merkle root over txids, zero-padded to a power of two (no duplicate-last malleability).
pub fn tx_root(txs: &[Tx]) -> [u8; 32] { root_of(txs.iter().map(|t| t.txid()).collect()) }
fn root_of(mut level: Vec<[u8; 32]>) -> [u8; 32] {
    if level.is_empty() { return [0u8; 32]; }
    while !level.len().is_power_of_two() { level.push([0u8; 32]); }
    while level.len() > 1 {
        level = level.chunks(2).map(|p| sha256d(&[p[0], p[1]].concat())).collect();
    }
    level[0]
}

/// LWMA-1 (Zawy) over the last `window` headers, clamped to ×/÷ `clamp` per block. A solve time is measured from
/// the latest timestamp so far (at least 1 s, at most 6 targets), so a timestamp set back and then forward cannot
/// earn an easier target the way a symmetric clamp of raw differences allows.
pub fn next_bits(p: &Params, headers: &[Header]) -> u32 {
    let n = headers.len().min(p.lwma_window);
    if n < 2 { return p.min_bits; }
    let hs = &headers[headers.len() - n..];
    let t = p.block_target_seconds as i64;
    let (mut weighted, mut sum_targets) = (0i64, U256::ZERO);
    let mut latest = hs[0].time as i64;
    for i in 1..n {
        let this = (hs[i].time as i64).max(latest + 1);
        let solve = (this - latest).min(6 * t);
        latest = this;
        weighted += solve * i as i64;
        sum_targets = sum_targets.add(&U256::from_compact(hs[i].bits).div_u64(n as u64 - 1));   // the mean of the n-1 targets
    }
    let k = (n as i64 - 1) * n as i64 / 2 * t;
    let weighted = weighted.max(k / 10) as u64; // never let the window collapse to zero
    let mut next = sum_targets.div_u64(k as u64).mul_u64(weighted);
    let last = U256::from_compact(hs[n - 1].bits);
    let (lo, hi) = (last.div_u64(p.lwma_clamp), last.mul_u64(p.lwma_clamp));
    if next < lo { next = lo } else if next > hi { next = hi }
    let max = U256::from_compact(p.min_bits);
    if next > max { next = max }
    next.to_compact()
}

/// Main-chain blocks: in memory (tests, no --data) or left in the data file and read back by offset,
/// so a node's memory does not grow with the chain. `at[h]` is the (offset, length) of block h.
/// `Count` keeps nothing but how many there are: a reorg replays into it, so nothing is stored until the new branch
/// has proved valid.
pub enum Blocks { Mem(Vec<Block>), File { path: std::path::PathBuf, genesis: Block, at: Vec<(u64, u32)> }, Host { genesis: Block, n: usize, io: HostBlocks }, Count(usize) }
/// Block storage kept by a host, by height (the edge node keeps blocks in a Durable Object's database):
/// `get` the encoded block at a height, `put` one there, replacing what was there.
#[derive(Clone, Copy)]
pub struct HostBlocks { pub get: fn(usize) -> Option<Vec<u8>>, pub put: fn(usize, &[u8]) }
impl Blocks {
    pub fn len(&self) -> usize { match self { Blocks::Mem(v) => v.len(), Blocks::File { at, .. } => at.len(), Blocks::Host { n, .. } | Blocks::Count(n) => *n } }
    pub fn get(&self, h: usize) -> Option<Block> {
        match self {
            Blocks::Mem(v) => v.get(h).cloned(),
            Blocks::File { path, genesis, at } => {
                if h == 0 { return Some(genesis.clone()); }
                let &(off, len) = at.get(h)?;
                use std::io::{Read, Seek, SeekFrom};
                let mut f = std::fs::File::open(path).ok()?;
                f.seek(SeekFrom::Start(off)).ok()?;
                let mut buf = vec![0u8; len as usize];
                f.read_exact(&mut buf).ok()?;
                Block::decode(&buf).ok()
            }
            Blocks::Host { genesis, n, io } => if h == 0 { Some(genesis.clone()) } else if h < *n { Block::decode(&(io.get)(h)?).ok() } else { None },
            Blocks::Count(_) => None,
        }
    }
    /// Encoded blocks `from..from+n` (fewer at the tip), opening the file once.
    pub fn read_many(&self, from: usize, count: usize) -> Vec<Vec<u8>> {
        match self {
            Blocks::Mem(v) => v.iter().skip(from).take(count).map(|b| b.encode()).collect(),
            Blocks::File { path, genesis, at } => {
                use std::io::{Read, Seek, SeekFrom};
                let mut out = Vec::new();
                let Ok(mut f) = std::fs::File::open(path) else { return out };
                for h in from..(from + count).min(at.len()) {
                    if h == 0 { out.push(genesis.encode()); continue; }
                    let (off, len) = at[h];
                    let mut buf = vec![0u8; len as usize];
                    if f.seek(SeekFrom::Start(off)).is_err() || f.read_exact(&mut buf).is_err() { break; }
                    out.push(buf);
                }
                out
            }
            Blocks::Host { genesis, n, io } => (from..(from + count).min(*n)).map_while(|h| if h == 0 { Some(genesis.encode()) } else { (io.get)(h) }).collect(),
            Blocks::Count(_) => Vec::new(),
        }
    }
    /// A copy holding only blocks `from..from+n` (block 0 stays at index 0), so a peer's request
    /// can be served without copying the whole chain index under the lock.
    pub fn window(&self, from: usize, n: usize) -> (Blocks, usize) {
        let end = (from + n).min(self.len());
        let from = from.clamp(1, end.max(1));
        match self {
            Blocks::Mem(v) => (Blocks::Mem([&v[..1], &v[from..end]].concat()), 1),
            Blocks::File { path, genesis, at } => (Blocks::File { path: path.clone(), genesis: genesis.clone(), at: [&at[..1], &at[from..end]].concat() }, 1),
            Blocks::Host { genesis, io, .. } => (Blocks::Host { genesis: genesis.clone(), n: end, io: *io }, from),
            Blocks::Count(_) => (Blocks::Count(end), from),
        }
    }
    pub fn loc(&self, h: usize) -> Option<(u64, u32)> { if let Blocks::File { at, .. } = self { at.get(h).copied() } else { None } }
    pub fn push(&mut self, b: &Block, loc: Option<(u64, u32)>) {
        match self {
            Blocks::Mem(v) => v.push(b.clone()),
            Blocks::File { at, .. } => at.push(loc.expect("a file-backed chain needs the block's location")),
            Blocks::Host { n, io, .. } => { (io.put)(*n, &b.encode()); *n += 1 }
            Blocks::Count(n) => *n += 1,
        }
    }
    pub fn truncate(&mut self, k: usize) { match self { Blocks::Mem(v) => v.truncate(k), Blocks::File { at, .. } => at.truncate(k), Blocks::Host { n, .. } | Blocks::Count(n) => *n = (*n).min(k) } }
    /// The same kind of store holding only block 0.
    pub fn empty_like(&self) -> Blocks { self.prefix(1) }
    /// The first `k` blocks (genesis included), sharing the same storage: nothing is read or written.
    pub fn prefix(&self, k: usize) -> Blocks {
        match self {
            Blocks::Mem(v) => Blocks::Mem(v[..k.min(v.len())].to_vec()),
            Blocks::File { path, genesis, at } => Blocks::File { path: path.clone(), genesis: genesis.clone(), at: at[..k.min(at.len())].to_vec() },
            Blocks::Host { genesis, n, io } => Blocks::Host { genesis: genesis.clone(), n: k.min(*n), io: *io },
            Blocks::Count(n) => Blocks::Count(k.min(*n)),
        }
    }
}

/// Recent events per account, newest last, at most HISTORY_CAP each. Rebuilt with the chain (startup, reorg), never persisted.
pub const HISTORY_CAP: usize = 50;
#[derive(Clone, Debug)]
pub struct Entry { pub height: u32, pub event: Event }

/// Lifetime counters, updated once per block (O(1)) and rebuilt with the chain. Not consensus.
#[derive(Clone, Debug, Default)]
pub struct Totals { pub txs: u64, pub pieces: u64, pub registrations: u64, pub transfers: u64, pub rewards: u64 }

/// Target with stall relief: when `stall_relief` is on and the chain has been silent for more than two
/// targets, the allowed target doubles for every further two targets of silence (never easier than
/// `min_bits`). So a chain abandoned at a high difficulty can be restarted by whoever is left (DESIGN.md §12.3).
/// Silence is measured from the latest time among the last 11 headers, and a block may claim no relief
/// for the `max_future_seconds` it could have faked: otherwise a miner could alternate a low and a
/// far-future timestamp and mine every other block at minimum difficulty (Bitcoin testnet's 20-minute bug).
pub fn relieved_bits(p: &Params, headers: &[Header], time: u32) -> u32 {
    let base = next_bits(p, headers);
    let last = headers.iter().rev().take(11).map(|h| h.time).max().unwrap_or(0);
    let t2 = 2 * p.block_target_seconds;
    let start = last.saturating_add(p.max_future_seconds).saturating_add(t2);
    if !p.stall_relief || time <= start { return base; }
    let steps = ((time - start) / t2 + 1).min(255);
    let max = U256::from_compact(p.min_bits);
    let mut t = U256::from_compact(base);
    for _ in 0..steps { t = t.shl(1); if t > max { t = max; break; } }
    t.to_compact()
}

/// `headers`/`hashes` hold heights `base ..= height()`. A node keeps them all (`keep` None, `base` 0); the edge node
/// keeps only the most recent `keep` (a Durable Object has 128 MB, and the rules look back 60 blocks at most).
pub struct Chain { pub params: Params, pub blocks: Blocks, pub headers: Vec<Header>, pub hashes: Vec<[u8; 32]>, pub state: State,
                   pub history: HashMap<AccountId, VecDeque<Entry>>, pub totals: Totals, pub base: u32, pub keep: Option<usize> }

impl Chain {
    /// History and totals as bytes, for a state snapshot.
    pub fn encode_index(&self) -> Vec<u8> {
        let mut w = W(Vec::new());
        w.u32(self.history.len() as u32);
        for (id, es) in &self.history {
            w.bytes(id); w.u32(es.len() as u32);
            for e in es { w.u32(e.height); match &e.event {
                Event::Register { id, number } => { w.u8(0); w.bytes(id); w.u32(*number) }
                Event::Reward { number, amount } => { w.u8(1); w.u32(*number); w.u64(*amount) }
                Event::Transfer { from, cheque, to, amount, fee, digits } => { w.u8(2); w.bytes(from); w.u16(*cheque); w.u32(*to); w.u64(*amount); w.u64(*fee); w.0.extend_from_slice(digits) } } }
        }
        for x in [self.totals.txs, self.totals.pieces, self.totals.registrations, self.totals.transfers, self.totals.rewards] { w.u64(x); }
        w.0
    }
    pub fn decode_index(&mut self, r: &mut R) -> Result<(), &'static str> {
        let mut h = HashMap::new();
        for _ in 0..r.u32()? {
            let id = r.bytes()?; let n = r.u32()?; let mut es = VecDeque::new();
            for _ in 0..n { let height = r.u32()?; let event = match r.u8()? {
                0 => Event::Register { id: r.bytes()?, number: r.u32()? },
                1 => Event::Reward { number: r.u32()?, amount: r.u64()? },
                2 => Event::Transfer { from: r.bytes()?, cheque: r.u16()?, to: r.u32()?, amount: r.u64()?, fee: r.u64()?, digits: r.take(18)?.try_into().map_err(|_| "digits")? },
                _ => return Err("bad history") }; es.push_back(Entry { height, event }); }
            h.insert(id, es);
        }
        self.history = h;
        self.totals = Totals { txs: r.u64()?, pieces: r.u64()?, registrations: r.u64()?, transfers: r.u64()?, rewards: r.u64()? };
        Ok(())
    }
    /// Block 0 (§12): coinbase to number 0, zero state root by definition, mined.
    pub fn genesis(p: &Params, time: u32, message: &[u8]) -> Block {
        let cb = Tx::Coinbase { height: 0, payee: 0, message: message.to_vec() };
        let mut header = Header { version: 1, prev: [0; 32], tx_root: tx_root(std::slice::from_ref(&cb)), state_root: [0; 32], time, bits: p.initial_bits, nonce: 0 };
        header.mine();
        Block { header, txs: vec![cb] }
    }
    pub fn new(p: Params, genesis: &Block) -> Result<Chain, &'static str> {
        if !genesis.header.meets_target() || genesis.header.bits != p.initial_bits { return Err("bad genesis"); }
        // block 0's hash is no registration anchor: it is known before launch, so work anchored to it could be done early
        let state = State::new(&p);
        Ok(Chain { params: p, blocks: Blocks::Mem(vec![genesis.clone()]), headers: vec![genesis.header.clone()], hashes: vec![genesis.header.hash()], state, history: HashMap::new(), totals: Totals::default(), base: 0, keep: None })
    }
    pub fn height(&self) -> u32 { self.base + self.headers.len() as u32 - 1 }
    /// The header and hash at height `h`, while it is in memory.
    pub fn header_at(&self, h: u32) -> Option<&Header> { h.checked_sub(self.base).and_then(|i| self.headers.get(i as usize)) }
    pub fn hash_at(&self, h: u32) -> Option<[u8; 32]> { h.checked_sub(self.base).and_then(|i| self.hashes.get(i as usize)).copied() }
    /// Headers from height `h` to the tip (from the oldest in memory if `h` is below it).
    pub fn headers_from(&self, h: u32) -> &[Header] { &self.headers[(h.saturating_sub(self.base) as usize).min(self.headers.len())..] }
    fn push_header(&mut self, h: Header) {
        self.hashes.push(h.hash()); self.headers.push(h);
        // drop the oldest in chunks, so the window is trimmed once every so often rather than on every block
        if let Some(k) = self.keep { if self.headers.len() > k + k / 4 { let d = self.headers.len() - k; self.headers.drain(..d); self.hashes.drain(..d); self.base += d as u32; } }
    }
    pub fn tip(&self) -> [u8; 32] { *self.hashes.last().unwrap() }
    pub fn median_time(&self) -> u32 {
        let mut t: Vec<u32> = self.headers.iter().rev().take(11).map(|h| h.time).collect();
        t.sort_unstable();
        t[t.len() / 2]
    }
    /// Validate and apply the state transition without committing. Returns the new state.
    pub fn check(&self, b: &Block, now: u32) -> Result<State, &'static str> {
        let p = &self.params;
        let height = self.height() + 1;
        let h = &b.header;
        if h.prev != self.tip() { return Err("prev hash"); }
        if h.time <= self.median_time() || h.time > now.saturating_add(p.max_future_seconds) { return Err("time"); }
        if h.bits != next_bits(p, &self.headers) && h.bits != relieved_bits(p, &self.headers, h.time) { return Err("bits"); }
        if !h.meets_target() { return Err("pow"); }
        if b.encode().len() > p.max_block_bytes { return Err("block too large"); }
        let ids: Vec<[u8; 32]> = b.txs.iter().map(|t| t.txid()).collect();
        if h.tx_root != root_of(ids.clone()) { return Err("tx root"); }
        // the same transaction twice is never valid (a copy of a fee-paying one would charge its account again)
        if ids.iter().collect::<std::collections::HashSet<_>>().len() != ids.len() { return Err("duplicate transaction"); }
        let payee = match b.txs.first() { Some(Tx::Coinbase { height: ch, payee, .. }) if *ch == height => *payee, _ => return Err("coinbase") };
        if b.txs[1..].iter().any(|t| matches!(t, Tx::Coinbase { .. })) { return Err("second coinbase"); }
        let mut s = self.state.clone();
        s.begin_block(p, height);
        let mut fees = 0u64;
        for t in &b.txs[1..] { fees += s.apply(p, t)?; }
        s.apply_coinbase(p, height, payee, fees)?;
        if s.root() != h.state_root { return Err("state root"); }
        Ok(s)
    }
    pub fn add(&mut self, b: &Block, now: u32) -> Result<(), &'static str> { self.add_at(b, now, None) }
    /// `loc`: where the block sits in the data file, for a file-backed chain.
    pub fn add_at(&mut self, b: &Block, now: u32, loc: Option<(u64, u32)>) -> Result<(), &'static str> {
        let mut s = self.check(b, now)?;
        let height = self.height() + 1;
        self.totals.txs += b.txs.len() as u64 - 1;
        self.totals.pieces += b.txs.iter().filter(|t| matches!(t, Tx::ChequePiece { .. })).count() as u64;
        for e in s.log.drain(..) {
            match &e { Event::Register { .. } => self.totals.registrations += 1, Event::Transfer { .. } => self.totals.transfers += 1, Event::Reward { .. } => self.totals.rewards += 1 }
            let mut ids: Vec<AccountId> = match &e {
                Event::Register { id, .. } => vec![id.clone()],
                Event::Reward { number, .. } => s.numbers.get(number).map(|(id, _)| id.clone()).into_iter().collect(),
                Event::Transfer { from, to, .. } => [Some(from.clone()), s.numbers.get(to).map(|(id, _)| id.clone())].into_iter().flatten().collect(),
            };
            ids.dedup();
            for id in ids {
                let h = self.history.entry(id).or_default();
                if h.len() == HISTORY_CAP { h.pop_front(); }
                h.push_back(Entry { height, event: e.clone() });
            }
        }
        self.state = s;
        self.state.push_hash(&self.params, b.header.hash());   // a registration anchor for the next reg_anchor_window blocks
        self.blocks.push(b, loc);
        self.push_header(b.header.clone());
        Ok(())
    }
    /// Assemble, finalize and mine the next block (miner side).
    pub fn make_block(&self, time: u32, payee: u32, txs: Vec<Tx>) -> Result<Block, &'static str> {
        let mut b = self.template(time, payee, txs)?;
        b.header.mine();
        Ok(b)
    }
    /// The next block with every field set except a valid nonce.
    pub fn template(&self, time: u32, payee: u32, txs: Vec<Tx>) -> Result<Block, &'static str> {
        let p = &self.params;
        let height = self.height() + 1;
        let mut all = vec![Tx::Coinbase { height, payee, message: Vec::new() }];
        all.extend(txs);
        let mut header = Header { version: 1, prev: self.tip(), tx_root: tx_root(&all), state_root: [0; 32], time, bits: relieved_bits(p, &self.headers, time), nonce: 0 };
        let mut s = self.state.clone();
        s.begin_block(p, height);
        let mut fees = 0u64;
        for t in &all[1..] { fees += s.apply(p, t)?; }
        s.apply_coinbase(p, height, payee, fees)?;
        header.state_root = s.root();
        Ok(Block { header, txs: all })
    }
}

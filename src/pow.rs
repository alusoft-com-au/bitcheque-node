//! Proof of work (DESIGN.md §1.1). A table of 2^26 pseudo-random 32-byte elements, the same for EPOCH blocks; a try reads
//! the 32 of them that the block id picks, sums them and hashes the sum. A miner holding the table (2 GiB) spends a few
//! hashes and 32 random reads a try, so the memory system sets the pace, which graphics cards have most of. Without the
//! table an element costs ROUNDS hashes to recompute, 16,000 a try: ROUNDS is what makes a chip built for SHA-256 alone
//! read the table like a card instead of recomputing (at 128 recomputing was the cheaper path; at 512 it is not, and what
//! is left to such a chip is the memory path's few-fold edge, as with Ethash). A node holding nothing recomputes the 32
//! elements it needs, a few milliseconds, from the header alone: its height names the table, and a header is verified
//! once (`verified`). Bitcoin's miners cannot mine this: their chips hash an 80-byte header and nothing else.
use crate::sha256::sha256;
use crate::u256::U256;
use std::collections::{HashSet, VecDeque};
use std::sync::{Mutex, OnceLock};

pub const N: usize = 1 << 26;   // elements in the table: 2 GiB
pub const K: usize = 32;        // elements a try reads
pub const ROUNDS: usize = 512;  // hashes to recompute one element (see above: never lower it)
pub const EPOCH: u32 = 1024;    // blocks a table serves (about 17 hours): miners rebuild theirs then

pub fn epoch(height: u32) -> u32 { height / EPOCH }
pub fn seed(epoch: u32) -> [u8; 32] { let mut m = *b"bitcheque table\0\0\0\0"; m[15..].copy_from_slice(&epoch.to_le_bytes()); sha256(&m) }
/// Element `i` of the table grown from `seed`: ROUNDS chained hashes, each of one 64-byte block, so no midstate can be
/// shared between elements, and a chain cannot be split across cores.
pub fn element(seed: &[u8; 32], i: u32) -> [u8; 32] {
    let mut m = [0u8; 36]; m[..32].copy_from_slice(seed); m[32..].copy_from_slice(&i.to_le_bytes());
    let mut x = sha256(&m);
    for _ in 1..ROUNDS { x = sha256(&x); }
    x
}
/// The K elements a block id reads: 32 words of four hashes, each cut to N (a power of two: no bias).
pub fn indices(id: &[u8; 32]) -> [u32; K] {
    let mut idx = [0u32; K];
    let mut m = [0u8; 33]; m[..32].copy_from_slice(id);
    for c in 0..K / 8 {
        m[32] = c as u8;
        let w = sha256(&m);
        for j in 0..8 { idx[8 * c + j] = u32::from_le_bytes(w[4 * j..4 * j + 4].try_into().unwrap()) & (N as u32 - 1); }
    }
    idx
}
/// The proof-of-work hash of the header with block id `id`, `get` supplying the table's elements (a miner's table, or
/// `element` for a node without one): SHA-256(id ‖ the sum of the K elements as a little-endian 256-bit number).
pub fn hash(id: &[u8; 32], get: &mut dyn FnMut(u32) -> [u8; 32]) -> [u8; 32] {
    let mut f = U256::ZERO;
    for i in indices(id) { f = f.add(&U256::from_le_bytes(&get(i))); }
    let mut m = [0u8; 64]; m[..32].copy_from_slice(id);
    for (k, w) in f.0.iter().enumerate() { m[32 + 8 * k..40 + 8 * k].copy_from_slice(&w.to_le_bytes()); }
    sha256(&m)
}

/// Block ids whose header's work has been checked and holds (a header is verified once, wherever it arrives: a peer, the
/// RPC, the store, a replay; the rest is a lookup). Only what passed is kept: the store remembers bad blocks itself.
const VERIFIED_KEEP: usize = 4096;
static VERIFIED: OnceLock<Mutex<(HashSet<[u8; 32]>, VecDeque<[u8; 32]>)>> = OnceLock::new();
pub fn verified(id: &[u8; 32]) -> bool { VERIFIED.get().is_some_and(|v| v.lock().unwrap().0.contains(id)) }
pub fn remember(id: [u8; 32]) {
    let mut v = VERIFIED.get_or_init(Mutex::default).lock().unwrap();
    if v.0.insert(id) { v.1.push_back(id); if v.1.len() > VERIFIED_KEEP { if let Some(old) = v.1.pop_front() { v.0.remove(&old); } } }
}

/// One epoch's table, for miners. Built on `threads` threads: 2^26 × ROUNDS hashes, a quarter of an hour on a many-core
/// machine, seconds on a graphics card.
pub struct Table { pub epoch: u32, pub cells: Vec<[u8; 32]> }
impl Table {
    pub fn build(epoch: u32, threads: usize) -> Table {
        let s = seed(epoch);
        let mut cells = vec![[0u8; 32]; N];
        let chunk = N.div_ceil(threads.max(1));
        std::thread::scope(|sc| {
            for (t, part) in cells.chunks_mut(chunk).enumerate() {
                let s = &s;
                sc.spawn(move || for (k, c) in part.iter_mut().enumerate() { *c = element(s, (t * chunk + k) as u32); });
            }
        });
        Table { epoch, cells }
    }
    pub fn hash(&self, id: &[u8; 32]) -> [u8; 32] { hash(id, &mut |i| self.cells[i as usize]) }
}

//! Edge node: the node's own Store, mempool and RPC routes, compiled to WebAssembly and driven by a
//! Cloudflare Durable Object (edge/worker.js). It has no sockets and mines only as a backup (`mine`,
//! when the chain has gone quiet and the host is configured to): the host fetches
//! blocks from other nodes' RPC and feeds them in, stores what was accepted, and answers RPC
//! requests through the same `route` the node serves. Inputs go in through `io`, as in wallet-wasm.
//! Blocks live with the host (`host_get`/`host_put`, by height) and state snapshots go to `host_snap`,
//! so memory holds headers and state, and a cold start replays only the blocks after the last snapshot.
use std::sync::atomic::Ordering;
use std::sync::Arc;
use bitcheque::block::{Block, Chain, HostBlocks};
use bitcheque::net::{Node, NOW};
use bitcheque::params::{genesis_message, Params, LOCAL_TIME, TESTNET_TIME};
use bitcheque::store::Store;

static mut IO: Vec<u8> = Vec::new();
static mut BUF: Vec<u8> = Vec::new();   // where the host writes a block it was asked for
static mut NODE: Option<Arc<Node>> = None;
/// Waiting transactions kept: a Durable Object has 128 MB in all, and they are kept decoded, with copies of the state.
const MEMPOOL_BYTES: usize = 8 << 20;

#[link(wasm_import_module = "env")]
extern "C" {
    /// Write the block stored at height `h` with `buf_reserve`, return its length (0: none stored).
    fn host_get(h: u32) -> u32;
    /// Store this block at height `h`, replacing any block there.
    fn host_put(h: u32, ptr: *const u8, len: u32);
    /// Keep this state snapshot (replacing the previous one).
    fn host_snap(ptr: *const u8, len: u32);
}
#[allow(static_mut_refs)]
fn get(h: usize) -> Option<Vec<u8>> { let n = unsafe { host_get(h as u32) } as usize; unsafe { (n > 0 && n <= BUF.len()).then(|| BUF[..n].to_vec()) } }
fn put(h: usize, b: &[u8]) { unsafe { host_put(h as u32, b.as_ptr(), b.len() as u32) } }
fn snap(b: &[u8]) { unsafe { host_snap(b.as_ptr(), b.len() as u32) } }

#[allow(static_mut_refs)]
fn io() -> &'static mut Vec<u8> { unsafe { &mut IO } }
#[allow(static_mut_refs)]
fn node() -> &'static Arc<Node> { unsafe { NODE.as_ref().expect("init first") } }
fn out(s: &str) -> usize { let b = io(); *b = s.as_bytes().to_vec(); b.len() }

#[no_mangle]
pub extern "C" fn io_reserve(len: usize) -> *mut u8 { let b = io(); b.clear(); b.resize(len, 0); b.as_mut_ptr() }
#[no_mangle]
pub extern "C" fn io_ptr() -> *const u8 { io().as_ptr() }
#[no_mangle]
pub extern "C" fn io_len() -> usize { io().len() }
/// For `host_get`: make room for a block of `len` bytes and return where to write it.
#[no_mangle]
#[allow(static_mut_refs)]
pub extern "C" fn buf_reserve(len: usize) -> *mut u8 { unsafe { BUF.clear(); BUF.resize(len, 0); BUF.as_mut_ptr() } }

/// The current Unix time, set by the host before every other call (WebAssembly has no clock).
#[no_mangle]
pub extern "C" fn set_now(t: u32) { NOW.store(t, Ordering::Relaxed) }

/// Start the node: net 0 = the public research network, 1 = a local devnet. io = the last snapshot's
/// length (u32 LE), the snapshot, then the stored headers from block 1 (112 bytes each); empty for a
/// fresh node. A snapshot is taken every `every` blocks. Returns the restored height + 1 (0: failed);
/// the host then adds the blocks it stored above that height.
#[no_mangle]
pub extern "C" fn open(net: u32, every: u32) -> u32 {
    let (p, t) = if net == 1 { (Params::local(), LOCAL_TIME) } else { (Params::testnet(), TESTNET_TIME) };
    let g = Chain::genesis(&p, t, &genesis_message(&p));
    let raw = std::mem::take(io());
    let n = if raw.len() >= 4 { u32::from_le_bytes(raw[..4].try_into().unwrap()) as usize } else { 0 };
    let (sn, headers) = if n > 0 && raw.len() >= 4 + n { (Some(&raw[4..4 + n]), &raw[4 + n..]) } else { (None, &raw[raw.len().min(4 + n)..]) };
    let Ok(store) = Store::open_host(p, &g, HostBlocks { get, put }, sn, headers, every, snap) else { return 0 };
    let h = store.chain.height();
    let node = Node::new(store);
    node.set_mempool_cap(MEMPOOL_BYTES);
    unsafe { NODE = Some(node) };
    h + 1
}

#[no_mangle]
pub extern "C" fn height() -> u32 { node().height() }

/// io = an encoded block. 1 = accepted, and the main chain moved (extended or reorganised); 3 = kept as a side block;
/// 2 = already known; 0 = refused, with the reason in io. Main-chain blocks reach the host through `host_put`.
#[no_mangle]
pub extern "C" fn add_block() -> u32 {
    let Ok(b) = Block::decode(io()) else { out("bad block"); return 0 };
    match node().submit_block(&b, None) { Ok(true) => 1, Ok(false) => 3, Err("known") => 2, Err(e) => { out(e); 0 } }
}

/// io = "METHOD /path\n" then the body -> io = the status code, a newline, then the reply text.
#[no_mangle]
pub extern "C" fn rpc() -> usize {
    let req = String::from_utf8_lossy(io()).into_owned();
    let (line, body) = req.split_once('\n').unwrap_or((&req, ""));
    let (method, path) = line.split_once(' ').unwrap_or((line, "/"));
    match node().route(method, path, body) { Ok(t) => out(&format!("200\n{t}")), Err(e) => out(&format!("400\n{e}")) }
}

/// Seconds since the tip block's timestamp: how long the chain has been quiet.
#[no_mangle]
pub extern "C" fn quiet() -> u32 {
    let t = node().store.lock().unwrap().chain.headers.last().map_or(0, |h| h.time);
    bitcheque::net::now().saturating_sub(t)
}

/// The backup miner, for when nobody else is mining: build a template paying `payee` and try nonces
/// `start .. start + tries`. Each call takes a fresh template (the tip or the time may have moved), and every
/// try is an independent chance, so the host just moves `start` on. 1 = a block was found and accepted, with
/// its hex in io for the host to pass on; 0 = none in this range; 2 = no template (reason in io).
#[no_mangle]
pub extern "C" fn mine(payee: u32, start: u32, tries: u32) -> u32 {
    let n = node();
    let mut b = match n.template(payee) { Ok(b) => b, Err(e) => { out(e); return 2 } };
    for k in 0..tries {
        b.header.nonce = start.wrapping_add(k);
        if b.header.meets_target() {
            return match n.submit_block(&b, None) { Ok(true) => { out(&bitcheque::crypto::hex(&b.encode())); 1 } Ok(false) => { out("side block"); 2 } Err(e) => { out(e); 2 } };
        }
    }
    0
}

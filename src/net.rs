//! Peer-to-peer layer (DESIGN.md §7, minus transport encryption for now): framed messages
//! over TCP, one reader thread per peer, block and transaction relay, linear initial sync,
//! and peer discovery the way Bitcoin does it: seed nodes compiled in, `getaddr`/`addr`
//! gossip, an address book saved next to the data file, and about eight outbound connections.
//! Frame: magic(4) | type(1) | length(u32 LE) | payload.
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use crate::block::Block;
use crate::params::Params;
use crate::state::State;
use crate::store::{Accepted, Store};
use crate::tx::{Tx, R};

const HELLO: u8 = 0;      // height u32, tip hash
const GET_BLOCKS: u8 = 1; // from height u32
const BLOCK: u8 = 2;      // encoded block
const TX: u8 = 3;         // encoded tx
const ADDR: u8 = 4;       // known peer addresses, "host:port" lines
const GET_ADDR: u8 = 5;   // empty: please send ADDR
const BATCH: usize = 500; // blocks per GET_BLOCKS reply
const MAX_FRAME: usize = 9_000_000;
const MAX_OUTBOUND: usize = 8;   // connections this node keeps dialling on its own
const MAX_BOOK: usize = 1000;    // addresses remembered
const ADDR_REPLY: usize = 50;    // addresses shared per GET_ADDR
const GIVE_UP: u32 = 3;          // failed dials before an address is forgotten
const MAX_INBOUND: usize = 125;  // inbound connections accepted (Bitcoin's default)
const MAX_PER_IP: usize = 4;     // connections from one address
const MAX_PER_GROUP: usize = 8;  // ...and from one /24 (IPv4) or /64 (IPv6)
const BOOK_PER_GROUP: usize = 8; // addresses remembered per /16 (IPv4) or /32 (IPv6): one network cannot fill the book
const HELLO_WAIT: Duration = Duration::from_secs(10);  // a new connection that has not said HELLO by then (in all) is dropped
const HELLO_MAX: usize = 200;    // ...and its HELLO frame may be no longer than this (height, tip, advertised address)
const IDLE: Duration = Duration::from_secs(600);       // after HELLO, the longest wait for a frame to start
const FRAME_WAIT: Duration = Duration::from_secs(120); // ...and once started, the longest it may take to arrive in full
const DIAL_WAIT: Duration = Duration::from_secs(3);    // outbound dials, made in parallel, so one round never takes long
const STRIKES: u32 = 3;          // bad messages before a peer is dropped
const GET_BLOCKS_GAP: Duration = Duration::from_millis(200); // fastest a peer may ask for the next batch
const QUEUE_BYTES: usize = 64 << 20;   // bytes waiting to be written to one peer; past this, messages to it are dropped
const QUEUE_FRAMES: usize = 4096;      // frames waiting to be written to one peer
const STALL: Duration = Duration::from_secs(30);       // a sync source must raise our height by PROGRESS blocks (or all it
const PROGRESS: u32 = 50;                              // has left) every STALL, or it is replaced: a trickle is not progress
const SYNC_AHEAD: u32 = 6;                             // no templates while a usable peer is this far ahead of us
const BAR: Duration = Duration::from_secs(600);        // ...and not chosen again for this long
const BAN: Duration = Duration::from_secs(1800);       // a misbehaving peer's address is refused for this long
const ADDR_GAP: Duration = Duration::from_secs(10);    // fastest a peer's ADDR messages are read
const MEMPOOL_BYTES: usize = 64 << 20; // waiting transactions kept, in encoded bytes (Bitcoin keeps 300 MB); see set_mempool_cap
const HTTP_MAX: usize = 32 << 20;      // largest reply the HTTP client reads
const HTTP_DEADLINE: Duration = Duration::from_secs(60);   // ...and the longest it waits for one, in all
const UPSTREAM_QUEUE: usize = 1000;    // posts waiting for one upstream; past this the newest are dropped (the pull catches up)
const BAD_TXS: usize = 4096;           // txids that can never be valid (failed a stateless check), remembered
const TPL_PAYEES: usize = 16;          // templates kept per tip and mempool, one per payee

/// Seed nodes a fresh node dials when it knows nobody else (DESIGN.md §7). Placeholders: the
/// project has no domain yet, so these names do not resolve and a node just moves on.
pub fn seeds(magic: &[u8; 4]) -> &'static [&'static str] {
    match magic[3] {
        0x00 => &["seed1.bitcheque.example:8730", "seed2.bitcheque.example:8730"],
        0x01 => &[],   // the research network's seeds are the edge nodes, reached over HTTP (http_seeds)
        0x02 => &["127.0.0.1:18441"],   // --local: the first node of a devnet on this machine
        _ => &[],
    }
}
/// The research network's seed nodes: the edge nodes on Cloudflare (bitcheque-node/edge), which speak only the HTTP
/// RPC, not this TCP protocol. A node follows them as upstreams (`follow`) unless told otherwise.
pub fn http_seeds(magic: &[u8; 4]) -> &'static [&'static str] {
    match magic[3] {
        0x01 => &["node-ap.bitcheque.org:80", "node-us.bitcheque.org:80", "node-eu.bitcheque.org:80", "node-oc.bitcheque.org:80", "node-sa.bitcheque.org:80"],
        _ => &[],
    }
}
/// `from` for blocks pulled from an upstream: relayed to peers, never pushed back up.
const FROM_UPSTREAM: u64 = u64::MAX - 1;
const UPSTREAM_BATCH: u32 = 2000;   // blocks pulled from an upstream per round

/// A plain HTTP/1.0 request to a node's RPC at "host:port" (no TLS: blocks and transactions check themselves, so a
/// party in between can at most withhold them, or lie about what it has not shown). The reply body, or an error with
/// the status line. A reply is read up to HTTP_MAX bytes within HTTP_DEADLINE, so a hostile server cannot exhaust
/// memory or hold the caller forever. Text from the server is cleaned of control characters before it is shown.
pub fn http(addr: &str, method: &str, path: &str, body: &str) -> Result<String, String> {
    let sa = addr.to_socket_addrs().map_err(|e| format!("{addr}: {e}"))?.next().ok_or(format!("{addr}: no address"))?;
    let mut s = TcpStream::connect_timeout(&sa, Duration::from_secs(10)).map_err(|e| format!("{addr}: {e}"))?;
    s.set_write_timeout(Some(Duration::from_secs(30))).ok();
    write!(s, "{method} {path} HTTP/1.0\r\nHost: {addr}\r\nContent-Length: {}\r\n\r\n{body}", body.len()).map_err(|e| e.to_string())?;
    let (start, mut out, mut buf) = (Instant::now(), Vec::new(), [0u8; 16384]);
    loop {
        let left = HTTP_DEADLINE.checked_sub(start.elapsed()).filter(|d| !d.is_zero()).ok_or(format!("{addr}: reply too slow"))?;
        s.set_read_timeout(Some(left.min(Duration::from_secs(30)))).ok();
        match s.read(&mut buf) { Ok(0) => break, Ok(n) => out.extend_from_slice(&buf[..n]), Err(e) => return Err(format!("{addr}: {e}")) }
        if out.len() > HTTP_MAX { return Err(format!("{addr}: reply too large")); }
    }
    let out = String::from_utf8_lossy(&out);
    let (head, text) = out.split_once("\r\n\r\n").ok_or("bad reply")?;
    if head.split_whitespace().nth(1) == Some("200") { Ok(text.to_string()) } else { Err(format!("{path}: {}", clean(text.trim()))) }
}

/// Text from another machine, safe to print to a terminal: control characters (escape sequences) become '?', and
/// invisible format characters (bidirectional overrides that reorder what is shown, zero-width ones) are dropped.
pub fn clean(s: &str) -> String {
    s.chars().filter(|c| !matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{206F}' | '\u{FEFF}'))
        .map(|c| if c.is_control() && c != '\n' { '?' } else { c }).collect()
}

/// The network an address belongs to for diversity limits: /16 or /24 of IPv4, /32 or /64 of IPv6 (`wide` picks the first).
fn group(ip: std::net::IpAddr, wide: bool) -> Vec<u8> {
    match ip {
        std::net::IpAddr::V4(a) => a.octets()[..if wide { 2 } else { 3 }].to_vec(),
        std::net::IpAddr::V6(a) => match a.to_ipv4_mapped() { Some(v4) => group(std::net::IpAddr::V4(v4), wide), None => a.octets()[..if wide { 4 } else { 8 }].to_vec() },
    }
}
/// An address another node may pass us: a public IP literal (no names to look up, no private or loopback hosts).
fn public_ip(a: &str) -> Option<std::net::IpAddr> {
    let ip = a.parse::<SocketAddr>().ok()?.ip();
    // an IPv4 address written as IPv6 (::ffff:10.0.0.1) is judged as the IPv4 address it reaches
    let v = match ip { std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, std::net::IpAddr::V4), x => x };
    let ok = match v {
        std::net::IpAddr::V4(v) => !(v.is_private() || v.is_loopback() || v.is_link_local() || v.is_unspecified() || v.is_broadcast() || v.is_documentation() || v.octets()[0] == 0 || v.octets()[0] >= 224 || (v.octets()[0] == 100 && v.octets()[1] & 0xC0 == 64)),
        std::net::IpAddr::V6(v) => !(v.is_loopback() || v.is_unspecified() || v.is_multicast() || (v.segments()[0] & 0xfe00) == 0xfc00 || (v.segments()[0] & 0xffc0) == 0xfe80 || (v.segments()[0], v.segments()[1]) == (0x2001, 0xdb8)),
    };
    ok.then_some(ip)
}
/// What a ban applies to: an IPv4 address, or the /64 an IPv6 address is in (one machine has a whole /64).
fn ban_key(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip { std::net::IpAddr::V6(a) if a.to_ipv4_mapped().is_none() => { let s = a.segments(); std::net::IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0)) } x => x }
}
/// A cheap random number (no crypto needed): for picking which addresses to share, dial or evict.
fn rand64() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64));
    h.finish()
}
fn shuffle<T>(v: &mut [T]) { for i in (1..v.len()).rev() { v.swap(i, rand64() as usize % (i + 1)); } }

/// "host:port" with a numeric port and no spaces or control characters.
pub fn valid_addr(a: &str) -> bool {
    a.len() <= 128 && a.rsplit_once(':').map_or(false, |(h, p)| !h.is_empty() && p.parse::<u16>().is_ok()) && a.chars().all(|c| c.is_ascii_graphic())
}

#[cfg(not(target_arch = "wasm32"))]
pub fn now() -> u32 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as u32 }
/// WebAssembly has no system clock: the host (the edge node) sets the time before each call.
#[cfg(target_arch = "wasm32")]
pub static NOW: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
#[cfg(target_arch = "wasm32")]
pub fn now() -> u32 { NOW.load(Ordering::Relaxed) }

/// Waiting transactions, oldest first, with their txids (an O(1) duplicate check) and a running total of their encoded
/// bytes. `version` changes with every change (for the template and /mempool caches).
#[derive(Default)]
pub struct Mempool { txs: Vec<Tx>, meta: Vec<([u8; 32], usize)>, ids: HashSet<[u8; 32]>, pub bytes: usize, pub version: usize }
impl std::ops::Deref for Mempool { type Target = Vec<Tx>; fn deref(&self) -> &Vec<Tx> { &self.txs } }
impl Mempool {
    pub fn push(&mut self, t: Tx) -> bool { let (id, n) = (t.txid(), t.encode().len()); self.put(t, id, n) }
    fn put(&mut self, t: Tx, id: [u8; 32], n: usize) -> bool {
        if !self.ids.insert(id) { return false; }
        self.txs.push(t); self.meta.push((id, n)); self.bytes += n; self.version += 1;
        true
    }
    pub fn has(&self, id: &[u8; 32]) -> bool { self.ids.contains(id) }
    fn retain(&mut self, mut keep: impl FnMut(&Tx, &[u8; 32]) -> bool) {
        let (txs, meta) = (std::mem::take(&mut self.txs), std::mem::take(&mut self.meta));
        for (t, (id, n)) in txs.into_iter().zip(meta) {
            if keep(&t, &id) { self.txs.push(t); self.meta.push((id, n)); } else { self.ids.remove(&id); self.bytes -= n; }
        }
        self.version += 1;
    }
    fn take(&mut self) -> Vec<Tx> { self.ids.clear(); self.meta.clear(); self.bytes = 0; self.version += 1; std::mem::take(&mut self.txs) }
}

/// A template cache: the transactions chosen for (tip, mempool version, time), and the blocks built from them per payee.
struct Tpl { key: ([u8; 32], usize, u32), txs: Vec<Tx>, made: Vec<(u32, Block)> }

/// One connection. Messages to it go through a bounded queue drained by its own writer thread,
/// so no other thread ever blocks on a slow or silent peer (Bitcoin Core's per-peer send buffer).
struct Peer {
    id: u64,
    stream: Mutex<TcpStream>,          // kept to shut the connection down
    out: SyncSender<Vec<u8>>, queued: Arc<AtomicUsize>,
    addr: Mutex<Option<String>>,       // dialled address, or what an inbound peer advertised from its own IP
    outbound: bool, ip: Option<std::net::IpAddr>,
    height: Mutex<u32>,                // the best height it told us, or reached while serving us
    barred: Mutex<Option<Instant>>,    // not to be used as a sync source before this
    got: AtomicUsize,                  // blocks received from it since we last asked it for a batch
}

pub struct Node {
    pub store: Mutex<Store>,
    pub mempool: Mutex<Mempool>,
    peers: Mutex<Vec<Arc<Peer>>>,
    next_id: Mutex<u64>,
    magic: [u8; 4],
    book: Mutex<BTreeMap<String, u32>>, // address -> failed dials in a row
    book_path: Mutex<Option<PathBuf>>,
    advertise: Mutex<Option<String>>,   // our own reachable address, told to peers in HELLO
    sync: Mutex<Option<(u64, u32, std::time::Instant)>>,   // (peer, our height when its window started, when): the one source we pull batches from
    pub rpc_limit: Mutex<std::collections::HashMap<std::net::IpAddr, (u32, std::time::Instant)>>,
    pub top_cache: Mutex<Option<(u32, String, Vec<String>)>>,   // height, header, ranked rows
    next: Mutex<Option<State>>,        // the tip state with the mempool applied; None = rebuild on next use
    banned: Mutex<HashMap<std::net::IpAddr, Instant>>,
    strikes: Mutex<HashMap<std::net::IpAddr, (u32, Instant)>>,   // bad messages per address (ban_key), since when
    tried: Mutex<HashSet<String>>,     // addresses we dialled that answered with HELLO: dialled before untried ones
    bad_txs: Mutex<(HashMap<[u8; 32], &'static str>, VecDeque<[u8; 32]>)>,   // txids that can never be valid -> why, oldest first
    pub mempool_text: Mutex<Option<((usize, [u8; 32]), String)>>,   // /mempool's reply for (mempool version, tip)
    params: Params,
    upstream: Mutex<Vec<SyncSender<(&'static str, String)>>>,   // per upstream: (path, body) to POST to it, in order
    mempool_cap: AtomicUsize,
    tpl_cache: Mutex<Option<Tpl>>,
}

/// Queue a message for a peer. Never blocks: false when the peer's queue is full (it is not reading).
fn send(peer: &Peer, magic: &[u8; 4], kind: u8, payload: &[u8]) -> bool {
    let len = 9 + payload.len();
    if peer.queued.load(Ordering::Relaxed) + len > QUEUE_BYTES { return false; }
    let mut f = Vec::with_capacity(len);
    f.extend_from_slice(magic); f.push(kind); f.extend_from_slice(&(payload.len() as u32).to_le_bytes()); f.extend_from_slice(payload);
    peer.queued.fetch_add(len, Ordering::Relaxed);
    if peer.out.try_send(f).is_err() { peer.queued.fetch_sub(len, Ordering::Relaxed); return false; }
    true
}
/// Fill `buf` by the instant `by`, however the bytes are paced (a per-read timeout alone lets a trickle last forever).
fn read_by(s: &mut TcpStream, buf: &mut [u8], by: Instant) -> std::io::Result<()> {
    let mut i = 0;
    while i < buf.len() {
        let left = by.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()).ok_or(std::io::ErrorKind::TimedOut)?;
        s.set_read_timeout(Some(left))?;
        match s.read(&mut buf[i..]) { Ok(0) => return Err(std::io::ErrorKind::UnexpectedEof.into()), Ok(n) => i += n, Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {} Err(e) => return Err(e) }
    }
    Ok(())
}
/// One frame, which must start by `start_by`. Before HELLO (`hello`) the whole frame must be in by then, and only a
/// short HELLO is read at all; after it, a frame once started must be complete within FRAME_WAIT.
fn recv(stream: &mut TcpStream, magic: &[u8; 4], start_by: Instant, hello: bool) -> std::io::Result<(u8, Vec<u8>)> {
    let mut head = [0u8; 9];
    read_by(stream, &mut head[..1], start_by)?;
    let by = if hello { start_by } else { Instant::now() + FRAME_WAIT };
    read_by(stream, &mut head[1..], by)?;
    if head[..4] != *magic { return Err(std::io::Error::other("wrong network")); }
    let len = u32::from_le_bytes(head[5..9].try_into().unwrap()) as usize;
    if hello && (head[4] != HELLO || len > HELLO_MAX) { return Err(std::io::Error::other("no hello")); }
    if len > MAX_FRAME { return Err(std::io::Error::other("frame too large")); }
    // grow as the bytes arrive instead of trusting the claimed length up front
    let mut payload = Vec::new();
    while payload.len() < len { let k = payload.len(); payload.resize(k + (len - k).min(1 << 16), 0); read_by(stream, &mut payload[k..], by)?; }
    Ok((head[4], payload))
}

impl Node {
    pub fn new(store: Store) -> Arc<Node> {
        let magic = store.chain.params.magic;
        let params = store.chain.params.clone();
        Arc::new(Node { store: Mutex::new(store), mempool: Mutex::default(), peers: Mutex::new(Vec::new()), next_id: Mutex::new(1), magic,
                        book: Mutex::new(BTreeMap::new()), book_path: Mutex::new(None), advertise: Mutex::new(None),
                        sync: Mutex::new(None), rpc_limit: Mutex::new(std::collections::HashMap::new()), top_cache: Mutex::new(None),
                        next: Mutex::new(None), banned: Mutex::default(), strikes: Mutex::default(), tried: Mutex::default(), bad_txs: Mutex::default(),
                        mempool_text: Mutex::new(None), params, upstream: Mutex::new(Vec::new()),
                        mempool_cap: AtomicUsize::new(MEMPOOL_BYTES), tpl_cache: Mutex::new(None) })
    }
    /// Keep at most this many bytes of waiting transactions (the edge node, with 128 MB in all, keeps far fewer).
    pub fn set_mempool_cap(&self, bytes: usize) { self.mempool_cap.store(bytes, Ordering::Relaxed); }
    pub fn height(&self) -> u32 { self.store.lock().unwrap().chain.height() }
    /// The address other nodes can reach us on; sent in HELLO so peers can pass it around.
    pub fn set_advertise(&self, addr: &str) { if valid_addr(addr) { *self.advertise.lock().unwrap() = Some(addr.to_string()); } }
    /// Remember addresses in this file across restarts (one per line).
    pub fn set_book_path(&self, path: PathBuf) {
        if let Ok(text) = std::fs::read_to_string(&path) {
            let mut b = self.book.lock().unwrap();
            for l in text.lines().map(str::trim).filter(|l| valid_addr(l)).take(MAX_BOOK) { b.entry(l.to_string()).or_insert(0); }
        }
        *self.book_path.lock().unwrap() = Some(path);
    }
    pub fn known_addrs(&self) -> Vec<String> { self.book.lock().unwrap().keys().cloned().collect() }
    /// An address a peer told us about: only a public IP literal (a local devnet may use loopback, and `seen` marks one
    /// we saw the peer connect from), and only a few per network, so gossip can neither point us at private or
    /// arbitrary hosts nor fill the book from one network.
    fn add_addr(&self, a: &str, seen: bool) -> bool {
        if !valid_addr(a) || self.advertise.lock().unwrap().as_deref() == Some(a) { return false; }
        let devnet = self.magic[3] == 0x02;
        let ip = match public_ip(a) { Some(ip) => ip, None if devnet || seen => match a.parse::<SocketAddr>() { Ok(s) => s.ip(), Err(_) => return false }, None => return false };
        let mut b = self.book.lock().unwrap();
        if b.contains_key(a) { return false; }
        // one entry per IP (not one host on many ports), except loopback, where a devnet runs many nodes
        if !devnet && !ip.is_loopback() && b.keys().any(|k| k.parse::<SocketAddr>().is_ok_and(|s| s.ip() == ip)) { return false; }
        let g = group(ip, true);
        if !devnet && b.keys().filter(|k| k.parse::<SocketAddr>().is_ok_and(|s| group(s.ip(), true) == g)).count() >= BOOK_PER_GROUP { return false; }
        if b.len() >= MAX_BOOK {
            // full: replace a random entry, so nobody can fill the book once and keep it (Bitcoin's addrman evicts too)
            let k = rand64() as usize % b.len();
            if let Some(old) = b.keys().nth(k).cloned() { if seeds(&self.magic).contains(&old.as_str()) { return false; } b.remove(&old); }
        }
        b.insert(a.to_string(), 0);
        true
    }
    /// One bad message from `ip`, counted per address (an IPv6 /64) for BAN, not per connection, so reconnecting does not
    /// start afresh. True from the STRIKES-th on: drop the peer, and refuse the address for BAN (loopback is never
    /// refused, as devnets run many nodes on one machine, but it is still dropped).
    pub fn strike(&self, ip: std::net::IpAddr) -> bool {
        let (k, now) = (ban_key(ip), Instant::now());
        let mut s = self.strikes.lock().unwrap();
        if s.len() > 10_000 { s.retain(|_, v| now < v.1 + BAN); }
        let e = s.entry(k).or_insert((0, now));
        if now > e.1 + BAN { *e = (0, now); }
        e.0 += 1;
        if e.0 < STRIKES { return false; }
        if !ip.is_loopback() { self.banned.lock().unwrap().insert(k, now + BAN); }
        true
    }
    fn is_banned(&self, ip: Option<std::net::IpAddr>) -> bool {
        let Some(ip) = ip else { return false };
        let mut b = self.banned.lock().unwrap();
        b.retain(|_, until| *until > Instant::now());
        b.contains_key(&ban_key(ip))
    }
    fn save_book(&self) {
        if let Some(p) = self.book_path.lock().unwrap().clone() {
            let text: String = self.book.lock().unwrap().keys().map(|a| a.clone() + "\n").collect();
            let _ = std::fs::write(p, text);
        }
    }

    /// Accept inbound peers on `addr` in a background thread. Returns the bound address.
    pub fn listen(self: &Arc<Self>, addr: &str) -> std::io::Result<SocketAddr> {
        let l = TcpListener::bind(addr)?;
        let local = l.local_addr()?;
        let node = self.clone();
        std::thread::spawn(move || for s in l.incoming().flatten() {
            let ip = s.peer_addr().ok().map(|a| a.ip());
            let (inbound, same_ip, same_group) = { let ps = node.peers.lock().unwrap();
                (ps.iter().filter(|p| !p.outbound).count(), ps.iter().filter(|p| p.ip == ip && ip.is_some()).count(),
                 ps.iter().filter(|p| ip.is_some() && p.ip.map(|x| group(x, false)) == ip.map(|x| group(x, false))).count()) };
            let local = ip.map_or(false, |a| a.is_loopback());   // many nodes on one machine share 127.0.0.1
            if inbound >= MAX_INBOUND || ((same_ip >= MAX_PER_IP || same_group >= MAX_PER_GROUP) && !local) || node.is_banned(ip) { continue; }   // dropped: over the cap, or banned
            node.add_peer(s);
        });
        Ok(local)
    }
    pub fn connect(self: &Arc<Self>, addr: &str) -> std::io::Result<()> {
        let a = addr.to_socket_addrs()?.next().ok_or_else(|| std::io::Error::other("no address"))?;
        if !a.ip().is_loopback() && self.is_banned(Some(a.ip())) { return Err(std::io::Error::other("banned for a while")); }
        let s = TcpStream::connect_timeout(&a, DIAL_WAIT)?;
        self.add_peer_from(s, Some(addr.to_string()), true);
        Ok(())
    }
    /// Keeps this node connected, forever: redials `pinned` addresses (from --peer) whenever they
    /// drop, fills up to MAX_OUTBOUND connections from the address book, and when the book is
    /// empty and nobody is connected, tries the compiled-in seeds. Runs every `every`.
    pub fn maintain(self: &Arc<Self>, pinned: Vec<String>, every: Duration) {
        let node = self.clone();
        std::thread::spawn(move || { let mut tick = 0u64; loop {
            let connected: Vec<String> = node.peers.lock().unwrap().iter().filter_map(|p| p.addr.lock().unwrap().clone()).collect();
            for a in &pinned {
                if !connected.contains(a) { if let Err(e) = node.connect(a) { eprintln!("peer {a}: {e}"); } }
            }
            let (outbound, mut groups): (usize, Vec<Vec<u8>>) = { let ps = node.peers.lock().unwrap();
                (ps.iter().filter(|p| p.outbound).count(), ps.iter().filter(|p| p.outbound).filter_map(|p| p.ip).filter(|ip| !ip.is_loopback()).map(|ip| group(ip, true)).collect()) };
            if outbound < MAX_OUTBOUND {
                // at random, addresses that answered before (tried) taking turns with new ones, and at most one per
                // network (/16, /32), so neither a run of sorted keys nor one network's many addresses take every slot
                let (mut old, mut new): (Vec<String>, Vec<String>) = { let (b, t) = (node.book.lock().unwrap(), node.tried.lock().unwrap());
                    b.iter().filter(|(a, &f)| f < GIVE_UP && !connected.contains(a) && !pinned.contains(a)).map(|(a, _)| a.clone()).partition(|a| t.contains(a)) };
                if old.is_empty() && new.is_empty() && node.peers.lock().unwrap().is_empty() && pinned.is_empty() {
                    new = seeds(&node.magic).iter().map(|s| s.to_string()).collect();
                }
                shuffle(&mut old); shuffle(&mut new);
                let mut picks = Vec::new();
                let (mut o, mut n) = (old.into_iter(), new.into_iter());
                while picks.len() < MAX_OUTBOUND - outbound {
                    let Some(a) = (if picks.len() % 2 == 0 { o.next().or_else(|| n.next()) } else { n.next().or_else(|| o.next()) }) else { break };
                    let g = a.parse::<SocketAddr>().ok().map(|s| s.ip()).filter(|ip| !ip.is_loopback()).map(|ip| group(ip, true));
                    if g.as_ref().is_some_and(|g| groups.contains(g)) { continue; }
                    groups.extend(g); picks.push(a);
                }
                // dialled in parallel: a round takes one DIAL_WAIT at most, however many addresses are dead
                let dials: Vec<_> = picks.into_iter().map(|a| { let n = node.clone(); std::thread::spawn(move || { let r = n.connect(&a); (a, r) }) }).collect();
                for (a, r) in dials.into_iter().filter_map(|d| d.join().ok()) {
                    match r {
                        Ok(()) => { node.book.lock().unwrap().insert(a, 0); }
                        Err(e) => { let mut b = node.book.lock().unwrap(); let f = b.entry(a.clone()).or_insert(0); *f += 1;
                                    if *f == 1 { eprintln!("peer {a}: {e}"); } if *f >= GIVE_UP && !seeds(&node.magic).contains(&a.as_str()) { b.remove(&a); node.tried.lock().unwrap().remove(&a); } }
                    }
                }
            }
            // still behind someone? pull from a peer that is ahead, replacing a source that is not really delivering
            {
                let my = node.height();
                let pick = {
                    let mut s = node.sync.lock().unwrap();
                    if let Some((id, at, since)) = *s { if since.elapsed() > STALL {
                        let p = node.peers.lock().unwrap().iter().find(|p| p.id == id).cloned();
                        // what it could still give us in a batch; PROGRESS of that (or all of it) per STALL, not a drip
                        let left = p.as_ref().map_or(0, |p| (*p.height.lock().unwrap()).min(at + BATCH as u32).saturating_sub(at));
                        if left == 0 { *s = None; } else if my >= at + left.min(PROGRESS) { *s = Some((id, my, Instant::now())); } else {
                            // it claimed more than it delivered: believe our own height for it, try someone else, and keep its
                            // address away for a while (a fresh connection with a fresh claim would otherwise take the slot again)
                            *s = None;
                            if let Some(p) = p {
                                *p.height.lock().unwrap() = my; *p.barred.lock().unwrap() = Some(Instant::now() + BAR);
                                if let Some(ip) = p.ip.filter(|a| !a.is_loopback()) { node.banned.lock().unwrap().insert(ban_key(ip), Instant::now() + BAR); let _ = p.stream.lock().unwrap().shutdown(std::net::Shutdown::Both); }
                            }
                        }
                    } }
                    if s.is_some() { None } else {
                        let usable = |p: &&Arc<Peer>| p.barred.lock().unwrap().map_or(true, |t| t < Instant::now());
                        let taller = |p: &&Arc<Peer>| *p.height.lock().unwrap() > my + 1;
                        let ps = node.peers.lock().unwrap();
                        // a claimed height is not trusted to choose by (the biggest claim is the easiest lie): a random
                        // peer that is ahead, one we dialled if any; with nobody else left, a barred one gets another go
                        let mut c: Vec<Arc<Peer>> = ps.iter().filter(usable).filter(taller).cloned().collect();
                        if c.is_empty() { c = ps.iter().filter(taller).cloned().collect(); }
                        drop(ps);
                        if c.iter().any(|p| p.outbound) { c.retain(|p| p.outbound); }
                        let best = (!c.is_empty()).then(|| c[rand64() as usize % c.len()].clone());
                        if let Some(p) = &best { *s = Some((p.id, my, std::time::Instant::now())); }
                        best
                    }
                };
                // never hold a lock across network I/O: a peer that stops reading would freeze the node
                if let Some(p) = pick { node.request_from(&p, my + 1); }
            }
            if tick % 6 == 0 { node.save_book(); }
            tick += 1;
            std::thread::sleep(every);
        }});
    }
    pub fn peer_count(&self) -> usize { self.peers.lock().unwrap().len() }
    fn add_peer(self: &Arc<Self>, stream: TcpStream) { self.add_peer_from(stream, None, false) }
    fn add_peer_from(self: &Arc<Self>, stream: TcpStream, addr: Option<String>, outbound: bool) {
        let hello_by = Instant::now() + HELLO_WAIT;   // the whole HELLO by then, however it is paced
        let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));   // a peer that stops reading is dropped, not waited on forever
        let reader = match stream.try_clone() { Ok(r) => r, Err(_) => return };
        let mut writer = match stream.try_clone() { Ok(w) => w, Err(_) => return };
        let id = { let mut n = self.next_id.lock().unwrap(); *n += 1; *n };
        let ip = stream.peer_addr().ok().map(|a| a.ip());
        let (out, rx) = sync_channel::<Vec<u8>>(QUEUE_FRAMES);
        let queued = Arc::new(AtomicUsize::new(0));
        let q = queued.clone();
        std::thread::spawn(move || {
            for f in rx {
                let ok = writer.write_all(&f).is_ok();
                q.fetch_sub(f.len(), Ordering::Relaxed);
                if !ok { let _ = writer.shutdown(std::net::Shutdown::Both); break; }   // the reader then fails and the peer is cleaned up
            }
        });
        let peer = Arc::new(Peer { id, stream: Mutex::new(stream), out, queued, addr: Mutex::new(addr), outbound, ip, height: Mutex::new(0), barred: Mutex::new(None), got: AtomicUsize::new(0) });
        self.peers.lock().unwrap().push(peer.clone());
        let node = self.clone();
        std::thread::spawn(move || {
            // a panic while serving must still free the slot (and the sync source)
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| node.serve(peer.clone(), reader, hello_by)));
            let _ = peer.stream.lock().unwrap().shutdown(std::net::Shutdown::Both);
            node.peers.lock().unwrap().retain(|p| p.id != id);
            { let mut s = node.sync.lock().unwrap(); if s.map_or(false, |(p, _, _)| p == id) { *s = None; } }
        });
    }
    fn hello(&self) -> Vec<u8> {
        let c = &self.store.lock().unwrap().chain;
        let mut v = [c.height().to_le_bytes().as_slice(), &c.tip()].concat();
        if let Some(a) = self.advertise.lock().unwrap().as_ref() { v.extend_from_slice(a.as_bytes()); }
        v
    }
    fn serve(&self, peer: Arc<Peer>, mut reader: TcpStream, hello_by: Instant) -> std::io::Result<()> {
        send(&peer, &self.magic, HELLO, &self.hello());
        let mut peer_height = 0u32;
        let mut last_get = std::time::Instant::now() - GET_BLOCKS_GAP;
        let mut last_addr = Instant::now() - ADDR_GAP;
        let mut last_backoff = (0u32, std::time::Instant::now() - Duration::from_secs(10), 100u32);   // (our height, when, how far) we last stepped back during sync
        let mut said_hello = false;
        loop {
            let (kind, payload) = recv(&mut reader, &self.magic, if said_hello { Instant::now() + IDLE } else { hello_by }, !said_hello)?;
            let mut bad = false;
            match kind {
                HELLO if payload.len() >= 36 && !said_hello => {
                    // once per connection: a peer cannot keep re-claiming a height to hold the sync slot
                    said_hello = true;
                    peer_height = u32::from_le_bytes(payload[..4].try_into().unwrap());
                    *peer.height.lock().unwrap() = peer_height;
                    // a peer we dialled answered: dial it again before untried addresses
                    if peer.outbound { if let Some(a) = peer.addr.lock().unwrap().clone() { let mut t = self.tried.lock().unwrap(); if t.len() < MAX_BOOK { t.insert(a); } } }
                    // only a peer we chose takes the sync slot at once; one that called us waits for maintain's pick
                    let barred = peer.barred.lock().unwrap().is_some_and(|t| t > Instant::now());
                    let want_sync = peer.outbound && !barred && peer_height > self.height() && { let mut s = self.sync.lock().unwrap(); if s.is_none() { *s = Some((peer.id, self.height(), std::time::Instant::now())); true } else { false } };
                    if let Ok(a) = std::str::from_utf8(&payload[36..]) { if !a.is_empty() && valid_addr(a) {
                        // believe an advertised address only when it is the IP the peer is really connecting from;
                        // otherwise a peer could claim honest nodes' addresses and stop us dialling them
                        let own = a.rsplit_once(':').and_then(|(h, _)| h.trim_matches(['[', ']']).parse::<std::net::IpAddr>().ok()).is_some_and(|h| Some(h) == peer.ip);
                        if own {
                            peer.addr.lock().unwrap().get_or_insert_with(|| a.to_string());   // so we never dial a peer that is already connected to us
                            if self.add_addr(a, true) { self.relay(ADDR, a.as_bytes(), Some(peer.id)); }
                        } } }
                    send(&peer, &self.magic, GET_ADDR, &[]);
                    if want_sync { self.request_from(&peer, self.height() + 1); }
                }
                GET_ADDR => {
                    // a random sample, so no address (chosen to sort first, say) spreads further than any other
                    let own = peer.addr.lock().unwrap().clone();
                    let mut list: Vec<String> = self.book.lock().unwrap().keys().filter(|a| Some(a.as_str()) != own.as_deref()).cloned().collect();
                    shuffle(&mut list);
                    list.truncate(ADDR_REPLY);
                    send(&peer, &self.magic, ADDR, list.join("\n").as_bytes());
                }
                ADDR => {
                    if last_addr.elapsed() < ADDR_GAP { continue; }   // a peer may not flood the address book
                    last_addr = Instant::now();
                    if let Ok(text) = std::str::from_utf8(&payload) { for a in text.lines().take(ADDR_REPLY) { self.add_addr(a, false); } }
                }
                GET_BLOCKS if payload.len() == 4 => {
                    if last_get.elapsed() < GET_BLOCKS_GAP { continue; }   // a batch is 500 blocks: faster than this is ignored, not served
                    last_get = std::time::Instant::now();
                    let from = u32::from_le_bytes(payload[..4].try_into().unwrap()) as usize;
                    let (window, at) = { let st = self.store.lock().unwrap(); st.chain.blocks.window(from, BATCH) };   // copy only what is asked for
                    // read a few at a time, and stop once its queue is full (it asks again), so a batch never sits in memory whole
                    let mut i = 0;
                    'batch: while i < BATCH {
                        let chunk = window.read_many(at + i, 16);
                        if chunk.is_empty() { break; }
                        i += chunk.len();
                        for b in chunk { if !send(&peer, &self.magic, BLOCK, &b) { break 'batch; } }
                    }
                }
                BLOCK => {
                    let res = match Block::decode(&payload) { Ok(b) => self.submit_block(&b, Some(peer.id)).map(|_| ()), Err(_) => Err("decode") };
                    let from_source = self.sync.lock().unwrap().is_some_and(|(id, _, _)| id == peer.id);
                    // a reply to our batch request counts whatever became of the block (new, side, already known)
                    if from_source && matches!(res, Ok(()) | Err("known")) {
                        let got = peer.got.fetch_add(1, Ordering::Relaxed) + 1;
                        let my = self.height();
                        { let mut ph = peer.height.lock().unwrap(); if *ph < my { *ph = my; } }
                        let more = {
                            // (the stall clock is maintain's: a block now and then does not hold the slot)
                            let mut s = self.sync.lock().unwrap();
                            if peer_height <= my { if let Some((id, _, _)) = *s { if id == peer.id { *s = None; } } }   // caught up with this source
                            peer_height > my && got >= BATCH
                        };
                        if more { self.request_from(&peer, my + 1); }
                    }
                    match res {
                            Ok(()) => { let my = self.height(); let mut ph = peer.height.lock().unwrap(); if *ph < my { *ph = my; } }
                            Err("prev unknown") if self.sync.lock().unwrap().map_or(false, |(id, _, _)| id == peer.id) && (last_backoff.0 != self.height() || last_backoff.1.elapsed() > Duration::from_secs(1)) => {
                                // our tip is on a fork: fetch from further back, twice as far each time the fork point is not yet reached
                                let depth = if last_backoff.0 == self.height() { last_backoff.2.saturating_mul(2) } else { 100 };
                                last_backoff = (self.height(), std::time::Instant::now(), depth);
                                self.request_from(&peer, self.height().saturating_sub(depth).max(1));
                            }
                            // invalid, not merely unknown: a time too far ahead can be clock skew, one at or below the median cannot
                            Err("pow" | "bits" | "tx root" | "state root" | "decode" | "coinbase" | "block too large" | "duplicate transaction" | "old time" | "bad parent") => bad = true,
                            _ => {}
                    }
                }
                TX => { match Tx::decode(&mut R::new(&payload)) { Ok(t) => { let _ = self.submit_tx(t, Some(peer.id)); } Err(_) => bad = true } }
                _ => bad = true,
            }
            if bad && self.strike(peer.ip.unwrap_or(std::net::Ipv4Addr::UNSPECIFIED.into())) { return Err(std::io::Error::other("misbehaving peer dropped")); }
        }
    }
    fn request_from(&self, peer: &Peer, from: u32) -> bool { peer.got.store(0, Ordering::Relaxed); send(peer, &self.magic, GET_BLOCKS, &from.to_le_bytes()) }
    fn relay(&self, kind: u8, payload: &[u8], except: Option<u64>) {
        let peers: Vec<Arc<Peer>> = self.peers.lock().unwrap().clone();
        for p in peers { if Some(p.id) != except { send(&p, &self.magic, kind, payload); } }
    }
    /// Hand something to the upstreams (POST path body), unless it came from one.
    fn push_up(&self, path: &'static str, body: String, from: Option<u64>) {
        if from == Some(FROM_UPSTREAM) { return; }
        for q in self.upstream.lock().unwrap().iter() { let _ = q.try_send((path, body.clone())); }   // full: dropped, the pull catches up
    }

    /// Follow upstream nodes over their HTTP RPC (the edge nodes speak no TCP): every `every`, pull new blocks from the
    /// first that answers; push every transaction and block this node accepts (from its RPC or its peers) to all of
    /// them, in order. Pulled blocks are relayed to TCP peers too, so this node bridges the two.
    pub fn follow(self: &Arc<Self>, ups: Vec<String>, every: Duration) {
        if ups.is_empty() { return; }
        // one bounded queue and thread per upstream: a slow or dead one delays nobody else, and its backlog stays small
        for up in ups.clone() {
            let (q, rx) = sync_channel::<(&'static str, String)>(UPSTREAM_QUEUE);
            self.upstream.lock().unwrap().push(q);
            std::thread::spawn(move || for (path, body) in rx { if let Err(e) = http(&up, "POST", path, &body) { eprintln!("upstream {up}: {e}"); } });
        }
        let node = self.clone();
        std::thread::spawn(move || loop {
            for up in &ups { match node.pull_from(up) { Ok(()) => break, Err(e) => eprintln!("upstream {up}: {e}") } }
            std::thread::sleep(every);
        });
    }
    /// Fetch the blocks `up` has above our tip, oldest first; on a fork, walk back (up to 200) to where we agree.
    fn pull_from(&self, up: &str) -> Result<(), String> {
        let theirs: u32 = http(up, "GET", "/height", "")?.trim().parse().map_err(|_| "bad height")?;
        let (mut h, mut back, mut n) = (self.height() + 1, 0, 0);
        while h <= theirs && n < UPSTREAM_BATCH {
            let raw = crate::rpc::unhex(http(up, "GET", &format!("/block/{h}"), "")?.trim()).ok_or("bad hex")?;
            let b = Block::decode(&raw).map_err(|e| format!("block {h}: {e}"))?;
            n += 1;
            match self.submit_block(&b, Some(FROM_UPSTREAM)) {
                // the tip moved (extended or reorganised): carry on above it; a side block or a known one: the next height
                Ok(true) => h = self.height() + 1,
                Ok(false) | Err("known") => h += 1,
                Err("prev unknown") if back < 200 && h > 1 => { back += 1; h -= 1; }
                Err(e) => return Err(format!("block {h}: {e}")),
            }
        }
        Ok(())
    }

    /// Store the block, extend or reorganize the chain, fix up the mempool, relay. Ok(true): the main chain changed
    /// (and the block was relayed); Ok(false): kept as a side block (not relayed: nobody needs it unless it wins).
    pub fn submit_block(&self, b: &Block, from: Option<u64>) -> Result<bool, &'static str> {
        let (branch, back) = {
            let mut s = self.store.lock().unwrap();
            match s.accept(b, now())? {
                Accepted::Known => return Err("known"),
                Accepted::Side => return Ok(false),
                Accepted::Extended => {
                    let mut m = self.mempool.lock().unwrap();
                    let ids: HashSet<[u8; 32]> = b.txs.iter().map(|t| t.txid()).collect();
                    m.retain(|_, id| !ids.contains(id));
                    *self.next.lock().unwrap() = Some(Self::evict(&s.chain, &mut m));
                    (Vec::new(), Vec::new())
                }
                Accepted::Reorged(abandoned, fork) => {
                    // the whole new branch goes to the peers, not just this block: side blocks are not relayed, so a
                    // peer may never have seen the earlier ones (at most a batch's worth; a peer missing more asks)
                    // (this block itself, the tip, goes out below as usual)
                    let tip = s.chain.height() as usize;
                    let start = (fork as usize + 1).max(tip.saturating_sub(BATCH - 1));
                    let branch = s.chain.blocks.read_many(start, tip - start).into_iter().take(tip - start).collect();
                    // the abandoned blocks' transactions first (what was waiting may build on them), then what was waiting;
                    // whatever the new branch already holds or no longer allows is dropped, nothing is resubmitted one by one
                    let mut m = self.mempool.lock().unwrap();
                    let old = m.take();
                    let ids: HashSet<[u8; 32]> = abandoned.into_iter().filter_map(|t| { let id = t.txid(); m.push(t).then_some(id) }).collect();
                    for t in old { m.push(t); }
                    *self.next.lock().unwrap() = Some(Self::evict(&s.chain, &mut m));
                    let cap = self.mempool_cap.load(Ordering::Relaxed);
                    if m.bytes > cap { let mut total = 0; m.retain(|t, _| { total += t.encode().len(); total <= cap }); *self.next.lock().unwrap() = None; }
                    // only the abandoned ones go out again: peers already have the rest
                    let back = m.iter().zip(&m.meta).filter(|(_, (id, _))| ids.contains(id)).map(|(t, _)| t.encode()).collect();
                    (branch, back)
                }
            }
        };
        // blocks first, so peers have them before the transactions that follow
        for raw in branch { self.relay(BLOCK, &raw, from); }
        let raw = b.encode();
        self.relay(BLOCK, &raw, from);
        self.push_up("/block", crate::crypto::hex(&raw), from);
        if !back.is_empty() { self.push_up("/tx", back.iter().map(|r| crate::crypto::hex(r)).collect::<Vec<_>>().join("\n"), from); }
        for t in back { self.relay(TX, &t, from); }
        Ok(true)
    }
    /// Drop queued transactions the chain can no longer mine (their account moved on, their cheque
    /// expired...). Without this a dead transaction would sit in memory, and in the explorer, forever.
    /// Returns the next block's state with the survivors applied.
    fn evict(c: &crate::block::Chain, m: &mut Mempool) -> State {
        let mut s = c.state.clone();
        s.begin_block(&c.params, c.height() + 1);
        m.retain(|t, _| s.apply(&c.params, t).is_ok());
        s
    }
    /// The next block's state with every queued transaction applied, rebuilt only after a reorg.
    /// Lock order: store, mempool, next.
    fn next_state<'a>(c: &crate::block::Chain, m: &[Tx], next: &'a mut Option<State>) -> &'a mut State {
        next.get_or_insert_with(|| {
            let mut s = c.state.clone();
            s.begin_block(&c.params, c.height() + 1);
            for x in m { let _ = s.apply(&c.params, x); }
            s
        })
    }
    /// What a transaction can be checked for without the chain, done before the store lock is taken: a registration's
    /// proof of work (against the easiest target there can be) and its batch against its root. Such a failure can never
    /// turn into a success, so the txid is remembered and refused at once if it comes again. Returns the txid.
    fn precheck(&self, t: &Tx) -> Result<[u8; 32], &'static str> {
        let id = t.txid();
        if let Some(e) = self.bad_txs.lock().unwrap().0.get(&id) { return Err(e); }
        if let Tx::RegisterBook { pay: crate::tx::Payment::Pow(anchor, _), .. } = t {
            // the anchor's recency depends on the chain, so it is taken as recent here and checked under the lock
            let mut s = State::new(&self.params);
            s.begin_block(&self.params, 1);
            s.recent.push_back(*anchor);
            if let Err(e) = s.apply(&self.params, t) {
                let mut b = self.bad_txs.lock().unwrap();
                if b.0.insert(id, e).is_none() { b.1.push_back(id); }
                while b.1.len() > BAD_TXS { if let Some(o) = b.1.pop_front() { b.0.remove(&o); } }
                return Err(e);
            }
        }
        Ok(id)
    }
    /// Validate against the tip state plus the current mempool, add, relay. A failed apply leaves
    /// the state untouched, so the cached state stays right either way.
    pub fn submit_tx(&self, t: Tx, from: Option<u64>) -> Result<(), &'static str> { self.submit_txs(vec![t], from).remove(0) }
    /// Several transactions, in order, checked and queued under one lock: a block template sees either none of
    /// them or every one that was accepted, so a cheque's 18 pieces (or a registration and its cheque 0) sent
    /// together land in the same block. One result per transaction; the accepted ones are relayed.
    pub fn submit_txs(&self, txs: Vec<Tx>, from: Option<u64>) -> Vec<Result<(), &'static str>> {
        let mut seen = HashSet::new();
        let pre: Vec<_> = txs.iter().map(|t| if seen.insert(t.txid()) { self.precheck(t) } else { Err("duplicate transaction") }).collect();
        if pre.iter().all(|r| r.is_err()) { return pre.into_iter().map(|r| r.map(|_| ())).collect(); }   // no need for the store
        let (mut out, mut accepted) = (Vec::with_capacity(txs.len()), Vec::new());
        {
            let s = self.store.lock().unwrap(); let c = &s.chain;
            let mut m = self.mempool.lock().unwrap();
            let mut next = self.next.lock().unwrap();
            for (t, pre) in txs.into_iter().zip(pre) {
                let raw = t.encode();
                let r = match pre {
                    Err(e) => Err(e),
                    Ok(_) if m.bytes + raw.len() > self.mempool_cap.load(Ordering::Relaxed) => Err("mempool full"),
                    Ok(id) if m.has(&id) => Err("already in mempool"),
                    Ok(_) => Self::next_state(c, &m, &mut next).apply(&c.params, &t).map(|_| ()),
                };
                if let (Ok(()), Ok(id)) = (r, pre) { m.put(t, id, raw.len()); accepted.push(raw); }
                out.push(r);
            }
        }
        // to the upstreams as one request, so a batch lands in one block there too
        if !accepted.is_empty() { self.push_up("/tx", accepted.iter().map(|r| crate::crypto::hex(r)).collect::<Vec<_>>().join("\n"), from); }
        for raw in accepted { self.relay(TX, &raw, from); }
        out
    }
    /// Dry run: apply `txs` in order on a copy of the next block's state (after the mempool).
    /// Nothing is stored or relayed. Returns one result per transaction: for a cheque piece, the row (digit) its
    /// cell matched, so a wallet can tell a cell copied from the wrong row of the right column. A repeat of an earlier
    /// line is answered "duplicate transaction" without being checked again.
    pub fn check_txs(&self, txs: &[Tx]) -> Vec<Result<Option<u8>, &'static str>> {
        if txs.is_empty() { return Vec::new(); }
        let mut seen = HashSet::new();
        let pre: Vec<_> = txs.iter().map(|t| if seen.insert(t.txid()) { self.precheck(t) } else { Err("duplicate transaction") }).collect();
        if pre.iter().all(|r| r.is_err()) { return pre.into_iter().map(|r| r.map(|_| None)).collect(); }
        let s = self.store.lock().unwrap(); let c = &s.chain;
        let m = self.mempool.lock().unwrap();
        let mut st = Self::next_state(c, &m, &mut self.next.lock().unwrap()).clone();
        txs.iter().zip(pre).map(|(t, pre)| {
            pre?;
            let row = match t { Tx::ChequePiece { account, cheque, column, shares } => st.piece_digit(account, *cheque, *column, shares), _ => None };
            st.apply(&c.params, t).map(|_| row)
        }).collect()
    }
    /// The next block to mine for `payee`, nonce 0: the tip, the time, and waiting transactions oldest
    /// first up to the block size limit. The node does not mine: miners fetch this over RPC
    /// (GET /template/<number>), search nonces themselves and send the block back (POST /block).
    pub fn template(&self, payee: u32) -> Result<Block, &'static str> {
        // never hand out a stale tip while a usable peer is well ahead (a claim alone holds this only until the peer is
        // found not to deliver: maintain then bars it)
        let my = self.height();
        if self.peers.lock().unwrap().iter().any(|p| *p.height.lock().unwrap() > my.saturating_add(SYNC_AHEAD) && p.barred.lock().unwrap().map_or(true, |t| t < Instant::now())) { return Err("syncing"); }
        let st = self.store.lock().unwrap(); let c = &st.chain;
        let m = self.mempool.lock().unwrap();
        // for the same tip, mempool and second the transactions are chosen once, and a block is built once per payee
        // (a few payees kept): a flood of requests, or miners with different payees taking turns, costs one build each
        let key = (c.tip(), m.version, now().max(c.median_time() + 1));
        let mut cache = self.tpl_cache.lock().unwrap();
        if cache.as_ref().map_or(true, |t| t.key != key) {
            let mut s = c.state.clone();
            s.begin_block(&c.params, c.height() + 1);
            // fill up to the block size limit (header and coinbase take well under the margin), oldest first
            let room = c.params.max_block_bytes.saturating_sub(4096);
            let mut used = 0;
            let txs: Vec<Tx> = m.iter().zip(&m.meta).filter(|(t, (_, n))| {
                if used + n + 4 > room || s.apply(&c.params, t).is_err() { return false; }
                used += n + 4; true
            }).map(|(t, _)| t.clone()).collect();
            *cache = Some(Tpl { key, txs, made: Vec::new() });
        }
        let t = cache.as_mut().unwrap();
        if let Some((_, b)) = t.made.iter().find(|(p, _)| *p == payee) { return Ok(b.clone()); }
        let b = c.template(key.2, payee, t.txs.clone())?;
        if t.made.len() >= TPL_PAYEES { t.made.remove(0); }
        t.made.push((payee, b.clone()));
        Ok(b)
    }
}

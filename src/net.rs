//! Peer-to-peer layer (DESIGN.md §7, minus transport encryption for now): framed messages
//! over TCP, one reader thread per peer, block and transaction relay, linear initial sync,
//! and peer discovery the way Bitcoin does it: seed nodes compiled in, `getaddr`/`addr`
//! gossip, an address book saved next to the data file, and about eight outbound connections.
//! Frame: magic(4) | type(1) | length(u32 LE) | payload.
use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use crate::block::Block;
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
const TEMPLATE_REFRESH: u64 = 10; // seconds between template rebuilds while mining
const ADDR_REPLY: usize = 50;    // addresses shared per GET_ADDR
const GIVE_UP: u32 = 3;          // failed dials before an address is forgotten
const MAX_INBOUND: usize = 125;  // inbound connections accepted (Bitcoin's default)
const MAX_PER_IP: usize = 4;     // connections from one address
const STRIKES: u32 = 3;          // bad messages before a peer is dropped
const GET_BLOCKS_GAP: Duration = Duration::from_millis(200); // fastest a peer may ask for the next batch
const QUEUE_BYTES: usize = 64 << 20;   // bytes waiting to be written to one peer; past this, messages to it are dropped
const QUEUE_FRAMES: usize = 4096;      // frames waiting to be written to one peer
const STALL: Duration = Duration::from_secs(30);       // a sync source that delivers nothing new for this long is replaced
const BAR: Duration = Duration::from_secs(600);        // ...and not chosen again for this long
const BAN: Duration = Duration::from_secs(1800);       // a misbehaving peer's address is refused for this long
const ADDR_GAP: Duration = Duration::from_secs(10);    // fastest a peer's ADDR messages are read
const MEMPOOL_BYTES: usize = 64 << 20; // waiting transactions kept, in encoded bytes (Bitcoin keeps 300 MB)

/// Seed nodes a fresh node dials when it knows nobody else (DESIGN.md §7). Placeholders: the
/// project has no domain yet, so these names do not resolve and a node just moves on.
pub fn seeds(magic: &[u8; 4]) -> &'static [&'static str] {
    match magic[3] {
        0x00 => &["seed1.bitcheque.example:8730", "seed2.bitcheque.example:8730"],
        0x01 => &["seed1.bitcheque.example:8731", "seed2.bitcheque.example:8731"],
        0x02 => &["127.0.0.1:18441"],   // --local: the first node of a devnet on this machine
        _ => &[],
    }
}
/// "host:port" with a numeric port and no spaces or control characters.
pub fn valid_addr(a: &str) -> bool {
    a.len() <= 128 && a.rsplit_once(':').map_or(false, |(h, p)| !h.is_empty() && p.parse::<u16>().is_ok()) && a.chars().all(|c| c.is_ascii_graphic())
}

pub fn now() -> u32 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32 }

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
    pub mempool: Mutex<Vec<Tx>>,
    peers: Mutex<Vec<Arc<Peer>>>,
    next_id: Mutex<u64>,
    magic: [u8; 4],
    book: Mutex<BTreeMap<String, u32>>, // address -> failed dials in a row
    book_path: Mutex<Option<PathBuf>>,
    advertise: Mutex<Option<String>>,   // our own reachable address, told to peers in HELLO
    sync: Mutex<Option<(u64, u32, std::time::Instant)>>,   // (peer, our height when we last progressed, when): the one source we pull batches from
    pub rpc_limit: Mutex<std::collections::HashMap<std::net::IpAddr, (u32, std::time::Instant)>>,
    pub top_cache: Mutex<Option<(u32, String, Vec<String>)>>,   // height, header, ranked rows
    next: Mutex<Option<State>>,        // the tip state with the mempool applied; None = rebuild on next use
    mempool_bytes: AtomicUsize,
    banned: Mutex<HashMap<std::net::IpAddr, Instant>>,
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
fn recv(stream: &mut TcpStream, magic: &[u8; 4]) -> std::io::Result<(u8, Vec<u8>)> {
    let mut head = [0u8; 9];
    stream.read_exact(&mut head)?;
    if head[..4] != *magic { return Err(std::io::Error::other("wrong network")); }
    let len = u32::from_le_bytes(head[5..9].try_into().unwrap()) as usize;
    if len > MAX_FRAME { return Err(std::io::Error::other("frame too large")); }
    // grow as the bytes arrive instead of trusting the claimed length up front
    let mut payload = Vec::new();
    stream.take(len as u64).read_to_end(&mut payload)?;
    if payload.len() != len { return Err(std::io::Error::other("truncated frame")); }
    Ok((head[4], payload))
}

impl Node {
    pub fn new(store: Store) -> Arc<Node> {
        let magic = store.chain.params.magic;
        Arc::new(Node { store: Mutex::new(store), mempool: Mutex::new(Vec::new()), peers: Mutex::new(Vec::new()), next_id: Mutex::new(1), magic,
                        book: Mutex::new(BTreeMap::new()), book_path: Mutex::new(None), advertise: Mutex::new(None),
                        sync: Mutex::new(None), rpc_limit: Mutex::new(std::collections::HashMap::new()), top_cache: Mutex::new(None),
                        next: Mutex::new(None), mempool_bytes: AtomicUsize::new(0), banned: Mutex::new(HashMap::new()) })
    }
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
    fn add_addr(&self, a: &str) -> bool {
        if !valid_addr(a) || self.advertise.lock().unwrap().as_deref() == Some(a) { return false; }
        let mut b = self.book.lock().unwrap();
        if b.contains_key(a) { return false; }
        if b.len() >= MAX_BOOK {
            // full: replace a random entry, so nobody can fill the book once and keep it (Bitcoin's addrman evicts too)
            let k = (Instant::now().elapsed().subsec_nanos() as usize ^ a.len().wrapping_mul(2654435761) ^ now() as usize) % b.len();
            if let Some(old) = b.keys().nth(k).cloned() { if seeds(&self.magic).contains(&old.as_str()) { return false; } b.remove(&old); }
        }
        b.insert(a.to_string(), 0);
        true
    }
    fn is_banned(&self, ip: Option<std::net::IpAddr>) -> bool {
        let Some(ip) = ip else { return false };
        let mut b = self.banned.lock().unwrap();
        b.retain(|_, until| *until > Instant::now());
        b.contains_key(&ip)
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
            let (inbound, same_ip) = { let ps = node.peers.lock().unwrap(); (ps.iter().filter(|p| !p.outbound).count(), ps.iter().filter(|p| p.ip == ip && ip.is_some()).count()) };
            let local = ip.map_or(false, |a| a.is_loopback());   // many nodes on one machine share 127.0.0.1
            if inbound >= MAX_INBOUND || (same_ip >= MAX_PER_IP && !local) || node.is_banned(ip) { continue; }   // dropped: over the cap, or banned
            node.add_peer(s);
        });
        Ok(local)
    }
    pub fn connect(self: &Arc<Self>, addr: &str) -> std::io::Result<()> {
        let a = addr.to_socket_addrs()?.next().ok_or_else(|| std::io::Error::other("no address"))?;
        let s = TcpStream::connect_timeout(&a, Duration::from_secs(5))?;
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
            let outbound = node.peers.lock().unwrap().iter().filter(|p| p.outbound).count();
            if outbound < MAX_OUTBOUND {
                let mut candidates: Vec<String> = node.book.lock().unwrap().iter().filter(|(a, &f)| f < GIVE_UP && !connected.contains(a) && !pinned.contains(a)).map(|(a, _)| a.clone()).collect();
                if candidates.is_empty() && node.peers.lock().unwrap().is_empty() && pinned.is_empty() {
                    candidates = seeds(&node.magic).iter().map(|s| s.to_string()).collect();
                }
                let n = candidates.len(); if n > 0 { candidates.rotate_left(tick as usize % n); }
                for a in candidates.into_iter().take(MAX_OUTBOUND - outbound) {
                    match node.connect(&a) {
                        Ok(()) => { node.book.lock().unwrap().insert(a, 0); }
                        Err(e) => { let mut b = node.book.lock().unwrap(); let f = b.entry(a.clone()).or_insert(0); *f += 1;
                                    if *f == 1 { eprintln!("peer {a}: {e}"); } if *f >= GIVE_UP && !seeds(&node.magic).contains(&a.as_str()) { b.remove(&a); } }
                    }
                }
            }
            // still behind someone? pull from the highest peer, dropping a source that stopped delivering
            {
                let my = node.height();
                let pick = {
                    let mut s = node.sync.lock().unwrap();
                    if let Some((id, at, since)) = *s { if my == at && since.elapsed() > STALL {
                        // it claimed more than it delivered: believe our own height for it, and try someone else for a while
                        *s = None;
                        if let Some(p) = node.peers.lock().unwrap().iter().find(|p| p.id == id) { *p.height.lock().unwrap() = my; *p.barred.lock().unwrap() = Some(Instant::now() + BAR); }
                    } }
                    if s.is_some() { None } else {
                        let usable = |p: &&Arc<Peer>| p.barred.lock().unwrap().map_or(true, |t| t < Instant::now());
                        let taller = |p: &&Arc<Peer>| *p.height.lock().unwrap() > my + 1;
                        let ps = node.peers.lock().unwrap();
                        // prefer peers not recently barred; with nobody else left, give a barred one another go
                        let best = ps.iter().filter(usable).filter(taller).max_by_key(|p| *p.height.lock().unwrap())
                            .or_else(|| ps.iter().filter(taller).max_by_key(|p| *p.height.lock().unwrap())).cloned();
                        drop(ps);
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
        let _ = stream.set_read_timeout(Some(Duration::from_secs(600)));
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
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| node.serve(peer.clone(), reader)));
            if matches!(&r, Ok(Err(e)) if e.to_string() == "misbehaving peer dropped") {
                if let Some(ip) = ip.filter(|a| !a.is_loopback()) { node.banned.lock().unwrap().insert(ip, Instant::now() + BAN); }
            }
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
    fn serve(&self, peer: Arc<Peer>, mut reader: TcpStream) -> std::io::Result<()> {
        send(&peer, &self.magic, HELLO, &self.hello());
        let mut peer_height = 0u32;
        let (mut strikes, mut last_get) = (0u32, std::time::Instant::now() - GET_BLOCKS_GAP);
        let mut last_addr = Instant::now() - ADDR_GAP;
        let mut last_backoff = (0u32, std::time::Instant::now() - Duration::from_secs(10), 100u32);   // (our height, when, how far) we last stepped back during sync
        loop {
            let (kind, payload) = recv(&mut reader, &self.magic)?;
            let mut bad = false;
            match kind {
                HELLO if payload.len() >= 36 => {
                    peer_height = u32::from_le_bytes(payload[..4].try_into().unwrap());
                    *peer.height.lock().unwrap() = peer_height;
                    let want_sync = peer_height > self.height() && { let mut s = self.sync.lock().unwrap(); if s.is_none() { *s = Some((peer.id, self.height(), std::time::Instant::now())); true } else { false } };
                    if let Ok(a) = std::str::from_utf8(&payload[36..]) { if !a.is_empty() && valid_addr(a) {
                        // believe an advertised address only when it is the IP the peer is really connecting from;
                        // otherwise a peer could claim honest nodes' addresses and stop us dialling them
                        let own = a.rsplit_once(':').and_then(|(h, _)| h.trim_matches(['[', ']']).parse::<std::net::IpAddr>().ok()).is_some_and(|h| Some(h) == peer.ip);
                        if own {
                            peer.addr.lock().unwrap().get_or_insert_with(|| a.to_string());   // so we never dial a peer that is already connected to us
                            if self.add_addr(a) { self.relay(ADDR, a.as_bytes(), Some(peer.id)); }
                        } } }
                    send(&peer, &self.magic, GET_ADDR, &[]);
                    if want_sync { self.request_from(&peer, self.height() + 1); }
                }
                GET_ADDR => {
                    let own = peer.addr.lock().unwrap().clone();
                    let list: Vec<String> = self.book.lock().unwrap().keys().filter(|a| Some(a.as_str()) != own.as_deref()).take(ADDR_REPLY).cloned().collect();
                    send(&peer, &self.magic, ADDR, list.join("\n").as_bytes());
                }
                ADDR => {
                    if last_addr.elapsed() < ADDR_GAP { continue; }   // a peer may not flood the address book
                    last_addr = Instant::now();
                    if let Ok(text) = std::str::from_utf8(&payload) { for a in text.lines().take(ADDR_REPLY) { self.add_addr(a); } }
                }
                GET_BLOCKS if payload.len() == 4 => {
                    if last_get.elapsed() < GET_BLOCKS_GAP { continue; }   // a batch is 500 blocks: faster than this is ignored, not served
                    last_get = std::time::Instant::now();
                    let from = u32::from_le_bytes(payload[..4].try_into().unwrap()) as usize;
                    let (window, at) = { let st = self.store.lock().unwrap(); st.chain.blocks.window(from, BATCH) };   // copy only what is asked for
                    for b in window.read_many(at, BATCH) { if !send(&peer, &self.magic, BLOCK, &b) { break; } }   // queue full: it asks again
                }
                BLOCK => {
                    let res = match Block::decode(&payload) { Ok(b) => self.submit_block(&b, Some(peer.id)), Err(_) => Err("decode") };
                    let from_source = self.sync.lock().unwrap().is_some_and(|(id, _, _)| id == peer.id);
                    // a reply to our batch request counts whatever became of the block (new, side, already known)
                    if from_source && matches!(res, Ok(()) | Err("known")) {
                        let got = peer.got.fetch_add(1, Ordering::Relaxed) + 1;
                        let my = self.height();
                        { let mut ph = peer.height.lock().unwrap(); if *ph < my { *ph = my; } }
                        let more = {
                            let mut s = self.sync.lock().unwrap();
                            // only real progress resets the stall clock: side blocks keep a source busy but get us nowhere
                            if let Some((id, at, _)) = *s { if id == peer.id && my > at { *s = Some((id, my, Instant::now())); } }
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
                            Err("pow") | Err("bits") | Err("tx root") | Err("state root") | Err("decode") => bad = true,   // invalid, not merely unknown (a bad time can be clock skew)
                            _ => {}
                    }
                }
                TX => { match Tx::decode(&mut R::new(&payload)) { Ok(t) => { let _ = self.submit_tx(t, Some(peer.id)); } Err(_) => bad = true } }
                _ => bad = true,
            }
            if bad { strikes += 1; if strikes >= STRIKES { return Err(std::io::Error::other("misbehaving peer dropped")); } }
        }
    }
    fn request_from(&self, peer: &Peer, from: u32) -> bool { peer.got.store(0, Ordering::Relaxed); send(peer, &self.magic, GET_BLOCKS, &from.to_le_bytes()) }
    fn relay(&self, kind: u8, payload: &[u8], except: Option<u64>) {
        let peers: Vec<Arc<Peer>> = self.peers.lock().unwrap().clone();
        for p in peers { if Some(p.id) != except { send(&p, &self.magic, kind, payload); } }
    }

    /// Store the block, extend or reorganize the chain, fix up the mempool, relay.
    pub fn submit_block(&self, b: &Block, from: Option<u64>) -> Result<(), &'static str> {
        let returned = {
            let mut s = self.store.lock().unwrap();
            match s.accept(b, now())? {
                Accepted::Known => return Err("known"),
                Accepted::Side => return Ok(()),
                Accepted::Extended => {
                    let mut m = self.mempool.lock().unwrap();
                    m.retain(|t| !b.txs.contains(t));
                    *self.next.lock().unwrap() = Some(Self::evict(&s.chain, &mut m));
                    self.mempool_bytes.store(m.iter().map(|t| t.encode().len()).sum(), Ordering::Relaxed);
                    Vec::new()
                }
                Accepted::Reorged(abandoned) => {
                    let mut m = self.mempool.lock().unwrap();
                    let old = std::mem::take(&mut *m);
                    *self.next.lock().unwrap() = None; self.mempool_bytes.store(0, Ordering::Relaxed);
                    [abandoned, old].concat()
                }
            }
        };
        for t in returned { let _ = self.submit_tx(t, Some(u64::MAX)); }
        self.relay(BLOCK, &b.encode(), from);
        Ok(())
    }
    /// Drop queued transactions the chain can no longer mine (their account moved on, their cheque
    /// expired...). Without this a dead transaction would sit in memory, and in the explorer, forever.
    /// Returns the next block's state with the survivors applied.
    fn evict(c: &crate::block::Chain, m: &mut Vec<Tx>) -> State {
        let mut s = c.state.clone();
        s.begin_block(&c.params, c.height() + 1);
        m.retain(|t| s.apply(&c.params, t).is_ok());
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
    /// Validate against the tip state plus the current mempool, add, relay. A failed apply leaves
    /// the state untouched, so the cached state stays right either way.
    pub fn submit_tx(&self, t: Tx, from: Option<u64>) -> Result<(), &'static str> {
        let raw = t.encode();
        {
            let s = self.store.lock().unwrap(); let c = &s.chain;
            let mut m = self.mempool.lock().unwrap();
            if self.mempool_bytes.load(Ordering::Relaxed) + raw.len() > MEMPOOL_BYTES { return Err("mempool full"); }
            if m.contains(&t) { return Err("already in mempool"); }
            let mut next = self.next.lock().unwrap();
            Self::next_state(c, &m, &mut next).apply(&c.params, &t)?;
            m.push(t);
            self.mempool_bytes.fetch_add(raw.len(), Ordering::Relaxed);
        }
        self.relay(TX, &raw, from);
        Ok(())
    }
    /// Dry run: apply `txs` in order on a copy of the next block's state (after the mempool).
    /// Nothing is stored or relayed. Returns one result per transaction.
    pub fn check_txs(&self, txs: &[Tx]) -> Vec<Result<(), &'static str>> {
        let s = self.store.lock().unwrap(); let c = &s.chain;
        let m = self.mempool.lock().unwrap();
        let mut st = Self::next_state(c, &m, &mut self.next.lock().unwrap()).clone();
        txs.iter().map(|t| st.apply(&c.params, t).map(|_| ())).collect()
    }
    /// Build a block from the mempool under the lock, search nonces without it (so RPC and
    /// peers stay responsive), and give up as soon as the tip moves. Like a Bitcoin miner, the
    /// template is rebuilt every TEMPLATE_REFRESH seconds when the mempool has changed, so
    /// transactions that arrive while a block is being mined still make it in.
    pub fn mine_once(&self, payee: u32) -> Result<Block, &'static str> {
        if self.sync.lock().unwrap().is_some() { return Err("syncing"); }   // never mine on a stale tip while catching up
        let build = || -> Result<(Block, [u8; 32], usize), &'static str> {
            let st = self.store.lock().unwrap(); let c = &st.chain;
            let m = self.mempool.lock().unwrap();
            let mut s = c.state.clone();
            s.begin_block(&c.params, c.height() + 1);
            // fill up to the block size limit (header and coinbase take well under the margin), oldest first
            let room = c.params.max_block_bytes.saturating_sub(4096);
            let mut used = 0;
            let txs: Vec<Tx> = m.iter().filter(|t| {
                let n = t.encode().len() + 4;
                if used + n > room || s.apply(&c.params, t).is_err() { return false; }
                used += n; true
            }).cloned().collect();
            Ok((c.template(now().max(c.median_time() + 1), payee, txs)?, c.tip(), m.len()))
        };
        let (mut b, tip, mut seen) = build()?;
        let mut built = std::time::Instant::now();
        loop {
            for _ in 0..200_000 {
                if b.header.meets_target() { self.submit_block(&b, None)?; return Ok(b); }
                b.header.nonce = b.header.nonce.wrapping_add(1);
            }
            if self.store.lock().unwrap().chain.tip() != tip { return Err("tip moved"); }
            // refresh on a changed mempool, and always before the nonce space runs out
            if built.elapsed().as_secs() >= TEMPLATE_REFRESH && (self.mempool.lock().unwrap().len() != seen || b.header.nonce > u32::MAX - 400_000) {
                let (nb, ntip, n) = build()?;
                if ntip != tip { return Err("tip moved"); }
                b = nb; seen = n; built = std::time::Instant::now();
            }
        }
    }
}

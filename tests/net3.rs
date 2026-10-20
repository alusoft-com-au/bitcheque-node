//! Regression tests for the third audit's networking, storage and RPC findings (in-process nodes on 127.0.0.1 only;
//! the one maintain() without an honest peer pins the dead 127.0.0.1:1, and the address book entries are never dialled).
//! Each asserts the fixed behaviour of what used to be an attack.
mod common;
use common::mine;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use bitcheque::block::{Block, Chain};
use bitcheque::net::{now, Node};
use bitcheque::params::Params;
use bitcheque::store::Store;
use bitcheque::tx::{Payment, Tx};
use bitcheque::u256::U256;
use bitcheque::wallet::{mine_registration, Book, Domain};

fn rp() -> Params {
    Params { initial_bits: 0x207F_FFFF, min_bits: 0x207F_FFFF, reg_pow_target: U256::MAX.shr(4), reward_maturity: 2, number_maturity: 2,
             launch_blocks: 0, max_future_seconds: 1 << 30, ..Params::mainnet() }
}
fn frame(magic: &[u8; 4], kind: u8, payload: &[u8]) -> Vec<u8> { [&magic[..], &[kind], &(payload.len() as u32).to_le_bytes(), payload].concat() }
fn hello(n: &Node, height: u32) -> Vec<u8> { [height.to_le_bytes().as_slice(), &n.store.lock().unwrap().chain.tip()].concat() }
fn drain(mut s: TcpStream) { std::thread::spawn(move || { let mut b = [0u8; 65536]; while let Ok(k) = s.read(&mut b) { if k == 0 { break } } }); }
fn wait(secs: u64, cond: impl Fn() -> bool) -> bool { let t = Instant::now(); while !cond() { if t.elapsed() > Duration::from_secs(secs) { return false; } std::thread::sleep(Duration::from_millis(20)); } true }
/// True once the node has closed `s` (read gives EOF or an error) within `secs`.
fn closed(s: &mut TcpStream, secs: u64) -> bool {
    s.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    let (t, mut b) = (Instant::now(), [0u8; 65536]);
    while t.elapsed() < Duration::from_secs(secs) { match s.read(&mut b) { Ok(0) => return true, Ok(_) => {} Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {} Err(_) => return true } }
    false
}
/// Every node of a test on one genesis block (a fixed time: nodes made a second apart must agree).
fn node(p: &Params) -> Arc<Node> { let g = Chain::genesis(p, 1_790_000_000, b"a3"); Node::new(Store::open(p.clone(), &g, None).unwrap()) }
fn book(k: u8) -> Book { Book { salt: [k; 16], n256: false, book_size: 256, domains: vec![Domain([k; 32])], net: rp().magic } }
fn tmp(name: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("bitcheque-net3-{name}-{}.dat", std::process::id()));
    for q in [p.clone(), p.with_extension("snap"), p.with_extension("peers"), std::path::PathBuf::from(format!("{}.corrupt", p.display()))] { let _ = std::fs::remove_file(q); }
    p
}
/// Mine one block whose coinbase message makes it about `size` bytes.
fn mine_big(n: &Node, size: usize) {
    let mut b = n.template(0).unwrap();
    if let Tx::Coinbase { message, .. } = &mut b.txs[0] { *message = vec![7u8; size]; }
    b.header.tx_root = bitcheque::block::tx_root(&b.txs);
    b.header.mine();
    n.submit_block(&b, None).unwrap();
}

/// A1: connections that called us and merely claim a big height in HELLO no longer stop templates at all: only a peer
/// we dialled, or a sync source that is delivering new blocks, holds them back.
#[test]
fn height_claims_from_inbound_peers_do_not_deny_templates() {
    let p = rp();
    let v = node(&p);
    for _ in 0..3 { mine(&v, 0).unwrap(); }
    let addr = v.listen("127.0.0.1:0").unwrap();
    v.maintain(vec!["127.0.0.1:1".into()], Duration::from_secs(1));
    let liars: Vec<TcpStream> = (0..3).map(|_| { let mut s = TcpStream::connect(addr).unwrap(); drain(s.try_clone().unwrap()); s.write_all(&frame(&p.magic, 0, &hello(&v, 1_000_000))).unwrap(); s }).collect();
    assert!(wait(5, || v.peer_count() == 3));
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(4) {   // (one of them takes the sync slot within a second, and delivers nothing)
        assert!(v.template(0).is_ok(), "templates refused by {:?} of mere claims", t.elapsed());
        std::thread::sleep(Duration::from_millis(100));
    }
    drop(liars);
}

/// A2: GET_ADDR is answered once per connection; repeats are strikes, so a flood ends with the connection.
#[test]
fn a_getaddr_flood_is_cut_off() {
    let p = rp();
    let v = node(&p);
    let path = tmp("getaddr");
    let lines: String = (0..1000u32).map(|i| format!("[2a0{}:{:x}::1]:8731\n", 1 + i % 9, i)).collect();
    std::fs::write(path.with_extension("peers"), lines).unwrap();
    v.set_book_path(path.with_extension("peers"));
    assert_eq!(v.known_addrs().len(), 1000);
    let addr = v.listen("127.0.0.1:0").unwrap();
    let mut s = TcpStream::connect(addr).unwrap();
    s.write_all(&frame(&p.magic, 0, &hello(&v, 0))).unwrap();
    let flood: Vec<u8> = (0..50_000).flat_map(|_| frame(&p.magic, 5, &[])).collect();
    let _ = s.write_all(&flood);
    assert!(closed(&mut s, 5), "dropped after a few repeats");
    let _ = std::fs::remove_file(path.with_extension("peers"));
}

/// A3: cheque pieces that match no commitment are struck (no honest relay sends one) and their txids remembered: a
/// flood ends with the connection, and a resend is refused without the store.
#[test]
fn junk_cheque_pieces_are_struck_and_remembered() {
    let p = rp();
    let v = node(&p);
    let b = book(7);
    mine(&v, 0).unwrap();   // block 0 is no registration anchor
    v.submit_tx(mine_registration(b.register(0, 16, Payment::Pow([0; 32], 0)), common::tip(&v), p.reg_pow_target), None).unwrap();
    mine(&v, 0).unwrap();
    let Tx::ChequePiece { account, .. } = b.pieces(1, &[0u8; 18]).remove(0) else { panic!() };
    let junk = |i: u32| { let mut cell = vec![0u8; 16]; cell[..4].copy_from_slice(&i.to_le_bytes()); Tx::ChequePiece { account: account.clone(), cheque: 1, column: (i % 18) as u8, shares: vec![cell] } };
    // direct: refused, then refused again at once while the store is held (the txid is remembered as bad)
    assert_eq!(v.submit_tx(junk(1_000_000), None), Err("no commitment matches"));
    let st = v.store.lock().unwrap();
    assert_eq!(v.submit_tx(junk(1_000_000), None), Err("no commitment matches"));
    drop(st);
    // over the wire: dropped after STRIKES
    let addr = v.listen("127.0.0.1:0").unwrap();
    let mut s = TcpStream::connect(addr).unwrap();
    s.write_all(&frame(&p.magic, 0, &hello(&v, 0))).unwrap();
    let flood: Vec<u8> = (0..30_000u32).flat_map(|i| frame(&p.magic, 3, &junk(i).encode())).collect();
    let _ = s.write_all(&flood);
    assert!(closed(&mut s, 5), "dropped after a few junk pieces");
    // and an honest piece is still taken
    assert!(v.submit_tx(b.pieces(1, &[0u8; 18]).remove(0), None).is_ok());
}

/// A4: a BLOCK frame may be no larger than a block can be, and a block's header is looked at before its transactions
/// are decoded: a known block with junk after it is recognised as known (it used to fail decoding, a strike).
#[test]
fn block_frames_are_bounded_and_checked_by_header_first() {
    let p = rp();
    let v = node(&p);
    for _ in 0..2 { mine(&v, 0).unwrap(); }
    let addr = v.listen("127.0.0.1:0").unwrap();
    let mut s = TcpStream::connect(addr).unwrap(); drain(s.try_clone().unwrap());
    s.write_all(&frame(&p.magic, 0, &hello(&v, 0))).unwrap();
    let mut raw = v.store.lock().unwrap().chain.blocks.get(1).unwrap().encode();
    raw.extend_from_slice(&[0xAB; 1000]);
    for _ in 0..5 { s.write_all(&frame(&p.magic, 2, &raw)).unwrap(); }
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(v.peer_count(), 1, "a known block is not decoded, so its tail is never looked at");
    let mut big = TcpStream::connect(addr).unwrap();
    big.write_all(&frame(&p.magic, 0, &hello(&v, 0))).unwrap();
    big.write_all(&frame(&p.magic, 2, &[])[..5]).unwrap(); big.write_all(&((p.max_block_bytes + 5000) as u32).to_le_bytes()).unwrap();
    assert!(closed(&mut big, 3), "a frame larger than any block is refused before it is read");
}

/// A5: gossip from many connections of one network takes at most ADDR_PER_SOURCE addresses per period, and never pushes
/// out an address that answered our dial.
#[test]
fn an_addr_flood_keeps_the_book() {
    let p = rp();
    let honest = node(&p);
    let haddr = honest.listen("127.0.0.1:0").unwrap();
    let v = node(&p);
    let vaddr = v.listen("127.0.0.1:0").unwrap();
    let path = tmp("addr");
    let lines: String = (0..999u32).map(|i| format!("[2b0{}:{:x}::1]:8731\n", 1 + i % 9, i)).collect();
    std::fs::write(path.with_extension("peers"), lines).unwrap();
    v.set_book_path(path.with_extension("peers"));
    v.connect(&haddr.to_string()).unwrap();
    assert!(wait(5, || v.book_addrs().contains(&haddr.to_string())), "dialled and answered: in the book, tried");
    let mut conns = Vec::new();
    for c in 0..80u32 {
        let mut s = TcpStream::connect(vaddr).unwrap(); drain(s.try_clone().unwrap());
        s.write_all(&frame(&p.magic, 0, &hello(&v, 0))).unwrap();
        let addrs: Vec<String> = (0..50u32).map(|k| format!("[2c{:02x}:{:x}::{:x}]:8731", (c * 50 + k) % 250, c * 50 + k, k + 1)).collect();
        s.write_all(&frame(&p.magic, 4, addrs.join("\n").as_bytes())).unwrap();
        conns.push(s);
    }
    std::thread::sleep(Duration::from_secs(1));
    let book = v.book_addrs();
    let left = book.iter().filter(|a| a.starts_with("[2b")).count();
    assert!(left >= 899, "{left}/999 original entries left");
    let taken = book.iter().filter(|a| a.starts_with("[2c")).count();
    assert!((90..=100).contains(&taken), "at most ADDR_PER_SOURCE from one network (a few may replace each other): {taken}");
    assert!(book.contains(&haddr.to_string()), "the tried address stays");
    let _ = std::fs::remove_file(path.with_extension("peers"));
}

/// Addresses that carry an IPv4 address inside (or lead nowhere) are not taken from gossip.
#[test]
fn gossip_refuses_embedded_ipv4_ranges() {
    let p = rp();
    let v = node(&p);
    let addr = v.listen("127.0.0.1:0").unwrap();
    let mut s = TcpStream::connect(addr).unwrap(); drain(s.try_clone().unwrap());
    s.write_all(&frame(&p.magic, 0, &hello(&v, 0))).unwrap();
    let bad = ["[64:ff9b::a00:1]:8731", "[64:ff9b:1::1]:8731", "[2002:a00:1::1]:8731", "[::10.0.0.1]:8731", "[2001:0:a00:1::1]:8731", "[100::1]:8731", "[::ffff:10.0.0.1]:8731"];
    let good = "[2a01:4f8:1:2::1]:8731";
    s.write_all(&frame(&p.magic, 4, [&bad[..], &[good]].concat().join("\n").as_bytes())).unwrap();
    assert!(wait(5, || !v.known_addrs().is_empty()));
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(v.known_addrs(), vec![good.to_string()]);
}

/// M4: with every inbound slot taken, a newcomer is let in by dropping the newest connection of the network holding the
/// most, never one of the longest-connected.
#[test]
fn full_inbound_slots_evict_the_newest_not_the_oldest() {
    let p = rp();
    let v = node(&p);
    let addr = v.listen("127.0.0.1:0").unwrap();
    let mut conns: Vec<TcpStream> = Vec::new();
    for i in 0..125 {
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(&frame(&p.magic, 0, &hello(&v, 0))).unwrap();
        conns.push(s);
        if i < 8 { std::thread::sleep(Duration::from_millis(5)); }   // the first ones are clearly the oldest
    }
    assert!(wait(10, || v.peer_count() == 125));
    for c in &conns { drain(c.try_clone().unwrap()); }
    let mut last = TcpStream::connect(addr).unwrap();
    last.write_all(&frame(&p.magic, 0, &hello(&v, 0))).unwrap();
    assert!(closed(&mut conns[124], 3), "the newest before it is dropped");
    std::thread::sleep(Duration::from_millis(300));
    assert!(!closed(&mut last, 1), "the newcomer is in");
    assert!(!closed(&mut conns[0], 1), "the oldest stays");
    assert_eq!(v.peer_count(), 125);
}

/// A6 and item 18: behind a proxy that adds its own X-Forwarded-For line, the last line's last entry is the client; IPv6
/// clients are limited per /48; and /check, /proof and /template share one budget per second.
#[test]
fn rpc_limits_hold_behind_a_proxy() {
    let p = rp();
    let v = node(&p);
    let rpc = v.serve_rpc("127.0.0.1:0").unwrap();
    let get = |path: &str, fwd: &str| { let mut s = TcpStream::connect(rpc).unwrap(); write!(s, "GET {path} HTTP/1.0\r\n{fwd}\r\n").unwrap(); let mut o = String::new(); let _ = s.read_to_string(&mut o); o };
    let ok = (0..300u32).filter(|i| get("/height", &format!("X-Forwarded-For: 198.51.{}.{}\r\nX-Forwarded-For: 203.0.113.9\r\n", i / 250, i % 250)).starts_with("HTTP/1.0 200")).count();
    assert_eq!(ok, 120, "one client, whatever it claims first");
    let ok = (0..300u32).filter(|i| get("/height", &format!("X-Forwarded-For: 2001:db8:5:{:x}::1\r\n", i)).starts_with("HTTP/1.0 200")).count();
    assert_eq!(ok, 120, "300 /64s of one /48");
    let t = Instant::now();
    // (each for another payee: a template already built for one is served without being charged)
    let busy = (0..300u32).filter(|i| get(&format!("/template/{i}"), &format!("X-Forwarded-For: 198.18.{}.{}\r\n", i / 250, i % 250)).starts_with("HTTP/1.0 503")).count();
    if t.elapsed() < Duration::from_secs(2) { assert!(busy > 0, "300 /template requests from 300 addresses within 2 s: some refused"); }
    assert!(get("/height", "X-Forwarded-For: 198.18.9.9\r\n").starts_with("HTTP/1.0 200"), "cheap routes are not in that budget");
}

/// A7: a stale first upstream no longer stops the node following the others: every upstream's height is asked, and
/// the highest is pulled from.
#[test]
fn a_stale_first_upstream_does_not_shadow_the_rest() {
    let p = rp();
    let ahead = node(&p);
    for _ in 0..5 { mine(&ahead, 0).unwrap(); }
    let good = ahead.serve_rpc("127.0.0.1:0").unwrap();
    let stale = TcpListener::bind("127.0.0.1:0").unwrap();
    let stale_addr = stale.local_addr().unwrap();
    std::thread::spawn(move || for s in stale.incoming().flatten() { let mut s = s; let mut got = Vec::new(); let mut b = [0u8; 4096]; while !got.windows(4).any(|w| w == b"\r\n\r\n") { match s.read(&mut b) { Ok(0) | Err(_) => break, Ok(k) => got.extend_from_slice(&b[..k]) } } let _ = s.write_all(b"HTTP/1.0 200 OK\r\n\r\n0"); });
    let v = node(&p);
    v.follow(vec![stale_addr.to_string(), good.to_string()], Duration::from_millis(300));
    assert!(wait(10, || v.height() == 5), "height {}", v.height());
}

/// A fake upstream that answers every request with "0" and keeps the bodies of POST /tx and POST /block.
fn recorder() -> (String, Arc<Mutex<Vec<(String, String)>>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap().to_string();
    let seen: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
    let s2 = seen.clone();
    std::thread::spawn(move || for s in l.incoming().flatten() {
        let mut s = s; let mut got = Vec::new(); let mut b = [0u8; 65536];
        loop {
            if let Some(i) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&got[..i]).to_string();
                let len: usize = head.lines().find_map(|l| l.strip_prefix("Content-Length: ")).and_then(|v| v.trim().parse().ok()).unwrap_or(0);
                if got.len() >= i + 4 + len {
                    let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
                    if head.starts_with("POST") { s2.lock().unwrap().push((path, String::from_utf8_lossy(&got[i + 4..i + 4 + len]).to_string())); }
                    break;
                }
            }
            match s.read(&mut b) { Ok(0) | Err(_) => break, Ok(k) => got.extend_from_slice(&b[..k]) }
        }
        let _ = s.write_all(b"HTTP/1.0 200 OK\r\n\r\n0");
    });
    (a, seen)
}

/// L6 and L7: transactions go up UPSTREAM_LINES per POST at most, and an old block from a peer (an initial sync) is not posted
/// up, while a block mined here is.
#[test]
fn upstream_posts_are_chunked_and_skip_old_blocks() {
    let p = rp();
    let g = Chain::genesis(&p, now() - 100_000, b"a3");
    let v = Node::new(Store::open(p.clone(), &g, None).unwrap());
    let books: Vec<Book> = (20..24).map(book).collect();
    // an old block, as from a peer during an initial sync (it is also the registrations' anchor: block 0 is none)
    let old = { let st = v.store.lock().unwrap(); let mut b: Block = st.chain.template(g.header.time + 60, 0, vec![]).unwrap(); b.header.mine(); b };
    let (up, seen) = recorder();
    v.follow(vec![up], Duration::from_secs(60));
    assert_eq!(v.submit_block(&old, Some(7)), Ok(true));
    for b in &books { v.submit_tx(mine_registration(b.register(0, 16, Payment::Pow([0; 32], 0)), common::tip(&v), p.reg_pow_target), None).unwrap(); }
    mine(&v, 0).unwrap();
    assert!(wait(5, || seen.lock().unwrap().iter().any(|(p, _)| p == "/block")));
    // the registrations went up too, now that it follows: only what comes after them is counted
    let regs = seen.lock().unwrap().iter().filter(|(p, _)| p == "/tx").count();
    let pieces: Vec<Tx> = books.iter().flat_map(|b| b.pieces(1, &[0u8; 18]).into_iter().take(17)).collect();
    assert_eq!(pieces.len(), 68);
    assert!(v.submit_txs(pieces, None).iter().all(|r| r.is_ok()));
    assert!(wait(12, || seen.lock().unwrap().iter().filter(|(p, _)| p == "/tx").count() == regs + 2));   // (posts are UPSTREAM_GAP apart)
    std::thread::sleep(Duration::from_millis(300));
    let seen = seen.lock().unwrap();
    assert_eq!(seen.iter().filter(|(p, _)| p == "/block").count(), 1, "only the block mined here");
    let lines: Vec<usize> = seen.iter().filter(|(p, _)| p == "/tx").skip(regs).map(|(_, b)| b.lines().count()).collect();
    assert_eq!(lines, vec![64, 4]);
}

/// A8: a chain bigger than a peer's send queue syncs from one honest source without a stall: batches are bounded by
/// bytes, the asker asks again when one ends, and the source is never barred, dropped or banned.
#[test]
fn big_blocks_sync_without_barring_the_source() {
    let p = rp();
    let honest = node(&p);
    for _ in 0..80 { mine_big(&honest, 900_000); }   // about 72 MB: several batches, more than any queue holds
    let h = honest.height();
    let haddr = honest.listen("127.0.0.1:0").unwrap();
    let v = node(&p);
    v.maintain(vec![haddr.to_string()], Duration::from_secs(1));
    let t = Instant::now();
    let mut drops = 0;
    let mut was = 0;
    while v.height() < h && t.elapsed() < Duration::from_secs(60) {
        let pc = v.peer_count(); if pc < was { drops += 1; } was = pc;
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(v.height(), h, "synced in {:?}", t.elapsed());
    assert_eq!(drops, 0, "the honest source was never dropped");
}

/// A9: a data file whose tail is zeros (the file grew, its data never reached the disk) loses only that tail.
#[test]
fn a_zero_filled_tail_is_cut_off() {
    let p = rp();
    let g = Chain::genesis(&p, now() - 100_000, b"a3");
    let path = tmp("zero");
    { let n = Node::new(Store::open(p.clone(), &g, Some(&path)).unwrap()); for _ in 0..20 { mine(&n, 0).unwrap(); } }
    let len = std::fs::metadata(&path).unwrap().len();
    let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
    f.write_all(&[0u8; 4096]).unwrap(); drop(f);
    let s = Store::open(p.clone(), &g, Some(&path)).unwrap();
    assert_eq!(s.chain.height(), 20);
    assert_eq!(std::fs::metadata(&path).unwrap().len(), len, "the zeros are cut off, so blocks appended next are readable");
    drop(s);
    // zeros followed by anything else are damage, not a torn tail: refused as before
    let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
    f.write_all(&[0u8; 100]).unwrap(); f.write_all(&[1]).unwrap(); drop(f);
    assert!(Store::open(p.clone(), &g, Some(&path)).is_err());
    let _ = std::fs::remove_file(&path); let _ = std::fs::remove_file(path.with_extension("snap"));
    let _ = std::fs::remove_file(format!("{}.corrupt", path.display()));
}

/// A10: a peer we dial whose taller chain breaks our rules (here, an older rule set's registration anchored further back
/// than ours allows) is dropped at its first invalid block and not dialled again for a while, so it cannot keep holding
/// templates back with its height claim while it keeps mining.
#[test]
fn a_peer_on_an_invalid_chain_does_not_hold_templates_back() {
    let (pa, pb) = (rp(), Params { reg_anchor_window: 2, ..rp() });
    let (a, b) = (node(&pa), node(&pb));
    for _ in 0..4 { mine(&a, 0).unwrap(); }
    let anchor = a.store.lock().unwrap().chain.hashes[1];
    a.submit_tx(mine_registration(book(1).register(0, 16, Payment::Pow([0; 32], 0)), anchor, pa.reg_pow_target), None).unwrap();
    for _ in 0..20 { mine(&a, 0).unwrap(); }
    let addr = a.listen("127.0.0.1:0").unwrap().to_string();
    let stop = Arc::new(Mutex::new(false));
    let (a2, s2) = (a.clone(), stop.clone());
    let miner = std::thread::spawn(move || while !*s2.lock().unwrap() { mine(&a2, 0).unwrap(); std::thread::sleep(Duration::from_millis(100)); });
    b.maintain(vec![addr], Duration::from_millis(500));   // pinned: redialled whenever it drops
    assert!(wait(10, || b.height() == 4), "the valid blocks are taken: {}", b.height());
    assert!(wait(5, || b.peer_count() == 0), "dropped at the first invalid block");
    let t = Instant::now();
    let mut refused = 0;
    while t.elapsed() < Duration::from_secs(6) {
        if b.template(0).is_err() { refused += 1; }
        std::thread::sleep(Duration::from_millis(20));
    }
    *stop.lock().unwrap() = true; miner.join().unwrap();
    assert_eq!(refused, 0, "templates refused while a peer on an invalid chain was connected");
    assert_eq!(b.peer_count(), 0, "the peer is dropped and not dialled again");
    assert_eq!(b.height(), 4);
}

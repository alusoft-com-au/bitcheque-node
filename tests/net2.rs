//! Regression tests for the second audit's networking, storage and RPC findings (in-process nodes on 127.0.0.1 only;
//! the one maintain() pins the dead 127.0.0.1:1). Each asserts the fixed behaviour of what used to be an attack.
//! Slow ones (STALL, HELLO_WAIT and RPC deadlines) take up to about 45 s, in parallel.
mod common;
use common::mine;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};
use bitcheque::block::{Block, Chain};
use bitcheque::net::{now, Node};
use bitcheque::params::Params;
use bitcheque::store::{Accepted, Store};
use bitcheque::tx::{Payment, Tx};
use bitcheque::u256::U256;
use bitcheque::wallet::{mine_registration, Book, Domain};

fn p_local() -> Params { Params { initial_bits: 0x207F_FFFF, min_bits: 0x207F_FFFF, reg_pow_target: U256::MAX.shr(4), launch_blocks: 0, ..Params::mainnet() } }
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
fn tmp(name: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("bitcheque-net2-{name}-{}.dat", std::process::id()));
    for q in [p.clone(), p.with_extension("snap"), std::path::PathBuf::from(format!("{}.corrupt", p.display()))] { let _ = std::fs::remove_file(q); }
    p
}
fn book(k: u8) -> Book { Book { salt: [k; 16], n256: false, book_size: 256, domains: vec![Domain([k; 32])] } }

/// Before HELLO: the whole HELLO must arrive within HELLO_WAIT from accept (a byte every few seconds no longer holds a
/// slot), a HELLO header claiming more than a HELLO can hold is refused at once, and so is any other first frame.
#[test]
fn pre_hello_trickle_and_big_frames_are_dropped() {
    let p = p_local();
    let g = Chain::genesis(&p, now() - 100_000, b"a2");
    let a = Node::new(Store::open(p.clone(), &g, None).unwrap());
    let addr = a.listen("127.0.0.1:0").unwrap();
    let mut big = TcpStream::connect(addr).unwrap();
    big.write_all(&frame(&p.magic, 0, &[])[..5]).unwrap(); big.write_all(&1000u32.to_le_bytes()).unwrap();
    assert!(closed(&mut big, 2), "a 1000-byte HELLO is refused before its payload is read");
    let mut other = TcpStream::connect(addr).unwrap();
    other.write_all(&frame(&p.magic, 2, &[0; 10])).unwrap();
    assert!(closed(&mut other, 2), "a first frame that is not HELLO");
    let mut s = TcpStream::connect(addr).unwrap();
    drain(s.try_clone().unwrap());
    s.write_all(&frame(&p.magic, 0, &[])[..5]).unwrap(); s.write_all(&100u32.to_le_bytes()).unwrap();
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(13) { std::thread::sleep(Duration::from_secs(2)); let _ = s.write_all(&[0]); }
    assert_eq!(a.peer_count(), 0, "the trickling connection is gone after HELLO_WAIT");
}

/// A tip block with valid proof of work and a time at or below the median: refused before anything is written,
/// remembered (a resend is one lookup), and a strike, counted per address across connections.
#[test]
fn an_old_time_block_is_refused_unwritten_remembered_and_struck() {
    let p = p_local();
    let g = Chain::genesis(&p, now() - 100_000, b"a2");
    let path = tmp("churn");
    let a = Node::new(Store::open(p.clone(), &g, Some(&path)).unwrap());
    for _ in 0..12 { mine(&a, 0).unwrap(); }
    let mut b = a.template(0).unwrap();
    let med = a.store.lock().unwrap().chain.median_time();
    if let Tx::Coinbase { message, .. } = &mut b.txs[0] { *message = vec![7u8; 900_000]; }
    b.header.tx_root = bitcheque::block::tx_root(&b.txs);
    b.header.time = med; b.header.mine();
    let len0 = std::fs::metadata(&path).unwrap().len();
    assert_eq!(a.submit_block(&b, None), Err("old time"));
    let t = Instant::now();
    for _ in 0..200 { assert_eq!(a.submit_block(&b, None), Err("old time")); }
    assert!(t.elapsed() < Duration::from_millis(500), "200 resends took {:?}", t.elapsed());
    assert_eq!(std::fs::metadata(&path).unwrap().len(), len0, "never written");
    // and a child of it is refused as such
    let mut child = b.clone(); child.header.prev = b.header.hash(); child.header.time = med + 100; child.header.mine();
    assert_eq!(a.submit_block(&child, None), Err("bad parent"));
    // over the wire: dropped after STRIKES copies; a new connection from the same address starts where it left off
    let addr = a.listen("127.0.0.1:0").unwrap();
    let f = frame(&p.magic, 2, &b.encode());
    let mut s = TcpStream::connect(addr).unwrap();
    s.write_all(&frame(&p.magic, 0, &hello(&a, 0))).unwrap();
    for _ in 0..3 { let _ = s.write_all(&f); }
    assert!(closed(&mut s, 5), "three invalid blocks: dropped");
    let mut s2 = TcpStream::connect(addr).unwrap();
    s2.write_all(&frame(&p.magic, 0, &hello(&a, 0))).unwrap();
    std::thread::sleep(Duration::from_millis(200));
    assert!(!closed(&mut s2, 1), "loopback is never banned (devnets): it may reconnect");
    let _ = s2.write_all(&f);
    assert!(closed(&mut s2, 5), "one more strike after reconnecting: dropped at once");
    let _ = std::fs::remove_file(&path); let _ = std::fs::remove_file(path.with_extension("snap"));
}

/// Strikes are kept per address (an IPv6 /64), not per connection; a public address that reaches STRIKES is refused,
/// before any dial (192.0.2.1 is a documentation address: nothing is ever sent to it).
#[test]
fn strikes_are_per_address_and_ban_public_ones() {
    let p = p_local();
    let g = Chain::genesis(&p, now() - 100_000, b"a2");
    let a = Node::new(Store::open(p.clone(), &g, None).unwrap());
    let ip: std::net::IpAddr = "192.0.2.1".parse().unwrap();
    assert!(!a.strike(ip) && !a.strike(ip) && a.strike(ip));
    assert_eq!(a.connect("192.0.2.1:1").err().map(|e| e.to_string()).as_deref(), Some("banned for a while"));
    let v6 = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
    assert!(!a.strike(v6("2001:db8:1:2::1")) && !a.strike(v6("2001:db8:1:2::ffff")) && a.strike(v6("2001:db8:1:2:3::9")), "one /64 is one address");
    assert!(!a.strike(v6("2001:db8:1:3::1")), "the next /64 is another");
}

/// One flipped length prefix in the middle of the data file: the node refuses to start and keeps the file (moved aside)
/// instead of cutting off every block after the damage. A torn last record is still cut off (tests/hardening.rs).
#[test]
fn a_corrupt_length_is_refused_not_truncated() {
    let p = p_local();
    let g = Chain::genesis(&p, now() - 100_000, b"a2");
    let path = tmp("corrupt");
    { let a = Node::new(Store::open(p.clone(), &g, Some(&path)).unwrap()); for _ in 0..20 { mine(&a, 0).unwrap(); } }
    let mut raw = std::fs::read(&path).unwrap();
    let mut i = 0; for _ in 0..5 { let l = u32::from_le_bytes(raw[i..i + 4].try_into().unwrap()) as usize; i += 4 + l; }
    raw[i + 3] |= 0x40; std::fs::write(&path, &raw).unwrap();
    let e = Store::open(p.clone(), &g, Some(&path)).err().expect("refuses to start");
    assert!(e.to_string().contains("damaged"), "{e}");
    let aside = std::path::PathBuf::from(format!("{}.corrupt", path.display()));
    assert_eq!(std::fs::read(&aside).unwrap(), raw, "kept whole, moved aside");
    assert!(!path.exists());
    // the next start begins afresh
    assert_eq!(Store::open(p.clone(), &g, Some(&path)).unwrap().chain.height(), 0);
    let _ = std::fs::remove_file(&path); let _ = std::fs::remove_file(&aside); let _ = std::fs::remove_file(path.with_extension("snap"));
}

/// Gossip may not fill the address book with one host on many ports: one entry per IP.
#[test]
fn gossip_keeps_one_address_per_ip() {
    let p = Params { magic: Params::mainnet().magic, ..p_local() };
    let g = Chain::genesis(&p, now() - 100_000, b"a2");
    let a = Node::new(Store::open(p.clone(), &g, None).unwrap());
    let addr = a.listen("127.0.0.1:0").unwrap();
    let mut s = TcpStream::connect(addr).unwrap(); drain(s.try_clone().unwrap());
    s.write_all(&frame(&p.magic, 0, &hello(&a, 0))).unwrap();
    let mut lines: Vec<String> = (1..=8).map(|k| format!("8.8.8.8:{k}")).collect();
    lines.extend((0..42).map(|k| format!("{}.{}.1.1:8730", 11 + k, 3)));
    s.write_all(&frame(&p.magic, 4, lines.join("\n").as_bytes())).unwrap();
    assert!(wait(5, || a.known_addrs().len() == 43));
    std::thread::sleep(Duration::from_millis(200));
    let known = a.known_addrs();
    assert_eq!(known.iter().filter(|k| k.starts_with("8.8.8.8:")).count(), 1, "{known:?}");
    assert_eq!(known.len(), 43);
}

/// A peer claiming a huge height and dripping a real block every 20 s: an honest peer we dialled is used at once, and the
/// liar loses the slot (and stops holding back templates) after STALL, because a drip is not progress.
#[test]
fn a_drip_feeding_liar_cannot_hold_the_sync_slot() {
    let p = p_local();
    let g = Chain::genesis(&p, now() - 100_000, b"a2");
    let honest = Node::new(Store::open(p.clone(), &g, None).unwrap());
    for _ in 0..50 { mine(&honest, 0).unwrap(); }
    let blocks: Vec<Vec<u8>> = (1..=50).map(|h| honest.store.lock().unwrap().chain.blocks.get(h).unwrap().encode()).collect();
    let v = Node::new(Store::open(p.clone(), &g, None).unwrap());
    let vaddr = v.listen("127.0.0.1:0").unwrap();
    v.maintain(vec!["127.0.0.1:1".into()], Duration::from_secs(1));
    let mut s = TcpStream::connect(vaddr).unwrap(); drain(s.try_clone().unwrap());
    s.write_all(&frame(&p.magic, 0, &hello(&v, u32::MAX))).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    let haddr = honest.listen("127.0.0.1:0").unwrap();
    v.connect(&haddr.to_string()).unwrap();
    assert!(wait(10, || v.height() == 50), "synced from the honest peer at once (height {})", v.height());
    let (t, mut k) = (Instant::now(), 0);
    let ok = loop {
        if v.template(0).is_ok() { break true; }
        if t.elapsed() > Duration::from_secs(50) { break false; }
        if t.elapsed() > Duration::from_secs(20 * k as u64) && k < blocks.len() { let _ = s.write_all(&frame(&p.magic, 2, &blocks[k])); k += 1; }
        std::thread::sleep(Duration::from_millis(250));
    };
    assert!(ok, "templates again once the liar is found out");
}

/// A shallow fork whose tip has a bad state root: the replay starts from an in-memory snapshot (at most about
/// 2 x max_reorg blocks), and a resend of the bad block, or a block on it, is refused without any replay.
#[test]
fn a_bad_branch_tip_is_replayed_once_then_refused_at_once() {
    let p = p_local();
    let g = Chain::genesis(&p, now() - 100_000, b"a2");
    let path = tmp("replay");
    let v = Node::new(Store::open(p.clone(), &g, Some(&path)).unwrap());
    { let mut st = v.store.lock().unwrap(); let n = now(); for i in 1..=999u32 { let b = st.chain.make_block(g.header.time + 60 * i, 0, vec![]).unwrap(); st.accept(&b, n).unwrap(); } }
    let mut att = Store::open(p.clone(), &g, None).unwrap();
    for h in 1..=998 { let b = v.store.lock().unwrap().chain.blocks.get(h).unwrap(); att.accept(&b, now()).unwrap(); }
    let n = now();
    let t0 = att.chain.headers.last().unwrap().time + 61;
    let side = att.chain.make_block(t0, 0, vec![]).unwrap();
    assert!(matches!(att.accept(&side, n).unwrap(), Accepted::Extended));
    assert!(matches!(v.store.lock().unwrap().accept(&side, n).unwrap(), Accepted::Side));
    let mut bad: Block = att.chain.template(t0 + 1, 0, vec![]).unwrap();
    bad.header.state_root = [1; 32]; bad.header.mine();
    assert_eq!(v.store.lock().unwrap().accept(&bad, n).err(), Some("state root"));
    let t = Instant::now();
    for _ in 0..50 { assert_eq!(v.store.lock().unwrap().accept(&bad, n).err(), Some("state root")); }
    let mut child = att.chain.template(t0 + 1, 0, vec![]).unwrap();
    child.header.prev = bad.header.hash(); child.header.mine();
    assert_eq!(v.store.lock().unwrap().accept(&child, n).err(), Some("bad parent"));
    assert!(t.elapsed() < Duration::from_millis(200), "resends cost no replay: {:?}", t.elapsed());
    assert_eq!(v.height(), 999);
    let _ = std::fs::remove_file(&path); let _ = std::fs::remove_file(path.with_extension("snap"));
}

/// Side blocks: work comes from headers (no branch copy per block), a fork further back than side blocks are kept is
/// refused, and a branch forking more than max_reorg back must keep up with the main chain's work.
#[test]
fn side_blocks_are_cheap_and_deep_light_forks_are_refused() {
    let p = p_local();
    let g = Chain::genesis(&p, now() - 1_000_000, b"a2");
    let v = Node::new(Store::open(p.clone(), &g, None).unwrap());
    for _ in 0..40 { mine(&v, 0).unwrap(); }
    let mut att = Store::open(p.clone(), &g, None).unwrap();
    let n = now();
    let mut t = g.header.time + 1;
    let mut times = Vec::new();
    for i in 0..30 {
        let mut b = att.chain.template(t, 0, vec![]).unwrap();
        if let Tx::Coinbase { message, .. } = &mut b.txs[0] { *message = vec![i as u8; 990_000]; }
        b.header.tx_root = bitcheque::block::tx_root(&b.txs); b.header.state_root = att.chain.template(t, 0, vec![]).unwrap().header.state_root; b.header.mine();
        att.accept(&b, n).unwrap();
        let s = Instant::now();
        let r = v.store.lock().unwrap().accept(&b, n);
        times.push(s.elapsed());
        assert!(matches!(r, Ok(Accepted::Side)), "{:?}", r.err());
        t += 60;
    }
    assert!(times[29] < times[0] * 4 + Duration::from_millis(30), "the 30th side block costs about what the 1st did: {:?} vs {:?}", times[29], times[0]);

    // a main chain that got harder (blocks 1 s apart) and a branch off block 1 that stayed easy (600 s apart)
    let q = Params { initial_bits: 0x2000_FFFF, min_bits: 0x2000_FFFF, max_reorg: 5, ..p_local() };
    let g = Chain::genesis(&q, now() - 1_000_000, b"light");
    let mut s = Store::open(q.clone(), &g, None).unwrap();
    let mut main = Chain::new(q.clone(), &g).unwrap();
    for i in 1..=14 { let b = main.make_block(g.header.time + 600 + i, 0, vec![]).unwrap(); main.add(&b, now()).unwrap(); s.accept(&b, now()).unwrap(); }
    let mut light = Chain::new(q.clone(), &g).unwrap();
    light.add(&main.blocks.get(1).unwrap(), now()).unwrap();
    let mut refused = false;
    for k in 0..8u32 {
        let b = light.make_block(g.header.time + 1200 + 600 * k, 0, vec![]).unwrap(); light.add(&b, now()).unwrap();
        match s.accept(&b, now()) { Err("branch too light") => { refused = true; break; } r => assert!(matches!(r, Ok(Accepted::Side)), "{:?}", r.err()) }
    }
    assert!(refused, "a deep branch at a fraction of the main chain's work is refused");

    // a fork further back than SIDE_CAP (2000) side blocks
    let gl = Chain::genesis(&p, 1_000_000, b"long");
    let mut s = Store::open(p.clone(), &gl, None).unwrap();
    let mut main = Chain::new(p.clone(), &gl).unwrap();
    for i in 0..2010 { let b = main.make_block(gl.header.time + 600 * (i + 1), 0, vec![]).unwrap(); main.add(&b, now()).unwrap(); s.accept(&b, now()).unwrap(); }
    let mut side = Chain::new(p.clone(), &gl).unwrap();
    side.add(&main.blocks.get(1).unwrap(), now()).unwrap();
    let b = side.make_block(gl.header.time + 1201, 0, vec![]).unwrap();
    assert_eq!(s.accept(&b, now()).err(), Some("reorg too deep"));
}

// ---- RPC ----

fn rp() -> Params {
    Params { initial_bits: 0x207F_FFFF, min_bits: 0x207F_FFFF, reg_pow_target: U256::MAX.shr(4), reward_maturity: 2, number_maturity: 2,
             launch_blocks: 0, max_future_seconds: 1 << 30, ..Params::mainnet() }
}
fn get(addr: std::net::SocketAddr, path: &str) -> String { let mut s = TcpStream::connect(addr).unwrap(); write!(s, "GET {path} HTTP/1.0\r\n\r\n").unwrap(); let mut o = String::new(); let _ = s.read_to_string(&mut o); o }

/// Over the RPC socket (one test: the count of requests being served is shared by every node in the process).
/// Behind a proxy (loopback, X-Forwarded-For) a client is held to PER_IP connections, IPv6 by /56; a body that is not
/// ASCII is refused before it is turned into text; and a Content-Length of 8 MB no longer stretches the deadline before
/// any body arrives: 256 such connections trickling a byte now and then are gone after DEADLINE.
#[test]
fn rpc_connections_are_limited_and_deadlines_hold() {
    let p = rp();
    let g = Chain::genesis(&p, now() - 100_000, b"a");
    let node = Node::new(Store::open(p.clone(), &g, None).unwrap());
    let rpc = node.serve_rpc("127.0.0.1:0").unwrap();
    let hold = |who: &str| { let mut s = TcpStream::connect(rpc).unwrap(); write!(s, "POST /tx HTTP/1.0\r\nX-Forwarded-For: {who}\r\nContent-Length: 10\r\n\r\n").unwrap(); s };
    // the body only once the reply did not come at once (a refused request closes with no unread bytes, so its reply is not reset away)
    let status = |who: &str| { let mut s = hold(who); s.set_read_timeout(Some(Duration::from_millis(500))).unwrap(); let mut o = String::new(); if s.read_to_string(&mut o).is_err() { s.set_read_timeout(None).unwrap(); s.write_all(b"0123456789").unwrap(); let _ = s.read_to_string(&mut o); } o.lines().next().unwrap_or("").to_string() };
    let held: Vec<TcpStream> = (0..8).map(|k| hold(&format!("2001:db8:0:1{k:02x}::1"))).collect();
    std::thread::sleep(Duration::from_millis(300));
    assert!(status("2001:db8:0:1ff::7").contains("503"), "a ninth from the same /56");
    assert!(status("2001:db8:0:200::7").contains("400"), "another /56 is served (and its junk body refused)");
    drop(held);
    let mut s = TcpStream::connect(rpc).unwrap();
    s.write_all(b"POST /tx HTTP/1.0\r\nContent-Length: 4\r\n\r\n\xC3\xA9\xC3\xA9").unwrap();
    let mut o = String::new(); let _ = s.read_to_string(&mut o);
    assert!(o.starts_with("HTTP/1.0 400") && !o.contains("bad hex"), "{o}");
    std::thread::sleep(Duration::from_millis(300));
    let mut conns: Vec<TcpStream> = (0..256).map(|_| { let mut s = TcpStream::connect(rpc).unwrap(); s.write_all(b"POST /tx HTTP/1.0\r\nContent-Length: 8388608\r\n\r\n").unwrap(); s }).collect();
    for _ in 0..4 { std::thread::sleep(Duration::from_secs(6)); for c in conns.iter_mut() { let _ = c.write_all(b"0"); } }
    let r = get(rpc, "/height");
    assert!(r.contains("200 OK"), "{}", r.lines().next().unwrap_or(""));
}

/// One PoW-valid registration with a bad batch, sent many times in one /check: refused as too many registrations; twice:
/// the repeat is not checked again; and afterwards the txid is refused at once, outside the store lock.
#[test]
fn a_bad_registration_is_checked_once() {
    let p = rp();
    let g = Chain::genesis(&p, now() - 100_000, b"a");
    let node = Node::new(Store::open(p.clone(), &g, None).unwrap());
    let mut reg = book(4).register(0, 16, Payment::Pow(0));
    if let Tx::RegisterBook { batch, .. } = &mut reg { batch.cheques[15][17][9][0][0] ^= 1; }
    let reg = mine_registration(reg, p.reg_pow_target);
    let line = bitcheque::crypto::hex(&reg.encode());
    assert_eq!(node.route("POST", "/check", &vec![line.as_str(); 64].join("\n")).err(), Some("too many registrations in one check"));
    let r = node.route("POST", "/check", &[line.as_str(), &line].join("\n")).unwrap();
    let r: Vec<&str> = r.lines().collect();
    assert_eq!(r.len(), 2);
    assert!(r[0].contains("root") && r[1] == "duplicate transaction", "{r:?}");
    let st = node.store.lock().unwrap();   // held: a known-bad txid needs no store
    let t = Instant::now();
    assert_eq!(node.submit_txs(vec![reg.clone()], None)[0].err(), Some(r[0]));
    assert!(t.elapsed() < Duration::from_millis(50));
    drop(st);
    // an empty /check answers at once, without the store
    let st = node.store.lock().unwrap();
    assert_eq!(node.route("POST", "/check", "").unwrap(), "");
    drop(st);
}

/// /mempool is decoded once per mempool version and tip, then served from the cache until either changes.
#[test]
fn the_mempool_listing_is_cached() {
    let p = rp();
    let g = Chain::genesis(&p, now() - 100_000, b"a");
    let node = Node::new(Store::open(p.clone(), &g, None).unwrap());
    let books: Vec<Book> = (10..30).map(book).collect();
    for ch in books.chunks(10) {
        for b in ch { node.submit_tx(mine_registration(b.register(0, 16, Payment::Pow(0)), p.reg_pow_target), None).unwrap(); }
        mine(&node, 0).unwrap();
    }
    { let mut m = node.mempool.lock().unwrap(); for b in &books { for t in b.pieces(1, &[9u8; 18]).into_iter().take(17) { assert!(m.push(t)); } } }
    let t = Instant::now();
    let first = node.route("GET", "/mempool", "").unwrap();
    let cold = t.elapsed();
    let t = Instant::now();
    for _ in 0..10 { assert_eq!(node.route("GET", "/mempool", "").unwrap(), first); }
    assert!(t.elapsed() < cold, "10 cached replies ({:?}) cost less than one decode ({cold:?})", t.elapsed());
    node.mempool.lock().unwrap().push(books[0].pieces(1, &[9u8; 18]).pop().unwrap());
    assert!(node.route("GET", "/mempool", "").unwrap().starts_with(&format!("count {}\n", 20 * 17 + 1)), "a changed mempool is listed afresh");
}

/// Format characters that would reorder or hide text are dropped from what another machine says.
#[test]
fn clean_drops_bidi_and_zero_width() {
    assert_eq!(bitcheque::net::clean("pay\u{202E}evil\u{200B}\u{2066}x\u{FEFF}\x1b[2J\nok"), "payevilx?[2J\nok");
}

// ---- host store (edge node) ----
use std::sync::atomic::{AtomicUsize, Ordering};
static GETS: AtomicUsize = AtomicUsize::new(0);
thread_local! { static DB: std::cell::RefCell<std::collections::HashMap<usize, Vec<u8>>> = Default::default(); }
fn host_get(h: usize) -> Option<Vec<u8>> { GETS.fetch_add(1, Ordering::Relaxed); DB.with(|d| d.borrow().get(&h).cloned()) }
fn host_put(h: usize, b: &[u8]) { DB.with(|d| { d.borrow_mut().insert(h, b.to_vec()); }) }
fn host_snap(_b: &[u8]) {}

/// A host store with no snapshot reaching the fork (201 blocks back, below the snapshots kept) refuses the reorg instead
/// of replaying from block 1, and a resend costs no replay either.
#[test]
fn a_host_never_replays_from_genesis() {
    let p = Params { reward_maturity: 1, number_maturity: 1, ..p_local() };
    let g = Chain::genesis(&p, now() - 10_000_000, b"audit");
    let mut maker = Chain::new(p.clone(), &g).unwrap();
    let mut st = Store::open_host(p.clone(), &g, bitcheque::block::HostBlocks { get: host_get, put: host_put }, None, &[], 100, host_snap).unwrap();
    let main_h = 1450u32;
    for _ in 0..main_h { let b = maker.make_block(maker.headers.last().unwrap().time + 600, 0, vec![]).unwrap(); maker.add(&b, now()).unwrap(); st.accept(&b, now()).unwrap(); }
    let fork = main_h - 201;
    let mut alt = Chain::new(p.clone(), &g).unwrap();
    for k in 1..=fork { alt.add(&maker.blocks.get(k as usize).unwrap(), now()).unwrap(); }
    for _ in 0..402 { let b = alt.make_block(alt.headers.last().unwrap().time + 300, 0, vec![]).unwrap(); alt.add(&b, now()).unwrap(); assert!(matches!(st.accept(&b, now()), Ok(Accepted::Side))); }
    let mut bad = alt.make_block(alt.headers.last().unwrap().time + 300, 0, vec![]).unwrap();
    bad.header.state_root = [9; 32]; bad.header.mine();
    for round in 0..3 {
        GETS.store(0, Ordering::Relaxed);
        let r = st.accept(&bad, now());
        if round == 0 { assert_eq!(r.err(), Some("reorg too deep")); } else { assert!(matches!(r, Ok(Accepted::Known) | Err("reorg too deep"))); }
        assert_eq!(GETS.load(Ordering::Relaxed), 0, "no block read back from the host");
        assert_eq!(st.chain.tip(), maker.tip());
    }
}

//! Regression tests for the fourth audit's networking, storage and RPC findings, and the bugs found with them
//! (in-process nodes on 127.0.0.1 only; maintain() always pins a dead 127.0.0.1 port or a local node, so no seed is
//! dialled, and the addresses in address books are never reachable).
mod common;
use common::{mine, tip};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
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
/// Every node of a test on one genesis block (a fixed time: nodes made a second apart must agree).
fn node(p: &Params) -> Arc<Node> { let g = Chain::genesis(p, 1_790_000_000, b"a4"); Node::new(Store::open(p.clone(), &g, None).unwrap()) }
fn book(k: u8) -> Book { Book { salt: [k; 16], n256: false, book_size: 256, domains: vec![Domain([k; 32])], net: rp().magic } }
fn tmp(name: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("bitcheque-net4-{name}-{}.dat", std::process::id()));
    for q in [p.clone(), p.with_extension("snap"), p.with_extension("peers"), std::path::PathBuf::from(format!("{}.corrupt", p.display()))] { let _ = std::fs::remove_file(q); }
    p
}
fn reg(k: u8, n: &Node) -> Tx { mine_registration(book(k).register(0, 16, Payment::Pow([0; 32], 0)), tip(n), rp().reg_pow_target) }
fn has(n: &Node, t: &Tx) -> bool { n.mempool.lock().unwrap().iter().any(|x| x.txid() == t.txid()) }
fn block(n: &Node, h: usize) -> Block { n.store.lock().unwrap().chain.blocks.get(h).unwrap() }
/// Mine one block whose coinbase message makes it about `size` bytes.
fn mine_big(n: &Node, size: usize) {
    let mut b = n.template(0).unwrap();
    if let Tx::Coinbase { message, .. } = &mut b.txs[0] { *message = vec![7u8; size]; }
    b.header.tx_root = bitcheque::block::tx_root(&b.txs);
    b.header.mine();
    n.submit_block(&b, None).unwrap();
}
/// A peer we dial that serves `h`'s chain: HELLO claiming `claim`, then `first` (frames) if any, then each GET_BLOCKS
/// answered with up to 500 blocks from the height asked (the first answer sent twice over with `dup_first`). Counts the asks.
fn fake_source(h: Arc<Node>, claim: u32, dup_first: bool, first: Vec<u8>) -> (String, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap().to_string();
    let asks = Arc::new(AtomicUsize::new(0));
    let asks2 = asks.clone();
    std::thread::spawn(move || for s in l.incoming().flatten() {
        let (h, asks, first) = (h.clone(), asks2.clone(), first.clone());
        std::thread::spawn(move || {
            let magic = rp().magic;
            let (mut s, mut r) = (s.try_clone().unwrap(), s);
            if s.write_all(&frame(&magic, 0, &hello(&h, claim))).is_err() || s.write_all(&first).is_err() { return; }
            loop {
                let mut head = [0u8; 9];
                if r.read_exact(&mut head).is_err() { return; }
                let mut pl = vec![0u8; u32::from_le_bytes(head[5..9].try_into().unwrap()) as usize];
                if r.read_exact(&mut pl).is_err() { return; }
                if head[4] != 1 { continue; }
                let from = u32::from_le_bytes(pl[..4].try_into().unwrap()) as usize;
                let n = asks.fetch_add(1, Ordering::SeqCst) + 1;
                for _ in 0..if dup_first && n == 1 { 2 } else { 1 } {
                    for k in from..from + 500 {
                        let Some(b) = h.store.lock().unwrap().chain.blocks.get(k) else { break };
                        if s.write_all(&frame(&magic, 2, &b.encode())).is_err() { return; }
                    }
                }
            }
        });
    });
    (a, asks)
}

/// F1: transactions refused only against our state (here pieces of cheques not registered; likewise a conflicting piece
/// of a cheque another node has, as honest peers relay) are no strike, however many: honest peers no longer drop and ban
/// each other over them. (A flood of them is still only counted, and the rest of the minute's ignored.)
#[test]
fn refused_transactions_from_a_peer_are_no_strike() {
    let p = rp();
    let v = node(&p);
    mine(&v, 0).unwrap();   // block 0 is no registration anchor
    v.submit_tx(reg(7, &v), None).unwrap();
    mine(&v, 0).unwrap();
    let one = book(7).pieces(16, &[0u8; 18]);
    let pieces: Vec<Tx> = (16..34u16).flat_map(|c| one.iter().map(move |t| match t.clone() { Tx::ChequePiece { account, column, shares, .. } => Tx::ChequePiece { account, cheque: c, column, shares }, x => x })).collect();
    assert!(pieces.len() > 300);
    assert!(v.submit_tx(pieces[0].clone(), None).is_err());
    let addr = v.listen("127.0.0.1:0").unwrap();
    let mut s = TcpStream::connect(addr).unwrap(); drain(s.try_clone().unwrap());
    s.write_all(&frame(&p.magic, 0, &hello(&v, 0))).unwrap();
    for t in &pieces { s.write_all(&frame(&p.magic, 3, &t.encode())).unwrap(); }
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(v.peer_count(), 1, "still connected");
    let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    assert!(!v.strike(ip) && !v.strike(ip), "the flood left no strike behind");
}

/// F1: a peer we refuse to dial for a while (here shunned: it served a block our rules reject) is not counted as a failed
/// dial, so a tried address is not forgotten over our own refusals.
#[test]
fn our_own_refusals_do_not_forget_a_tried_address() {
    let (pa, pb) = (rp(), Params { reg_anchor_window: 2, ..rp() });
    let (a, b) = (node(&pa), node(&pb));
    for _ in 0..4 { mine(&a, 0).unwrap(); }
    let anchor = a.store.lock().unwrap().chain.hashes[1];
    a.submit_tx(mine_registration(book(1).register(0, 16, Payment::Pow([0; 32], 0)), anchor, pa.reg_pow_target), None).unwrap();
    for _ in 0..3 { mine(&a, 0).unwrap(); }
    let addr = a.listen("127.0.0.1:0").unwrap().to_string();
    let path = tmp("shun").with_extension("peers");
    std::fs::write(&path, format!("{addr} tried\n")).unwrap();
    b.set_book_path(path.clone());
    b.maintain(vec!["127.0.0.1:1".into()], Duration::from_millis(200));
    assert!(wait(10, || b.height() == 4), "the valid blocks are taken: {}", b.height());
    std::thread::sleep(Duration::from_secs(3));   // 15 rounds of maintain, each refusing to dial it
    assert_eq!(b.height(), 4);
    assert!(b.book_addrs().contains(&addr), "still in the book: {:?}", b.book_addrs());
    let _ = std::fs::remove_file(&path);
}

/// F2: /check, /proof and /template are charged on the path as routed ("//template//7/" and "/check/" no longer slip
/// past), one address gets at most its share of the budget per second, and a template already built costs nothing.
#[test]
fn costly_routes_are_charged_as_routed_and_shared_fairly() {
    let p = rp();
    let v = node(&p);
    let rpc = v.serve_rpc("127.0.0.1:0").unwrap();
    let ask = |head: String| { let mut s = TcpStream::connect(rpc).unwrap(); s.write_all(head.as_bytes()).unwrap(); let mut o = String::new(); let _ = s.read_to_string(&mut o); o };
    let get = |path: &str, who: &str| ask(format!("GET {path} HTTP/1.0\r\nX-Forwarded-For: {who}\r\n\r\n"));
    let t = Instant::now();
    let codes: Vec<String> = (0..40u32).map(|i| get(&format!("//template//{i}/"), "198.51.100.7")).collect();
    if t.elapsed() < Duration::from_millis(900) {
        // (served: built, for payee 0, or refused by the chain rules for a number nobody has, which costs the same)
        let served = codes.iter().filter(|c| !c.starts_with("HTTP/1.0 503")).count();
        assert!((1..=20).contains(&served), "one address, its share of a second or two: {served}");
    }
    assert!(!get("/template/77", "198.51.100.8").starts_with("HTTP/1.0 503"), "another address is still served");
    let t = Instant::now();
    let checks = (0..40).filter(|_| ask("POST /check/ HTTP/1.0\r\nX-Forwarded-For: 198.51.100.9\r\nContent-Length: 3\r\n\r\n00\n".into()).starts_with("HTTP/1.0 503")).count();
    if t.elapsed() < Duration::from_millis(900) { assert!(checks >= 20, "/check/ is /check: {checks} refused"); }
    // the same template over and over: built once (a second), served from the cache
    std::thread::sleep(Duration::from_millis(1100));
    assert!((0..40).all(|_| get("/template/0", "198.51.100.10").starts_with("HTTP/1.0 200")), "cache hits are not charged");
}

/// F3: one IPv6 /48 (here behind the proxy, each client from its own /56) holds at most PER_48 RPC connections, however
/// slowly they send; a request head must be complete within HEAD_DEADLINE; everyone else is still served.
#[test]
fn one_site_cannot_hold_the_rpc() {
    let p = rp();
    let v = node(&p);
    let rpc = v.serve_rpc("127.0.0.1:0").unwrap();
    let mut conns: Vec<TcpStream> = (0..40u32).map(|i| {
        let mut s = TcpStream::connect(rpc).unwrap();
        write!(s, "POST /tx HTTP/1.0\r\nX-Forwarded-For: 2001:db8:7:{i:x}00::1\r\nContent-Length: 100\r\n\r\n").unwrap();   // and no body
        s
    }).collect();
    std::thread::sleep(Duration::from_millis(500));
    let refused = conns.iter_mut().map(|s| {
        s.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        let mut b = [0u8; 64];
        matches!(s.read(&mut b), Ok(k) if b[..k].starts_with(b"HTTP/1.0 503"))
    }).filter(|&r| r).count();
    assert_eq!(refused, 40 - 16, "past PER_48");
    let mut slow = TcpStream::connect(rpc).unwrap();
    slow.write_all(b"GET /height HTTP/1.0\r\n").unwrap();   // the head never ends
    slow.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let t = Instant::now();
    let _ = slow.read(&mut [0u8; 64]);
    assert!(t.elapsed() < Duration::from_secs(7), "cut off at the head deadline: {:?}", t.elapsed());
    let mut s = TcpStream::connect(rpc).unwrap();
    s.write_all(b"GET /height HTTP/1.0\r\nX-Forwarded-For: 2001:db8:8::1\r\n\r\n").unwrap();
    let mut o = String::new(); let _ = s.read_to_string(&mut o);
    assert!(o.starts_with("HTTP/1.0 200"), "{o}");
    drop(conns);
}

/// F4: the address book is written aside and renamed into place, and an address that answered our dial survives more
/// failed dials (GIVE_UP_TRIED) than one never reached (GIVE_UP).
#[test]
fn the_address_book_is_saved_whole_and_keeps_tried_addresses() {
    let p = rp();
    let v = node(&p);
    let path = tmp("book").with_extension("peers");
    std::fs::write(&path, "127.0.0.1:1 tried\n127.0.0.1:2\n").unwrap();
    v.set_book_path(path.clone());
    v.maintain(vec!["127.0.0.1:3".into()], Duration::from_millis(200));   // every one refuses the dial
    assert!(wait(10, || !v.book_addrs().contains(&"127.0.0.1:2".to_string())), "the new address is forgotten");
    assert!(v.book_addrs().contains(&"127.0.0.1:1".to_string()), "the tried one is kept for now");
    assert!(wait(5, || std::fs::read_to_string(&path).is_ok_and(|t| t == "127.0.0.1:1 tried\n")), "saved whole");
    assert!(!std::path::Path::new(&format!("{}.tmp", path.display())).exists(), "nothing left aside");
    let _ = std::fs::remove_file(&path);
}

/// /addrs (and GET_ADDR) list neither a built-in seed that never answered nor, on a public network, loopback addresses.
#[test]
fn addrs_lists_only_what_was_learned() {
    let p = Params { magic: Params::local().magic, ..rp() };   // a devnet: its seed is 127.0.0.1:18441 (never dialled here)
    let v = node(&p);
    let path = tmp("seeds").with_extension("peers");
    std::fs::write(&path, "127.0.0.1:18441\n127.0.0.1:18442\n").unwrap();
    v.set_book_path(path.clone());
    assert_eq!(v.route("GET", "/addrs", "").unwrap(), "count 1\n127.0.0.1:18442");
    let w = node(&p);
    std::fs::write(&path, "127.0.0.1:18441 tried\n").unwrap();
    w.set_book_path(path.clone());
    assert_eq!(w.known_addrs(), vec!["127.0.0.1:18441".to_string()], "a seed that answered is learned");
    let m = node(&rp());
    std::fs::write(&path, "127.0.0.1:5 tried\n[2a01:4f8:1:2::1]:8731\n").unwrap();
    m.set_book_path(path.clone());
    assert_eq!(m.known_addrs(), vec!["[2a01:4f8:1:2::1]:8731".to_string()]);
    let _ = std::fs::remove_file(&path);
}

/// F5: a peer we dialled that claims a great height but sends no blocks no longer holds templates back at all; a peer
/// that is ahead and delivering still does, while it delivers.
#[test]
fn only_a_delivering_peer_holds_templates_back() {
    let p = rp();
    let v = node(&p);
    for _ in 0..3 { mine(&v, 0).unwrap(); }
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let liar = l.local_addr().unwrap().to_string();
    let hv = hello(&v, 1_000_000);
    std::thread::spawn(move || for s in l.incoming().flatten() { let mut s = s; let _ = s.write_all(&frame(&rp().magic, 0, &hv)); drain(s); });
    v.connect(&liar).unwrap();
    assert!(wait(5, || v.peer_count() == 1));
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(4) {
        assert!(v.template(0).is_ok(), "templates refused by {:?} of a mere claim from a peer we dialled", t.elapsed());
        std::thread::sleep(Duration::from_millis(50));
    }
    let honest = node(&p);
    for _ in 0..40 { mine_big(&honest, 900_000); }
    let haddr = honest.listen("127.0.0.1:0").unwrap();
    let w = node(&p);
    w.connect(&haddr.to_string()).unwrap();
    let mut refused = 0;
    while w.height() < 40 && refused < 1000 { if matches!(w.template(0), Err("syncing")) { refused += 1; } std::thread::sleep(Duration::from_millis(5)); }
    assert!(refused > 0, "templates are refused while a delivering source is well ahead");
    assert!(wait(30, || w.height() == 40));
    assert!(w.template(0).is_ok());
}

/// F6: strikes and bans apply to an IPv6 /48, and the ban map stays bounded however many /48s misbehave.
#[test]
fn bans_cover_a_48_and_stay_bounded() {
    let v = node(&rp());
    let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
    assert!(!v.strike(ip("2001:db8:aa:1::1")) && !v.strike(ip("2001:db8:aa:2::1")) && v.strike(ip("2001:db8:aa:3::1")));
    let e = v.connect("[2001:db8:aa:ffff::9]:8731").unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "another /64 of the same /48 is refused before any dial");
    for i in 0..12_000u32 { let a = std::net::IpAddr::V6(std::net::Ipv6Addr::new(0x2a0b, (i >> 16) as u16, i as u16, 0, 0, 0, 0, 1)); for _ in 0..3 { v.strike(a); } }
    assert!(v.ban_count() <= 10_000, "{}", v.ban_count());
}

/// F7: a connection that called us and advertises an address on its IP (another node may share that IP) does not stop
/// us dialling that address.
#[test]
fn an_inbound_claim_does_not_take_an_address() {
    let p = rp();
    let h = node(&p);
    let haddr = h.listen("127.0.0.1:0").unwrap().to_string();
    let v = node(&p);
    let vaddr = v.listen("127.0.0.1:0").unwrap();
    let mut s = TcpStream::connect(vaddr).unwrap(); drain(s.try_clone().unwrap());
    s.write_all(&frame(&p.magic, 0, &[hello(&v, 0), haddr.as_bytes().to_vec()].concat())).unwrap();
    assert!(wait(5, || v.peer_count() == 1));
    v.maintain(vec![haddr.clone()], Duration::from_millis(200));
    assert!(wait(5, || h.peer_count() == 1), "the pinned address is dialled although a connection claimed it");
}

/// F9: an unsolicited ADDR (gossip passing one address on) just before the reply to our GET_ADDR no longer uses up the
/// reply's turn.
#[test]
fn gossip_does_not_shadow_the_getaddr_reply() {
    let p = rp();
    let v = node(&p);
    let addr = v.listen("127.0.0.1:0").unwrap();
    let mut s = TcpStream::connect(addr).unwrap(); drain(s.try_clone().unwrap());
    s.write_all(&frame(&p.magic, 0, &hello(&v, 0))).unwrap();
    s.write_all(&frame(&p.magic, 4, b"[2a01:4f8:1:2::1]:8731")).unwrap();
    s.write_all(&frame(&p.magic, 4, b"[2a02:4f8:1:2::1]:8731\n[2a03:4f8:1:2::1]:8731")).unwrap();
    assert!(wait(5, || v.known_addrs().len() == 3), "{:?}", v.known_addrs());
}

/// F10: a block with an unknown parent, replayed by the sync source, makes us step back at most REASKS times (it used
/// to be once a second for as long as it kept sending). Slow (20 s): cargo test -- --ignored
#[test]
#[ignore]
fn a_replayed_orphan_is_bounded() {
    let p = rp();
    let x = node(&p);
    for _ in 0..2 { mine(&x, 0).unwrap(); }
    let orphan = frame(&p.magic, 2, &block(&x, 2).encode());   // its parent is x's block 1, which v never sees
    let v = node(&p);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let asks = Arc::new(AtomicUsize::new(0));
    let (a2, hv) = (asks.clone(), hello(&v, 1000));
    std::thread::spawn(move || if let Some(Ok(s)) = l.incoming().next() {
        let (mut w, mut r) = (s.try_clone().unwrap(), s);
        std::thread::spawn(move || loop {
            let mut head = [0u8; 9]; if r.read_exact(&mut head).is_err() { return; }
            let mut pl = vec![0u8; u32::from_le_bytes(head[5..9].try_into().unwrap()) as usize]; if r.read_exact(&mut pl).is_err() { return; }
            if head[4] == 1 { a2.fetch_add(1, Ordering::SeqCst); }
        });
        let _ = w.write_all(&frame(&rp().magic, 0, &hv));
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(20) { if w.write_all(&orphan).is_err() { return; } std::thread::sleep(Duration::from_millis(5)); }
    });
    v.connect(&addr).unwrap();
    std::thread::sleep(Duration::from_secs(20));
    let n = asks.load(Ordering::SeqCst);
    assert!(n <= 13, "asked {n} times: once at HELLO, then at most REASKS steps back");
    assert!(v.template(0).is_ok());
}

/// Sync: blocks a source sends twice (here every answer is its whole chain, and the first twice over) are not counted
/// toward the batch, so we ask once per batch: from 1, and from 11 once ten big blocks (about BATCH_BYTES) are in.
/// (Every block counted, new or known, used to trigger asks of its own, which snowballed.)
#[test]
fn a_repeated_batch_asks_for_nothing_more() {
    let p = rp();
    let h = node(&p);
    for _ in 0..20 { mine_big(&h, 900_000); }
    let (addr, asks) = fake_source(h.clone(), 20, true, Vec::new());
    let v = node(&p);
    v.connect(&addr).unwrap();
    assert!(wait(60, || v.height() == 20), "height {}", v.height());
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(asks.load(Ordering::SeqCst), 2);
}

/// A node whose peers all said a lower height in HELLO (or were reset to ours) is not stuck behind: a block a peer sends
/// shows it is ahead, and that peer is asked.
#[test]
fn a_peer_shown_ahead_by_its_blocks_is_synced_from() {
    let p = rp();
    let h = node(&p);
    for _ in 0..30 { mine(&h, 0).unwrap(); }
    let tip_block = frame(&p.magic, 2, &block(&h, 30).encode());
    let (addr, asks) = fake_source(h.clone(), 0, false, tip_block);   // says height 0, then relays its tip
    let v = node(&p);
    v.maintain(vec![addr], Duration::from_millis(200));
    assert!(wait(15, || v.height() == 30), "height {}", v.height());
    assert!(asks.load(Ordering::SeqCst) >= 1);
}

/// After a reorg the abandoned transactions go to every peer, the one that sent the winning branch too.
#[test]
fn abandoned_transactions_reach_the_sender_of_the_winning_branch() {
    let p = rp();
    let (a, b) = (node(&p), node(&p));
    let b1 = mine(&a, 0).unwrap();
    b.submit_block(&b1, None).unwrap();   // a common block 1, the registration's anchor
    let t = reg(9, &a);
    a.submit_tx(t.clone(), None).unwrap();
    mine(&a, 0).unwrap();   // a: block 2 holds t
    for _ in 0..2 { mine(&b, 0).unwrap(); }   // b: a heavier branch without it
    let baddr = b.listen("127.0.0.1:0").unwrap();
    a.connect(&baddr.to_string()).unwrap();
    assert!(wait(10, || a.height() == 3 && tip(&a) == tip(&b)), "a reorganised onto b's branch");
    assert!(wait(5, || has(&b, &t)), "b had t from a after the reorg");
}

/// Our own waiting transactions (from our RPC) are offered again to the peers: one that missed the first relay gets them.
#[test]
fn our_own_waiting_transactions_are_offered_again() {
    let p = rp();
    let (a, b) = (node(&p), node(&p));
    let b1 = mine(&a, 0).unwrap();
    b.submit_block(&b1, None).unwrap();
    let t = reg(10, &a);
    a.submit_tx(t.clone(), None).unwrap();   // relayed to nobody: no peers yet
    let baddr = b.listen("127.0.0.1:0").unwrap();
    a.connect(&baddr.to_string()).unwrap();
    assert!(wait(5, || b.peer_count() == 1));
    std::thread::sleep(Duration::from_millis(300));
    assert!(!has(&b, &t));
    a.rebroadcast();
    assert!(wait(5, || has(&b, &t)));
}

/// An upstream (an edge node) refusing a post as too many (429) gets it again later, nothing dropped; posts carry at most
/// 16 registrations each and are UPSTREAM_GAP apart.
#[test]
fn upstream_posts_fit_an_edge_node_and_are_retried() {
    let p = Params { reg_pow_per_block_cap: 40, ..rp() };
    let g = Chain::genesis(&p, now() - 100_000, b"a4");
    let v = Node::new(Store::open(p.clone(), &g, None).unwrap());
    mine(&v, 0).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let up = l.local_addr().unwrap().to_string();
    let seen: Arc<Mutex<Vec<(String, Instant)>>> = Arc::default();
    let refused = Arc::new(AtomicUsize::new(0));
    let (s2, r2) = (seen.clone(), refused.clone());
    std::thread::spawn(move || for s in l.incoming().flatten() {
        let mut s = s; let mut got = Vec::new(); let mut b = [0u8; 65536];
        let mut code = "200 OK";
        loop {
            if let Some(i) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&got[..i]).to_string();
                let len: usize = head.lines().find_map(|l| l.strip_prefix("Content-Length: ")).and_then(|v| v.trim().parse().ok()).unwrap_or(0);
                if got.len() >= i + 4 + len {
                    if head.starts_with("POST /tx") {
                        if r2.fetch_add(1, Ordering::SeqCst) == 0 { code = "429 Too Many Requests"; }
                        else { s2.lock().unwrap().push((String::from_utf8_lossy(&got[i + 4..i + 4 + len]).to_string(), Instant::now())); }
                    }
                    break;
                }
            }
            match s.read(&mut b) { Ok(0) | Err(_) => break, Ok(k) => got.extend_from_slice(&b[..k]) }
        }
        let _ = write!(s, "HTTP/1.0 {code}\r\n\r\n0");
    });
    v.follow(vec![up], Duration::from_secs(60));
    let regs: Vec<Tx> = (30..47).map(|k| reg(k, &v)).collect();   // 17: one more than a post takes
    assert!(v.submit_txs(regs, None).iter().all(|r| r.is_ok()));
    assert!(wait(20, || seen.lock().unwrap().iter().map(|(b, _)| b.lines().count()).sum::<usize>() == 17), "all 17 arrive, the refused post sent again");
    let seen = seen.lock().unwrap();
    assert!(seen.iter().all(|(b, _)| b.lines().filter(|l| l.starts_with("01") || l.starts_with("02")).count() <= 16));
    assert!(seen.windows(2).all(|w| w[1].1 - w[0].1 >= Duration::from_secs(2)), "paced");
}

/// A data file found damaged is moved aside and the node says so and exits (code 2), instead of panicking. (The research
/// network, which follows no upstream with --no-upstream and has no TCP seeds: nothing is dialled but the dead pin.)
#[test]
fn a_damaged_data_file_is_a_clean_error() {
    let path = tmp("damaged");
    std::fs::write(&path, [5u8, 0, 0, 0, 1, 2, 3, 4, 5]).unwrap();   // a record length no block can have
    let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_bitcheque"))
        .args(["node", "--data", path.to_str().unwrap(), "--listen", "127.0.0.1:0", "--peer", "127.0.0.1:1", "--no-upstream"])
        .stderr(std::process::Stdio::piped()).stdout(std::process::Stdio::null()).spawn().unwrap();
    let t = Instant::now();
    let code = loop {
        if let Some(st) = c.try_wait().unwrap() { break st.code(); }
        if t.elapsed() > Duration::from_secs(10) { let _ = c.kill(); let _ = c.wait(); panic!("still running"); }
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut err = String::new(); c.stderr.take().unwrap().read_to_string(&mut err).unwrap();
    assert_eq!(code, Some(2), "{err}");
    assert!(err.contains("error: data file") && err.contains("damaged") && !err.contains("panicked"), "{err}");
    assert!(std::path::Path::new(&format!("{}.corrupt", path.display())).exists());
    let _ = std::fs::remove_file(format!("{}.corrupt", path.display()));
}

/// A block that arrives alone reaches the disk within seconds (it used to wait for the next block to be written).
#[test]
fn a_lone_block_is_flushed_soon() {
    let p = rp();
    let g = Chain::genesis(&p, 1_790_000_000, b"a4");
    let path = tmp("flush");
    let n = Node::new(Store::open(p.clone(), &g, Some(&path)).unwrap());
    mine(&n, 0).unwrap();   // the first write is flushed at once
    mine(&n, 0).unwrap();   // ...the next waits
    assert!(n.store.lock().unwrap().unsynced());
    n.maintain(vec!["127.0.0.1:1".into()], Duration::from_millis(500));
    assert!(wait(13, || !n.store.lock().unwrap().unsynced()), "flushed by maintain");
    let _ = std::fs::remove_file(&path);
}

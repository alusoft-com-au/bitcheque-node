//! Hostile and unlucky inputs that used to crash or wedge a node: malformed transactions and
//! requests, junk side blocks, a crash mid-write, a reorg below the snapshot, and a template
//! that must pick up transactions arriving while a block is being mined.
mod common;
use common::{mine, tip};
use std::io::{Read, Write};
use std::net::TcpStream;
use bitcheque::block::Chain;
use bitcheque::net::{now, Node};
use bitcheque::params::Params;
use bitcheque::rpc::unhex;
use bitcheque::store::{Store, SNAP_EVERY};
use bitcheque::tx::{Tx, R};

fn params() -> Params { Params { initial_bits: 0x207F_FFFF, min_bits: 0x207F_FFFF, launch_blocks: 0, reward_maturity: 1, number_maturity: 1, ..Params::mainnet() } }
fn tmp(name: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("bitcheque-hard-{name}-{}.dat", std::process::id()));
    let _ = std::fs::remove_file(&p); let _ = std::fs::remove_file(p.with_extension("snap"));
    p
}

#[test]
fn malformed_account_ids_are_refused_not_fatal() {
    let p = params();
    let g = Chain::genesis(&p, now() - 100_000, b"hard");
    let node = Node::new(Store::open(p, &g, None).unwrap());
    // a cheque piece with an empty account no longer decodes
    let t = Tx::ChequePiece { account: vec![], cheque: 0, column: 0, shares: vec![] };
    assert!(Tx::decode(&mut R::new(&t.encode())).is_err());
    // and one that bypasses the decoder is rejected, not a panic
    assert!(node.submit_tx(t, None).is_err());
    assert!(node.submit_tx(Tx::Renew { account: vec![0x13], start: 0 }, None).is_err());
    assert!(node.submit_tx(Tx::RegisterBatch { account: vec![], batch: bitcheque::tx::Batch { start: 0, count: 1, cheques: vec![], path: vec![] }, pay: bitcheque::tx::Payment::Pow([0; 32], 0) }, None).is_err());
    mine(&node, 0).unwrap();   // still alive, locks not poisoned
    assert_eq!(node.height(), 1);
}

#[test]
fn non_ascii_rpc_input_is_refused() {
    assert_eq!(unhex("a\u{FFFD}"), None);
    assert_eq!(unhex("ab"), Some(vec![0xAB]));
    let p = params();
    let g = Chain::genesis(&p, now() - 100_000, b"hard");
    let node = Node::new(Store::open(p, &g, None).unwrap());
    let addr = node.serve_rpc("127.0.0.1:0").unwrap();
    let get = |path: &[u8]| { let mut s = TcpStream::connect(addr).unwrap(); s.write_all(&[b"GET ", path, b" HTTP/1.0\r\n\r\n"].concat()).unwrap(); let mut o = String::new(); let _ = s.read_to_string(&mut o); o };
    let _ = get(b"/id/a\xFF");
    assert!(get(b"/height").ends_with("0\n") || get(b"/height").contains("\r\n\r\n0"));
    mine(&node, 0).unwrap();
}

#[test]
fn junk_side_blocks_are_refused_before_they_are_stored() {
    let mut p = params();
    p.min_bits = 0x2000_FFFF; p.initial_bits = 0x2000_FFFF;     // real (if small) work, so trivial bits stand out
    let g = Chain::genesis(&p, now() - 100_000, b"hard");
    let path = tmp("junk");
    let mut s = Store::open(p.clone(), &g, Some(&path)).unwrap();
    let mut c = Chain::new(p.clone(), &g).unwrap();
    for i in 0..3 { let b = c.make_block(g.header.time + 60 * (i + 1), 0, vec![]).unwrap(); c.add(&b, now()).unwrap(); s.accept(&b, now()).unwrap(); }
    let len = std::fs::metadata(&path).unwrap().len();
    // a side block off block 1 claiming an easier target than its ancestors allow
    let mut side = Chain::new(p.clone(), &g).unwrap();
    side.add(&c.blocks.get(1).unwrap(), now()).unwrap();
    let mut junk = side.template(g.header.time + 999, 0, vec![]).unwrap();
    junk.header.bits = 0x207F_FFFF; junk.header.mine();
    assert_eq!(s.accept(&junk, now()).err(), Some("bits"));
    assert_eq!(std::fs::metadata(&path).unwrap().len(), len, "nothing written for a refused block");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_long_side_branch_never_panics() {
    // more side blocks than the node keeps in memory: the branch root falls out, which used to panic
    let p = params();
    let g = Chain::genesis(&p, now() - 2_000_000, b"hard");
    let mut s = Store::open(p.clone(), &g, None).unwrap();
    let mut main = Chain::new(p.clone(), &g).unwrap();
    for i in 0..2200 { let b = main.make_block(g.header.time + 600 * (i + 1), 0, vec![]).unwrap(); main.add(&b, now()).unwrap(); s.accept(&b, now()).unwrap(); }
    let mut side = Chain::new(p.clone(), &g).unwrap();
    side.add(&main.blocks.get(1).unwrap(), now()).unwrap();
    // shorter than the main chain, so every block of this branch stays a side block
    for i in 0..2100u32 {
        let b = side.make_block(g.header.time + 601 + 600 * (i + 1), 0, vec![]).unwrap();
        side.add(&b, now()).unwrap();
        let _ = s.accept(&b, now());   // Ok or Err, but never a panic
    }
}

#[test]
fn a_crash_mid_write_loses_only_the_partial_block() {
    let p = params();
    let g = Chain::genesis(&p, now() - 100_000, b"hard");
    let path = tmp("trunc");
    { let n = Node::new(Store::open(p.clone(), &g, Some(&path)).unwrap()); for _ in 0..3 { mine(&n, 0).unwrap(); } }
    // simulate a crash halfway through writing block 4
    { let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap(); f.write_all(&500u32.to_le_bytes()).unwrap(); f.write_all(&[7; 100]).unwrap(); }
    { let n = Node::new(Store::open(p.clone(), &g, Some(&path)).unwrap()); assert_eq!(n.height(), 3); for _ in 0..5 { mine(&n, 0).unwrap(); } }
    // the blocks mined after the crash survive the next restart too
    assert_eq!(Store::open(p.clone(), &g, Some(&path)).unwrap().chain.height(), 8);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn a_reorg_below_the_snapshot_does_not_strand_the_node() {
    let p = params();
    let g = Chain::genesis(&p, now() - 1_000_000, b"hard");
    let path = tmp("snap");
    let mut s = Store::open(p.clone(), &g, Some(&path)).unwrap();
    let mut main = Chain::new(p.clone(), &g).unwrap();
    let t = |h: u32| g.header.time + 600 * h;
    for h in 1..=SNAP_EVERY + 1 { let b = main.make_block(t(h), 0, vec![]).unwrap(); main.add(&b, now()).unwrap(); s.accept(&b, now()).unwrap(); }
    assert!(path.with_extension("snap").exists());
    // a two-block branch from SNAP_EVERY - 1 wins: the snapshot at SNAP_EVERY is now off the chain
    let mut alt = Chain::new(p.clone(), &g).unwrap();
    for h in 1..SNAP_EVERY { alt.add(&main.blocks.get(h as usize).unwrap(), now()).unwrap(); }
    for k in 0..3 { let b = alt.make_block(t(SNAP_EVERY) + 7 + 600 * k, 0, vec![]).unwrap(); alt.add(&b, now()).unwrap(); s.accept(&b, now()).unwrap(); }
    assert_eq!(s.chain.tip(), alt.tip());
    // an ordinary one-block reorg at the tip still works (it used to fail with "state root")
    let mut alt2 = Chain::new(p.clone(), &g).unwrap();
    for h in 1..alt.height() { alt2.add(&alt.blocks.get(h as usize).unwrap(), now()).unwrap(); }
    for k in 0..2 { let b = alt2.make_block(t(SNAP_EVERY) + 500 + 600 * k, 0, vec![]).unwrap(); alt2.add(&b, now()).unwrap(); let _ = s.accept(&b, now()); }
    assert_eq!(s.chain.tip(), alt2.tip());
    drop(s);
    assert_eq!(Store::open(p.clone(), &g, Some(&path)).unwrap().chain.tip(), alt2.tip());
    let _ = std::fs::remove_file(&path); let _ = std::fs::remove_file(path.with_extension("snap"));
}

#[test]
fn a_data_file_from_another_genesis_is_reported() {
    let p = params();
    let g1 = Chain::genesis(&p, now() - 100_000, b"one");
    let g2 = Chain::genesis(&p, now() - 100_000, b"two");
    let path = tmp("genesis");
    { let n = Node::new(Store::open(p.clone(), &g1, Some(&path)).unwrap()); mine(&n, 0).unwrap(); }
    assert_eq!(Store::open(p.clone(), &g2, Some(&path)).unwrap().chain.height(), 0);   // sets the file aside, does not panic
    let old = format!("{}.old", path.display());
    assert!(std::path::Path::new(&old).exists());
    let _ = std::fs::remove_file(&path); let _ = std::fs::remove_file(&old);
}

fn frame(magic: &[u8; 4], kind: u8, payload: &[u8]) -> Vec<u8> { [&magic[..], &[kind], &(payload.len() as u32).to_le_bytes(), payload].concat() }

#[test]
fn rpc_refuses_huge_bodies_at_once() {
    let p = params();
    let g = Chain::genesis(&p, now() - 100_000, b"hard");
    let node = Node::new(Store::open(p, &g, None).unwrap());
    let addr = node.serve_rpc("127.0.0.1:0").unwrap();
    let mut s = TcpStream::connect(addr).unwrap();
    s.write_all(b"POST /tx HTTP/1.0\r\nContent-Length: 999999999\r\n\r\n").unwrap();
    let mut o = String::new(); let _ = s.read_to_string(&mut o);
    assert!(o.starts_with("HTTP/1.0 413"), "{o}");
}

#[test]
fn a_spoofed_advertised_address_is_not_believed() {
    let p = params();
    let g = Chain::genesis(&p, now() - 100_000, b"hard");
    let node = Node::new(Store::open(p.clone(), &g, None).unwrap());
    let at = node.listen("127.0.0.1:0").unwrap();
    let mut s = TcpStream::connect(at).unwrap();
    // HELLO from 127.0.0.1 claiming to be some other machine
    let hello = [&0u32.to_le_bytes()[..], &[0u8; 32], b"10.9.8.7:8731"].concat();
    s.write_all(&frame(&p.magic, 0, &hello)).unwrap();
    // and one that tells the truth
    let mut t = TcpStream::connect(at).unwrap();
    t.write_all(&frame(&p.magic, 0, &[&0u32.to_le_bytes()[..], &[0u8; 32], b"127.0.0.1:9"].concat())).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(300));
    let book = node.book_addrs();
    assert!(!book.contains(&"10.9.8.7:8731".to_string()));
    assert!(book.contains(&"127.0.0.1:9".to_string()));
    assert!(node.known_addrs().is_empty(), "a loopback address is kept for our own dials, never shared on a public network");
}

#[test]
fn a_peer_that_never_reads_does_not_block_the_node() {
    let p = params();
    let g = Chain::genesis(&p, now() - 1_000_000, b"hard");
    let node = Node::new(Store::open(p.clone(), &g, None).unwrap());
    let at = node.listen("127.0.0.1:0").unwrap();
    // connect, say hello, then never read a byte
    let mut s = TcpStream::connect(at).unwrap();
    s.write_all(&frame(&p.magic, 0, &[&0u32.to_le_bytes()[..], &[0u8; 32]].concat())).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(200));
    // keep mining (every block is relayed to it) while it keeps asking for batches it never reads
    let t0 = std::time::Instant::now();
    for _ in 0..40 {
        mine(&node, 0).unwrap();
        // ask the node for 500 blocks over and over, from the silent peer
        s.write_all(&frame(&p.magic, 1, &1u32.to_le_bytes())).unwrap();
    }
    assert_eq!(node.height(), 40);
    assert!(t0.elapsed() < std::time::Duration::from_secs(20), "mining was held up by a silent peer");
    drop(s);
}

#[test]
fn a_full_mempool_is_mined_over_several_blocks_not_into_one_oversized_block() {
    use bitcheque::tx::Payment;
    use bitcheque::wallet::{mine_registration, Book, Domain};
    // registrations are about 40 KB each; ten of them do not fit in a 150 KB block
    let p = Params { max_block_bytes: 150_000, reg_pow_target: bitcheque::u256::U256::MAX.shr(4), ..params() };
    let g = Chain::genesis(&p, now() - 100_000, b"hard");
    let node = Node::new(Store::open(p.clone(), &g, None).unwrap());
    mine(&node, 0).unwrap();   // block 0 is no registration anchor
    for k in 0..10u8 {
        let b = Book { salt: [k; 16], n256: false, book_size: 256, domains: vec![Domain([k + 1; 32])], net: Params::mainnet().magic };
        // mined well below the target: the registrations mined into the first block tighten it for the next (by
        // (W+1)/(W+10k)), and one mined to exactly the old target could then fall out of the mempool as insufficient
        let target = node.store.lock().unwrap().chain.state.next_reg_target(&p).shr(1);
        node.submit_tx(mine_registration(b.register(0, 16, Payment::Pow([0; 32], 0)), tip(&node), target), None).unwrap();
    }
    let mut mined = 0;
    for _ in 0..10 {
        let b = mine(&node, 0).unwrap();
        assert!(b.encode().len() <= p.max_block_bytes, "block of {} bytes", b.encode().len());
        mined += b.txs.len() - 1;
        if mined == 10 { break; }
    }
    assert_eq!(mined, 10, "every registration is mined eventually");
    assert!(node.height() > 2, "they took more than one block");
}

#[test]
fn a_number_is_published_only_once_final_and_the_lookup_code_finds_it() {
    use bitcheque::tx::Payment;
    use bitcheque::wallet::{mine_registration, Book, Domain};
    let p = Params { number_maturity: 3, reg_pow_target: bitcheque::u256::U256::MAX.shr(4), ..params() };
    let g = Chain::genesis(&p, now() - 100_000, b"hard");
    let node = Node::new(Store::open(p.clone(), &g, None).unwrap());
    mine(&node, 0).unwrap();   // block 0 is no registration anchor
    let addr = node.serve_rpc("127.0.0.1:0").unwrap();
    let get = |path: &str| { let mut s = TcpStream::connect(addr).unwrap(); s.write_all(format!("GET {path} HTTP/1.0\r\n\r\n").as_bytes()).unwrap(); let mut o = String::new(); let _ = s.read_to_string(&mut o); o };
    let b = Book { salt: [5; 16], n256: false, book_size: 256, domains: vec![Domain([6; 32])], net: Params::mainnet().magic };
    let id = bitcheque::crypto::hex(&b.id());
    let target = node.store.lock().unwrap().chain.state.next_reg_target(&p);
    node.submit_tx(mine_registration(b.register(0, 16, Payment::Pow([0; 32], 0)), tip(&node), target), None).unwrap();
    mine(&node, 0).unwrap();
    let code = &id[2..14];                                   // the id's root, after the scheme byte
    let young = get(&format!("/lookup/{}-{}-{}", &code[..4], &code[4..8], &code[8..]));
    assert!(young.contains(&format!("id {id}")) && young.contains("mature false"), "{young}");
    assert!(!young.contains("\nnumber "), "a young number is not shown: {young}");
    assert!(!get("/summary/2").contains("number="), "nor in the block");
    // asking for it by number gives exactly what an unknown number gives, so new numbers cannot be probed for
    for path in ["/history/1", "/proof/1"] {
        assert_eq!(get(path).split("\r\n\r\n").nth(1), get(&path.replace('1', "77")).split("\r\n\r\n").nth(1), "{path}");
        assert!(get(path).contains("no such number"), "{path}");
    }
    // by number it says only that the number is pending and when it becomes final, never whose it is
    let pending = get("/account/1");
    assert!(pending.ends_with("pending\nready_at 5") && !pending.contains(&id), "{pending}");
    assert!(get("/account/77").contains("no such number"));
    // and a block cannot pay it yet
    assert_eq!(node.template(1).err(), Some("coinbase payee not mature"));
    for _ in 0..3 { mine(&node, 0).unwrap(); }
    assert!(get("/account/1").contains(&format!("id {id}")) && get("/history/1").contains("register number=1"), "final: open to all");
    assert!(node.template(1).is_ok(), "and it can take a block reward");
    let fin = get(&format!("/lookup/{}", code.to_uppercase()));
    assert!(fin.contains("\nnumber 1\n") && fin.contains("mature true"), "{fin}");
    assert!(get("/summary/2").contains("number=1"), "final: shown in the block too");
    assert!(get("/lookup/1234").contains("8 or more"));
}

#[test]
fn a_cheque_to_yourself_shows_as_both_receive_and_send() {
    use bitcheque::message::Message;
    use bitcheque::tx::Payment;
    use bitcheque::wallet::{mine_registration, Book, Domain};
    let p = Params { reg_pow_target: bitcheque::u256::U256::MAX.shr(4), ..params() };
    let g = Chain::genesis(&p, now() - 100_000, b"hard");
    let node = Node::new(Store::open(p.clone(), &g, None).unwrap());
    mine(&node, 0).unwrap();   // block 0 is no registration anchor
    let addr = node.serve_rpc("127.0.0.1:0").unwrap();
    let get = |path: &str| { let mut s = TcpStream::connect(addr).unwrap(); s.write_all(format!("GET {path} HTTP/1.0\r\n\r\n").as_bytes()).unwrap(); let mut o = String::new(); let _ = s.read_to_string(&mut o); o };
    let b = Book { salt: [7; 16], n256: false, book_size: 256, domains: vec![Domain([8; 32])], net: Params::mainnet().magic };
    let target = node.store.lock().unwrap().chain.state.next_reg_target(&p);
    node.submit_tx(mine_registration(b.register(0, 16, Payment::Pow([0; 32], 0)), tip(&node), target), None).unwrap();
    mine(&node, 0).unwrap();                                // the registration's block: number 1 is not final yet
    for _ in 0..4 { mine(&node, 1).unwrap(); }              // account 1 mines its own rewards
    for t in b.sign(1, &Message::new(1, 1000, 5, 1)) { node.submit_tx(t, None).unwrap(); }   // 1 coin to itself
    mine(&node, 1).unwrap();
    let h = get("/history/1");
    assert!(h.contains(" receive from=1 cheque=1 amount=100000000"), "{h}");
    assert!(h.contains(" send cheque=1 to=1 amount=100000000"), "{h}");
}

/// A registration and its cheque 0 posted in one /tx request are queued together and land in the same block,
/// with one result per line; the same body again reports each one as already queued.
#[test]
fn a_batch_of_transactions_lands_in_one_block() {
    use bitcheque::crypto::hex;
    use bitcheque::message::Message;
    use bitcheque::tx::Payment;
    use bitcheque::wallet::{mine_registration, Book, Domain};
    let p = Params { reg_pow_target: bitcheque::u256::U256::MAX.shr(4), ..params() };
    let g = Chain::genesis(&p, now() - 100_000, b"hard");
    let node = Node::new(Store::open(p.clone(), &g, None).unwrap());
    mine(&node, 0).unwrap();   // block 0 is no registration anchor
    let b = Book { salt: [9; 16], n256: false, book_size: 256, domains: vec![Domain([10; 32])], net: Params::mainnet().magic };
    let target = node.store.lock().unwrap().chain.state.next_reg_target(&p);
    let mut txs = vec![mine_registration(b.register(0, 16, Payment::Pow([0; 32], 0)), tip(&node), target)];
    txs.extend(b.sign(0, &Message::new(0, 0, 0, 0)));
    let body = txs.iter().map(|t| hex(&t.encode())).collect::<Vec<_>>().join("\n");
    let reply = node.route("POST", "/tx", &body).unwrap();
    assert_eq!(reply.lines().filter(|l| *l == "ok").count(), 7, "{reply}");
    let again = node.route("POST", "/tx", &body).unwrap();
    assert!(again.lines().all(|l| l == "already in mempool"), "{again}");
    let block = mine(&node, 0).unwrap();
    assert_eq!(block.txs.len(), 1 + 7);   // coinbase, the registration and cheque 0 (its opening and 5 pieces)
    assert_eq!(node.store.lock().unwrap().chain.state.accounts[&b.id()].nonce, Some(0));
}

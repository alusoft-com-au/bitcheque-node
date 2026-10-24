//! The table proof of work (DESIGN.md §1.1, src/pow.rs): vectors shared with the Python cross-check and the CUDA miner,
//! the header's height rule, the epoch boundary, what a lying or workless header costs its sender, and the floors.
mod common;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};
use bitcheque::block::{Chain, Header};
use bitcheque::crypto::{hex, sha256};
use bitcheque::net::Node;
use bitcheque::params::{Params, GENESIS_MESSAGE, LAUNCH_TIME, TESTNET_TIME};
use bitcheque::pow::{element, epoch, hash, indices, seed, Table, EPOCH, K, N, ROUNDS};
use bitcheque::store::Store;
use bitcheque::u256::U256;

fn params() -> Params { Params { initial_bits: 0x207F_FFFF, min_bits: 0x207F_FFFF, launch_blocks: 0, max_future_seconds: 1 << 30, ..Params::mainnet() } }
fn frame(magic: &[u8; 4], kind: u8, payload: &[u8]) -> Vec<u8> { [&magic[..], &[kind], &(payload.len() as u32).to_le_bytes(), payload].concat() }
fn closed(s: &mut TcpStream, secs: u64) -> bool {
    s.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    let (t, mut b) = (Instant::now(), [0u8; 65536]);
    while t.elapsed() < Duration::from_secs(secs) { match s.read(&mut b) { Ok(0) => return true, Ok(_) => {} Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {} Err(_) => return true } }
    false
}
/// Mine `h` against another epoch's table until it meets its target there but not with its own: a miner on a stale table.
fn mine_with_wrong_table(h: &mut Header, wrong: u32) {
    let s = seed(wrong);
    loop {
        let id = h.hash();
        if h.meets(&hash(&id, &mut |i| element(&s, i))) && !h.meets_target() { return; }
        h.nonce = h.nonce.wrapping_add(1);
    }
}

/// The values genesis.py computes with its own code (and the CUDA miner's self-test checks on the card).
#[test]
fn vectors_match_the_python_cross_check() {
    assert_eq!((N, K, ROUNDS, EPOCH), (1 << 26, 32, 512, 1024));
    assert_eq!(hex(&seed(0)), "586ed6dff289102f1527e5648afa39758018f46c7aa76d874d946f8cee510d53");
    assert_eq!(hex(&element(&seed(0), 0)), "0a5cfa9ca9dfdc070f30cf50c98222e2ce461364e31e998549bc72eb8276318f");
    assert_eq!(hex(&element(&seed(1), 12345)), "05ef8b66d9f9d3241c2b66b3470a5f9bc9ef2eaa164a2c7fe30b78e7c19f802b");
    let id = sha256(b"x");
    let ix = indices(&id);
    assert_eq!((ix[0], ix[1], ix[31]), (23781606, 19991627, 32125694));
    assert!(ix.iter().all(|&i| (i as usize) < N));
    let light = |e: u32| { let s = seed(e); hash(&id, &mut |i| element(&s, i)) };
    assert_eq!(hex(&light(0)), "9f8f3809e9c27beffacf0ce76f72544d59bb0274ef1d842bff9ec477da368b4f");
    assert_eq!(hex(&light(1)), "6712403938fd011a452e0e3a6d9a7df8d373671e2050f281beed887f5372bd6b");
    // a header's own pow() is the light hash under its epoch's table
    let mut h = Header { height: 1024, prev: [1; 32], tx_root: [2; 32], state_root: [3; 32], time: 5, bits: 0x207F_FFFF, nonce: 9 };
    let (id, s1, s0) = (h.hash(), seed(1), seed(0));
    assert_eq!(h.pow(), hash(&id, &mut |i| element(&s1, i)));
    assert_ne!(h.pow(), hash(&id, &mut |i| element(&s0, i)), "another epoch, another table");
    h.height = 1023;
    assert_eq!(h.pow(), hash(&h.hash(), &mut |i| element(&s0, i)));
    assert_eq!((epoch(0), epoch(1023), epoch(1024), epoch(u32::MAX)), (0, 0, 1, u32::MAX / 1024));
}

/// The miner's table gives the same hash as recomputing the elements. 2^26 elements: a quarter of an hour on many cores.
/// `cargo test --release --test pow -- --ignored`
#[test]
#[ignore]
fn the_table_agrees_with_the_light_path() {
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    let t = Instant::now();
    let tb = Table::build(1, threads);
    eprintln!("table of epoch 1 built in {:.1} s on {threads} threads", t.elapsed().as_secs_f64());
    assert_eq!((tb.epoch, tb.cells.len()), (1, N));
    let s = seed(1);
    for i in [0u32, 1, 12345, N as u32 / 2, N as u32 - 1] { assert_eq!(tb.cells[i as usize], element(&s, i)); }
    assert_eq!(hex(&tb.cells[12345]), "05ef8b66d9f9d3241c2b66b3470a5f9bc9ef2eaa164a2c7fe30b78e7c19f802b");
    for k in 0..20u8 {
        let h = Header { height: 1024 + k as u32, prev: [k; 32], tx_root: [2; 32], state_root: [3; 32], time: 5, bits: 0x207F_FFFF, nonce: k as u32 };
        assert_eq!(tb.hash(&h.hash()), h.pow());
    }
    let t = Instant::now(); let mut acc = 0u8;
    for n in 0..20_000u32 { let mut id = [0u8; 32]; id[..4].copy_from_slice(&n.to_le_bytes()); acc ^= tb.hash(&id)[0]; }
    eprintln!("table mode: {:.0} tries/s on one thread (acc {acc})", 20_000.0 / t.elapsed().as_secs_f64());
}

/// A header carries its height, and it must be the parent's plus one: on the main chain and on a side branch, a block
/// claiming any other height is refused, with work spent on it or not. The coinbase's height must agree too.
#[test]
fn a_header_must_carry_its_height() {
    let p = params();
    let g = Chain::genesis(&p, 1000, b"h");
    assert_eq!(g.header.height, 0);
    let n = Node::new(Store::open(p.clone(), &g, None).unwrap());
    for _ in 0..3 { common::mine(&n, 0).unwrap(); }
    let tip_h = n.height();
    for wrong in [tip_h, tip_h + 2, 0, u32::MAX] {
        let mut b = n.template(0).unwrap();
        b.header.height = wrong;
        b.header.mine();
        assert_eq!(n.submit_block(&b, None), Err("height"), "a block at height {} claiming {wrong}", tip_h + 1);
    }
    // the coinbase disagreeing with a truthful header
    let mut b = n.template(0).unwrap();
    if let bitcheque::tx::Tx::Coinbase { height, .. } = &mut b.txs[0] { *height += 1; }
    b.header.tx_root = bitcheque::block::tx_root(&b.txs);
    b.header.mine();
    assert_eq!(n.submit_block(&b, None), Err("coinbase"));
    // a side branch: a block on block 1 must say 2
    let one = { let st = n.store.lock().unwrap(); st.chain.blocks.get(1).unwrap() };
    let now = bitcheque::net::now();
    let mut side = Chain::new(p.clone(), &g).unwrap(); side.add(&one, now + 1).unwrap();
    let mut b2 = side.template(now + 2, 0, vec![]).unwrap();   // a second later than the main chain's block 2: another block
    assert_eq!(b2.header.height, 2);
    b2.header.height = 3; b2.header.mine();
    assert_eq!(n.submit_block(&b2, None), Err("height"), "a side block claiming the wrong height");
    b2.header.height = 2; b2.header.mine();
    assert_eq!(n.submit_block(&b2, None), Ok(false), "the truthful side block is kept");
    assert_eq!(n.store.lock().unwrap().height_of(&b2.header.hash()), Some(2), "a side block's height is read from its header");
}

/// Across an epoch boundary the table changes: block EPOCH is mined and verified with the next table, and a miner still
/// on the old one finds nonces the chain refuses.
#[test]
fn the_table_changes_at_the_epoch_boundary() {
    let p = params();
    let g = Chain::genesis(&p, 1000, b"e");
    let mut c = Chain::new(p.clone(), &g).unwrap();
    let mut t = 1000;
    for _ in 1..EPOCH { t += 60; let b = c.make_block(t, 0, vec![]).unwrap(); c.add(&b, t + 1).unwrap(); }
    assert_eq!(c.height(), EPOCH - 1);
    t += 60;
    let mut stale = c.template(t, 0, vec![]).unwrap();
    assert_eq!((stale.header.height, epoch(stale.header.height)), (EPOCH, 1));
    mine_with_wrong_table(&mut stale.header, 0);
    assert_eq!(c.add(&stale, t + 1), Err("pow"), "mined against epoch 0's table");
    let b = c.make_block(t, 0, vec![]).unwrap();
    let s1 = seed(1);
    assert!(b.header.meets(&hash(&b.header.hash(), &mut |i| element(&s1, i))));
    c.add(&b, t + 1).unwrap();
    assert_eq!(c.height(), EPOCH);
    // and the one after, still epoch 1
    t += 60; let b = c.make_block(t, 0, vec![]).unwrap(); c.add(&b, t + 1).unwrap();
    assert_eq!(c.header_at(EPOCH + 1).unwrap().height, EPOCH + 1);
}

/// A peer sending headers without work, or with work but a lie about the height, is struck for each and dropped at the
/// third: a verification costs about a millisecond, a strike is all a sender gets for it.
#[test]
fn workless_and_lying_headers_cost_strikes() {
    let p = params();
    let g = Chain::genesis(&p, 1_790_000_000, b"s");
    let n = Node::new(Store::open(p.clone(), &g, None).unwrap());
    for _ in 0..2 { common::mine(&n, 0).unwrap(); }
    let addr = n.listen("127.0.0.1:0").unwrap();
    let hello = [0u32.to_le_bytes().as_slice(), &n.store.lock().unwrap().chain.tip()].concat();
    // no work: a template with a nonce that does not meet the target
    let mut s = TcpStream::connect(addr).unwrap();
    s.write_all(&frame(&p.magic, 0, &hello)).unwrap();
    let mut b = n.template(0).unwrap();
    while b.header.meets_target() { b.header.nonce += 1; }
    for k in 0..3u32 { let mut x = b.clone(); x.header.time += k; while x.header.meets_target() { x.header.nonce += 1; } let _ = s.write_all(&frame(&p.magic, 2, &x.encode())); }
    assert!(closed(&mut s, 5), "three workless headers: dropped");
    assert_eq!(n.height(), 2, "nothing was taken");
    // work, but a lie about the height: refused, remembered as bad, and the sender dropped
    let mut s = TcpStream::connect(addr).unwrap();
    s.write_all(&frame(&p.magic, 0, &hello)).unwrap();
    for k in 0..3u32 { let mut x = n.template(0).unwrap(); x.header.height = 10 + k; x.header.mine(); let _ = s.write_all(&frame(&p.magic, 2, &x.encode())); }   // (the node may close it before the third)
    assert!(closed(&mut s, 5), "three lying headers: dropped");
    assert_eq!(n.height(), 2);
    // an honest block still goes through from a fresh connection (loopback is never banned)
    let mut s = TcpStream::connect(addr).unwrap();
    s.write_all(&frame(&p.magic, 0, &hello)).unwrap();
    let mut good = n.template(0).unwrap(); good.header.mine();
    s.write_all(&frame(&p.magic, 2, &good.encode())).unwrap();
    let t = Instant::now(); while n.height() < 3 && t.elapsed() < Duration::from_secs(5) { std::thread::sleep(Duration::from_millis(20)); }
    assert_eq!(n.height(), 3);
}

/// Every network's block 0 is mined at start-up without a table, so its target asks about 2^8 tries; the floors are what
/// the parameters say, in the order the design wants (research network easiest, then mainnet), and block 0's nonces are
/// the ones genesis.py finds.
#[test]
fn floors_and_block_zero() {
    for p in [Params::mainnet(), Params::testnet()] { assert_eq!(U256::from_compact(p.initial_bits), U256::one_shl(250)); }
    assert_eq!(U256::from_compact(Params::testnet().min_bits), U256::one_shl(248), "the research floor: ~2^8 tries");
    assert_eq!(U256::from_compact(Params::mainnet().min_bits), U256::one_shl(236), "the mainnet floor: ~2^20 tries");
    assert!(U256::from_compact(Params::testnet().min_bits) > U256::from_compact(Params::mainnet().min_bits));
    assert_eq!(Params::mainnet().easiest_target(), U256::one_shl(250), "block 0's target is the easiest any mainnet block may carry");
    assert_eq!(Params::local().easiest_target(), U256::from_compact(0x207F_FFFF));
    let t = Instant::now();
    let g = Chain::genesis(&Params::testnet(), TESTNET_TIME, GENESIS_MESSAGE);
    assert_eq!((g.header.height, g.header.nonce), (0, 174));
    assert_eq!(Chain::genesis(&Params::mainnet(), LAUNCH_TIME, GENESIS_MESSAGE).header.nonce, 60);
    assert!(t.elapsed() < Duration::from_secs(30), "two block 0s took {:?}", t.elapsed());
    // a light verification is a few milliseconds (far more would mean the hash was changed by mistake)
    let t = Instant::now();
    for k in 0..20u32 { let h = Header { height: k, prev: [0; 32], tx_root: [0; 32], state_root: [0; 32], time: 0, bits: 0x207F_FFFF, nonce: k }; let _ = h.pow(); }
    let per = t.elapsed() / 20;
    eprintln!("light verification: {per:?}");
    assert!(per < Duration::from_millis(100), "{per:?} per verification");
}

/// A header's work is verified once: the second look at the same header is a lookup (pow::verified), wherever it comes
/// from. Only what passed is remembered.
#[test]
fn a_header_is_verified_once() {
    let mut h = Header { height: 7, prev: [9; 32], tx_root: [0; 32], state_root: [0; 32], time: 1, bits: 0x207F_FFFF, nonce: 0 };
    while !h.meets(&h.pow()) { h.nonce += 1; }
    assert!(!bitcheque::pow::verified(&h.hash()), "not looked at by meets_target yet");
    assert!(h.meets_target());
    assert!(bitcheque::pow::verified(&h.hash()), "remembered");
    let t = Instant::now();
    for _ in 0..200 { assert!(h.meets_target()); }
    assert!(t.elapsed() < Duration::from_millis(100), "200 repeats took {:?}: not cached", t.elapsed());
    let mut bad = h.clone(); while bad.meets(&bad.pow()) { bad.nonce += 1; }
    assert!(!bad.meets_target() && !bitcheque::pow::verified(&bad.hash()), "what fails is not remembered");
}

/// Headers on a parent we do not know are answered "prev unknown" without their work being checked (as the parent itself
/// was), so they are no strike and cost a lookup: a peer may send many, and stays connected. Side blocks offered unasked
/// (on a known parent other than our tip) are taken 30 a minute from one peer; the rest are dropped unverified.
#[test]
fn unknown_parents_cost_nothing_and_unasked_side_blocks_are_capped() {
    let p = params();
    let g = Chain::genesis(&p, 1_790_000_000, b"c");
    let n = Node::new(Store::open(p.clone(), &g, None).unwrap());
    for _ in 0..3 { common::mine(&n, 0).unwrap(); }
    let addr = n.listen("127.0.0.1:0").unwrap();
    let hello = [0u32.to_le_bytes().as_slice(), &n.store.lock().unwrap().chain.tip()].concat();
    let mut s = TcpStream::connect(addr).unwrap();
    s.write_all(&frame(&p.magic, 0, &hello)).unwrap();
    // 300 headers on unknown parents, none with work: 300 ms of verification if they were looked at
    let t = Instant::now();
    for k in 0..300u32 { let mut b = n.template(0).unwrap(); b.header.prev = [k as u8; 32]; b.header.prev[1] = (k >> 8) as u8; b.header.nonce = 77; s.write_all(&frame(&p.magic, 2, &b.encode())).unwrap(); }
    let mut probe = n.template(0).unwrap(); probe.header.mine();
    s.write_all(&frame(&p.magic, 2, &probe.encode())).unwrap();
    let w = Instant::now(); while n.height() < 4 && w.elapsed() < Duration::from_secs(5) { std::thread::sleep(Duration::from_millis(10)); }
    assert_eq!(n.height(), 4, "the connection is still open and taking blocks after 300 unknown parents");
    assert!(t.elapsed() < Duration::from_secs(3), "{:?} for 300 unknown parents and a block", t.elapsed());
    // 40 valid side blocks on block 1 from the same connection, unasked: 30 are taken
    let one = { let st = n.store.lock().unwrap(); st.chain.blocks.get(1).unwrap() };
    let now = bitcheque::net::now();
    let mut side = Chain::new(p.clone(), &g).unwrap(); side.add(&one, now + 1).unwrap();
    let mut hashes = Vec::new();
    for k in 0..40u32 { let mut b = side.template(now + 10 + k, 0, vec![]).unwrap(); b.header.mine(); hashes.push(b.header.hash()); s.write_all(&frame(&p.magic, 2, &b.encode())).unwrap(); }
    let mut again = n.template(0).unwrap(); again.header.mine();
    s.write_all(&frame(&p.magic, 2, &again.encode())).unwrap();
    let w = Instant::now(); while n.height() < 5 && w.elapsed() < Duration::from_secs(5) { std::thread::sleep(Duration::from_millis(10)); }
    assert_eq!(n.height(), 5, "still connected: dropping side blocks is no strike");
    let kept = { let st = n.store.lock().unwrap(); hashes.iter().filter(|h| st.height_of(h) == Some(2)).count() };
    assert_eq!(kept, 30, "{kept} side blocks kept of 40 offered unasked");
}

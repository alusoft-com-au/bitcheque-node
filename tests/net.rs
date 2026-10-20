//! Two in-process nodes: B syncs A's history, then a tx submitted at B is relayed to A,
//! mined there and relayed back as a block.
mod common;
use common::{mine, tip};
use std::time::{Duration, Instant};
use bitcheque::block::Chain;
use bitcheque::net::Node;
use bitcheque::params::Params;
use bitcheque::store::Store;
use bitcheque::tx::Payment;
use bitcheque::u256::U256;
use bitcheque::wallet::{mine_registration, Book, Domain};

fn wait(cond: impl Fn() -> bool) { let t = Instant::now(); while !cond() { assert!(t.elapsed() < Duration::from_secs(10), "timeout"); std::thread::sleep(Duration::from_millis(20)); } }

#[test]
fn sync_and_relay() {
    let p = Params { initial_bits: 0x207F_FFFF, min_bits: 0x207F_FFFF, reg_pow_target: U256::MAX.shr(4), launch_blocks: 0, ..Params::mainnet() };
    let g = Chain::genesis(&p, bitcheque::net::now() - 100_000, b"net test");
    let a = Node::new(Store::open(p.clone(), &g, None).unwrap());
    let b = Node::new(Store::open(p.clone(), &g, None).unwrap());
    mine(&a, 0).unwrap();   // block 0 is no registration anchor
    let miner = Book { salt: [1; 16], n256: false, book_size: 256, domains: vec![Domain([7; 32])], net: Params::mainnet().magic };
    a.submit_tx(mine_registration(miner.register(0, 16, Payment::Pow([0; 32], 0)), tip(&a), p.reg_pow_target), None).unwrap();
    for _ in 0..3 { mine(&a, 0).unwrap(); }   // number 1 is not final for 100 blocks: mine to nobody
    assert_eq!(a.height(), 4);

    let addr = a.listen("127.0.0.1:0").unwrap();
    b.connect(&addr.to_string()).unwrap();
    wait(|| b.height() == 4);
    assert_eq!(b.store.lock().unwrap().chain.tip(), a.store.lock().unwrap().chain.tip());

    let user = Book { salt: [2; 16], n256: false, book_size: 256, domains: vec![Domain([8; 32]), Domain([9; 32])], net: Params::mainnet().magic };
    b.submit_tx(mine_registration(user.register(0, 16, Payment::Pow([0; 32], 0)), tip(&b), p.reg_pow_target), None).unwrap();
    wait(|| a.mempool.lock().unwrap().len() == 1);
    mine(&a, 0).unwrap();
    wait(|| b.height() == 5);
    assert!(b.store.lock().unwrap().chain.state.accounts.contains_key(&user.id()));
    assert!(b.mempool.lock().unwrap().is_empty());
}

/// A cheque whose opening and pieces wait unmined in the queue must not block the account: the next cheque
/// number abandons it (DESIGN.md §10.12), and the wallet relies on the exact rejection texts here.
#[test]
fn queued_cheque_does_not_block_the_next() {
    use bitcheque::message::Message;
    use bitcheque::params::COIN;
    let p = Params { initial_bits: 0x207F_FFFF, min_bits: 0x207F_FFFF, reg_pow_target: U256::MAX.shr(4), launch_blocks: 0, reward_maturity: 2, number_maturity: 2,
                     piece_lifetime: 3, reward_base: 50 * COIN, ..Params::mainnet() };
    let g = Chain::genesis(&p, bitcheque::net::now() - 100_000, b"queue test");
    let a = Node::new(Store::open(p.clone(), &g, None).unwrap());
    let miner = Book { salt: [1; 16], n256: false, book_size: 256, domains: vec![Domain([7; 32])], net: Params::mainnet().magic };
    let user = Book { salt: [2; 16], n256: false, book_size: 256, domains: vec![Domain([8; 32])], net: Params::mainnet().magic };
    mine(&a, 0).unwrap();   // block 0 is no registration anchor
    a.submit_tx(mine_registration(miner.register(0, 16, Payment::Pow([0; 32], 0)), tip(&a), p.reg_pow_target), None).unwrap();
    a.submit_tx(mine_registration(user.register(0, 16, Payment::Pow([0; 32], 0)), tip(&a), p.reg_pow_target), None).unwrap();
    // miner is number 1, user number 2 (height 2); both are final at height 4, when the miner's rewards start,
    // and the height-4 reward is credited at height 6
    for k in 0..5 { mine(&a, if k < 2 { 0 } else { 1 }).unwrap(); }
    let balance = |b: &Book| a.store.lock().unwrap().chain.state.accounts[&b.id()].balance;
    assert!(balance(&miner) >= 50 * COIN);

    // cheque 1: opened and 4 of its 5 remaining pieces queued, never completed
    let half = miner.sign(1, &Message::new(2, 1, 8, 1));
    for t in &half[..5] { a.submit_tx(t.clone(), None).unwrap(); }
    // the queue knows the cheque is open and which columns are taken: the wallet relies on exactly these texts
    assert_eq!(a.check_txs(&half[..1])[0], Err("cheque already open"));
    assert_eq!(a.check_txs(&half[1..2])[0], Err("column already revealed"));
    // another digit, in an opening or a piece: someone else holds this cheque, and the wallet stops on exactly these texts
    let other = miner.sign(1, &Message::new(3, 1, 8, 1));
    assert_eq!(a.check_txs(&other[..1])[0], Err("cheque open with other digits"));
    let wrong = miner.pieces(1, &Message::new(2, 2, 8, 1).digits());
    assert_eq!(a.check_txs(&wrong[15..16])[0], Err("column revealed with other digits"));
    // cheque 2 is accepted on top of the queue: it abandons cheque 1
    let next = miner.sign(2, &Message::new(2, 3, 8, 1)); // 3 coins
    assert!(a.check_txs(&next).iter().all(|r| r.is_ok()));
    for t in &next { a.submit_tx(t.clone(), None).unwrap(); }
    mine(&a, 1).unwrap();
    let st = a.store.lock().unwrap();
    let m = &st.chain.state.accounts[&miner.id()];
    assert_eq!((m.nonce, m.open.is_empty(), m.commits.contains_key(&1)), (Some(2), true, false));
    assert_eq!(st.chain.state.accounts[&user.id()].balance, 3 * COIN);
    drop(st);
    // and a finished number is refused with the text the wallet looks for
    assert_eq!(a.check_txs(&next[..1])[0], Err("cheque number already consumed"));
}

/// Discovery: C is told only about A, learns B's address from A (B advertised it in HELLO,
/// A passed it on in reply to GET_ADDR), and dials B on its own.
#[test]
fn peers_find_each_other_through_gossip() {
    // a devnet: gossip passes loopback addresses only there (elsewhere only public IPs; see below)
    let p = Params { initial_bits: 0x207F_FFFF, min_bits: 0x207F_FFFF, launch_blocks: 0, magic: Params::local().magic, ..Params::mainnet() };
    let g = Chain::genesis(&p, bitcheque::net::now() - 100_000, b"gossip test");
    let mk = || Node::new(Store::open(p.clone(), &g, None).unwrap());
    let (a, b, c) = (mk(), mk(), mk());
    let addr_a = a.listen("127.0.0.1:0").unwrap().to_string();
    let addr_b = b.listen("127.0.0.1:0").unwrap().to_string();
    b.set_advertise(&addr_b);
    b.connect(&addr_a).unwrap();
    wait(|| a.known_addrs() == vec![addr_b.clone()]);   // A learned B from B's HELLO
    c.connect(&addr_a).unwrap();
    wait(|| c.known_addrs().contains(&addr_b));          // C asked A and was told about B
    c.maintain(vec![], Duration::from_millis(200));
    wait(|| c.peer_count() == 2 && b.peer_count() == 2); // C dialled B; B now sees A and C
    assert!(bitcheque::net::valid_addr("seed1.bitcheque.example:8731") && !bitcheque::net::valid_addr("no port") && !bitcheque::net::valid_addr("x:99999"));
}

/// On a public network, gossip may not plant private, loopback or named hosts in the address book.
#[test]
fn gossip_takes_only_public_addresses() {
    use std::io::Write;
    let p = Params { initial_bits: 0x207F_FFFF, min_bits: 0x207F_FFFF, launch_blocks: 0, ..Params::mainnet() };
    let g = Chain::genesis(&p, bitcheque::net::now() - 100_000, b"gossip test");
    let a = Node::new(Store::open(p.clone(), &g, None).unwrap());
    let at = a.listen("127.0.0.1:0").unwrap();
    let frame = |kind: u8, payload: &[u8]| [&p.magic[..], &[kind], &(payload.len() as u32).to_le_bytes(), payload].concat();
    let mut s = std::net::TcpStream::connect(at).unwrap();
    s.write_all(&frame(0, &[&0u32.to_le_bytes()[..], &[0u8; 32]].concat())).unwrap();
    s.write_all(&frame(4, b"10.1.2.3:8730\n127.0.0.1:8730\n192.168.1.1:8730\nsome.host.example:8730\n8.8.4.4:8730")).unwrap();
    wait(|| !a.known_addrs().is_empty());
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(a.known_addrs(), vec!["8.8.4.4:8730".to_string()]);
}

/// A node that follows an upstream over its HTTP RPC (as nodes follow the edge nodes, which speak no TCP): it pulls
/// the upstream's blocks, and what it accepts itself (a registration sent to it, a block mined against it) goes up.
#[test]
fn a_follower_pulls_blocks_and_pushes_what_it_accepts() {
    let p = Params { initial_bits: 0x207F_FFFF, min_bits: 0x207F_FFFF, reg_pow_target: U256::MAX.shr(4), launch_blocks: 0, ..Params::mainnet() };
    let g = Chain::genesis(&p, bitcheque::net::now() - 100_000, b"follow test");
    let a = Node::new(Store::open(p.clone(), &g, None).unwrap());
    let b = Node::new(Store::open(p.clone(), &g, None).unwrap());
    let up = a.serve_rpc("127.0.0.1:0").unwrap().to_string();
    for _ in 0..5 { mine(&a, 0).unwrap(); }
    b.follow(vec![up], Duration::from_millis(200));
    wait(|| b.height() == 5);
    assert_eq!(b.store.lock().unwrap().chain.tip(), a.store.lock().unwrap().chain.tip());

    // a registration sent to the follower reaches the upstream; a block mined on the follower does too
    let user = Book { salt: [3; 16], n256: false, book_size: 256, domains: vec![Domain([4; 32])], net: Params::mainnet().magic };
    b.submit_tx(mine_registration(user.register(0, 16, Payment::Pow([0; 32], 0)), tip(&b), p.reg_pow_target), None).unwrap();
    wait(|| a.mempool.lock().unwrap().len() == 1);
    mine(&b, 0).unwrap();
    wait(|| a.height() == 6);
    assert!(a.store.lock().unwrap().chain.state.accounts.contains_key(&user.id()));
    // and blocks it pulled are not pushed back: the upstream saw only the one block mined on the follower
    for _ in 0..3 { mine(&a, 0).unwrap(); }
    wait(|| b.height() == 9);
}

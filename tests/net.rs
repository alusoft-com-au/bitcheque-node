//! Two in-process nodes: B syncs A's history, then a tx submitted at B is relayed to A,
//! mined there and relayed back as a block.
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
    let p = Params { initial_bits: 0x207F_FFFF, min_bits: 0x207F_FFFF, reg_pow_target: U256::MAX.shr(4), slow_start_blocks: 1, ..Params::mainnet() };
    let g = Chain::genesis(&p, bitcheque::net::now() - 100_000, b"net test");
    let a = Node::new(Store::open(p.clone(), &g, None).unwrap());
    let b = Node::new(Store::open(p.clone(), &g, None).unwrap());
    let miner = Book { salt: [1; 16], n256: false, book_size: 16, domains: vec![Domain([7; 32])] };
    a.submit_tx(mine_registration(miner.register(0, 16, Payment::Pow(0)), p.reg_pow_target), None).unwrap();
    for _ in 0..3 { a.mine_once(1).unwrap(); }
    assert_eq!(a.height(), 3);

    let addr = a.listen("127.0.0.1:0").unwrap();
    b.connect(&addr.to_string()).unwrap();
    wait(|| b.height() == 3);
    assert_eq!(b.store.lock().unwrap().chain.tip(), a.store.lock().unwrap().chain.tip());

    let user = Book { salt: [2; 16], n256: false, book_size: 11, domains: vec![Domain([8; 32]), Domain([9; 32])] };
    b.submit_tx(mine_registration(user.register(0, 16, Payment::Pow(0)), p.reg_pow_target), None).unwrap();
    wait(|| a.mempool.lock().unwrap().len() == 1);
    a.mine_once(1).unwrap();
    wait(|| b.height() == 4);
    assert!(b.store.lock().unwrap().chain.state.accounts.contains_key(&user.id()));
    assert!(b.mempool.lock().unwrap().is_empty());
}

/// A cheque whose first pieces wait unmined in the queue must not block the account: the next cheque
/// number abandons it (DESIGN.md §10.12), and the wallet relies on the exact rejection texts here.
#[test]
fn queued_cheque_does_not_block_the_next() {
    use bitcheque::message::Message;
    use bitcheque::params::COIN;
    let p = Params { initial_bits: 0x207F_FFFF, min_bits: 0x207F_FFFF, reg_pow_target: U256::MAX.shr(4), slow_start_blocks: 1, reward_maturity: 2, number_maturity: 2,
                     piece_lifetime: 3, reward_base: 50 * COIN, ..Params::mainnet() };
    let g = Chain::genesis(&p, bitcheque::net::now() - 100_000, b"queue test");
    let a = Node::new(Store::open(p.clone(), &g, None).unwrap());
    let miner = Book { salt: [1; 16], n256: false, book_size: 16, domains: vec![Domain([7; 32])] };
    let user = Book { salt: [2; 16], n256: false, book_size: 11, domains: vec![Domain([8; 32])] };
    a.submit_tx(mine_registration(miner.register(0, 16, Payment::Pow(0)), p.reg_pow_target), None).unwrap();
    a.submit_tx(mine_registration(user.register(0, 16, Payment::Pow(0)), p.reg_pow_target), None).unwrap();
    for _ in 0..4 { a.mine_once(1).unwrap(); } // miner is number 1, user number 2; rewards matured, numbers mature
    let balance = |b: &Book| a.store.lock().unwrap().chain.state.accounts[&b.id()].balance;
    assert!(balance(&miner) >= 50 * COIN);

    // cheque 1: 17 of 18 pieces queued, never completed
    let half = miner.sign(1, &Message::new(2, 1, 8, 1));
    for t in &half[..17] { a.submit_tx(t.clone(), None).unwrap(); }
    // the queue knows those columns are taken: the wallet skips a number on exactly this text
    let again = a.check_txs(&half[..1]);
    assert_eq!(again[0], Err("column already revealed"));
    // cheque 2 is accepted on top of the queue: it abandons cheque 1
    let next = miner.sign(2, &Message::new(2, 3, 8, 1)); // 3 coins
    assert!(a.check_txs(&next).iter().all(|r| r.is_ok()));
    for t in &next { a.submit_tx(t.clone(), None).unwrap(); }
    a.mine_once(1).unwrap();
    let st = a.store.lock().unwrap();
    let m = &st.chain.state.accounts[&miner.id()];
    assert_eq!((m.nonce, m.open.is_none(), m.commits.contains_key(&1)), (Some(2), true, false));
    assert_eq!(st.chain.state.accounts[&user.id()].balance, 3 * COIN);
    drop(st);
    // and a finished number is refused with the text the wallet looks for
    assert_eq!(a.check_txs(&next[..1])[0], Err("cheque number already consumed"));
}

/// Discovery: C is told only about A, learns B's address from A (B advertised it in HELLO,
/// A passed it on in reply to GET_ADDR), and dials B on its own.
#[test]
fn peers_find_each_other_through_gossip() {
    let p = Params { initial_bits: 0x207F_FFFF, min_bits: 0x207F_FFFF, slow_start_blocks: 1, ..Params::mainnet() };
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

//! Regression tests for the security audit of October 2026: each was a working attack before its fix.
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use bitcheque::block::{Block, Chain};
use bitcheque::message::Message;
use bitcheque::net::{now, Node};
use bitcheque::params::{Params, COIN};
use bitcheque::store::{Accepted, Store};
use bitcheque::tx::{Payment, Tx};
use bitcheque::u256::U256;
use bitcheque::wallet::{mine_registration, Book, Domain};

fn params() -> Params {
    Params { initial_bits: 0x207F_FFFF, min_bits: 0x207F_FFFF, reg_pow_target: U256::MAX.shr(4), reward_maturity: 2, number_maturity: 2,
             launch_blocks: 0, piece_lifetime: 3, unfunded_pow_lifetime: 5, max_future_seconds: 1 << 30, reward_base: 50 * COIN, ..Params::mainnet() }
}
struct Net { chain: Chain, t: u32 }
impl Net {
    fn new(p: &Params) -> Net { let g = Chain::genesis(p, 1000, b"t"); Net { chain: Chain::new(p.clone(), &g).unwrap(), t: 1000 } }
    fn mine(&mut self, payee: u32, txs: Vec<Tx>) -> Result<(), &'static str> {
        self.t += 600;
        let b = self.chain.make_block(self.t, payee, txs)?;
        self.chain.add(&b, self.t)
    }
}
fn book(k: u8) -> Book { Book { salt: [k; 16], n256: false, book_size: 256, domains: vec![Domain([k; 32])], net: Params::mainnet().magic } }

/// Renew carries no authority, so it is valid only near a batch's expiry, and only once; a block may not repeat a tx.
#[test]
fn renew_cannot_drain_an_account() {
    let p = Params { batch_lifetime: 30, renew_window: 10, ..params() };
    let mut net = Net::new(&p);
    let victim = book(1);
    net.mine(0, vec![mine_registration(victim.register(0, 16, Payment::Pow([0; 32], 0)), net.chain.tip(), p.reg_pow_target)]).unwrap();
    for _ in 0..2 { net.mine(0, vec![]).unwrap(); }
    for _ in 0..4 { net.mine(1, vec![]).unwrap(); }   // the victim (number 1) earns rewards
    for _ in 0..3 { net.mine(0, vec![]).unwrap(); }
    let renew = Tx::Renew { account: victim.id(), start: 0 };
    let before = net.chain.state.accounts[&victim.id()].balance;
    assert!(before > 0);
    assert_eq!(net.mine(0, vec![renew.clone()]), Err("batch not near expiry"));
    while net.chain.state.accounts[&victim.id()].batches[&0].1 > net.chain.height() + 1 + p.renew_window { net.mine(0, vec![]).unwrap(); }
    // a block repeating a transaction is refused before anything is applied (a miner builds it by hand)
    let mut dup = net.chain.template(net.t + 600, 0, vec![renew.clone()]).unwrap();
    dup.txs.push(renew.clone()); dup.header.tx_root = bitcheque::block::tx_root(&dup.txs); dup.header.mine();
    assert_eq!(net.chain.check(&dup, net.t + 600).err(), Some("duplicate transaction"));
    net.mine(0, vec![renew.clone()]).unwrap();   // near expiry: one renewal, one fee
    assert_eq!(net.chain.state.accounts[&victim.id()].balance, before - p.renew_fee);
    assert_eq!(net.mine(0, vec![renew]), Err("batch not near expiry"));   // and not again
}

/// A deleted account's registration replayed: it comes back, but the cheques it used stay used.
#[test]
fn a_replayed_registration_keeps_used_cheques_used() {
    let p = params();
    let mut net = Net::new(&p);
    let u = book(2);
    let reg = mine_registration(u.register(0, 16, Payment::Pow([0; 32], 0)), net.chain.tip(), p.reg_pow_target);
    let mut txs = vec![reg.clone()]; txs.extend(u.sign(3, &Message::new(0, 0, 0, 0)));
    net.mine(0, txs).unwrap();
    for _ in 0..6 { net.mine(0, vec![]).unwrap(); }
    assert!(!net.chain.state.accounts.contains_key(&u.id()), "unfunded: deleted");
    net.mine(0, vec![reg]).unwrap();
    let a = &net.chain.state.accounts[&u.id()];
    assert_eq!(a.nonce, Some(3));
    assert!(!a.commits.contains_key(&3) && a.commits.contains_key(&4));
    assert_eq!(net.mine(0, u.sign(3, &Message::new(0, 0, 0, 0))), Err("cheque number already consumed"));
}

/// A zero-coin cheque does not keep an unfunded account alive.
#[test]
fn a_zero_cheque_does_not_fund() {
    let p = params();
    let mut net = Net::new(&p);
    let (a, b) = (book(3), book(4));
    net.mine(0, vec![mine_registration(a.register(0, 16, Payment::Pow([0; 32], 0)), net.chain.tip(), p.reg_pow_target), mine_registration(b.register(0, 16, Payment::Pow([0; 32], 0)), net.chain.tip(), p.reg_pow_target)]).unwrap();
    for _ in 0..2 { net.mine(0, vec![]).unwrap(); }
    let nb = net.chain.state.accounts[&b.id()].number;
    net.mine(0, a.sign(1, &Message::new(nb, 0, 0, 0))).unwrap();
    for _ in 0..10 { net.mine(0, vec![]).unwrap(); }
    assert!(!net.chain.state.accounts.contains_key(&b.id()));
}

/// Side blocks: no bigger than a block may be, with a real tx root and coinbase, kept in memory (never in the data
/// file), and only within max_reorg of the tip.
#[test]
fn side_blocks_are_checked_and_never_written() {
    let mut p = params();
    p.min_bits = 0x2000_FFFF; p.initial_bits = 0x2000_FFFF; p.max_reorg = 5;
    let g = Chain::genesis(&p, now() - 100_000, b"a");
    let path = std::env::temp_dir().join(format!("bitcheque-side-{}.dat", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let mut s = Store::open(p.clone(), &g, Some(&path)).unwrap();
    let mut c = Chain::new(p.clone(), &g).unwrap();
    for i in 0..3 { let b = c.make_block(g.header.time + 60 * (i + 1), 0, vec![]).unwrap(); c.add(&b, now()).unwrap(); s.accept(&b, now()).unwrap(); }
    let len0 = std::fs::metadata(&path).unwrap().len();
    let mut side = Chain::new(p.clone(), &g).unwrap();
    side.add(&c.blocks.get(1).unwrap(), now()).unwrap();
    // too big
    let mut big = side.template(g.header.time + 120, 0, vec![]).unwrap();
    big.txs.push(Tx::Coinbase { height: 0, payee: 0, message: vec![1; 3_000_000] });
    big.header.tx_root = bitcheque::block::tx_root(&big.txs); big.header.mine();
    assert_eq!(s.accept(&big, now()).err(), Some("block too large"));
    // a tx root that does not match
    let mut junk = side.template(g.header.time + 121, 0, vec![]).unwrap();
    junk.txs.push(Tx::Coinbase { height: 0, payee: 0, message: vec![2; 1000] }); junk.header.mine();
    assert_eq!(s.accept(&junk, now()).err(), Some("tx root"));
    // a second coinbase
    let mut two = side.template(g.header.time + 122, 0, vec![]).unwrap();
    two.txs.push(Tx::Coinbase { height: 2, payee: 0, message: vec![] });
    two.header.tx_root = bitcheque::block::tx_root(&two.txs); two.header.mine();
    assert_eq!(s.accept(&two, now()).err(), Some("coinbase"));
    // well-formed siblings are kept, in memory only
    for k in 0..20u32 { let mut b = side.template(g.header.time + 130 + k, 0, vec![]).unwrap(); b.header.mine(); assert!(matches!(s.accept(&b, now()), Ok(Accepted::Side))); }
    assert_eq!(std::fs::metadata(&path).unwrap().len(), len0, "side blocks never reach the data file");
    // the main chain grows past max_reorg: a branch from block 1 is kept, but more work alone no longer wins
    for i in 3..8 { let b = c.make_block(g.header.time + 60 * (i + 1), 0, vec![]).unwrap(); c.add(&b, now()).unwrap(); s.accept(&b, now()).unwrap(); }
    let mut branch = Chain::new(p.clone(), &g).unwrap();
    branch.add(&c.blocks.get(1).unwrap(), now()).unwrap();
    for k in 0..8u32 { let b = branch.make_block(g.header.time + 300 + 61 * k, 0, vec![]).unwrap(); branch.add(&b, now()).unwrap(); assert!(matches!(s.accept(&b, now()), Ok(Accepted::Side))); }
    assert_eq!(s.chain.tip(), c.tip(), "8 blocks against 7: deeper than max_reorg needs twice the work");
    let _ = std::fs::remove_file(&path);
}

fn quick() -> Params { Params { initial_bits: 0x207F_FFFF, min_bits: 0x207F_FFFF, reg_pow_target: U256::MAX.shr(4), launch_blocks: 0, reward_maturity: 1, number_maturity: 1, max_reorg: 10, ..Params::mainnet() } }
/// main[1..=fork] then `n` new blocks (`salt` shifts the times so the hashes differ)
fn build(p: &Params, g: &Block, base: &[Block], fork: usize, n: usize, salt: u32) -> Vec<Block> {
    let mut c = Chain::new(p.clone(), g).unwrap();
    let mut out = vec![g.clone()];
    for b in &base[1..=fork] { c.add(b, now()).unwrap(); out.push(b.clone()); }
    for _ in 0..n { let t = c.headers.last().unwrap().time + 60 + salt; let b = c.make_block(t, 0, vec![]).unwrap(); c.add(&b, now()).unwrap(); out.push(b); }
    out
}

/// A node that ended up deep on a lighter branch (synced from a liar first, say) moves to the honest one once it has
/// twice the work: deep reorgs are harder, not impossible.
#[test]
fn a_node_deep_on_a_wrong_branch_finds_its_way_back() {
    let p = quick();
    let g = Chain::genesis(&p, now() - 1_000_000, b"x");
    let liar = build(&p, &g, &[g.clone()], 0, 15, 0);
    let honest = build(&p, &g, &[g.clone()], 0, 40, 1);
    let mut s = Store::open(p.clone(), &g, None).unwrap();
    for x in &liar[1..] { s.accept(x, now()).unwrap(); }
    for x in &honest[1..] { s.accept(x, now()).unwrap(); }
    assert_eq!(s.chain.tip(), honest[40].header.hash());
}

thread_local! { static DB: std::cell::RefCell<std::collections::HashMap<usize, Vec<u8>>> = Default::default(); }
fn host_get(h: usize) -> Option<Vec<u8>> { DB.with(|d| d.borrow().get(&h).cloned()) }
fn host_put(h: usize, b: &[u8]) { DB.with(|d| { d.borrow_mut().insert(h, b.to_vec()); }) }
fn host_snap(_: &[u8]) {}

/// A reorg whose branch fails part-way leaves the host's stored blocks as they were.
#[test]
fn a_failed_reorg_writes_nothing_to_the_host() {
    let p = params();
    let now = 2_000_000_000u32;
    let g = Chain::genesis(&p, 1000, b"t");
    let mut st = Store::open_host(p.clone(), &g, bitcheque::block::HostBlocks { get: host_get, put: host_put }, None, &[], 100, host_snap).unwrap();
    let mut main = Chain::new(p.clone(), &g).unwrap();
    for i in 0..5 { let b = main.make_block(1000 + 600 * (i + 1), 0, vec![]).unwrap(); main.add(&b, now).unwrap(); st.accept(&b, now).unwrap(); }
    let mut alt = Chain::new(p.clone(), &g).unwrap();
    for h in 1..=3 { alt.add(&main.blocks.get(h).unwrap(), now).unwrap(); }
    let s4 = alt.make_block(1000 + 600 * 4 + 7, 0, vec![]).unwrap(); alt.add(&s4, now).unwrap();
    let s5 = alt.make_block(1000 + 600 * 5 + 7, 0, vec![]).unwrap(); alt.add(&s5, now).unwrap();
    let mut s6 = alt.template(1000 + 600 * 6 + 7, 0, vec![]).unwrap(); s6.header.state_root = [9; 32]; s6.header.mine();
    assert!(matches!(st.accept(&s4, now), Ok(Accepted::Side)));
    assert!(matches!(st.accept(&s5, now), Ok(Accepted::Side)));
    assert_eq!(st.accept(&s6, now).err(), Some("state root"));
    assert_eq!(st.chain.tip(), main.tip());
    for h in 1..=5 { assert_eq!(Block::decode(&host_get(h).unwrap()).unwrap(), main.blocks.get(h).unwrap(), "host block {h} untouched"); }
}

/// A heavier branch of big blocks wins on a host: making room never evicts the branch's own earlier blocks.
#[test]
fn eviction_keeps_the_branch_being_built() {
    let p = Params { max_reorg: 100, ..quick() };
    let g = Chain::genesis(&p, now() - 1_000_000, b"z");
    let mut st = Store::open_host(p.clone(), &g, bitcheque::block::HostBlocks { get: host_get, put: host_put }, None, &[], 100, host_snap).unwrap();
    let mut a = Chain::new(p.clone(), &g).unwrap();
    for _ in 0..9 { let t = a.headers.last().unwrap().time + 60; let b = a.make_block(t, 0, vec![]).unwrap(); a.add(&b, now()).unwrap(); st.accept(&b, now()).unwrap(); }
    let mut c = Chain::new(p.clone(), &g).unwrap();
    for _ in 0..12 {
        let t = c.headers.last().unwrap().time + 61;
        let mut b = c.template(t, 0, vec![]).unwrap();
        if let Tx::Coinbase { message, .. } = &mut b.txs[0] { *message = vec![7u8; 950_000]; }
        b.header.tx_root = bitcheque::block::tx_root(&b.txs); b.header.mine();
        c.add(&b, now()).unwrap();
        st.accept(&b, now()).unwrap();
    }
    assert_eq!(st.chain.tip(), c.tip());
}

static LOW: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
fn counting_get(h: usize) -> Option<Vec<u8>> { if h <= 3 { LOW.fetch_add(1, std::sync::atomic::Ordering::Relaxed); } host_get(h) }

/// Snapshots cover max_reorg even after a reorg replaced the latest: a second reorg never replays from genesis.
#[test]
fn a_reorg_after_a_reorg_starts_from_a_snapshot() {
    let p = quick();
    let g = Chain::genesis(&p, now() - 1_000_000, b"y");
    let mut st = Store::open_host(p.clone(), &g, bitcheque::block::HostBlocks { get: counting_get, put: host_put }, None, &[], 10, host_snap).unwrap();
    let main = build(&p, &g, &[g.clone()], 0, 25, 0);
    for x in &main[1..] { st.accept(x, now()).unwrap(); }
    let b1 = build(&p, &g, &main, 19, 7, 1);
    for x in &b1[20..] { st.accept(x, now()).unwrap(); }
    let b2 = build(&p, &g, &b1, 26, 8, 0);
    for x in &b2[27..] { st.accept(x, now()).unwrap(); }
    LOW.store(0, std::sync::atomic::Ordering::Relaxed);
    let b3 = build(&p, &g, &b2, 25, 10, 2);
    for x in &b3[26..] { st.accept(x, now()).unwrap(); }
    assert_eq!(st.chain.tip(), b3[35].header.hash());
    assert_eq!(LOW.load(std::sync::atomic::Ordering::Relaxed), 0, "no replay from genesis");
}

fn frame(magic: &[u8; 4], kind: u8, payload: &[u8]) -> Vec<u8> { [&magic[..], &[kind], &(payload.len() as u32).to_le_bytes(), payload].concat() }
fn get(addr: std::net::SocketAddr, path: &str) -> String { let mut s = TcpStream::connect(addr).unwrap(); write!(s, "GET {path} HTTP/1.0\r\n\r\n").unwrap(); let mut o = String::new(); let _ = s.read_to_string(&mut o); o }

/// A peer claiming a huge height holds the sync slot only until it stalls; then a second HELLO on the same connection
/// does not take it again (a new connection from the same address is banned for a while too, except from loopback,
/// where devnets run many nodes). Slow (35 s): cargo test --release -- --ignored
#[test]
#[ignore]
fn a_fake_height_cannot_hold_the_node_in_sync() {
    let p = Params { initial_bits: 0x207F_FFFF, min_bits: 0x207F_FFFF, launch_blocks: 0, reward_maturity: 1, number_maturity: 1, ..Params::mainnet() };
    let g = Chain::genesis(&p, now() - 100_000, b"a");
    let node = Node::new(Store::open(p.clone(), &g, None).unwrap());
    let rpc = node.serve_rpc("127.0.0.1:0").unwrap();
    let at = node.listen("127.0.0.1:0").unwrap();
    let hello = frame(&p.magic, 0, &[&u32::MAX.to_le_bytes()[..], &[0u8; 32]].concat());
    let mut s = TcpStream::connect(at).unwrap();
    s.write_all(&hello).unwrap();
    std::thread::sleep(Duration::from_millis(800));
    let r = get(rpc, "/template/0");
    assert!(r.contains("syncing"), "{r}");
    node.maintain(vec![], Duration::from_secs(1));
    std::thread::sleep(Duration::from_secs(33));
    assert!(get(rpc, "/template/0").contains("200 OK"), "the stalled source was dropped");
    let _ = s.write_all(&hello);   // the same connection again: refused (once per connection)
    std::thread::sleep(Duration::from_millis(800));
    assert!(get(rpc, "/template/0").contains("200 OK"));
}

/// Clients sending a byte now and then lose their connection at the request deadline, so the RPC stays available.
/// Slow (25 s): cargo test --release -- --ignored
#[test]
#[ignore]
fn trickling_clients_do_not_exhaust_the_rpc() {
    let p = params();
    let g = Chain::genesis(&p, now() - 100_000, b"a");
    let node = Node::new(Store::open(p.clone(), &g, None).unwrap());
    let rpc = node.serve_rpc("127.0.0.1:0").unwrap();
    let mut conns: Vec<TcpStream> = (0..256).map(|_| { let mut s = TcpStream::connect(rpc).unwrap(); s.write_all(b"G").unwrap(); s }).collect();
    for _ in 0..4 { std::thread::sleep(Duration::from_secs(6)); for c in conns.iter_mut() { let _ = c.write_all(b"E"); } }
    assert!(get(rpc, "/height").contains("200 OK"));
}

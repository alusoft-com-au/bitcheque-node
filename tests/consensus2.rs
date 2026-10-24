//! Regression tests for the second consensus audit: chain binding, fixed batches, anchored registration work, strict
//! decoding, the funding minimum, number reuse order, the /commits route; and (ignored) the state cost benches.
use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
use std::time::Instant;
use bitcheque::block::{Block, Chain};
use bitcheque::book;
use bitcheque::crypto::key;
use bitcheque::message::Message;
use bitcheque::net::{now, Node};
use bitcheque::params::{Params, COIN};
use bitcheque::state::{Account, Commits, State};
use bitcheque::store::Store;
use bitcheque::tx::{Batch, Payment, Tx, R};
use bitcheque::u256::U256;
use bitcheque::wallet::{mine_registration, Book, Domain};

fn params() -> Params {
    Params { initial_bits: 0x207F_FFFF, min_bits: 0x207F_FFFF, reg_pow_target: U256::MAX.shr(4), reward_maturity: 2, number_maturity: 2,
             launch_blocks: 0, piece_lifetime: 3, unfunded_pow_lifetime: 5, max_future_seconds: 1 << 30, reward_base: 50 * COIN, ..Params::mainnet() }
}
struct Net { chain: Chain, t: u32 }
impl Net {
    fn new(p: &Params, gt: u32) -> Net { let g = Chain::genesis(p, gt, b"t"); Net { chain: Chain::new(p.clone(), &g).unwrap(), t: gt } }
    fn mine(&mut self, payee: u32, txs: Vec<Tx>) -> Result<(), &'static str> {
        self.t += 600;
        let b = self.chain.make_block(self.t, payee, txs)?;
        self.chain.add(&b, self.t)
    }
    fn reg(&self, b: &Book) -> Tx { mine_registration(b.register(0, 16, Payment::Pow([0; 32], 0)), self.chain.tip(), self.chain.params.reg_pow_target) }
}
fn bk(k: u8, net: [u8; 4]) -> Book { Book { salt: [k; 16], n256: false, book_size: 256, domains: vec![Domain([k; 32])], net } }

/// A third party who sees a RegisterBook cannot register a fragment of it (only cheque 0, or a later batch first):
/// every batch is exactly 16 cheques and a book starts at cheque 0. The owner's registration then goes through.
#[test]
fn fragment_registration_refused() {
    let p = params();
    let mut net = Net::new(&p, 1000);
    net.mine(0, vec![]).unwrap();   // block 0 is no registration anchor
    let v = bk(9, p.magic);
    let victim_tx = net.reg(&v);
    let Tx::RegisterBook { salt, m, n256, book_size, root, batch, .. } = victim_tx.clone() else { panic!() };
    let k = key(&salt, &p.magic);
    let leaves: Vec<Vec<u8>> = batch.cheques.iter().enumerate().map(|(i, ch)| book::leaf_from_shares(&k, 16, i as u16, ch).0).collect();
    let mut path = vec![leaves[1].clone(), book::subtree_root(&k, 16, 2, &leaves[2..4]), book::subtree_root(&k, 16, 4, &leaves[4..8]), book::subtree_root(&k, 16, 8, &leaves[8..16])];
    path.extend(batch.path.iter().cloned());
    let evil = Tx::RegisterBook { salt, m, n256, book_size, root: root.clone(), batch: Batch { start: 0, count: 1, cheques: vec![batch.cheques[0].clone()], path }, pay: Payment::Pow([0; 32], 0) };
    assert_eq!(net.mine(0, vec![mine_registration(evil, net.chain.tip(), p.reg_pow_target)]), Err("batch not aligned"));
    // a later batch as the book's first registration
    let later = Tx::RegisterBook { salt, m, n256, book_size, root, batch: v.batch(16, 16), pay: Payment::Pow([0; 32], 0) };
    assert_eq!(net.mine(0, vec![mine_registration(later, net.chain.tip(), p.reg_pow_target)]), Err("book must start at cheque 0"));
    net.mine(0, vec![victim_tx]).unwrap();
    assert_eq!(net.chain.state.accounts[&v.id()].commits.len(), 16);
}

/// One seed is a different book on every network (the magic is in every hash): its registration and its pieces
/// from one network are worthless on another.
#[test]
fn cross_chain_replay_refused() {
    let pa = Params { magic: [1, 1, 1, 1], ..params() };
    let pb = Params { magic: [2, 2, 2, 2], ..params() };
    let (mut a, mut b) = (Net::new(&pa, 1000), Net::new(&pb, 5000));
    a.mine(0, vec![]).unwrap(); b.mine(0, vec![]).unwrap();
    let (ua, ub) = (bk(5, pa.magic), bk(5, pb.magic));
    assert_ne!(ua.id(), ub.id(), "the same seed, two accounts");
    let reg = a.reg(&ua);
    a.mine(0, vec![reg.clone()]).unwrap();
    assert_eq!(b.mine(0, vec![reg]), Err("registration anchor not recent"));
    // even anchored on B, A's registration does not verify under B's magic
    let rega = mine_registration(ua.register(0, 16, Payment::Pow([0; 32], 0)), b.chain.tip(), pb.reg_pow_target);
    assert_eq!(b.mine(0, vec![rega]), Err("batch does not match root"));
    let regb = b.reg(&ub);
    b.mine(0, vec![regb]).unwrap();
    for _ in 0..2 { a.mine(0, vec![]).unwrap(); b.mine(0, vec![]).unwrap(); }
    for _ in 0..3 { a.mine(1, vec![]).unwrap(); b.mine(1, vec![]).unwrap(); }
    for _ in 0..3 { a.mine(0, vec![]).unwrap(); b.mine(0, vec![]).unwrap(); }
    let pieces = ua.sign(1, &Message::new(0, 1234, 3, 1));
    a.mine(0, pieces.clone()).unwrap();
    assert_eq!(b.mine(0, pieces), Err("no such account"));
}

/// Registration work names a recent block: it is good for reg_anchor_window blocks on that chain, so the same tx
/// cannot be replayed after the account expires, nor anchored to a block this chain does not have.
#[test]
fn registration_pow_not_reusable() {
    let p = Params { reg_anchor_window: 3, ..params() };
    let mut net = Net::new(&p, 1000);
    net.mine(0, vec![]).unwrap();   // block 0 is no registration anchor
    let u = bk(6, p.magic);
    let reg = net.reg(&u);
    net.mine(0, vec![]).unwrap();
    net.mine(0, vec![]).unwrap();
    net.mine(0, vec![reg.clone()]).unwrap();   // anchored three blocks back: still good
    while net.chain.state.accounts.contains_key(&u.id()) { net.mine(0, vec![]).unwrap(); }
    assert_eq!(net.mine(0, vec![reg]), Err("registration anchor not recent"));
    let stale = net.chain.hash_at(net.chain.height() - 3).unwrap();
    assert_eq!(net.mine(0, vec![mine_registration(u.register(0, 16, Payment::Pow([0; 32], 0)), stale, p.reg_pow_target)]), Err("registration anchor not recent"));
    assert_eq!(net.mine(0, vec![mine_registration(u.register(0, 16, Payment::Pow([0; 32], 0)), [7; 32], p.reg_pow_target)]), Err("registration anchor not recent"));
    let fresh = net.reg(&u);
    net.mine(0, vec![fresh]).unwrap();
}

/// One block, one encoding; one tx, one encoding.
#[test]
fn decode_is_strict() {
    let p = params();
    let net = Net::new(&p, 1000);
    let u = Book { salt: [7; 16], n256: true, book_size: 256, domains: vec![Domain([7; 32])], net: p.magic };
    let reg = u.register(0, 16, Payment::Pow([0; 32], 0));
    let t = net.chain.template(1600, 0, vec![]).unwrap();
    let b = Block { header: t.header, txs: vec![t.txs[0].clone(), reg.clone()] };
    assert_eq!(Block::decode(&b.encode()).unwrap(), b);
    let mut raw = b.encode(); raw.extend_from_slice(&[0xAB; 5]);
    assert_eq!(Block::decode(&raw), Err("trailing bytes"));
    // a tx frame with junk inside it (frame length grown to cover it)
    let mut raw = b.encode(); let first_len = 112 + 4;
    let cb = u32::from_le_bytes(raw[first_len..first_len + 4].try_into().unwrap()) as usize;
    raw.insert(first_len + 4 + cb, 0); raw[first_len..first_len + 4].copy_from_slice(&(cb as u32 + 1).to_le_bytes());
    assert_eq!(Block::decode(&raw), Err("trailing bytes"));
    let mut e = reg.encode(); e.extend_from_slice(b"junk");
    assert_eq!(Tx::decode(&mut R::new(&e)), Err("trailing bytes"));
    let mut e = reg.encode(); e[1 + 16 + 1] = 0x77;   // n256 byte
    assert_eq!(Tx::decode(&mut R::new(&e)), Err("bad n256"));
    let mut big = reg.clone();
    if let Tx::RegisterBook { batch, .. } = &mut big { batch.cheques.push(batch.cheques[0].clone()); }
    assert_eq!(Tx::decode(&mut R::new(&big.encode())), Err("batch too large"));
}

/// Permanence needs min_fund in the account: a dust cheque leaves it unfunded (and it expires), a coin keeps it.
#[test]
fn dust_does_not_fund() {
    let p = Params { unfunded_pow_lifetime: 30, ..params() };
    let mut net = Net::new(&p, 1000);
    net.mine(0, vec![]).unwrap();   // block 0 is no registration anchor
    let (miner, dust, coin) = (bk(1, p.magic), bk(2, p.magic), bk(3, p.magic));
    let regs = vec![net.reg(&miner), net.reg(&dust), net.reg(&coin)];
    net.mine(0, regs).unwrap();
    for _ in 0..2 { net.mine(0, vec![]).unwrap(); }
    for _ in 0..3 { net.mine(1, vec![]).unwrap(); }   // miner funded by its rewards
    let n = |b: &Book, net: &Net| net.chain.state.accounts[&b.id()].number;
    let (nd, nc) = (n(&dust, &net), n(&coin, &net));
    let mut txs = miner.sign(1, &Message::new(nd, 1, 0, 1));
    txs.extend(miner.sign(2, &Message::new(nc, 1, 8, 1)));
    net.mine(0, txs).unwrap();
    let st = &net.chain.state;
    assert!(!st.accounts[&dust.id()].funded && st.accounts[&dust.id()].balance == 1);
    assert!(st.accounts[&coin.id()].funded && st.accounts[&coin.id()].balance == COIN);
    while net.chain.height() < 32 { net.mine(0, vec![]).unwrap(); }
    assert!(!net.chain.state.accounts.contains_key(&dust.id()) && net.chain.state.accounts.contains_key(&coin.id()));
}

/// Freed numbers come back in the order they were released (oldest out of quarantine first).
#[test]
fn numbers_reused_oldest_first() {
    let p = Params { number_quarantine: 2, ..params() };
    let mut net = Net::new(&p, 1000);
    net.mine(0, vec![]).unwrap();   // block 0 is no registration anchor
    let old: Vec<Book> = (10..13).map(|k| bk(k, p.magic)).collect();
    for b in &old { let r = net.reg(b); net.mine(0, vec![r]).unwrap(); }   // numbers 1, 2, 3, released a block apart
    let nums: Vec<u32> = old.iter().map(|b| net.chain.state.accounts[&b.id()].number).collect();
    assert_eq!(nums, vec![1, 2, 3]);
    while old.iter().any(|b| net.chain.state.accounts.contains_key(&b.id())) { net.mine(0, vec![]).unwrap(); }
    for _ in 0..3 { net.mine(0, vec![]).unwrap(); }   // all out of quarantine
    let new: Vec<Book> = (20..23).map(|k| bk(k, p.magic)).collect();
    let regs: Vec<Tx> = new.iter().map(|b| net.reg(b)).collect();
    net.mine(0, regs).unwrap();
    assert_eq!(new.iter().map(|b| net.chain.state.accounts[&b.id()].number).collect::<Vec<_>>(), vec![1, 2, 3]);
}

/// GET /commits/<id>/<cheque>: the 180 commitments of a registered unspent cheque, as the wallet computes them.
#[test]
fn commits_route() {
    let p = Params { reward_maturity: 1, number_maturity: 1, ..params() };
    let g = Chain::genesis(&p, now() - 100_000, b"commits");
    let node = Node::new(Store::open(p.clone(), &g, None).unwrap());
    let mut b = node.template(0).unwrap(); b.header.mine(); node.submit_block(&b, None).unwrap();
    let u = bk(4, p.magic);
    let anchor = node.store.lock().unwrap().chain.tip();
    node.submit_tx(mine_registration(u.register(0, 16, Payment::Pow([0; 32], 0)), anchor, p.reg_pow_target), None).unwrap();
    let mut b = node.template(0).unwrap(); b.header.mine(); node.submit_block(&b, None).unwrap();
    let id = bitcheque::crypto::hex(&u.id());
    let text = node.route("GET", &format!("/commits/{id}/3"), "").unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 18);
    assert!(lines.iter().all(|l| l.split(' ').count() == 10 && l.split(' ').all(|h| h.len() == 32)));
    let mine = Commits::new(book::leaf_from_shares(&u.key(), 16, 3, &u.shares(3)).1);
    assert_eq!(text, mine.lines(16));
    // cell (column 5, row 7) as the page checks it: the commitment of that one cell's share
    let cell = u.domains[0].cell(&u.net, 16, 3, 5, 7);
    let c = book::commit(&u.key(), 16, 3, 5, 7, &[book::share_hash(&u.key(), 16, 3, 5, 7, 0, &cell)]);
    assert_eq!(lines[5].split(' ').nth(7).unwrap(), bitcheque::crypto::hex(&c));
    assert_eq!(node.route("GET", &format!("/commits/{id}/16"), ""), Err("no such cheque"));
    assert_eq!(node.route("GET", "/commits/13ab/0", ""), Err("no such cheque"));
}

/// Cached account leaves give the same root as a freshly decoded state, and the snapshot holds each cheque's
/// commitments without per-cell lengths.
#[test]
fn cached_root_and_compact_snapshot() {
    let p = Params { unfunded_pow_lifetime: 50, ..params() };
    let mut net = Net::new(&p, 1000);
    net.mine(0, vec![]).unwrap();   // block 0 is no registration anchor
    let (m, u) = (bk(1, p.magic), bk(2, p.magic));
    let regs = vec![net.reg(&m), net.reg(&u)];
    net.mine(0, regs).unwrap();
    for _ in 0..2 { net.mine(0, vec![]).unwrap(); }
    for _ in 0..3 { net.mine(1, vec![]).unwrap(); }
    net.mine(0, m.sign(1, &Message::new(2, 3, 8, 1))).unwrap();
    net.mine(0, u.sign(1, &Message::new(1, 5, 7, 1))[..4].to_vec()).unwrap();   // an open cheque
    let s = &net.chain.state;
    let e = s.encode();
    let fresh = State::decode(&mut R::new(&e)).unwrap();
    assert_eq!(fresh.root(), s.root());
    assert_eq!(fresh.encode(), e);
    assert_eq!(s.account_proof(&u.id()).unwrap().2, s.root());
    assert!(e.len() < 31 * 180 * 16 + 2000, "{} bytes for 31 cheques", e.len());
}

fn synth_state(p: &Params, accounts: usize, cheques: u16) -> State {
    let mut s = State::new(p);
    for i in 0..accounts {
        let mut id = vec![0x13u8]; id.extend_from_slice(&(i as u128).to_le_bytes());
        let mut commits = BTreeMap::new();
        for c in 0..cheques {
            let cells: Vec<u8> = (0..180).flat_map(|j| { let mut x = vec![0u8; 16]; x[..8].copy_from_slice(&(i as u64).to_le_bytes()); x[8] = c as u8; x[9] = j as u8; x }).collect();
            commits.insert(c, Commits::new(cells));
        }
        let mut batches = BTreeMap::new(); batches.insert(0u32, (16u32, 2_000_000u32));
        let number = i as u32 + 1;
        s.numbers.insert(number, (id.clone(), 0));
        s.accounts.insert(id, Arc::new(Account { number, balance: 5, nonce: None, book_size: 256, salt: [1; 16], funded: true, batches, commits, open: BTreeMap::new(), leaf: OnceLock::new() }));
    }
    s.next_number = accounts as u32 + 1;
    s
}

/// The per-block costs of a big state: copy, root (first and after one change), begin_block, snapshot.
#[test]
#[ignore]
fn bench_state_100k() {
    let p = Params::mainnet();
    for &(na, nc) in &[(100_000usize, 16u16), (10_000, 256)] {
        let s = synth_state(&p, na, nc);
        let t = Instant::now(); let r0 = s.root(); let first = t.elapsed();
        let t = Instant::now(); let mut c = s.clone(); let clone = t.elapsed();
        let t = Instant::now(); c.begin_block(&p, 10); let bb = t.elapsed();
        let t = Instant::now(); let r = c.root(); let root = t.elapsed();
        let t = Instant::now(); let e = s.encode(); let enc = t.elapsed();
        let t = Instant::now(); drop(c); let dr = t.elapsed();
        println!("accounts={na} commits/acct={nc}: first root={first:?} clone={clone:?} begin_block={bb:?} root={root:?} drop={dr:?} encode={enc:?} ({} MB) root={:02x?}{:02x?}", e.len() >> 20, &r0[..2], &r[..2]);
    }
}

fn rss_kb() -> usize { std::fs::read_to_string("/proc/self/status").unwrap().lines().find(|l| l.starts_with("VmRSS")).unwrap().split_whitespace().nth(1).unwrap().parse().unwrap() }
/// Memory per registered unspent cheque, via real registrations applied to a State.
#[test]
#[ignore]
fn bench_memory_per_cheque() {
    let p = Params { reg_pow_target: U256::MAX, reg_pow_per_block_cap: 100_000, ..Params::mainnet() };
    let regs: Vec<Tx> = (0..200u32).map(|k| { let mut s = [0u8; 16]; s[..4].copy_from_slice(&k.to_le_bytes());
        let b = Book { salt: s, n256: false, book_size: 256, domains: vec![Domain([k as u8; 32])], net: p.magic }; b.registrations(0, 15).remove(0) }).collect();
    let mut st = State::new(&p); st.push_hash(&p, [0; 32]); st.begin_block(&p, 1);
    let before = rss_kb();
    for r in &regs { st.apply(&p, r).unwrap(); }
    let after = rss_kb();
    println!("200 registrations x16 cheques: {} KB RSS => {} bytes per cheque, {} KB per registration; wire size {} B",
        after - before, (after - before) * 1024 / 3200, (after - before) / 200, regs[0].encode().len());
}

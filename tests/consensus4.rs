//! Audit 4 (consensus): the proofs of concept against the one-piece openings of audit 3, each of which now fails. A
//! cheque opens only by a `ChequeOpen` carrying both printed parts (every recipient column and an amount column), which
//! uses its number at once; a piece only adds a column to an open cheque; an open cheque that expires goes, its number
//! used. Also: the opening's one encoding, the residuals of §10.12 as they now stand, and the node's dry run and mempool.
mod common;
use bitcheque::block::Chain;
use bitcheque::message::Message;
use bitcheque::net::Node;
use bitcheque::params::{Params, COIN};
use bitcheque::store::Store;
use bitcheque::tx::{Payment, Tx, R};
use bitcheque::u256::U256;
use bitcheque::wallet::{mine_registration, Book, Domain};

fn params() -> Params {
    Params { initial_bits: 0x207F_FFFF, min_bits: 0x207F_FFFF, reg_pow_target: U256::MAX.shr(4), reward_maturity: 2, number_maturity: 2,
             launch_blocks: 0, piece_lifetime: 3, max_future_seconds: 1 << 30, reward_base: 50 * COIN, ..Params::mainnet() }
}
struct Net { chain: Chain, t: u32 }
impl Net {
    /// After one empty block: block 0's hash is no registration anchor.
    fn new(p: &Params) -> Net { let g = Chain::genesis(p, 1000, b"t"); let mut n = Net { chain: Chain::new(p.clone(), &g).unwrap(), t: 1000 }; n.mine(0, vec![]).unwrap(); n }
    fn mine(&mut self, payee: u32, txs: Vec<Tx>) -> Result<(), &'static str> {
        self.t += 60;
        let b = self.chain.make_block(self.t, payee, txs)?;
        self.chain.add(&b, self.t)
    }
    fn pow(&self, tx: Tx) -> Tx { mine_registration(tx, self.chain.tip(), self.chain.state.next_reg_target(&self.chain.params)) }
    fn reg(&mut self, b: &Book) { let r = self.pow(b.register(0, 16, Payment::Pow([0; 32], 0))); self.mine(0, vec![r]).unwrap(); }
    fn acct(&self, b: &Book) -> &bitcheque::state::Account { &self.chain.state.accounts[&b.id()] }
    /// Would `tx` go into the next block?
    fn try_apply(&self, tx: &Tx) -> Result<u64, &'static str> {
        let mut s = self.chain.state.clone();
        s.begin_block(&self.chain.params, self.chain.height() + 1);
        s.apply(&self.chain.params, tx)
    }
}
fn bk(k: u8, net: [u8; 4]) -> Book { Book { salt: [k; 16], n256: false, book_size: 256, domains: vec![Domain([k; 32])], net } }

/// A miner (number 1, with rewards) and an owner (number 2) holding 10 coins.
fn funded(p: &Params, owner: &Book, all: bool) -> Net {
    let mut net = Net::new(p);
    let miner = bk(8, p.magic);
    net.reg(&miner);
    if all { for chunk in owner.registrations(0, 255).chunks(8) { let txs = chunk.iter().map(|t| net.pow(t.clone())).collect(); net.mine(0, txs).unwrap(); } }
    else { net.reg(owner); }
    for _ in 0..3 { net.mine(0, vec![]).unwrap(); }
    for _ in 0..4 { net.mine(1, vec![]).unwrap(); }
    let onum = net.acct(owner).number;
    net.mine(0, miner.sign(1, &Message::new(onum, 1000, 6, 1))).unwrap();
    assert_eq!(net.acct(owner).balance, 10 * COIN);
    net
}

fn cell(k: u8, p: &Params, n: u16, col: u8, row: u8) -> Vec<u8> { Domain([k; 32]).cell(&p.magic, 16, n, col, row) }
fn piece(id: &[u8], k: u8, p: &Params, n: u16, col: u8, row: u8) -> Tx { Tx::ChequePiece { account: id.to_vec(), cheque: n, column: col, shares: vec![cell(k, p, n, col, row)] } }
/// An opening of the given columns of `digits` (any columns: the rules decide).
fn opening(id: &[u8], k: u8, p: &Params, n: u16, cols: impl Iterator<Item = u8>, digits: &[u8; 18]) -> Tx {
    Tx::ChequeOpen { account: id.to_vec(), cheque: n, pieces: cols.map(|c| (c, vec![cell(k, p, n, c, digits[c as usize % 18])])).collect() }
}

/// The cheques of a sample (low, middle, high) the owner can still move coins with, in the next block: a sweep and a
/// 1-coin payment to number 1 on each, written whole (one opening of all 18 columns).
const SAMPLE: [u16; 6] = [1, 2, 3, 100, 254, 255];
fn spendable(net: &Net, owner: &Book) -> Vec<u16> {
    SAMPLE.into_iter().filter(|&n| [Message::new(1, 0, 9, 1), Message::new(1, 1, 8, 1)].iter().any(|m| net.try_apply(&owner.open_all(n, &m.digits())).is_ok())).collect()
}

/// HIGH-1: a holder of one printed part used to pin every unused cheque with a junk piece each, and re-pin at expiry,
/// freezing the book for free. No piece opens anything now, and an opening needs both parts: nothing is pinned, ever.
#[test]
fn a_one_part_holder_cannot_freeze_the_book() {
    let p = Params { piece_lifetime: 5, ..params() };
    let owner = bk(7, p.magic);
    let mut net = funded(&p, &owner, true);
    let oid = owner.id();
    assert_eq!(spendable(&net, &owner), SAMPLE);
    // part A: column 0 = 9 (every payee out of range); part B: column 17 = 0 (zero cheques only); and all of either part
    let junk = Message::new(0, 0, 0, 0).digits();
    for n in [1u16, 100, 255] {
        for t in [piece(&oid, 7, &p, n, 0, 9), piece(&oid, 7, &p, n, 17, 0)] { assert_eq!(net.try_apply(&t), Err("cheque not open")); }
        for t in [opening(&oid, 7, &p, n, 0..12, &junk), opening(&oid, 7, &p, n, 12..18, &junk), opening(&oid, 7, &p, n, 1..13, &junk)] {
            assert_eq!(net.try_apply(&t), Err("bad opening columns"));
            assert_eq!(Tx::decode(&mut R::new(&t.encode())), Err("bad opening columns"));
        }
    }
    let pins: Vec<Tx> = (1..=255u16).map(|n| piece(&oid, 7, &p, n, 0, 9)).collect();
    assert_eq!(net.mine(0, pins), Err("cheque not open"));
    for _ in 0..2 * p.piece_lifetime { net.mine(0, vec![]).unwrap(); }
    let a = net.acct(&owner);
    assert_eq!((a.nonce, a.open.len(), a.commits.len(), a.balance), (None, 0, 256, 10 * COIN));
    assert_eq!(spendable(&net, &owner), SAMPLE);
}

/// HIGH-2: an opening that expired unbound was forgotten, so a wallet without the local record could sign the same
/// number again with other digits: two rows of a column public. An opening uses its number now: once expired, the
/// cheque is gone and nothing can be written on that number again.
#[test]
fn an_expired_opening_cannot_be_signed_again() {
    let p = params();
    let owner = bk(7, p.magic);
    let mut net = funded(&p, &owner, false);
    let (open, rest) = owner.halves(1, &Message::new(1, 1, 8, 1).digits());
    net.mine(0, vec![open]).unwrap();
    assert_eq!(net.acct(&owner).nonce, Some(1));
    while !net.acct(&owner).open.is_empty() { net.mine(0, vec![]).unwrap(); }
    // a second machine (no record) writes cheque 1 again, to someone else: refused whole, and piece by piece
    let other = Message::new(2, 3, 8, 1).digits();
    assert_eq!(net.try_apply(&owner.opening(1, &other, 12)), Err("cheque number already consumed"));
    assert_eq!(net.try_apply(&owner.open_all(1, &other)), Err("cheque number already consumed"));
    for t in owner.pieces(1, &other).iter().chain(&rest) { assert_eq!(net.try_apply(t), Err("cheque not open")); }
    let a = net.acct(&owner);
    assert_eq!((a.nonce, a.commits.contains_key(&1), a.balance), (Some(1), false, 10 * COIN));
}

/// LOW-3: the amount half landing after its opening expired used to open the cheque again from part B, for a part-A
/// thief to finish to any payee. Now it is refused, and so is every thief's piece or opening on that number.
#[test]
fn a_late_amount_half_completes_nothing() {
    let p = params();
    let owner = bk(7, p.magic);
    let mut net = funded(&p, &owner, false);
    let (open, rest) = owner.halves(1, &Message::new(2, 5, 8, 1).digits());
    net.mine(0, vec![open]).unwrap();
    for _ in 0..p.piece_lifetime - 1 { net.mine(0, vec![]).unwrap(); }
    // the amount lands in the expiry block itself: the open cheque went at its start
    assert_eq!(net.mine(0, rest.clone()), Err("cheque not open"));
    net.mine(0, vec![]).unwrap();
    for t in rest.iter().chain(&owner.pieces(1, &Message::new(1, 5, 8, 1).digits())[..12]) { assert_eq!(net.try_apply(t), Err("cheque not open")); }
    assert_eq!(net.try_apply(&owner.open_all(1, &Message::new(1, 5, 8, 1).digits())), Err("cheque number already consumed"));
    assert_eq!(net.acct(&owner).balance, 10 * COIN);
}

/// LOW-4: fee-less pieces could reopen a cheque again and again for free. An opening needs both parts and uses its
/// number; a cheque, once open, cannot be opened again (by anyone, with any digits).
#[test]
fn a_cheque_opens_once() {
    let p = Params { piece_lifetime: 20, ..params() };
    let owner = bk(7, p.magic);
    let mut net = funded(&p, &owner, false);
    let d = Message::new(1, 1, 8, 1).digits();
    net.mine(0, vec![owner.opening(3, &d, 12)]).unwrap();
    assert_eq!(net.try_apply(&owner.opening(3, &d, 12)), Err("cheque already open"));
    assert_eq!(net.try_apply(&owner.opening(3, &Message::new(2, 1, 8, 1).digits(), 13)), Err("cheque already open"));
    assert_eq!(net.try_apply(&owner.opening(2, &d, 12)), Err("cheque number already consumed"));
    assert_eq!(net.try_apply(&owner.pieces(3, &d)[12]), Err("column already revealed"));
}

/// §10.12 as it now stands, a residual: someone holding part B who sees the owner's opening (in the mempool, or in a
/// block) can choose the amount: a sweep of everything to the owner's own recipient, the fee tier to the miner. Before
/// the opening is mined, by racing it with the owner's own part-A cells; after, with the amount columns not yet shown.
#[test]
fn a_part_b_holder_can_choose_the_amount() {
    let p = params();
    let owner = bk(7, p.magic);
    // racing the opening from the mempool: the owner's recipient cells, the thief's amount
    let mut net = funded(&p, &owner, false);
    let (open, _) = owner.halves(1, &Message::new(1, 1, 8, 1).digits());
    let Tx::ChequeOpen { pieces, .. } = &open else { panic!() };
    let sweep = Message::new(1, 0, 9, 9).digits();
    let mut race = pieces[..12].to_vec();
    race.extend((12..18u8).map(|c| (c, vec![cell(7, &p, 1, c, sweep[c as usize])])));
    net.mine(0, vec![Tx::ChequeOpen { account: owner.id(), cheque: 1, pieces: race }]).unwrap();
    assert_eq!(net.acct(&owner).balance, 0, "swept to the owner's recipient");
    assert_eq!(net.try_apply(&open), Err("cheque number already consumed"));
    // after the opening is in a block: column 12 is the owner's, the rest the thief's (the most the balance allows)
    let mut net = funded(&p, &owner, false);
    let (open, _) = owner.halves(1, &Message::new(1, 1, 8, 1).digits());   // 1 coin; column 12 shows mantissa digit 0
    net.mine(0, vec![open]).unwrap();
    let more = Message::new(1, 999, 6, 9).digits();   // 9.99 coins
    net.mine(0, owner.pieces(1, &more)[13..].to_vec()).unwrap();
    assert_eq!(net.acct(&owner).balance, 10 * COIN - 999 * 1_000_000 - 9 * p.fee_unit);
}

/// §10.12, the other residual: a part-A holder who sees the owner's opening and gets a block first (a miner) can open
/// the cheque to its own recipient with the owner's amount cell. It cannot finish it (the rest of part B is still the
/// owner's), so it spoils that one cheque and steals nothing: the owner's wallet sees other digits and never sends more.
#[test]
fn a_mining_part_a_holder_spoils_one_cheque_and_steals_nothing() {
    let p = params();
    let owner = bk(7, p.magic);
    let mut net = funded(&p, &owner, false);
    let pay = Message::new(1, 1, 8, 1).digits();
    let (open, rest) = owner.halves(1, &pay);
    let Tx::ChequeOpen { pieces, .. } = &open else { panic!() };
    let thief = Message::new(2, 1, 8, 1).digits();
    let mut spoil: Vec<(u8, Vec<Vec<u8>>)> = (0..12u8).map(|c| (c, vec![cell(7, &p, 1, c, thief[c as usize])])).collect();
    spoil.push(pieces[12].clone());
    net.mine(0, vec![Tx::ChequeOpen { account: owner.id(), cheque: 1, pieces: spoil }]).unwrap();
    assert_eq!(net.try_apply(&open), Err("cheque already open"));
    // without the rest of part B nothing completes; the owner's wallet sees other digits on cheque 1 and stops
    assert_eq!(net.acct(&owner).open[&1].digits[..12].iter().map(|d| d.unwrap()).collect::<Vec<_>>(), thief[..12].to_vec());
    for _ in 0..p.piece_lifetime { net.mine(0, vec![]).unwrap(); }
    assert_eq!(net.try_apply(&rest[0]), Err("cheque not open"));
    assert_eq!((net.acct(&owner).balance, net.acct(&owner).nonce), (10 * COIN, Some(1)));
}

/// One opening, one encoding: columns strictly rising from 0, every share the book's size and count, nothing after it.
#[test]
fn an_opening_has_one_encoding() {
    let p = params();
    let owner = bk(7, p.magic);
    let d = Message::new(1, 1, 8, 1).digits();
    for last in [12usize, 15, 17] {
        let t = owner.opening(1, &d, last);
        assert_eq!(Tx::decode(&mut R::new(&t.encode())), Ok(t.clone()));
        let mut e = t.encode(); e.push(0);
        assert_eq!(Tx::decode(&mut R::new(&e)), Err("trailing bytes"));
    }
    let id = owner.id();
    let bad = [opening(&id, 7, &p, 1, (0..12).chain([12, 12]), &d), opening(&id, 7, &p, 1, (0..12).chain([14, 13]), &d),
               opening(&id, 7, &p, 1, (0..11).chain([12, 13]), &d), opening(&id, 7, &p, 1, (0..12).chain([18]), &d), opening(&id, 7, &p, 1, 0..12, &d)];
    for t in &bad { assert_eq!(Tx::decode(&mut R::new(&t.encode())), Err("bad opening columns"), "{t:?}"); }
    let Tx::ChequeOpen { account, cheque, mut pieces } = owner.opening(1, &d, 12) else { panic!() };
    let extra = pieces[3].1[0].clone(); pieces[3].1.push(extra);
    assert_eq!(Tx::decode(&mut R::new(&Tx::ChequeOpen { account: account.clone(), cheque, pieces: pieces.clone() }.encode())), Err("bad share count"));
    pieces[3].1.pop(); pieces[3].1[0].pop();
    assert_eq!(Tx::decode(&mut R::new(&Tx::ChequeOpen { account, cheque, pieces }.encode())), Err("bad share length"));
}

/// The node: two openings of one cheque conflict in the mempool, and the dry run tells a wallet which kind of conflict
/// it is ("cheque already open": its own opening again; "cheque open with other digits": someone else's), and the rows.
#[test]
fn the_mempool_holds_one_opening_per_cheque() {
    let p = Params { initial_bits: 0x207F_FFFF, min_bits: 0x207F_FFFF, reg_pow_target: U256::MAX.shr(4), launch_blocks: 0, reward_maturity: 2, number_maturity: 2,
                     reward_base: 50 * COIN, ..Params::mainnet() };
    let g = Chain::genesis(&p, bitcheque::net::now() - 100_000, b"open test");
    let a = Node::new(Store::open(p.clone(), &g, None).unwrap());
    let miner = bk(1, p.magic);
    common::mine(&a, 0).unwrap();
    a.submit_tx(mine_registration(miner.register(0, 16, Payment::Pow([0; 32], 0)), common::tip(&a), p.reg_pow_target), None).unwrap();
    for k in 0..5 { common::mine(&a, if k < 2 { 0 } else { 1 }).unwrap(); }
    let d = Message::new(1, 1, 8, 1).digits();
    let (open, rest) = miner.halves(1, &d);
    assert_eq!(a.check_txs(std::slice::from_ref(&open))[0], Ok(Some(d[..13].iter().map(|x| char::from(b'0' + x)).collect())));
    a.submit_tx(open.clone(), None).unwrap();
    let other = miner.opening(1, &Message::new(1, 2, 8, 1).digits(), 13);
    assert_eq!(a.submit_tx(other.clone(), None), Err("cheque already open"));
    assert_eq!(a.check_txs(&[open.clone(), other])[..], [Err("cheque already open"), Err("cheque open with other digits")]);
    assert_eq!(a.check_txs(&rest[..1])[0], Ok(Some(char::from(b'0' + d[13]).to_string())));
    let wrong = miner.pieces(1, &Message::new(1, 1, 8, 1).digits().map(|x| (x + 1) % 10));
    assert_eq!(a.check_txs(&wrong[5..6])[0], Err("column revealed with other digits"));
    common::mine(&a, 1).unwrap();
    for t in &rest { a.submit_tx(t.clone(), None).unwrap(); }
    common::mine(&a, 1).unwrap();
    assert_eq!(a.check_txs(&[open])[0], Err("cheque number already consumed"));
    assert!(a.store.lock().unwrap().chain.state.accounts[&miner.id()].open.is_empty());
}

//! Regression tests for the third consensus audit, on the audit 4 rules: a cheque opens only from both printed parts at
//! once (no burning or freezing a book from a stolen part or one leaked cell), one open cheque, a cheque's expiry fixed
//! by its opening, a cheque to an unknown number voided, block 0 no anchor, the batch overlap test, cells bound to the network,
//! and the snapshot codec at every height.
use bitcheque::block::Chain;
use bitcheque::crypto::sha256;
use bitcheque::message::Message;
use bitcheque::params::{Params, COIN, TESTNET_MAGIC};
use bitcheque::state::State;
use bitcheque::tx::{Batch, Payment, Tx, R};
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
}
fn bk(k: u8, net: [u8; 4]) -> Book { Book { salt: [k; 16], n256: false, book_size: 256, domains: vec![Domain([k; 32])], net } }
fn keys(b: &Book, net: &Net) -> Vec<u16> { net.acct(b).commits.keys().copied().collect() }

/// A miner (number 1, with rewards) and an owner (number 2) holding 10 coins.
fn funded(p: &Params, owner: &Book, all: bool) -> (Net, Book) {
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
    (net, miner)
}

/// Audit finding 1 (and audit 4): a leaked cell (one QR code) of any cheque does nothing at all: a piece is only
/// valid on an open cheque, and only an opening with both printed parts opens one.
#[test]
fn one_leaked_cell_does_nothing() {
    let p = params();
    let owner = bk(7, p.magic);
    let (mut net, _) = funded(&p, &owner, true);
    let piece = Tx::ChequePiece { account: owner.id(), cheque: 255, column: 3, shares: vec![Domain([7; 32]).cell(&p.magic, 16, 255, 3, 5)] };
    assert_eq!(net.mine(0, vec![piece]), Err("cheque not open"));
    // the owner sends with cheque 1 as the wallet does: the opening, then the amount once it is deep enough
    let (open, rest) = owner.halves(1, &Message::new(1, 1000, 5, 1).digits());
    net.mine(0, vec![open]).unwrap();
    assert_eq!(net.acct(&owner).nonce, Some(1), "an opening uses its number at once");
    net.mine(0, rest).unwrap();
    let a = net.acct(&owner);
    assert_eq!((a.balance, a.nonce, a.commits.len()), (9 * COIN - p.fee_unit, Some(1), 254));
    net.mine(0, owner.sign(255, &Message::new(1, 0, 9, 1))).unwrap();   // and sweeps
    assert_eq!(net.acct(&owner).balance, 0);
}

/// A holder of one printed part cannot open anything (an opening needs every recipient column and an amount column);
/// once the owner's opening is on chain a thief's other recipient cells or a second opening do not fit.
#[test]
fn one_part_holders_cannot_open_burn_or_steal() {
    let p = Params { piece_lifetime: 20, ..params() };
    let owner = bk(7, p.magic);
    let (mut net, _) = funded(&p, &owner, false);
    let to_thief = Message::new(1, 9999, 9, 9).digits();   // a part-A thief chooses the recipient, a part-B thief the amount
    let part_a = Tx::ChequeOpen { account: owner.id(), cheque: 15, pieces: (0..12u8).map(|c| (c, vec![Domain([7; 32]).cell(&p.magic, 16, 15, c, to_thief[c as usize])])).collect() };
    let part_b = Tx::ChequeOpen { account: owner.id(), cheque: 14, pieces: (12..18u8).map(|c| (c, vec![Domain([7; 32]).cell(&p.magic, 16, 14, c, to_thief[c as usize])])).collect() };
    for t in [&part_a, &part_b] {
        assert_eq!(net.chain.state.clone().apply(&p, t), Err("bad opening columns"));
        assert_eq!(Tx::decode(&mut R::new(&t.encode())), Err("bad opening columns"));
    }
    for t in owner.pieces(15, &to_thief) { assert_eq!(net.chain.state.clone().apply(&p, &t), Err("cheque not open")); }
    let (open, rest) = owner.halves(1, &Message::new(1, 1000, 5, 1).digits());
    net.mine(0, vec![open]).unwrap();
    // the part-A thief racing the owner's amount pieces: its recipient cells no longer fit, nor does a second opening
    let race = owner.pieces(1, &Message::new(2, 0, 9, 1).digits());
    assert_eq!(net.chain.state.clone().apply(&p, &race[10]), Err("column already revealed"));
    assert_eq!(net.chain.state.clone().apply(&p, &owner.opening(1, &Message::new(2, 1000, 5, 1).digits(), 12)), Err("cheque already open"));
    net.mine(0, rest).unwrap();
    assert_eq!((net.acct(&owner).nonce, net.acct(&owner).open.len()), (Some(1), 0));
    assert_eq!(keys(&owner, &net), (2..16).collect::<Vec<u16>>());
}

/// An opening binds at once: it consumes the number and every lower cheque; if the cheque is then left unfinished,
/// it goes at expiry and its number stays used.
#[test]
fn an_opening_binds_and_an_unfinished_cheque_stays_used() {
    let p = params();
    let owner = bk(7, p.magic);
    let (mut net, _) = funded(&p, &owner, false);
    let (open, rest) = owner.halves(5, &Message::new(1, 1000, 5, 1).digits());
    net.mine(0, vec![open]).unwrap();
    assert_eq!(net.acct(&owner).nonce, Some(5));
    assert_eq!(keys(&owner, &net), (5..16).collect::<Vec<u16>>());
    while !net.acct(&owner).open.is_empty() { net.mine(0, vec![]).unwrap(); }
    assert_eq!(keys(&owner, &net), (6..16).collect::<Vec<u16>>());
    assert_eq!(net.chain.state.clone().apply(&p, &rest[0]), Err("cheque not open"));
    assert_eq!(net.chain.state.clone().apply(&p, &owner.open_all(5, &Message::new(1, 1000, 5, 1).digits())), Err("cheque number already consumed"));
}

/// At most one cheque is open: opening a higher one (a void, say) removes the lower open one; the higher completes.
#[test]
fn a_higher_opening_closes_the_open_cheque() {
    let p = Params { piece_lifetime: 20, ..params() };
    let owner = bk(7, p.magic);
    let (mut net, _) = funded(&p, &owner, false);
    let d = Message::new(1, 1, 0, 1).digits();
    net.mine(0, vec![owner.opening(3, &d, 12)]).unwrap();
    net.mine(0, vec![owner.opening(7, &d, 14)]).unwrap();
    let a = net.acct(&owner);
    assert_eq!((a.nonce, a.open.keys().copied().collect::<Vec<_>>()), (Some(7), vec![7]));
    assert_eq!(keys(&owner, &net), (7..16).collect::<Vec<u16>>());
    assert_eq!(net.chain.state.clone().apply(&p, &owner.pieces(3, &d)[13]), Err("cheque not open"));
    net.mine(0, owner.pieces(7, &d)[15..].to_vec()).unwrap();   // and the higher one completes
    assert_eq!((net.acct(&owner).nonce, net.acct(&owner).balance), (Some(7), 10 * COIN - 1 - p.fee_unit));
}

/// Audit item 27: an open cheque expires piece_lifetime blocks after its opening, however many pieces follow.
#[test]
fn expiry_is_set_by_the_opening() {
    let p = params();
    let owner = bk(7, p.magic);
    let (mut net, _) = funded(&p, &owner, false);
    let (open, rest) = owner.halves(2, &Message::new(1, 1000, 5, 1).digits());
    net.mine(0, vec![open]).unwrap();
    let due = net.chain.height() + p.piece_lifetime;
    net.mine(0, vec![rest[0].clone()]).unwrap();
    net.mine(0, vec![rest[1].clone()]).unwrap();
    assert_eq!(net.acct(&owner).open[&2].expiry, due);
    net.mine(0, vec![]).unwrap();
    assert_eq!(net.chain.height(), due);
    assert!(net.acct(&owner).open.is_empty() && !net.acct(&owner).commits.contains_key(&2));
    assert_eq!(net.acct(&owner).nonce, Some(2));
}

/// Audit item 10: a cheque to a number nobody holds yet used to stay completable by whoever got that number. Its last
/// piece is now accepted and voids it: the number is used, nothing moves, and the later holder cannot collect.
#[test]
fn a_cheque_to_an_unknown_or_young_number_is_void() {
    let p = params();
    let owner = bk(7, p.magic);
    let (mut net, _) = funded(&p, &owner, false);
    let next = net.chain.state.next_number;
    let pieces = owner.sign(1, &Message::new(next + 1, 2, 8, 1));
    net.mine(0, pieces[..5].to_vec()).unwrap();
    net.mine(0, vec![pieces[5].clone()]).unwrap();
    let a = net.acct(&owner);
    assert_eq!((a.balance, a.nonce, a.open.is_empty(), a.commits.contains_key(&1)), (10 * COIN, Some(1), true, false));
    let (filler, thief) = (bk(4, p.magic), bk(5, p.magic));
    net.reg(&filler); net.reg(&thief);
    assert_eq!(net.acct(&thief).number, next + 1);
    // a number assigned but not yet final voids a cheque too
    net.mine(0, owner.sign(2, &Message::new(next + 1, 2, 8, 1))).unwrap();
    assert_eq!((net.acct(&owner).balance, net.acct(&thief).balance, net.acct(&owner).nonce), (10 * COIN, 0, Some(2)));
    for _ in 0..3 { net.mine(0, vec![]).unwrap(); }
    assert_eq!(net.mine(0, vec![pieces[0].clone()]), Err("cheque number already consumed"));
    assert_eq!(net.acct(&thief).balance, 0);
}

/// Audit item 26: block 0 is known before launch, so its hash is no registration anchor.
#[test]
fn genesis_hash_is_no_anchor() {
    let p = params();
    let g = Chain::genesis(&p, 1000, b"t");
    let pre = mine_registration(bk(5, p.magic).register(0, 16, Payment::Pow([0; 32], 0)), g.header.hash(), p.reg_pow_target);
    let mut net = Net::new(&p);
    assert_eq!(net.mine(0, vec![pre]), Err("registration anchor not recent"));
}

/// Audit item 28: the batch's shape is checked before its end is computed (an overflow panic with debug assertions).
#[test]
fn register_batch_shape_before_overlap() {
    let p = params();
    let mut net = Net::new(&p);
    let b = bk(3, p.magic);
    net.reg(&b);
    for (start, count) in [(1, u32::MAX), (u32::MAX, 16), (0, 0), (256, 16)] {
        let tx = Tx::RegisterBatch { account: b.id(), batch: Batch { start, count, cheques: vec![], path: vec![] }, pay: Payment::Pow([0; 32], 0) };
        assert_eq!(net.chain.state.clone().apply(&p, &tx), Err("batch not aligned"));
    }
    let again = Tx::RegisterBatch { account: b.id(), batch: b.batch(0, 16), pay: Payment::Pow([0; 32], 0) };
    assert_eq!(net.chain.state.clone().apply(&p, &again), Err("batch overlaps"));
}

/// Audit item 3: cells are derived with the network's magic, so a cheque written on one network is no cheque of the
/// same seed's book on another. The research network keeps the old derivation (printed books stay valid).
#[test]
fn cells_are_bound_to_the_network() {
    let seed = [7u8; 32];
    let old = sha256(&[b"bitcheque/key".as_slice(), &seed, &3u16.to_le_bytes()].concat());
    assert_eq!(Domain(seed).key(&TESTNET_MAGIC, 3), old);
    assert_ne!(Domain(seed).key(&Params::local().magic, 3), old);
    assert_ne!(Domain(seed).key(&Params::mainnet().magic, 3), Domain(seed).key(&Params::local().magic, 3));

    let (pa, pb) = (Params { magic: Params::local().magic, ..params() }, Params { magic: TESTNET_MAGIC, ..params() });
    let (mut a, mut b) = (Net::new(&pa), Net::new(&pb));
    let (va, vb) = (bk(7, pa.magic), bk(7, pb.magic));
    a.reg(&va); b.reg(&vb);
    for _ in 0..3 { a.mine(0, vec![]).unwrap(); b.mine(0, vec![]).unwrap(); }
    for _ in 0..3 { a.mine(1, vec![]).unwrap(); b.mine(1, vec![]).unwrap(); }
    let pieces = va.sign(1, &Message::new(1, 5, 8, 1));
    a.mine(0, pieces.clone()).unwrap();
    let replay: Vec<Tx> = pieces.into_iter().map(|t| match t {
        Tx::ChequePiece { cheque, column, shares, .. } => Tx::ChequePiece { account: vb.id(), cheque, column, shares },
        Tx::ChequeOpen { cheque, pieces, .. } => Tx::ChequeOpen { account: vb.id(), cheque, pieces },
        _ => unreachable!() }).collect();
    assert_eq!(b.mine(0, replay), Err("no commitment matches"));
}

/// A state restored from its snapshot encoding at every height accepts the same next block with the same root as the
/// live state: open cheques, expiries, renewals, number reuse, re-registration.
#[test]
fn snapshot_restore_differential() {
    let p = Params { unfunded_pow_lifetime: 6, number_quarantine: 4, piece_lifetime: 3, batch_lifetime: 30, renew_window: 20, renew_fee: 10, ..params() };
    let g = Chain::genesis(&p, 1000, b"t");
    let (mut live, mut twin) = (Chain::new(p.clone(), &g).unwrap(), Chain::new(p.clone(), &g).unwrap());
    let mut t = 1000;
    let mut step = |live: &mut Chain, twin: &mut Chain, txs: Vec<Tx>, payee: u32| -> Result<(), &'static str> {
        t += 60;
        let b = live.make_block(t, payee, txs)?;
        live.add(&b, t)?;
        twin.add(&b, t).expect("restored state refused a block the live state accepted");
        assert_eq!(twin.state.root(), live.state.root());
        twin.state = State::decode(&mut R::new(&twin.state.encode())).unwrap();
        assert_eq!((twin.state.root(), twin.state.encode()), (live.state.root(), live.state.encode()));
        Ok(())
    };
    let pow = |c: &Chain, tx: Tx| mine_registration(tx, c.tip(), c.state.next_reg_target(&p));
    let books: Vec<Book> = (1..=6).map(|k| bk(k, p.magic)).collect();
    step(&mut live, &mut twin, vec![], 0).unwrap();
    let r0 = pow(&live, books[0].register(0, 16, Payment::Pow([0; 32], 0)));
    step(&mut live, &mut twin, vec![r0], 0).unwrap();
    for _ in 0..3 { step(&mut live, &mut twin, vec![], 0).unwrap(); }
    for _ in 0..3 { step(&mut live, &mut twin, vec![], 1).unwrap(); }
    for b in &books[1..] { let r = pow(&live, b.register(0, 16, Payment::Pow([0; 32], 0))); step(&mut live, &mut twin, vec![r], 1).unwrap(); }
    let n1 = live.state.accounts[&books[1].id()].number;
    step(&mut live, &mut twin, books[0].sign(1, &Message::new(n1, 2, 8, 1)), 1).unwrap();
    // book 5: one cheque opened and unfinished, one more piece in the next block
    let d = Message::new(0, 0, 0, 0).digits();
    step(&mut live, &mut twin, vec![books[5].opening(4, &d, 13)], 1).unwrap();
    step(&mut live, &mut twin, vec![books[5].pieces(4, &d)[15].clone()], 1).unwrap();
    for h in 0..30 {
        let mut txs = vec![];
        if h == 6 { txs.push(Tx::Renew { account: books[0].id(), start: 0 }); }
        if h == 8 { txs.push(pow(&live, books[1].registrations(16, 31).remove(0))); }
        if h == 12 { txs.push(pow(&live, books[2].register(0, 16, Payment::Pow([0; 32], 0)))); }
        if step(&mut live, &mut twin, txs, 1).is_err() { step(&mut live, &mut twin, vec![], 1).unwrap(); }
    }
}

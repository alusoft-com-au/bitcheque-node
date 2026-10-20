//! End to end: mine from block 0, register books, honesty check, reward, pay, piecewise,
//! replay and check-digit rejections, fee-paid registration, sweep, expiry.
use bitcheque::block::{Block, Chain};
use bitcheque::message::Message;
use bitcheque::params::{Params, COIN};
use bitcheque::tx::{Payment, Tx};
use bitcheque::u256::U256;
use bitcheque::wallet::{mine_registration, Book, Domain};

fn params() -> Params {
    Params { initial_bits: 0x207F_FFFF, min_bits: 0x207F_FFFF, reg_pow_target: U256::MAX.shr(4), reward_maturity: 2, number_maturity: 2,
             launch_blocks: 0, piece_lifetime: 3, unfunded_pow_lifetime: 50, max_future_seconds: 1 << 30, reward_base: 50 * COIN, ..Params::mainnet() }
}
struct Net { chain: Chain, t: u32 }
impl Net {
    fn mine(&mut self, payee: u32, txs: Vec<Tx>) -> Result<(), &'static str> {
        self.t += 600;
        let b = self.chain.make_block(self.t, payee, txs)?;
        assert_eq!(Block::decode(&b.encode()).unwrap(), b);
        self.chain.add(&b, self.t)
    }
    fn balance(&self, id: &[u8]) -> u64 { self.chain.state.accounts[id].balance }
}

#[test]
fn life_of_the_chain() {
    let p = params();
    let g = Chain::genesis(&p, 1000, b"test");
    let mut net = Net { chain: Chain::new(p.clone(), &g).unwrap(), t: 1000 };
    net.mine(0, vec![]).unwrap();   // block 0 is no registration anchor

    // miner: software book, m = 1, 16 cheques, PoW-paid. A number takes rewards only once final (number_maturity
    // blocks deep, as for a cheque's payee), so it mines to nobody until then (§12.2)
    let miner = Book { salt: [1; 16], n256: false, book_size: 256, domains: vec![Domain([7; 32])], net: Params::mainnet().magic };
    let reg = mine_registration(miner.register(0, 16, Payment::Pow([0; 32], 0)), net.chain.tip(), p.reg_pow_target);
    assert_eq!(net.chain.make_block(net.t + 600, 1, vec![reg.clone()]).err(), Some("coinbase payee not mature"));   // not even in its own block
    assert_eq!(net.chain.make_block(net.t + 600, 2, vec![]).err(), Some("coinbase payee unknown"));
    assert!(net.mine(0, vec![reg]).is_ok());           // height 1: number 1 assigned
    assert_eq!(net.chain.state.accounts[&miner.id()].number, 1);
    assert_eq!(net.chain.make_block(net.t + 600, 1, vec![]).err(), Some("coinbase payee not mature"));
    net.mine(0, vec![]).unwrap();                       // height 2
    net.mine(1, vec![]).unwrap();                       // height 3: number 1 is final, its first reward
    net.mine(1, vec![]).unwrap();
    net.mine(1, vec![]).unwrap();                       // height 5: the block-3 reward is credited
    assert_eq!(net.balance(&miner.id()), 50 * COIN);

    // user: a split book (two seeds), first 16 cheques registered; honesty check (cheque 0, zero coins, tier 0) in the same block
    let user = Book { salt: [2; 16], n256: false, book_size: 256, domains: vec![Domain([8; 32]), Domain([9; 32])], net: Params::mainnet().magic };
    let mut txs = vec![mine_registration(user.register(0, 16, Payment::Pow([0; 32], 0)), net.chain.tip(), p.reg_pow_target)];
    txs.extend(user.sign(0, &Message::new(0, 0, 0, 0)));
    net.mine(1, txs).unwrap();
    let u = &net.chain.state.accounts[&user.id()];
    assert_eq!((u.number, u.nonce, u.commits.len()), (2, Some(0), 15));

    // miner pays user 1 coin: number 2 is mature two blocks after assignment
    net.mine(1, vec![]).unwrap();
    assert_eq!(net.mine(1, miner.sign(0, &Message::new(2, 1000, 5, 1))), Ok(()));
    assert_eq!(net.balance(&user.id()), COIN);

    // user pays 0.5 coin back with cheque 3, payee columns in one block, the rest in the next
    let pieces = user.sign(3, &Message::new(1, 5000, 4, 2));
    net.mine(1, pieces[..12].to_vec()).unwrap();
    assert!(net.chain.state.accounts[&user.id()].open.contains_key(&3));
    net.mine(1, pieces[12..].to_vec()).unwrap();
    let u = &net.chain.state.accounts[&user.id()];
    assert_eq!((u.balance, u.nonce, u.open.is_empty()), (COIN - 5000 * 10_000 - 2 * p.fee_unit, Some(3), true));
    assert!(!u.commits.contains_key(&1) && !u.commits.contains_key(&2) && !u.commits.contains_key(&3));

    // rejections: lower number, replay, wrong shares
    let s = &net.chain.state;
    assert_eq!(s.clone().apply(&p, &user.sign(2, &Message::new(1, 1, 0, 1))[0]), Err("cheque number already consumed"));
    assert_eq!(s.clone().apply(&p, &pieces[0]), Err("cheque number already consumed"));
    let mut bad = user.sign(4, &Message::new(1, 1, 0, 1));
    if let Tx::ChequePiece { shares, .. } = &mut bad[0] { shares[0][0] ^= 1 }
    assert_eq!(s.clone().apply(&p, &bad[0]), Err("no commitment matches"));

    // wrong check digit: every piece is a valid preimage, completion fails, cheque 4 expires unspent
    let mut d = Message::new(1, 1000, 0, 1).digits();
    d[11] = (d[11] + 1) % 10;
    let wrong = user.pieces(4, &d);
    net.mine(1, wrong[..17].to_vec()).unwrap();
    assert_eq!(net.chain.state.clone().apply(&p, &wrong[17]), Err("payee check digit wrong"));
    for _ in 0..3 { net.mine(1, vec![]).unwrap(); }
    let u = &net.chain.state.accounts[&user.id()];
    assert!(u.open.is_empty() && !u.commits.contains_key(&4) && u.nonce == Some(4));

    // sweep: user empties the account to the miner with cheque 10; only cheques above it stay spendable
    net.mine(1, user.sign(10, &Message::new(1, 0, 9, 1))).unwrap();
    assert_eq!(net.balance(&user.id()), 0);
    assert_eq!(net.chain.state.accounts[&user.id()].commits.keys().copied().collect::<Vec<u16>>(), (11..16).collect::<Vec<u16>>());
    // and a book of any size but 256 is refused
    let small = Book { salt: [6; 16], n256: false, book_size: 12, domains: vec![Domain([6; 32])], net: Params::mainnet().magic };
    assert_eq!(net.chain.state.clone().apply(&p, &mine_registration(small.register(0, 16, Payment::Pow([0; 32], 0)), net.chain.tip(), p.reg_pow_target)), Err("bad book parameters"));
}

/// Block 0 of mainnet with the placeholder message and launch time must equal the Python
/// cross-check (`genesis.py`). Slow in debug builds: `cargo test --release -- --ignored`.
#[test]
#[ignore]
fn genesis_vector() {
    let g = Chain::genesis(&Params::mainnet(), 1_798_761_600, b"Bitcheque genesis. Message text and launch timestamp to be set (DESIGN.md 12.4).");
    let mut h = g.header.hash(); h.reverse();
    assert_eq!(bitcheque::crypto::hex(&h), "000000f31d51d0a837e08646aeb546c8081b9e0d910d22499f1ba2b87444be58");
    assert_eq!(g.header.nonce, 2106192);
}

/// Stall relief: after fast blocks the difficulty is high; once the chain has been silent for two
/// targets beyond the latest recent timestamp and the future-time allowance, the target doubles per
/// further two targets; an on-time block may not use it.
#[test]
fn stall_relief_restarts_an_abandoned_chain() {
    use bitcheque::block::{next_bits, relieved_bits};
    use bitcheque::u256::U256;
    let p = Params { initial_bits: 0x207F_FFFF, min_bits: 0x207F_FFFF, stall_relief: true, launch_blocks: 0, ..Params::mainnet() };
    let (t, f) = (p.block_target_seconds, p.max_future_seconds);
    let t0 = 1000u32;
    let mut c = Chain::new(p.clone(), &Chain::genesis(&p, t0, b"relief")).unwrap();
    for i in 1..=6 { let b = c.make_block(t0 + 5 * i, 0, vec![]).unwrap(); c.add(&b, t0 + 100_000).unwrap(); } // fast blocks: difficulty climbs
    let base = next_bits(&p, &c.headers);
    assert!(U256::from_compact(base) < U256::from_compact(p.initial_bits), "difficulty rose above genesis");
    let last = c.headers.last().unwrap().time;
    let start = last + f + 2 * t;
    assert_eq!(relieved_bits(&p, &c.headers, last + t), base, "on time: no relief");
    assert_eq!(relieved_bits(&p, &c.headers, start), base, "within the future-time allowance: no relief");
    let eased = relieved_bits(&p, &c.headers, start + 1);
    assert_eq!(U256::from_compact(eased), U256::from_compact(base).shl(1), "two targets past the allowance: target doubled");
    assert_eq!(relieved_bits(&p, &c.headers, start + 1000 * t), p.min_bits, "long silence: back to the easiest target");
    let late = c.make_block(start + 1, 0, vec![]).unwrap();
    assert_eq!(late.header.bits, eased);
    c.add(&late, start + 1).unwrap();
    let off = Params { stall_relief: false, ..p.clone() };
    let mut d = Chain::new(off.clone(), &Chain::genesis(&off, t0, b"relief")).unwrap();
    for h in 1..=6 { d.add(&c.blocks.get(h).unwrap(), t0 + 100_000).unwrap(); }
    assert_eq!(d.add(&late, start + 1), Err("bits"), "without relief the same block is invalid");
}

/// The Bitcoin-testnet exploit: a miner alternates a block stamped just after the median time with one
/// stamped as far ahead as allowed, hoping every second block gets minimum difficulty. The latest of
/// the recent timestamps is still the far-future one, so no relief is due.
#[test]
fn alternating_timestamps_earn_no_relief() {
    use bitcheque::block::{next_bits, relieved_bits};
    let p = Params { initial_bits: 0x207F_FFFF, min_bits: 0x207F_FFFF, stall_relief: true, launch_blocks: 0, ..Params::mainnet() };
    let now = 1_000_000u32;
    let mut c = Chain::new(p.clone(), &Chain::genesis(&p, now - 1000, b"relief")).unwrap();
    for i in 1..=12 { let b = c.make_block(now - 120 + 10 * i, 0, vec![]).unwrap(); c.add(&b, now).unwrap(); }   // an active chain, up to now
    for _ in 0..6 {
        let low = c.make_block(c.median_time() + 1, 0, vec![]).unwrap();
        c.add(&low, now).unwrap();
        let high_t = now + p.max_future_seconds;
        assert_eq!(relieved_bits(&p, &c.headers, high_t), next_bits(&p, &c.headers), "a far-future stamp alone earns no relief");
        let high = c.make_block(high_t, 0, vec![]).unwrap();
        c.add(&high, now).unwrap();
    }
}

/// Registration difficulty follows demand both ways, every block: a burst at the cap hardens it within hours, quiet
/// eases it back, and it is never easier than the genesis target (DESIGN.md §8).
#[test]
fn registration_target_tightens_and_loosens() {
    use bitcheque::state::State;
    let p = Params::mainnet();
    let mut s = State::new(&p);
    s.reg_target = p.reg_pow_target.div_u64(16);
    for h in 1..=144 { s.reg_block_count = p.reg_pow_per_block_cap; s.begin_block(&p, h); }   // 144 blocks at the cap
    assert!(s.reg_target < p.reg_pow_target.div_u64(64) && s.reg_target > p.reg_pow_target.div_u64(128), "a burst: about 4.5 times harder in 144 blocks");
    let hard = s.reg_target;
    s.reg_block_count = 1; s.begin_block(&p, 145);
    assert_eq!(s.reg_target.div_u64(1 << 20), hard.div_u64(1 << 20), "one a block: steady");
    for h in 146..146 + p.reg_pow_window { s.begin_block(&p, h); }
    assert!(s.reg_target > hard.mul_u64(2) && s.reg_target < hard.mul_u64(3), "a quiet day: about e times easier");
    for h in 0..20_000 { s.begin_block(&p, 10_000 + h); }
    assert_eq!(s.reg_target, p.reg_pow_target, "never easier than the genesis target");
}

/// A 256-cheque book registers 16 cheques at a time, each batch paying its own proof of work, on one account number.
#[test]
fn a_book_grows_a_batch_at_a_time() {
    let p = params();
    let g = Chain::genesis(&p, 1000, b"test");
    let mut net = Net { chain: Chain::new(p.clone(), &g).unwrap(), t: 1000 };
    net.mine(0, vec![]).unwrap();   // block 0 is no registration anchor
    let book = Book { salt: [3; 16], n256: false, book_size: bitcheque::wallet::BOOK_SIZE, domains: vec![Domain([4; 32])], net: Params::mainnet().magic };
    let first = book.registrations(0, 11);
    assert_eq!(first.len(), 1);
    let mut txs = vec![mine_registration(first[0].clone(), net.chain.tip(), p.reg_pow_target)];
    txs.extend(book.sign(0, &Message::new(0, 0, 0, 0)));
    net.mine(0, txs).unwrap();
    let number = net.chain.state.accounts[&book.id()].number;
    assert_eq!(net.chain.state.accounts[&book.id()].commits.len(), 15);

    // cheques 16-40 need two more batches (16-31, 32-47); unpaid work is refused
    let more = book.registrations(16, 40);
    assert_eq!(more.len(), 2);
    let mut unpaid = more[0].clone();
    while U256::from_le_bytes(&unpaid.txid()) < p.reg_pow_target { if let Tx::RegisterBatch { pay: Payment::Pow(_, n), .. } = &mut unpaid { *n += 1 } }
    assert_eq!(net.chain.state.clone().apply(&p, &unpaid), Err("registration pow insufficient"));
    net.mine(0, more.iter().map(|t| mine_registration(t.clone(), net.chain.tip(), p.reg_pow_target)).collect()).unwrap();
    let a = &net.chain.state.accounts[&book.id()];
    assert_eq!((a.number, a.commits.len()), (number, 15 + 32));

    // the same batch twice, and a batch past the 16-cheque limit, are refused
    assert_eq!(net.chain.state.clone().apply(&p, &mine_registration(more[0].clone(), net.chain.tip(), p.reg_pow_target)), Err("batch overlaps"));
    let mut big = book.registrations(64, 64).remove(0);
    if let Tx::RegisterBatch { batch, .. } = &mut big { batch.count = 32; }
    assert_eq!(net.chain.state.clone().apply(&p, &mine_registration(big, net.chain.tip(), p.reg_pow_target)), Err("batch not aligned"));

    // a cheque from a later batch spends like any other, and the last batch ends at cheque 255
    net.mine(0, book.sign(40, &Message::new(0, 0, 0, 0))).unwrap();
    assert_eq!(net.chain.state.accounts[&book.id()].nonce, Some(40));
    let last = book.registrations(240, 300);
    assert_eq!(last.len(), 1);
    if let Tx::RegisterBatch { batch, .. } = &last[0] { assert_eq!((batch.start, batch.cheques.len()), (240, 16)); } else { panic!() }
}

/// The fair launch: the first year mines 10% of the supply, the rest follows Bitcoin's halvings, and the total
/// stays under 21 million coins.
#[test]
fn launch_year_is_ten_percent() {
    let p = Params::testnet();
    assert_eq!((p.block_reward(0), p.block_reward(1), p.block_reward(525_000)), (0, 4 * COIN, 4 * COIN));
    assert_eq!((p.block_reward(525_001), p.block_reward(525_000 + 2_100_000)), (4 * COIN + COIN / 2, 4 * COIN + COIN / 2));
    assert_eq!(p.block_reward(525_000 + 2_100_001), 2 * COIN + COIN / 4);
    let year1 = 525_000u64 * p.block_reward(1);
    assert_eq!(year1, 2_100_000 * COIN);
    assert!(p.max_supply() <= 21_000_000 * COIN && p.max_supply() > 20_999_999 * COIN);
    assert_eq!(year1 * 10, 21_000_000 * COIN);
    assert_eq!((p.next_halving(1), p.next_halving(525_000 + 2_100_000)), (525_000 + 2_100_001, 525_000 + 2_100_001));
    assert_eq!(p.next_halving(525_000 + 2_100_001), 525_000 + 4_200_001);
}

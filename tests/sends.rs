//! GET /sends/<number>: every completed cheque of an account, kept for its lifetime (mined rewards push sends out of
//! /history's last 50 events), through a snapshot, a restart and a reorg; and the wallet's already-paid check reads it,
//! so a payment made from one state dir is refused from another however much the account mined since.
mod walletfake;
use bitcheque::block::Chain;
use bitcheque::message::Message;
use bitcheque::net::{now, Node};
use bitcheque::params::Params;
use bitcheque::store::{Store, SNAP_EVERY};
use bitcheque::tx::{Payment, R};
use bitcheque::u256::U256;
use bitcheque::wallet::{mine_registration, Book, Domain};
use walletfake::*;

fn params() -> Params { Params { initial_bits: 0x207F_FFFF, min_bits: 0x207F_FFFF, reg_pow_target: U256::MAX.shr(4), launch_blocks: 0, reward_maturity: 1, number_maturity: 1, ..Params::mainnet() } }
fn book(k: u8) -> Book { Book { salt: [k; 16], n256: false, book_size: 256, domains: vec![Domain([k + 6; 32])], net: Params::mainnet().magic } }

#[test]
fn sends_outlive_history_and_survive_snapshot_restart_and_reorg() {
    let p = params();
    let t0 = now() - 10_000_000;
    let g = Chain::genesis(&p, t0, b"sends test");
    let path = std::env::temp_dir().join(format!("bitcheque-sends-{}.dat", std::process::id()));
    let _ = std::fs::remove_file(&path); let _ = std::fs::remove_file(path.with_extension("snap"));
    let (payer, payee) = (book(1), book(2));
    let mut maker = Chain::new(p.clone(), &g).unwrap();
    let blk = |maker: &mut Chain, to: u32, txs: Vec<bitcheque::tx::Tx>| { let b = maker.make_block(maker.headers.last().unwrap().time + 600, to, txs).unwrap(); maker.add(&b, now()).unwrap(); b };
    let mut st = Store::open(p.clone(), &g, Some(&path)).unwrap();
    let b = blk(&mut maker, 0, vec![]); st.accept(&b, now()).unwrap();
    for k in [&payer, &payee] { let reg = mine_registration(k.register(0, 16, Payment::Pow([0; 32], 0)), maker.tip(), p.reg_pow_target); let b = blk(&mut maker, 0, vec![reg]); st.accept(&b, now()).unwrap(); }
    // the payer (number 1) mines, pays 1.5 coins to number 2 just below the first disk snapshot, then mines on
    let paid_at = SNAP_EVERY - 10;
    while maker.height() < paid_at - 1 { let b = blk(&mut maker, 1, vec![]); st.accept(&b, now()).unwrap(); }
    let b = blk(&mut maker, 1, payer.sign(1, &Message::new(2, 1500, 5, 1))); st.accept(&b, now()).unwrap();
    let a = Node::new(st);
    let line = a.route("GET", "/history/1", "").unwrap().lines().find(|l| l.contains(" send ")).unwrap().to_string();
    assert_eq!(line, format!("{paid_at} send cheque=1 to=2 amount=150000000 fee=1000"));
    assert_eq!(a.route("GET", "/sends/1", ""), Ok(line.clone()), "/sends writes a send as /history does");
    assert_eq!(a.route("GET", "/sends/2", ""), Ok("none".into()), "receiving is no send");
    assert_eq!(a.route("GET", "/sends/99", ""), Err("no such number"));
    // a second payment above the snapshot, then 70 rewards push both out of /history; /sends keeps both, newest first
    while maker.height() < SNAP_EVERY + 9 { let b = blk(&mut maker, 1, vec![]); a.submit_block(&b, None).unwrap(); }
    let b = blk(&mut maker, 1, payer.sign(2, &Message::new(2, 1, 5, 1))); a.submit_block(&b, None).unwrap();
    let both = format!("{} send cheque=2 to=2 amount=100000 fee=1000\n{line}", SNAP_EVERY + 10);
    for _ in 0..70 { let b = blk(&mut maker, 1, vec![]); a.submit_block(&b, None).unwrap(); }
    assert!(!a.route("GET", "/history/1", "").unwrap().contains(" send "), "70 rewards pushed the sends out of /history");
    assert_eq!(a.route("GET", "/sends/1", ""), Ok(both.clone()), "but /sends keeps them");
    // the index round-trips through a snapshot's bytes; a restart from the snapshot at SNAP_EVERY (cheque 1 is below
    // it: only the snapshot holds it) keeps it
    { let s = a.store.lock().unwrap(); let mut c = Chain::new(p.clone(), &g).unwrap(); c.decode_index(&mut R::new(&s.chain.encode_index())).unwrap(); assert_eq!(c.sends, s.chain.sends); }
    drop(a);
    assert!(path.with_extension("snap").exists());
    let a = Node::new(Store::open(p.clone(), &g, Some(&path)).unwrap());
    assert_eq!(a.height(), maker.height());
    assert_eq!(a.route("GET", "/sends/1", ""), Ok(both.clone()), "after a restart");
    // a reorg onto a heavier branch forked below cheque 2 (rebuilt from the snapshot): cheque 2 is gone, cheque 1 stays
    let mut alt = Chain::new(p.clone(), &g).unwrap();
    { let s = a.store.lock().unwrap(); for h in 1..=SNAP_EVERY as usize + 9 { alt.add(&s.chain.blocks.get(h).unwrap(), now()).unwrap(); } }
    for _ in 0..80 { let b = alt.make_block(alt.headers.last().unwrap().time + 601, 1, vec![]).unwrap(); alt.add(&b, now()).unwrap(); let _ = a.submit_block(&b, None); }
    assert_eq!(a.store.lock().unwrap().chain.tip(), alt.tip(), "reorged onto the heavier branch");
    assert_eq!(a.route("GET", "/sends/1", ""), Ok(line), "the abandoned payment is no send");
    let _ = std::fs::remove_file(&path); let _ = std::fs::remove_file(path.with_extension("snap"));
}

fn two(f: &Fake) -> [String; 2] { [f.addr.clone(), f.addr.replace("127.0.0.1", "[::ffff:127.0.0.1]")] }
fn wallet2(h: &std::path::Path, f: &Fake, args: &[&str]) -> (bool, String) { let r = two(f); wallet_rpcs(h, &[&r[0], &r[1]], args) }

/// The finding: an account that mines pushed its sends out of /history (its last 50 events), so a second state dir saw
/// no earlier payment and paid it again. The wallet reads /sends, which lists every one: refused.
#[test]
fn a_payment_mined_out_of_history_is_still_refused() {
    let (h1, h2) = (home("sends-dirA"), home("sends-dirB"));
    let f = fake(reply("none", &first16()));
    let to = num(7);
    assert!(wallet(&h1, &f, &["send", "--to", &to, "--amount", "1.5", "--fresh"]).1.contains("cheque 1 sent"));
    let (ok, out) = wallet2(&h2, &f, &["send", "--to", &to, "--amount", "1.5"]);
    assert!(!ok && out.contains("payment already made (cheque 1)") && out.contains("--again"), "{out}");
    assert_eq!(cheques(&f), vec![1]);
}

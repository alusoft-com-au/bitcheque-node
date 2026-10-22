//! Audit 6 hardening: account proofs come from a tree built once per tip (shared by every /proof at that tip) and must
//! match the uncached proof and verify against the tip's state root at every height; the easiest target of a network is
//! compared as a target, not as a compact integer.
mod common;
use common::{mine, tip};
use bitcheque::block::Chain;
use bitcheque::net::{now, Node};
use bitcheque::params::Params;
use bitcheque::rpc::unhex;
use bitcheque::state::verify_account_proof;
use bitcheque::store::Store;
use bitcheque::tx::Payment;
use bitcheque::u256::U256;
use bitcheque::wallet::{mine_registration, Book, Domain};

fn params() -> Params { Params { initial_bits: 0x207F_FFFF, min_bits: 0x207F_FFFF, reg_pow_target: U256::MAX.shr(4), launch_blocks: 0, reward_maturity: 1, number_maturity: 1, ..Params::mainnet() } }
fn book(k: u8) -> Book { Book { salt: [k; 16], n256: false, book_size: 256, domains: vec![Domain([k; 32])], net: Params::mainnet().magic } }

#[test]
fn proofs_from_the_cached_tree_verify_at_every_tip() {
    let p = params();
    let g = Chain::genesis(&p, now() - 100_000, b"proofs");
    let n = Node::new(Store::open(p.clone(), &g, None).unwrap());
    mine(&n, 0).unwrap();   // block 0 is no registration anchor
    for k in 1..=5u8 { n.submit_tx(mine_registration(book(k).register(0, 16, Payment::Pow([0; 32], 0)), tip(&n), p.reg_pow_target), None).unwrap(); }
    mine(&n, 0).unwrap();   // numbers 1-5 assigned, final from the next block
    mine(&n, 0).unwrap();
    for round in 0..4 {
        let (root, ids) = { let st = n.store.lock().unwrap(); (st.chain.headers.last().unwrap().state_root, st.chain.state.accounts.keys().cloned().collect::<Vec<_>>()) };
        // the same tip asked for every account: the first call builds the tree, the rest reuse it
        for (pos, id) in ids.iter().enumerate() {
            let num = n.store.lock().unwrap().chain.state.accounts[id].number;
            let text = n.route("GET", &format!("/proof/{num}"), "").unwrap();
            let field = |k: &str| text.lines().find_map(|l| l.strip_prefix(k)).unwrap().trim().to_string();
            let sr: [u8; 32] = unhex(&field("state_root ")).unwrap().try_into().unwrap();
            let leaf: [u8; 32] = unhex(&field("leaf ")).unwrap().try_into().unwrap();
            let path: Vec<[u8; 32]> = field("path ").split(' ').map(|x| unhex(x).unwrap().try_into().unwrap()).collect();
            assert_eq!(sr, root, "round {round}: the proof names the tip's state root");
            assert!(verify_account_proof(&root, &leaf, &path, pos), "round {round}, account {pos}: the proof verifies");
            assert_eq!(n.store.lock().unwrap().chain.state.account_proof(id).unwrap(), (leaf, path, sr), "round {round}: the cached proof is the uncached one");
            let cached = n.proof_cache.lock().unwrap().as_ref().map(|c| c.0);
            assert_eq!(cached, Some(tip(&n)), "the cache holds this tip's tree");
        }
        // a block changes the state (a reward to 1, a cheque from 2 to 3): the cache must follow the tip
        if round % 2 == 0 { n.submit_tx(book(2).open_all(1 + round as u16, &bitcheque::message::Message::new(3, 0, 0, 0).digits()), None).unwrap(); }
        mine(&n, 1).unwrap();
        assert_ne!(n.proof_cache.lock().unwrap().as_ref().map(|c| c.0), Some(tip(&n)), "the old tree is not the new tip's");
    }
    // unknown and not-final numbers get no proof at all
    assert_eq!(n.route("GET", "/proof/99", ""), Err("no such number"));
    assert_eq!(n.route("GET", "/proof/0", ""), Err("no such number"));
}

#[test]
fn the_easiest_target_is_compared_as_a_target() {
    // every configured network: the same answer as before (the compact encodings happen to be ordered)
    for p in [Params::mainnet(), Params::testnet(), Params::local()] {
        assert_eq!(p.easiest_target(), U256::from_compact(p.min_bits.max(p.initial_bits)));
    }
    // a floor with a larger exponent but a tiny mantissa is the harder target although it is the larger integer
    let p = Params { min_bits: 0x1F00_0001, initial_bits: 0x1E7F_FFFF, ..Params::mainnet() };
    assert_eq!(p.easiest_target(), U256::from_compact(0x1E7F_FFFF));
    assert_ne!(p.easiest_target(), U256::from_compact(p.min_bits.max(p.initial_bits)), "the integer comparison would pick the harder one");
    // a block claiming an easier target than any the network allows is refused at once, whatever the encoding
    let q = params();
    let g = Chain::genesis(&q, now() - 100_000, b"bits");
    let mut s = Store::open(q.clone(), &g, None).unwrap();
    let mut c = Chain::new(q.clone(), &g).unwrap();
    let mut b = c.make_block(g.header.time + 600, 0, vec![]).unwrap();
    b.header.bits = 0x2100_FFFF;   // 0xFFFF << 240, easier than the floor 0x7FFFFF << 232 (and than 0x2100_0100 = 2^248, which is harder)
    assert_eq!(s.accept(&b, now()).err(), Some("bits"));
    b.header.bits = q.min_bits; b.header.nonce = 0; b.header.mine();
    assert!(s.accept(&b, now()).is_ok()); c.add(&b, now()).unwrap();
}

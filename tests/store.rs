//! Reorg to the heavier branch, persistence across restart, account proofs, and the RPC.
mod common;
use common::mine;
use std::io::{Read, Write};
use std::net::TcpStream;
use bitcheque::block::Chain;
use bitcheque::message::Message;
use bitcheque::net::{now, Node};
use bitcheque::params::Params;
use bitcheque::state::verify_account_proof;
use bitcheque::store::{Accepted, Store};
use bitcheque::tx::Payment;
use bitcheque::u256::U256;
use bitcheque::wallet::{mine_registration, Book, Domain};

fn params() -> Params { Params { initial_bits: 0x207F_FFFF, min_bits: 0x207F_FFFF, reg_pow_target: U256::MAX.shr(4), launch_blocks: 0, reward_maturity: 1, number_maturity: 1, ..Params::mainnet() } }
fn miner() -> Book { Book { salt: [1; 16], n256: false, book_size: 16, domains: vec![Domain([7; 32])] } }

#[test]
fn reorg_and_persist() {
    let p = params();
    let g = Chain::genesis(&p, now() - 100_000, b"store test");
    let path = std::env::temp_dir().join(format!("bitcheque-test-{}.dat", std::process::id()));
    let _ = std::fs::remove_file(&path);

    // branch A: 2 blocks with a registration; branch B: 3 blocks, no txs
    let a = Node::new(Store::open(p.clone(), &g, Some(&path)).unwrap());
    a.submit_tx(mine_registration(miner().register(0, 16, Payment::Pow(0)), p.reg_pow_target), None).unwrap();
    mine(&a, 1).unwrap();
    mine(&a, 1).unwrap();
    let mut b = Store::open(p.clone(), &g, None).unwrap();
    let mut bc = Chain::new(p.clone(), &g).unwrap();
    for i in 0..3 { let blk = bc.make_block(g.header.time + 600 * (i + 1), 0, vec![]).unwrap(); bc.add(&blk, now()).unwrap(); b.accept(&blk, now()).unwrap(); }

    // feed B's branch to A: first two are side blocks (equal or less work), the third reorgs
    let mut results = Vec::new();
    for h in 1..=b.chain.height() as usize { let blk = b.chain.blocks.get(h).unwrap(); results.push(matches!(a.submit_block(&blk, None), Ok(()))); }
    assert_eq!(results, vec![true, true, true]);
    assert_eq!(a.store.lock().unwrap().chain.tip(), b.chain.tip());
    assert_eq!(a.height(), 3);
    // the abandoned registration went back to the mempool and the account no longer exists
    assert_eq!(a.mempool.lock().unwrap().len(), 1);
    assert!(a.store.lock().unwrap().chain.state.accounts.is_empty());
    // mine it again on the new branch
    mine(&a, 0).unwrap();
    assert_eq!(a.store.lock().unwrap().chain.state.accounts[&miner().id()].number, 1);
    let tip = a.store.lock().unwrap().chain.tip();
    drop(a);

    // restart from the file: same tip, same height, side blocks remembered
    let s = Store::open(p.clone(), &g, Some(&path)).unwrap();
    assert_eq!((s.chain.height(), s.chain.tip(), s.side.len()), (4, tip, 2));
    let _ = std::fs::remove_file(&path);

    // a side block with less work is kept but does not switch the chain
    let mut s = s;
    let lone = Chain::new(p.clone(), &g).unwrap().make_block(g.header.time + 601, 0, vec![]).unwrap();
    assert!(matches!(s.accept(&lone, now()), Ok(Accepted::Side)));
    assert_eq!(s.chain.height(), 4);
}

#[test]
fn proof_and_rpc() {
    let p = params();
    let g = Chain::genesis(&p, now() - 100_000, b"rpc test");
    let n = Node::new(Store::open(p.clone(), &g, None).unwrap());
    let m = miner();
    n.submit_tx(mine_registration(m.register(0, 16, Payment::Pow(0)), p.reg_pow_target), None).unwrap();
    mine(&n, 1).unwrap();
    mine(&n, 1).unwrap(); // reward credited
    // Merkle proof of the miner's account against the state root
    let st = n.store.lock().unwrap();
    let (leaf, path) = st.chain.state.account_proof(&m.id()).unwrap();
    assert!(verify_account_proof(&st.chain.state.root(), &leaf, &path, 0));
    assert_eq!(st.chain.state.root(), st.chain.headers.last().unwrap().state_root);
    drop(st);

    let addr = n.serve_rpc("127.0.0.1:0").unwrap();
    let http = |req: String| { let mut s = TcpStream::connect(addr).unwrap(); s.write_all(req.as_bytes()).unwrap(); let mut r = String::new(); s.read_to_string(&mut r).unwrap(); r.split("\r\n\r\n").nth(1).unwrap().to_string() };
    assert_eq!(http("GET /height HTTP/1.0\r\n\r\n".into()), "2");
    assert!(http("GET /account/1 HTTP/1.0\r\n\r\n".into()).contains(&format!("balance {}", p.reward_base)));
    let tx = m.sign(0, &Message::new(0, 1000, 2, 1)); // cheque to number 0
    let body = bitcheque::crypto::hex(&tx[0].encode());
    assert_eq!(http(format!("POST /tx HTTP/1.0\r\nContent-Length: {}\r\n\r\n{}", body.len(), body)), "ok");
    assert_eq!(http(format!("POST /tx HTTP/1.0\r\nContent-Length: {}\r\n\r\n{}", body.len(), body)), "already in mempool");
    assert!(http("GET /nothing HTTP/1.0\r\n\r\n".into()).contains("unknown route"));
    // dry run: checks without storing anything
    let pieces = m.sign(1, &Message::new(0, 1000, 2, 1));
    let body2: String = pieces.iter().map(|p| bitcheque::crypto::hex(&p.encode())).collect::<Vec<_>>().join("\n");
    let res = http(format!("POST /check HTTP/1.0\r\nContent-Length: {}\r\n\r\n{}", body2.len(), body2));
    assert_eq!(res.lines().filter(|l| *l == "ok").count(), 18);
    let mut bad = m.sign(2, &Message::new(0, 1000, 2, 1));
    if let bitcheque::tx::Tx::ChequePiece { shares, .. } = &mut bad[3] { shares[0][0] ^= 1 }
    let body3: String = bad.iter().map(|p| bitcheque::crypto::hex(&p.encode())).collect::<Vec<_>>().join("\n");
    let res3 = http(format!("POST /check HTTP/1.0\r\nContent-Length: {}\r\n\r\n{}", body3.len(), body3));
    assert_eq!(res3.lines().nth(3), Some("no commitment matches"));
    assert!(http("GET /account/1 HTTP/1.0\r\n\r\n".into()).contains("nonce none"), "a dry run must not consume a cheque");
}

/// Snapshots: a long chain restarts from `<data>.snap` instead of replaying, a truncated last
/// record is ignored, a reorg past the snapshot rebuilds from it, and the state codec round-trips.
#[test]
fn snapshot_restart_and_reorg() {
    use bitcheque::store::SNAP_EVERY;
    use bitcheque::tx::R;
    let p = params();
    let t0 = now() - 10_000_000;
    let g = Chain::genesis(&p, t0, b"snap test");
    let path = std::env::temp_dir().join(format!("bitcheque-snap-{}.dat", std::process::id()));
    let snap = path.with_extension("snap");
    let _ = std::fs::remove_file(&path); let _ = std::fs::remove_file(&snap);
    let n = 2 * SNAP_EVERY + 100;
    // blocks are made with 600 s spacing by an in-memory chain and fed to the file-backed store
    let mut maker = Chain::new(p.clone(), &g).unwrap();
    let mut blk = |maker: &mut Chain, txs: Vec<bitcheque::tx::Tx>| { let b = maker.make_block(maker.headers.last().unwrap().time + 600, 1, txs).unwrap(); maker.add(&b, now()).unwrap(); b };
    {
        let mut st = Store::open(p.clone(), &g, Some(&path)).unwrap();
        let reg = mine_registration(miner().register(0, 16, Payment::Pow(0)), p.reg_pow_target);
        let b1 = { let b = maker.make_block(t0 + 600, 0, vec![reg]).unwrap(); maker.add(&b, now()).unwrap(); b };
        st.accept(&b1, now()).unwrap();
        for _ in 1..n { let b = blk(&mut maker, vec![]); st.accept(&b, now()).unwrap(); }
        let b = blk(&mut maker, vec![miner().sign(1, &Message::new(1, 5, 8, 1))[0].clone()]); // leaves an open cheque in the state
        st.accept(&b, now()).unwrap();
        assert_eq!(bitcheque::state::State::decode(&mut R::new(&st.chain.state.encode())).unwrap().root(), st.chain.state.root(), "state codec round-trips");
        assert_eq!(st.chain.height(), n + 1);
    }
    assert!(snap.exists(), "snapshot written");
    // a crash mid-write leaves a partial record: must not stop the node starting
    { let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap(); f.write_all(&[200, 0, 0, 0, 1, 2, 3]).unwrap(); }
    let b = Store::open(p.clone(), &g, Some(&path)).unwrap();
    assert_eq!(b.chain.height(), n + 1);
    assert_eq!(b.chain.tip(), maker.tip());
    assert_eq!(b.chain.state.root(), maker.state.root(), "state after restart from snapshot matches a full replay");
    assert!(b.chain.state.accounts[&miner().id()].open.is_some());
    // reorg at a fork above the snapshot: a heavier branch from height n-10
    let fork = n - 10;
    let mut alt = Chain::new(p.clone(), &g).unwrap();
    for h in 1..=fork as usize { alt.add(&b.chain.blocks.get(h).unwrap(), now()).unwrap(); }
    let a = Node::new(Store::open(p.clone(), &g, Some(&path)).unwrap());
    for _ in 0..20 { let bb = blk(&mut alt, vec![]); let _ = a.submit_block(&bb, None); }
    assert_eq!(a.store.lock().unwrap().chain.tip(), alt.tip(), "reorged onto the heavier branch");
    assert_eq!(a.height(), fork + 20);
    assert_eq!(a.store.lock().unwrap().chain.state.root(), alt.state.root(), "state rebuilt from the snapshot matches");
    let _ = std::fs::remove_file(&path); let _ = std::fs::remove_file(&snap);
}

// host-backed store (the edge node): blocks and snapshots live with the host, here in thread-locals
thread_local! {
    static DB: std::cell::RefCell<std::collections::HashMap<usize, Vec<u8>>> = Default::default();
    static SNAP: std::cell::RefCell<Option<Vec<u8>>> = Default::default();
}
fn host_get(h: usize) -> Option<Vec<u8>> { DB.with(|d| d.borrow().get(&h).cloned()) }
fn host_put(h: usize, b: &[u8]) { DB.with(|d| { d.borrow_mut().insert(h, b.to_vec()); }) }
fn host_snap(b: &[u8]) { SNAP.with(|s| *s.borrow_mut() = Some(b.to_vec())) }
fn host_io() -> bitcheque::block::HostBlocks { bitcheque::block::HostBlocks { get: host_get, put: host_put } }
/// Snapshot height and the stored headers up to it, as the edge node's host hands them over.
fn host_restore(snap: &[u8]) -> (u32, Vec<u8>) {
    let sh = u32::from_le_bytes(snap[4..8].try_into().unwrap());
    (sh, (1..=sh as usize).flat_map(|h| host_get(h).unwrap()[..112].to_vec()).collect())
}

/// The edge node's store: blocks kept by the host, a restart from the host's snapshot and headers,
/// a reorg below the snapshot rewriting the host's blocks, and a snapshot of an abandoned branch refused.
#[test]
fn host_store_restore_and_reorg() {
    let p = params();
    let t0 = now() - 10_000_000;
    let g = Chain::genesis(&p, t0, b"host test");
    let mut maker = Chain::new(p.clone(), &g).unwrap();
    let blk = |maker: &mut Chain| { let b = maker.make_block(maker.headers.last().unwrap().time + 600, 1, vec![]).unwrap(); maker.add(&b, now()).unwrap(); b };
    let mut st = Store::open_host(p.clone(), &g, host_io(), None, &[], 100, host_snap).unwrap();
    let reg = mine_registration(miner().register(0, 16, Payment::Pow(0)), p.reg_pow_target);
    let b1 = maker.make_block(t0 + 600, 0, vec![reg]).unwrap(); maker.add(&b1, now()).unwrap(); st.accept(&b1, now()).unwrap();
    for _ in 1..251 { let b = blk(&mut maker); st.accept(&b, now()).unwrap(); }
    assert_eq!(st.chain.height(), 251);
    assert_eq!(st.chain.blocks.get(7).unwrap(), maker.blocks.get(7).unwrap(), "blocks are read back from the host");
    let snap = SNAP.with(|s| s.borrow().clone()).expect("snapshot handed to the host");

    // restart: snapshot + headers, then the blocks stored above the snapshot
    let (sh, headers) = host_restore(&snap);
    assert_eq!(sh, 200);
    let mut r = Store::open_host(p.clone(), &g, host_io(), Some(&snap), &headers, 100, host_snap).unwrap();
    assert_eq!(r.chain.height(), 200, "restored at the snapshot, without replaying");
    for h in 201..=251 { r.accept(&host_get(h).map(|b| bitcheque::block::Block::decode(&b).unwrap()).unwrap(), now()).unwrap(); }
    assert_eq!(r.chain.tip(), maker.tip());
    assert_eq!(r.chain.state.root(), maker.state.root(), "state after a restart matches a full replay");

    // a heavier branch from height 150, below the snapshot
    let mut alt = Chain::new(p.clone(), &g).unwrap();
    for h in 1..=150 { alt.add(&maker.blocks.get(h).unwrap(), now()).unwrap(); }
    let a = Node::new(r);
    for _ in 0..110 { let b = alt.make_block(alt.headers.last().unwrap().time + 601, 1, vec![]).unwrap(); alt.add(&b, now()).unwrap(); let _ = a.submit_block(&b, None); }
    assert_eq!(a.store.lock().unwrap().chain.tip(), alt.tip(), "reorged onto the heavier branch");
    for h in [151, 200, 251, 260] { assert_eq!(host_get(h).unwrap(), alt.blocks.get(h).unwrap().encode(), "host block {h} follows the new branch"); }

    // the old snapshot (height 200 of the abandoned branch) must not be trusted with the new headers
    let new_headers: Vec<u8> = (1..=200).flat_map(|h| host_get(h).unwrap()[..112].to_vec()).collect();
    let stale = Store::open_host(p.clone(), &g, host_io(), Some(&snap), &new_headers, 100, host_snap).unwrap();
    assert_eq!(stale.chain.height(), 0, "a snapshot of another branch is ignored: replay from genesis");
    // the new branch's own snapshot restores
    let fresh = SNAP.with(|s| s.borrow().clone()).unwrap();
    let (sh2, h2) = host_restore(&fresh);
    let ok = Store::open_host(p.clone(), &g, host_io(), Some(&fresh), &h2, 100, host_snap).unwrap();
    assert_eq!((ok.chain.height(), ok.chain.tip()), (sh2, alt.hashes[sh2 as usize]));
}

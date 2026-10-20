//! The command-line wallet against a fake node RPC on 127.0.0.1 (tests/walletfake): one cheque number is never signed
//! twice, whatever the node says, and nothing is signed for a cheque the chain would refuse.
//! Every run gets its own temporary HOME; nothing touches ~/.config or the network.
mod walletfake;
use walletfake::*;

/// The audit's attack: the registration lands, its cheque 0 (honesty check) does not. A later sweep must not sign
/// cheque 0 again, or the two halves mix into "sweep everything to number 0", which pays the miner.
#[test]
fn register_records_cheque_0_and_a_sweep_never_reuses_it() {
    let h = home("w2-cheque0");
    let f = fake(reply("none", &first16()));
    f.set(|s| { s.lose = 1; s.registered = false; });   // the honesty check never reaches the chain: nonce stays none
    let (ok, out) = wallet(&h, &f, &["register"]);
    assert!(ok, "{out}");
    assert_eq!(cheques(&f), vec![0]);
    assert_eq!(record(&h).as_deref(), Some("0"));
    let (ok, out) = wallet(&h, &f, &["sweep", "--to", &num(2), "--fresh"]);
    assert!(ok, "{out}");
    assert_eq!(cheques(&f), vec![0, 1]);
    never_two_messages(&[&f]);
    // without the record (lost, or never written by an older wallet) cheque 0 is still never a payment
    let h2 = home("w2-cheque0b");
    let f2 = fake(reply("none", "0"));
    let (ok, out) = wallet(&h2, &f2, &["sweep", "--to", &num(2), "--fresh"]);
    assert!(!ok && out.contains("no unused cheques"), "{out}");
    assert!(f2.posts.lock().unwrap().is_empty());
}

/// A register run again after this machine signed real cheques does not send the honesty check again.
#[test]
fn register_again_after_cheques_does_not_resign_cheque_0() {
    let h = home("w2-reregister");
    let f = fake(reply("none", &first16()));
    f.set(|s| s.registered = false);
    assert!(wallet(&h, &f, &["register"]).0);
    assert!(wallet(&h, &f, &["send", "--to", &num(7), "--amount", "1", "--fresh"]).0);
    // run again on the registered book: nothing to do, and it says so (no "account exists" from the node)
    let (ok, out) = wallet(&h, &f, &["register"]);
    assert!(ok && out.contains("already registered"), "{out}");
    // a book whose registration landed but whose record is gone (another machine) does not send cheque 0 again
    f.set(|s| s.registered = false);
    let (ok, out) = wallet(&h, &f, &["register"]);
    assert!(ok && out.contains("not sent again"), "{out}");
    assert_eq!(cheques(&f), vec![0, 1]);
    never_two_messages(&[&f]);
}

/// Several runs at once (one slow node) each take their own cheque: the record is locked from reading to posting.
#[test]
fn concurrent_runs_take_different_cheques() {
    let h = home("w2-concurrent");
    let f = fake(Reply { delay: 300, ..reply("none", &first16()) });
    let runs: Vec<_> = (0..4).map(|i| {
        let (h, a) = (h.clone(), f.addr.clone());
        std::thread::spawn(move || {
            let seed = h.join("seed");
            run(Some(&h), &h, &["send", "--to", &num(10 + i), "--amount", "1", "--fresh", "--seed-file", seed.to_str().unwrap(), "--rpc", &a], &[])
        })
    }).collect();
    for r in runs { let (ok, out) = r.join().unwrap(); assert!(ok, "{out}"); }
    let mut c = cheques(&f);
    c.sort();
    assert_eq!(c, vec![1, 2, 3, 4]);
    assert_eq!(record(&h).as_deref(), Some("4"));
    never_two_messages(&[&f]);
}

/// No place for the record, or a record that cannot be read: fail before anything is signed.
#[test]
fn the_record_fails_hard() {
    let h = home("w2-record");
    let f = fake(reply("none", &first16()));
    let seed = h.join("seed");
    let s = seed.to_str().unwrap();
    let to = num(7);
    let (ok, out) = run(None, &h, &["send", "--to", &to, "--amount", "1", "--seed-file", s, "--rpc", &f.addr], &[]);
    assert!(!ok && out.contains("nowhere to keep"), "{out}");
    assert!(f.posts.lock().unwrap().is_empty());
    // --state-dir or BITCHEQUE_STATE stand in for HOME
    let st = h.join("state");
    let (ok, out) = run(None, &h, &["send", "--to", &to, "--amount", "1", "--fresh", "--seed-file", s, "--rpc", &f.addr, "--state-dir", st.to_str().unwrap()], &[]);
    assert!(ok, "{out}");
    let (ok, out) = run(None, &h, &["send", "--to", &to, "--amount", "2", "--seed-file", s, "--rpc", &f.addr], &[("BITCHEQUE_STATE", st.to_str().unwrap())]);
    assert!(ok, "{out}");
    assert_eq!(cheques(&f), vec![1, 2]);
    // an empty or garbled record is not "nothing used"
    let used = std::fs::read_dir(&st).unwrap().flatten().map(|e| e.path()).find(|p| p.file_name().unwrap().to_string_lossy().starts_with("used-") && p.extension().is_none()).unwrap();
    for bad in ["", "abc", "300", "-1"] {
        std::fs::write(&used, bad).unwrap();
        let (ok, out) = run(None, &h, &["sweep", "--to", &to, "--seed-file", s, "--rpc", &f.addr, "--state-dir", st.to_str().unwrap()], &[]);
        assert!(!ok && out.contains("not a cheque number"), "{bad:?}: {out}");
    }
    assert_eq!(cheques(&f), vec![1, 2]);
    never_two_messages(&[&f]);
}

/// A stale or lying node cannot pick the cheque: no far jumps (each burns the cheques below), nothing outside the book.
#[test]
fn a_hostile_node_cannot_steer_the_cheque() {
    let h = home("w2-hostile");
    let f = fake(reply("0", "254"));   // only cheque 254 left, it says
    let (ok, out) = wallet(&h, &f, &["sweep", "--to", &num(7), "--fresh"]);
    assert!(!ok && out.contains("burn cheques 1-253"), "{out}");
    assert!(f.posts.lock().unwrap().is_empty() && record(&h).is_none());
    let (ok, out) = wallet(&h, &f, &["sweep", "--to", &num(7), "--fresh", "--force-skip"]);
    assert!(ok && out.contains("burned forever"), "{out}");
    assert_eq!(cheques(&f), vec![254]);
    // the same jump hidden in the queue
    let h = home("w2-hostile2");
    let f = fake(Reply { queued: (1..=10).map(|i| i.to_string()).collect::<Vec<_>>().join(","), ..reply("none", &first16()) });
    let (ok, out) = wallet(&h, &f, &["sweep", "--to", &num(7), "--fresh"]);
    assert!(!ok && out.contains("burn cheques 1-10"), "{out}");
    // values outside the book
    for r in [reply("9999", &first16()), reply("none", "1,2,300"), Reply { book: "512", ..reply("none", &first16()) },
              Reply { open: "70000", ..reply("none", &first16()) }, Reply { queued: "x".into(), ..reply("none", &first16()) }] {
        let f = fake(r);
        let (ok, out) = wallet(&h, &f, &["sweep", "--to", &num(7), "--fresh"]);
        assert!(!ok && out.contains("try another node"), "{out}");
        assert!(f.posts.lock().unwrap().is_empty());
    }
    // a few skipped cheques are fine (a cheque of this book waiting elsewhere)
    let f = fake(Reply { queued: "1,2".into(), ..reply("none", &first16()) });
    assert!(wallet(&h, &f, &["sweep", "--to", &num(7), "--fresh"]).0);
    assert_eq!(cheques(&f), vec![3]);
}

/// With --rpc A,B the nodes must report the book alike, and every queued cheque on any of them is skipped.
#[test]
fn a_second_rpc_cross_checks_the_cheque() {
    let h = home("w2-two");
    let a = fake(reply("none", &first16()));
    let b = fake(Reply { queued: "3".into(), ..reply("2", &first16()) });
    a.relay_to(&b);
    let seed = h.join("seed");
    let (ok, out) = run(Some(&h), &h, &["sweep", "--to", &num(7), "--fresh", "--seed-file", seed.to_str().unwrap(), "--rpc", &format!("{},{}", a.addr, b.addr)], &[]);
    assert!(!ok && out.contains("disagree"), "{out}");
    assert!(a.posts.lock().unwrap().is_empty() && record(&h).is_none());
    a.set(|s| s.nonce = "2".into());
    let (ok, out) = run(Some(&h), &h, &["sweep", "--to", &num(7), "--fresh", "--seed-file", seed.to_str().unwrap(), "--rpc", &format!("{},{}", a.addr, b.addr)], &[]);
    assert!(ok, "{out}");
    assert_eq!(cheques(&a), vec![4]);
    assert!(b.posts.lock().unwrap().is_empty());   // the cheque goes to the first node only
}

/// Fee tiers above 9, or tier 0 (a zero cheque is a void), are refused up front, before anything is signed.
#[test]
fn invalid_fee_tiers_are_refused_before_signing() {
    let h = home("w2-fee");
    let f = fake(reply("none", &first16()));
    let to = num(7);
    for args in [&["send", "--to", &to, "--amount", "1", "--fee", "10"][..], &["send", "--to", &to, "--amount", "1", "--fee", "255"],
                 &["sweep", "--to", &to, "--fee", "12"], &["send", "--to", &to, "--amount", "1", "--fee", "0"], &["sweep", "--to", &to, "--fee", "0"]] {
        let (ok, out) = wallet(&h, &f, args);
        assert!(!ok && (out.contains("tier from 1 to 9") || out.contains("only for a void")), "{args:?}: {out}");
    }
    let (ok, out) = wallet(&h, &f, &["send", "--to", &num(7), "--amount", "0", "--fee", "0", "--fresh"]);   // a zero cheque is a void
    assert!(!ok && out.contains("wallet void"), "{out}");
    assert!(f.posts.lock().unwrap().is_empty() && record(&h).is_none());
    let (ok, out) = wallet(&h, &f, &["void", "--fresh"]);   // which goes free
    assert!(ok, "{out}");
    assert_eq!(cheques(&f), vec![1]);
}

/// The seed never on the command line, never in an error, and its file kept private.
#[test]
fn the_seed_stays_private() {
    let h = home("w2-seed");
    let f = fake(reply("none", &first16()));
    let seed = h.join("seed");
    set_mode(&seed, 0o644);
    let (ok, out) = wallet(&h, &f, &["info"]);
    assert!(!ok && out.contains("chmod 600") && !out.contains(SEED), "{out}");
    set_mode(&seed, 0o600);
    assert!(wallet(&h, &f, &["info"]).0);
    let (ok, out) = run(Some(&h), &h, &["info", "--seed", SEED, "--rpc", &f.addr], &[]);
    assert!(!ok && out.contains("--seed is gone") && !out.contains(SEED), "{out}");
    let (ok, out) = run(Some(&h), &h, &["info", "--rpc", &f.addr], &[("BITCHEQUE_SEED", &format!("{SEED}zz"))]);
    assert!(!ok && !out.contains(SEED), "{out}");
    let (ok, out) = run(Some(&h), &h, &["info", "--rpc", &f.addr], &[("BITCHEQUE_SEED", SEED)]);
    assert!(ok && !out.contains(SEED), "{out}");
}

//! Security audit 4, command-line wallet: no double pay of the same payment, the amount half only behind a confirmed
//! opening far from its expiry, and every node asked agreeing on every decision. Against the fake node RPC of
//! tests/walletfake; nothing touches ~/.config or the network.
mod walletfake;
use walletfake::*;

fn columns(f: &Fake, cheque: u16) -> Vec<u8> { let mut v: Vec<u8> = pieces(f).into_iter().filter(|p| p.0 == cheque).map(|p| p.1).collect(); v.sort(); v }

/// The reproduced double pay: the reply to the amount half is lost but the cheque completes; running the same send
/// again used to write the next cheque and pay again. It is refused now, and --again pays the same again on purpose.
#[test]
fn the_same_payment_is_never_made_twice_by_accident() {
    let h = home("w4-double");
    let f = fake(reply("none", &first16()));
    let to = num(7);
    let (ok, out) = wallet(&h, &f, &["send", "--to", &to, "--amount", "5", "--fresh"]);
    assert!(ok && out.contains("cheque 1 sent"), "{out}");
    let (ok, out) = wallet(&h, &f, &["send", "--fresh", "--to", &to, "--amount", "5"]);
    assert!(!ok && out.contains("payment already made (cheque 1)") && out.contains("--again"), "{out}");
    assert_eq!(cheques(&f), vec![1]);
    // the amount half's reply lost (it lands all the same): the rerun refuses, never cheque 3
    let to2 = num(8);
    f.set(|s| s.drop_piece_replies = 1);
    let (ok, out) = wallet(&h, &f, &["send", "--fresh", "--to", &to2, "--amount", "5"]);
    assert!(!ok && out.contains("cheque 2 may still be live"), "{out}");
    let (ok, out) = wallet(&h, &f, &["send", "--fresh", "--to", &to2, "--amount", "5"]);
    assert!(!ok && out.contains("payment already made (cheque 2)"), "{out}");
    assert_eq!(cheques(&f), vec![1, 2]);
    // on purpose
    let (ok, out) = wallet(&h, &f, &["send", "--fresh", "--to", &to2, "--amount", "5", "--again"]);
    assert!(ok && out.contains("cheque 3 sent"), "{out}");
    assert_eq!(cheques(&f), vec![1, 2, 3]);
    never_two_messages(&[&f]);
}

/// A send whose amount half went out but whose reply never came, still open on chain: the rerun finishes the same
/// cheque (it never writes the next one), and a void after a done void has nothing to do.
#[test]
fn an_open_payment_of_ours_is_resumed() {
    let h = home("w4-resume");
    let f = fake(reply("none", &first16()));
    f.set(|s| s.mine_below = 13);   // the amount pieces stay queued
    let to = num(7);
    let (ok, out) = wallet(&h, &f, &["send", "--to", &to, "--amount", "5", "--fresh", "--wait", "1"]);
    assert!(ok && out.contains("cheque 1 posted, not in a block"), "{out}");
    // mined once the run has looked at the account twice (it has seen cheque 1 open, not done)
    let (st, ids) = (f.st.clone(), f.st.lock().unwrap().ids);
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_millis(50));
        let mut s = st.lock().unwrap();
        if s.ids >= ids + 2 { s.mine_below = 18; s.mine(); break; }
    });
    let (ok, out) = wallet(&h, &f, &["send", "--fresh", "--to", &to, "--amount", "5"]);
    assert!(ok && out.contains("finishing it") && out.contains("cheque 1 sent"), "{out}");
    assert_eq!(columns(&f, 1), (0..18).collect::<Vec<u8>>(), "nothing sent twice");
    let (ok, out) = wallet(&h, &f, &["send", "--fresh", "--to", &to, "--amount", "5"]);
    assert!(!ok && out.contains("payment already made (cheque 1)"), "{out}");
    assert!(wallet(&h, &f, &["void", "--fresh"]).0);
    let (ok, out) = wallet(&h, &f, &["void", "--fresh"]);
    assert!(ok && out.contains("done already") && out.contains("cheque 2 sent"), "{out}");
    assert_eq!(cheques(&f), vec![1, 2]);
    assert_eq!(openings(&f).iter().map(|o| (o.0, o.1.len())).collect::<Vec<_>>(), vec![(1, 13), (2, 18)]);   // a void: one opening of all 18
}

/// The amount's 5 pieces wait until the opening is --confirmations blocks deep (3 by default) on every node.
#[test]
fn the_amount_waits_for_confirmations() {
    let h = home("w4-conf");
    let f = fake(reply("none", &first16()));
    f.set(|s| s.extra = 0);   // the opening is 1 block deep once mined, and stays so
    let to = num(7);
    let (ok, out) = wallet(&h, &f, &["send", "--to", &to, "--amount", "5", "--fresh", "--wait", "4"]);
    assert!(!ok && out.contains("cheque 1 is half sent") && out.contains("not 3 blocks deep"), "{out}");
    assert_eq!(columns(&f, 1), (0..13).collect::<Vec<u8>>(), "no amount piece before 3 confirmations");
    // two more blocks while it waits: then it goes on
    let st = f.st.clone();
    std::thread::spawn(move || { std::thread::sleep(std::time::Duration::from_secs(2)); st.lock().unwrap().extra = 2; });
    let (ok, out) = wallet(&h, &f, &["send", "--fresh", "--to", &to, "--amount", "5"]);
    assert!(ok && out.contains("finishing it") && out.contains("cheque 1 sent"), "{out}");
    assert_eq!(columns(&f, 1), (0..18).collect::<Vec<u8>>());
    // --confirmations 1 trusts a single block
    f.set(|s| s.extra = 0);
    let (ok, out) = wallet(&h, &f, &["send", "--fresh", "--to", &to, "--amount", "6", "--confirmations", "1"]);
    assert!(ok && out.contains("cheque 2 sent"), "{out}");
    let (ok, out) = wallet(&h, &f, &["send", "--fresh", "--to", &to, "--amount", "6", "--confirmations", "0", "--again"]);
    assert!(!ok && out.contains("--confirmations"), "{out}");
}

/// Never the amount half when the opening is near its expiry (it could land after the opening is gone): void instead.
#[test]
fn the_amount_is_not_sent_near_the_openings_expiry() {
    let h = home("w4-expiry");
    let f = fake(reply("none", &first16()));
    f.set(|s| s.lifetime = 50);   // expires 50 blocks after its opening; the node's tip is 5 past that
    let (ok, out) = wallet(&h, &f, &["send", "--to", &num(7), "--amount", "5", "--fresh"]);
    assert!(!ok && out.contains("expires in 45 blocks") && out.contains("wallet void"), "{out}");
    assert_eq!(columns(&f, 1), (0..13).collect::<Vec<u8>>());
    let (ok, out) = wallet(&h, &f, &["send", "--fresh", "--to", &num(7), "--amount", "5"]);
    assert!(!ok && out.contains("expires in"), "{out}");
    assert_eq!(columns(&f, 1), (0..13).collect::<Vec<u8>>());
    let (ok, out) = wallet(&h, &f, &["void", "--fresh"]);
    assert!(!ok && out.contains("may still be in flight"), "{out}");
    let (ok, out) = wallet_rpcs(&h, &[&f.addr, &f.addr.replace("127.0.0.1", "[::ffff:127.0.0.1]")], &["void"]);
    assert!(ok && out.contains("cheque 2 sent"), "{out}");
}

/// MEDIUM-4: with --rpc given more than once, choosing a number, releasing the amount and deciding done each need every
/// node to report the book alike; one node alone works, with a note.
#[test]
fn every_node_must_agree_on_every_decision() {
    let h = home("w4-multi");
    let to = num(7);
    let (a, b) = (fake(reply("none", &first16())), fake(reply("3", &first16())));
    let (ok, out) = wallet_rpcs(&h, &[&a.addr, &b.addr], &["send", "--to", &to, "--amount", "5"]);
    assert!(!ok && out.contains("disagree"), "{out}");
    assert!(a.posts.lock().unwrap().is_empty() && record(&h).is_none());
    // they agree on the book, but the second node never sees the opening: the amount is never released
    b.set(|s| s.nonce = "none".into());
    let (ok, out) = wallet_rpcs(&h, &[&a.addr, &b.addr], &["send", "--to", &to, "--amount", "5", "--wait", "4"]);
    assert!(!ok && out.contains("cheque 1 is half sent") && !out.contains("only one node"), "{out}");
    assert_eq!(columns(&a, 1), (0..13).collect::<Vec<u8>>());
    // once both show it the run goes on, and it is done only when both show it done
    a.relay_to(&b);
    b.set(|s| { s.chain = a.st.lock().unwrap().chain.clone(); s.digits = a.st.lock().unwrap().digits.clone(); s.nonce = "1".into(); s.open = "1".into();
                s.opened = a.st.lock().unwrap().opened.clone(); s.height = a.st.lock().unwrap().height; });
    let (ok, out) = wallet_rpcs(&h, &[&a.addr, &b.addr], &["send", "--to", &to, "--amount", "5"]);
    assert!(ok && out.contains("cheque 1 sent"), "{out}");
    // one node alone: never for a new cheque on its word only (audit 5), and with --fresh (this book signs here only), a note
    let (ok, out) = wallet(&h, &a, &["send", "--to", &to, "--amount", "6"]);
    assert!(!ok && out.contains("only one node was asked") && out.contains("--rpc A --rpc B"), "{out}");
    let (ok, out) = wallet(&h, &a, &["send", "--to", &to, "--amount", "6", "--fresh"]);
    assert!(ok && out.contains("only one node"), "{out}");
    never_two_messages(&[&a, &b]);
}

/// The record's digits are digits: anything else in it stops the wallet (it is never silently dropped).
#[test]
fn a_garbled_record_digit_is_refused() {
    let h = home("w4-record");
    let f = fake(reply("none", &first16()));
    assert!(wallet(&h, &f, &["send", "--to", &num(7), "--amount", "1", "--fresh"]).0);
    let dir = h.join(".config/bitcheque");
    let used = std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.path()).find(|p| p.file_name().unwrap().to_string_lossy().starts_with("used-") && p.extension().is_none()).unwrap();
    let good = std::fs::read_to_string(&used).unwrap();
    for bad in [good.replacen('0', "x", 1), good.replacen('0', "-0", 1), format!("{}0", good.trim())] {
        std::fs::write(&used, &bad).unwrap();
        let (ok, out) = wallet(&h, &f, &["send", "--fresh", "--to", &num(7), "--amount", "2"]);
        assert!(!ok && out.contains("not a cheque number"), "{bad:?}: {out}");
    }
    assert_eq!(cheques(&f), vec![1]);
}

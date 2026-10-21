//! Security audit 5, command-line wallet: "sent" only for a payment the account's history shows made, no second pay of
//! the same payment from another state dir, one node never believed while the record's cheque may be in flight, the
//! same checks when finishing a recorded cheque, and clearer words for pieces waiting, a race between two of the
//! user's own machines and the explorer's short numbers. Against the fake node RPC of tests/walletfake.
mod walletfake;
use bitcheque::message::Message;
use walletfake::*;

fn two(f: &Fake) -> [String; 2] { [f.addr.clone(), f.addr.replace("127.0.0.1", "[::ffff:127.0.0.1]")] }
fn wallet2(h: &std::path::Path, f: &Fake, args: &[&str]) -> (bool, String) { let r = two(f); wallet_rpcs(h, &[&r[0], &r[1]], args) }
fn record_file(h: &std::path::Path) -> std::path::PathBuf {
    std::fs::read_dir(h.join(".config/bitcheque")).unwrap().flatten().map(|e| e.path())
        .find(|p| p.file_name().unwrap().to_string_lossy().starts_with("used-") && p.extension().is_none()).unwrap()
}
fn text(d: &[u8; 18]) -> String { d.iter().map(|x| char::from(b'0' + x)).collect() }

/// C5 (c17): while the payment waits for its confirmations a void from another machine lands on the next number. The
/// cheque is over but never paid: the run says so and fails, it never prints "sent".
#[test]
fn an_overtaken_payment_is_not_reported_sent() {
    let h = home("w5-overtaken");
    let f = fake(reply("none", &first16()));
    f.set(|s| s.extra = 0);   // the opening never gets deep on its own
    let (st, ids) = (f.st.clone(), f.st.lock().unwrap().ids);
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_millis(50));
        let mut s = st.lock().unwrap();
        if s.ids >= ids + 4 && s.chain.contains_key(&1) { s.nonce = "2".into(); s.open = "none".into(); break; }
    });
    let (ok, out) = wallet(&h, &f, &["send", "--to", &num(7), "--amount", "5", "--fresh", "--wait", "20"]);
    assert!(!ok && !out.contains("sent:") && out.contains("cheque 1 closed without paying 7") && out.contains("cheque 2 went into a block after it"), "{out}");
    assert_eq!(columns(&f, 1), (0..13).collect::<Vec<u8>>(), "no amount piece");
    // run again: the record's cheque closed unpaid, so the same payment needs --again, and then goes on cheque 3
    let r = wallet(&h, &f, &["send", "--fresh", "--to", &num(7), "--amount", "5"]);
    assert!(!r.0 && r.1.contains("not in the account's recent history") && r.1.contains("--again"), "{}", r.1);
    f.set(|s| s.extra = 5);
    let r = wallet2(&h, &f, &["send", "--to", &num(7), "--amount", "5", "--again"]);
    assert!(r.0 && r.1.contains("cheque 3 sent"), "{}", r.1);
}

/// C4 (c5, c5b): the same payment from a second state dir (a restored seed, another machine) is refused once the
/// account's history shows it made, or while it is open on chain; --again pays it again on purpose.
#[test]
fn the_same_payment_from_another_state_dir_is_refused() {
    let (h1, h2, h3) = (home("w5-dirA"), home("w5-dirB"), home("w5-dirC"));
    let f = fake(reply("none", &first16()));
    let to = num(7);
    assert!(wallet(&h1, &f, &["send", "--to", &to, "--amount", "5", "--fresh"]).1.contains("cheque 1 sent"));
    let (ok, out) = wallet2(&h2, &f, &["send", "--to", &to, "--amount", "5"]);
    assert!(!ok && out.contains("payment already made (cheque 1)") && out.contains("in block") && out.contains("--again"), "{out}");
    assert_eq!(cheques(&f), vec![1]);
    // another amount is another payment
    assert!(wallet2(&h2, &f, &["send", "--to", &to, "--amount", "6"]).1.contains("cheque 2 sent"));
    // still open on chain (its amount half not mined): refused from a third state dir too
    f.set(|s| s.mine_below = 13);
    let (ok, out) = wallet(&h1, &f, &["send", "--fresh", "--to", &to, "--amount", "7", "--wait", "1"]);
    assert!(ok && out.contains("cheque 3 posted, not in a block"), "{out}");
    let (ok, out) = wallet2(&h3, &f, &["send", "--to", &to, "--amount", "7"]);
    assert!(!ok && out.contains("cheque 3 is open on chain with this same payment"), "{out}");
    f.set(|s| { s.mine_below = 18; s.mine(); });
    let (ok, out) = wallet2(&h3, &f, &["send", "--to", &to, "--amount", "7"]);
    assert!(!ok && out.contains("payment already made (cheque 3)"), "{out}");
    let (ok, out) = wallet2(&h3, &f, &["send", "--to", &to, "--amount", "7", "--again"]);
    assert!(ok && out.contains("cheque 4 sent"), "{out}");
    never_two_messages(&[&f]);
}

/// a5-exploit run-fix.sh: one node could hide a cheque opened elsewhere, so no opening goes out on its word alone: a new
/// cheque needs a second node or --fresh (this book signs here only), and while the record's cheque is not in the
/// account's history as finished, neither a new cheque nor the record's own opening goes out on one node, --fresh or not.
#[test]
fn one_node_is_not_believed_while_the_records_cheque_may_be_in_flight() {
    let h = home("w5-onenode");
    let f = fake(reply("none", &first16()));
    assert!(wallet(&h, &f, &["send", "--to", &num(7), "--amount", "1", "--fresh"]).1.contains("cheque 1 sent"));
    // the history no longer lists cheque 1 (a node that will not say, or one that lies about the account)
    f.set(|s| s.history = Some(String::new()));
    let (ok, out) = wallet(&h, &f, &["send", "--fresh", "--to", &num(7), "--amount", "2"]);
    assert!(!ok && out.contains("cheque 1, the last this machine signed, may still be in flight") && out.contains("--rpc A --rpc B"), "{out}");
    assert_eq!(cheques(&f), vec![1], "no second opening");
    // two nodes that agree: on it goes (and "sent" needs the history again)
    f.set(|s| s.history = None);
    let (ok, out) = wallet2(&h, &f, &["send", "--to", &num(7), "--amount", "2"]);
    assert!(ok && out.contains("cheque 2 sent"), "{out}");
    // settled, but still one node: a new cheque only with --fresh, the holder's word that this book signs here only
    let (ok, out) = wallet(&h, &f, &["send", "--to", &num(7), "--amount", "3"]);
    assert!(!ok && out.contains("only one node was asked") && out.contains("--fresh"), "{out}");
    // the record's cheque recorded but its opening lost: finishing it on one node's word is refused too
    f.set(|s| s.lose = 1);
    let (ok, out) = wallet(&h, &f, &["send", "--fresh", "--to", &num(7), "--amount", "3", "--wait", "1"]);
    assert!(!ok && out.contains("cheque 3"), "{out}");
    let (ok, out) = wallet(&h, &f, &["send", "--fresh", "--to", &num(7), "--amount", "3"]);
    assert!(!ok && out.contains("cheque 3, the last this machine signed, may still be in flight"), "{out}");
    assert_eq!(openings(&f).len(), 3, "the lost one only");
    assert!(wallet2(&h, &f, &["send", "--to", &num(7), "--amount", "3"]).1.contains("cheque 3 sent"));
    never_two_messages(&[&f]);
}

/// C8 (c7 C7m): finishing a recorded cheque runs the recipient and balance checks too (the recipient here).
#[test]
fn finishing_a_recorded_cheque_runs_the_same_checks() {
    let h = home("w5-resume-checks");
    // recorded, then refused by the node's dry run: nothing posted
    let g = fake(reply("none", &first16()));
    g.set(|s| s.refuse = Some("busy".into()));
    let (ok, out) = wallet(&h, &g, &["send", "--to", &num(7), "--amount", "5", "--fresh"]);
    assert!(!ok && out.contains("refuses cheque 1: busy") && record(&h).as_deref() == Some("1"), "{out}");
    // the rerun, at nodes that do not know the recipient as a final number: refused before anything is posted
    let mut r = reply("none", &first16());
    r.acct = Some("id 00\nbalance 0\nfunded true".into());   // no "number 7"
    let f = fake(r);
    let (ok, out) = wallet2(&h, &f, &["send", "--to", &num(7), "--amount", "5"]);
    assert!(!ok && out.contains("finishing it") && out.contains("account 7 is not a final number"), "{out}");
    assert!(f.posts.lock().unwrap().is_empty(), "nothing posted");
    // where it is final, the same rerun finishes it
    let (ok, out) = wallet2(&h, &g, &["send", "--to", &num(7), "--amount", "5"]);
    assert!(!ok && out.contains("busy"), "{out}");
    g.set(|s| s.refuse = None);
    let (ok, out) = wallet2(&h, &g, &["send", "--to", &num(7), "--amount", "5"]);
    assert!(ok && out.contains("cheque 1 sent"), "{out}");
}

/// C3: the amount pieces went out but their reply was lost; a rerun while they wait to be mined says so.
#[test]
fn pieces_waiting_to_be_mined_are_waited_for() {
    let h = home("w5-waiting");
    let f = fake(reply("none", &first16()));
    f.set(|s| { s.drop_piece_replies = 1; s.mine_below = 13; });
    let (ok, out) = wallet(&h, &f, &["send", "--to", &num(7), "--amount", "5", "--fresh"]);
    assert!(!ok && out.contains("cheque 1 may still be live"), "{out}");
    let (ok, out) = wallet2(&h, &f, &["send", "--to", &num(7), "--amount", "5", "--wait", "1"]);
    assert!(!ok && out.contains("waiting for the pieces already sent to be mined") && !out.contains("not open"), "{out}");
    f.set(|s| { s.mine_below = 18; s.mine(); });
    let (ok, out) = wallet(&h, &f, &["send", "--fresh", "--to", &num(7), "--amount", "5"]);
    assert!(!ok && out.contains("payment already made (cheque 1)"), "{out}");
    assert_eq!(columns(&f, 1), (0..18).collect::<Vec<u8>>(), "each piece sent once");
}

/// Two of the user's machines race for one cheque: the loser is told another send from this seed took it (never that
/// someone holds a printed part), sends nothing on it, and once the winner is done its payment goes on a new cheque.
#[test]
fn a_race_between_two_of_our_machines_is_named_as_such() {
    let (h1, h2) = (home("w5-raceA"), home("w5-raceB"));
    let f = fake(reply("none", &first16()));
    f.set(|s| s.mine_below = 13);
    let (ok, out) = wallet(&h1, &f, &["send", "--to", &num(7), "--amount", "5", "--fresh", "--wait", "1"]);
    assert!(ok && out.contains("cheque 1 posted"), "{out}");
    // the other machine had picked cheque 1 too, for another payment
    let mine = record_file(&h1);
    let theirs = h2.join(".config/bitcheque").join(mine.file_name().unwrap());
    std::fs::create_dir_all(theirs.parent().unwrap()).unwrap();
    set_mode(theirs.parent().unwrap(), 0o700);
    std::fs::write(&theirs, format!("1 {}", text(&Message::new(8, 5000, 5, 1).digits()))).unwrap();
    let (ok, out) = wallet2(&h2, &f, &["send", "--to", &num(8), "--amount", "5"]);
    assert!(!ok && out.contains("cheque 1 was taken by another send from this seed") && out.contains("to 7") && !out.contains("printed part"), "{out}");
    assert_eq!(openings(&f).len(), 1);
    f.set(|s| { s.mine_below = 18; s.mine(); });
    let (ok, out) = wallet2(&h2, &f, &["send", "--to", &num(8), "--amount", "5"]);
    assert!(ok && out.contains("carried another payment") && out.contains("cheque 2 sent"), "{out}");
    never_two_messages(&[&f]);
}

/// W10b: --to takes the explorer's short form, the number without leading zeros and its check digit (over all 11).
#[test]
fn the_explorers_short_number_is_taken() {
    let h = home("w5-short");
    let f = fake(reply("none", &first16()));
    let short = format!("7-{}", num(7).rsplit('-').next().unwrap());
    let (ok, out) = wallet(&h, &f, &["send", "--to", &short, "--amount", "5", "--fresh"]);
    assert!(ok && out.contains("cheque 1 sent") && out.contains("to 7,"), "{out}");
    let wrong = format!("7-{}", (num(7).rsplit('-').next().unwrap().parse::<u8>().unwrap() + 1) % 10);
    let (ok, out) = wallet(&h, &f, &["send", "--fresh", "--to", &wrong, "--amount", "5"]);
    assert!(!ok && out.contains("check digit does not match"), "{out}");
    let (ok, out) = wallet(&h, &f, &["send", "--fresh", "--to", "123456789012-3", "--amount", "5"]);
    assert!(!ok && out.contains("--to takes"), "{out}");
}

fn columns(f: &Fake, cheque: u16) -> Vec<u8> { let mut v: Vec<u8> = pieces(f).into_iter().filter(|p| p.0 == cheque).map(|p| p.1).collect(); v.sort(); v }

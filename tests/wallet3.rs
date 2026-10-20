//! Security audit 3, command-line wallet: the auditors' attacks (w1-w7) and the rules that close them, against the fake
//! node RPC of tests/walletfake. Nothing touches ~/.config or the network.
mod walletfake;
use walletfake::*;

fn digits_of(f: &Fake, cheque: u16) -> Vec<(u8, Vec<u8>)> {
    let mut v: Vec<_> = pieces(f).into_iter().filter(|p| p.0 == cheque).map(|p| (p.1, p.2[0].clone())).collect();
    v.sort();
    v
}
fn columns(f: &Fake, cheque: u16) -> Vec<u8> { digits_of(f, cheque).into_iter().map(|p| p.0).collect() }

/// W1: the node takes the pieces but the reply is lost. Running the same command again finishes the same cheque
/// (never a second one on the next number); a different payment is refused until the cheque is over or voided.
#[test]
fn w1_lost_reply_never_pays_twice() {
    let h = home("w3-w1");
    let f = fake(reply("none", &first16()));
    f.set(|s| s.drop_replies = 1);
    let to = num(7);
    let (ok, out) = wallet(&h, &f, &["send", "--to", &to, "--amount", "5", "--fresh"]);
    assert!(!ok && out.contains("cheque 1 may still be live"), "{out}");
    let (ok, out) = wallet(&h, &f, &["send", "--to", &to, "--amount", "6"]);
    assert!(!ok && out.contains("cheque 1 may still be live") && out.contains("wallet void"), "{out}");
    let (ok, out) = wallet(&h, &f, &["send", "--to", &to, "--amount", "5"]);
    assert!(ok && out.contains("finishing it") && out.contains("cheque 1 sent"), "{out}");
    assert_eq!(cheques(&f), vec![1]);
    assert_eq!(columns(&f, 1), (0..18).collect::<Vec<u8>>());   // each piece sent once
    never_two_messages(&[&f]);
    // now over: the next payment takes the next number
    assert!(wallet(&h, &f, &["send", "--to", &to, "--amount", "6"]).0);
    assert_eq!(cheques(&f), vec![1, 2]);
}

/// The failed-broadcast rule (§10.13): `wallet void` confirms a zero cheque to 0 on the next number, and waits for it.
#[test]
fn void_kills_a_live_cheque() {
    let h = home("w3-void");
    let f = fake(reply("none", &first16()));
    f.set(|s| s.drop_replies = 1);
    let to = num(7);
    assert!(!wallet(&h, &f, &["send", "--to", &to, "--amount", "5", "--fresh"]).0);
    // the void is not mined in time: it says so, and a payment is still refused
    f.set(|s| s.mining = false);
    let (ok, out) = wallet(&h, &f, &["void", "--wait", "1"]);
    assert!(!ok && out.contains("void cheque 2 posted but not in a block"), "{out}");
    let (ok, out) = wallet(&h, &f, &["send", "--to", &to, "--amount", "5"]);
    assert!(!ok && out.contains("cheque 2 may still be live"), "{out}");
    // void again: the same void (already with the node, so nothing is sent again), waited for until mined
    let st = f.st.clone();
    std::thread::spawn(move || { std::thread::sleep(std::time::Duration::from_secs(2)); let mut s = st.lock().unwrap(); s.mining = true; s.mine(); });
    let (ok, out) = wallet(&h, &f, &["void"]);
    assert!(ok && out.contains("finishing it") && out.contains("cheque 2 sent") && out.contains("voids"), "{out}");
    assert_eq!(digits_of(&f, 2).len(), 18);
    let (ok, out) = wallet(&h, &f, &["send", "--to", &to, "--amount", "5"]);
    assert!(ok, "{out}");
    assert_eq!(cheques(&f), vec![1, 2, 3]);
    never_two_messages(&[&f]);
}

/// M3: the 12 recipient pieces first, in a block before the 6 amount pieces go out; a half-sent cheque is finished
/// by running the same command again, with the same digits.
#[test]
fn recipient_half_first_then_amount() {
    let h = home("w3-half");
    let f = fake(reply("none", &first16()));
    f.set(|s| s.mining = false);
    let to = num(7);
    let (ok, out) = wallet(&h, &f, &["send", "--to", &to, "--amount", "5", "--fresh", "--wait", "1"]);
    assert!(!ok && out.contains("cheque 1 is half sent") && out.contains("run the same command again"), "{out}");
    assert_eq!(columns(&f, 1), (0..12).collect::<Vec<u8>>());
    let (ok, out) = wallet(&h, &f, &["send", "--to", &to, "--amount", "9"]);
    assert!(!ok && out.contains("may still be live"), "{out}");
    f.set(|s| { s.mining = true; s.mine(); });
    let (ok, out) = wallet(&h, &f, &["send", "--to", &to, "--amount", "5"]);
    assert!(ok && out.contains("cheque 1 sent"), "{out}");
    assert_eq!(columns(&f, 1), (0..18).collect::<Vec<u8>>());
    never_two_messages(&[&f]);
    // the amount half not in a block in time: "posted", not "sent"
    f.set(|s| s.mine_below = 12);
    let (ok, out) = wallet(&h, &f, &["send", "--to", &to, "--amount", "5", "--wait", "1"]);
    assert!(ok && out.contains("cheque 2 posted, not in a block"), "{out}");
}

/// W2: --to takes the number as printed, check digit included, and verifies it; 0 takes coins only with --burn.
#[test]
fn w2_recipient_check_digit_and_burn() {
    let h = home("w3-w2");
    let f = fake(reply("none", &first16()));
    let n = num(48213);
    assert!(wallet(&h, &f, &["send", "--to", &n, "--amount", "1", "--fresh"]).0);
    assert!(wallet(&h, &f, &["send", "--to", &n.replace('-', ""), "--amount", "1"]).0);
    let wrong = format!("{}{}", &n[..12], (n.as_bytes()[12] - b'0' + 1) % 10);
    let transposed = format!("00000048231-{}", &n[12..]);
    for bad in ["48213", "48231", &wrong, &transposed, "0000004821-35", "+0000004821-3", "000000482135x"] {
        let (ok, out) = wallet(&h, &f, &["send", "--to", bad, "--amount", "1"]);
        assert!(!ok && (out.contains("check digit") || out.contains("12-digit")), "{bad}: {out}");
    }
    let zero = num(0);
    let (ok, out) = wallet(&h, &f, &["send", "--to", &zero, "--amount", "100"]);
    assert!(!ok && out.contains("--burn"), "{out}");
    let (ok, out) = wallet(&h, &f, &["sweep", "--to", &zero]);
    assert!(!ok && out.contains("--burn"), "{out}");
    assert_eq!(cheques(&f), vec![1, 2]);
    let (ok, out) = wallet(&h, &f, &["send", "--to", &zero, "--amount", "1", "--burn"]);
    assert!(ok, "{out}");
    assert_eq!(cheques(&f), vec![1, 2, 3]);
}

/// W3 / M5: with no record, one node is not believed about the book's last cheque: two that agree, or --fresh.
#[test]
fn w3_no_record_needs_two_agreeing_nodes() {
    let to = num(7);
    let h = home("w3-w3a");
    let stale = fake(reply("none", &first16()));
    let (ok, out) = wallet(&h, &stale, &["sweep", "--to", &to]);
    assert!(!ok && out.contains("no record") && out.contains("--fresh"), "{out}");
    let honest = fake(Reply { open: "1", ..reply("0", &first16()) });
    let (ok, out) = wallet_at(&h, &format!("{},{}", stale.addr, honest.addr), &["sweep", "--to", &to]);
    assert!(!ok && out.contains("disagree"), "{out}");
    assert!(pieces(&stale).is_empty() && pieces(&honest).is_empty() && record(&h).is_none());
    // two that agree: the open cheque is skipped, never signed again
    let other = fake(Reply { open: "1", ..reply("0", &first16()) });
    honest.relay_to(&other);
    let (ok, out) = wallet_at(&h, &format!("{},{}", honest.addr, other.addr), &["sweep", "--to", &to]);
    assert!(ok, "{out}");
    assert_eq!(cheques(&honest), vec![2]);
}

/// W4 / M2: every node must know the recipient as final, and every node dry-runs each half before it is posted.
#[test]
fn w4_every_node_vouches_for_the_cheque() {
    let to = num(999999);
    let h = home("w3-w4");
    let liar = fake(Reply { acct: Some("number 999999\nfunded true".into()), ..reply("none", &first16()) });
    let honest = fake(Reply { acct: Some("pending\nready_at 50".into()), ..reply("none", &first16()) });
    let (ok, out) = wallet_at(&h, &format!("{},{}", liar.addr, honest.addr), &["send", "--to", &to, "--amount", "1"]);
    assert!(!ok && out.contains("not a final number"), "{out}");
    assert!(pieces(&liar).is_empty() && record(&h).is_none());
    // a node that refuses the dry run: nothing posted anywhere
    let a = fake(reply("none", &first16()));
    let b = fake(reply("none", &first16()));
    b.set(|s| s.refuse = Some("payee number unknown".into()));
    let (ok, out) = wallet_at(&h, &format!("{},{}", a.addr, b.addr), &["send", "--to", &num(7), "--amount", "1"]);
    assert!(!ok && out.contains("refuses cheque 1: payee number unknown") && out.contains("may still be live"), "{out}");
    assert!(pieces(&a).is_empty());
}

/// L6: paying an account that is not permanent yet warns that small balances there can be burned.
#[test]
fn paying_an_unfunded_account_warns() {
    let h = home("w3-l6");
    let f = fake(Reply { acct: Some("id 00\nnumber 7\nbalance 0\nfunded false".into()), ..reply("none", &first16()) });
    let (ok, out) = wallet(&h, &f, &["send", "--to", &num(7), "--amount", "0.5", "--fresh"]);
    assert!(ok && out.contains("not permanent yet"), "{out}");
}

/// W5 / L1: `pieces` records the number like any cheque: a send never reuses it, nor does `pieces` with other digits.
#[test]
fn w5_pieces_command_is_recorded() {
    let h = home("w3-w5");
    let f = fake(reply("none", &first16()));
    let seed = h.join("seed");
    let s = seed.to_str().unwrap();
    let (ok, out) = run(Some(&h), &h, &["pieces", "--seed-file", s, "--cheque", "1", "--digits", "000000000077999981"], &[]);
    assert!(ok && out.lines().count() == 18, "{out}");
    assert_eq!(record(&h).as_deref(), Some("1"));
    let (ok, out) = run(Some(&h), &h, &["pieces", "--seed-file", s, "--cheque", "1", "--digits", "000000000077999981"], &[]);
    assert!(ok, "{out}");   // the same digits again are harmless
    for (c, d) in [("1", "000000000077999982"), ("0", "000000000000000000")] {
        let (ok, out) = run(Some(&h), &h, &["pieces", "--seed-file", s, "--cheque", c, "--digits", d], &[]);
        assert!(!ok && out.contains("never signed with other digits"), "{out}");
    }
    let (ok, out) = wallet(&h, &f, &["send", "--to", &num(7), "--amount", "1"]);
    assert!(!ok && out.contains("cheque 1 may still be live"), "{out}");
    assert!(f.posts.lock().unwrap().is_empty());
}

/// W6 / L2: a registration target too hard to meet, or easier than the chain allows, is refused at once.
#[test]
fn w6_implausible_regtarget_is_refused() {
    for t in ["0000000000000000 0000000000000000 0000000000000000 0000000000000001", "ffffffffffffffff ffffffffffffffff ffffffffffffffff 00000000000000ff",
              "ffffffffffffffff ffffffffffffffff ffffffffffffffff ffffffffffffffff"] {
        let h = home("w3-w6");
        let f = fake(Reply { regtarget: t.into(), ..reply("none", &first16()) });
        let t0 = std::time::Instant::now();
        let (ok, out) = wallet(&h, &f, &["register"]);
        assert!(!ok && out.contains("registration target") && t0.elapsed().as_secs() < 5, "{out}");
        assert!(f.posts.lock().unwrap().is_empty());
    }
}

/// W7 / L3: `more` with a node claiming a cheque past any book does not wrap around to batch 0.
#[test]
fn w7_more_does_not_wrap() {
    let h = home("w3-w7");
    let f = fake(reply("4294967295", ""));
    let (ok, out) = wallet(&h, &f, &["more"]);
    assert!(!ok && out.contains("try another node"), "{out}");
    assert!(f.posts.lock().unwrap().is_empty());
}

/// L4 / L7: the record lives in an absolute directory that is this user's alone, and its files are never reached
/// through a symbolic link.
#[test]
fn the_record_directory_is_private_and_absolute() {
    let h = home("w3-l4");
    let f = fake(reply("none", &first16()));
    let seed = h.join("seed");
    let s = seed.to_str().unwrap();
    let to = num(7);
    let send = |extra: &[&str], env: &[(&str, &str)], home: Option<&std::path::Path>| {
        let mut a = vec!["send", "--to", &to, "--amount", "1", "--fresh", "--seed-file", s, "--rpc", &f.addr];
        a.extend(extra);
        run(home, &h, &a, env)
    };
    for (extra, env) in [(&["--state-dir", "state"][..], &[][..]), (&[], &[("HOME", "")]), (&[], &[("BITCHEQUE_STATE", "")]), (&[], &[("BITCHEQUE_STATE", "rel/dir")])] {
        let (ok, out) = send(extra, env, None);
        assert!(!ok && out.contains("absolute directory"), "{extra:?} {env:?}: {out}");
    }
    let open = h.join("open");
    std::fs::create_dir_all(&open).unwrap();
    set_mode(&open, 0o777);
    let (ok, out) = send(&["--state-dir", open.to_str().unwrap()], &[], None);
    assert!(!ok && out.contains("others can write"), "{out}");
    // a planted symbolic link in place of the lock file is refused, not followed
    let st = h.join("state");
    let (ok, out) = send(&["--state-dir", st.to_str().unwrap()], &[], None);
    assert!(ok, "{out}");
    let lock = std::fs::read_dir(&st).unwrap().flatten().map(|e| e.path()).find(|p| p.extension().is_some_and(|e| e == "lock")).unwrap();
    std::fs::remove_file(&lock).unwrap();
    std::os::unix::fs::symlink(h.join("elsewhere"), &lock).unwrap();
    let (ok, out) = send(&["--state-dir", st.to_str().unwrap()], &[], None);
    assert!(!ok && !h.join("elsewhere").exists(), "{out}");
    assert_eq!(cheques(&f), vec![1]);
}

/// INFO: amounts are digits and one point only; 10,000 coins and more are written with exponent 9.
#[test]
fn amounts_are_plain_digits() {
    let h = home("w3-amt");
    let f = fake(reply("none", &first16()));
    for bad in ["1.+5", "+1", "-1", "1e3", " 1", "1.000000001", "."] {
        let (ok, out) = wallet(&h, &f, &["send", "--to", &num(7), "--amount", bad, "--fresh"]);
        assert!(!ok && out.contains("amount"), "{bad}: {out}");
    }
    let (ok, out) = wallet(&h, &f, &["send", "--to", &num(7), "--amount", "20000", "--fresh"]);
    assert!(!ok && out.contains("balance"), "{out}");   // well formed (2000 e9), more than the fake holds
    assert!(f.posts.lock().unwrap().is_empty());
}

/// L5 / L7: the seed file is checked through the handle it is read from; `register` from standard input still works
/// (the operator's miner re-registration).
#[test]
fn register_reads_the_seed_from_standard_input() {
    let h = home("w3-stdin");
    let f = fake(reply("none", &first16()));
    let st = h.join("state");
    let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_bitcheque"));
    c.env_clear().args(["wallet", "register", "--seed-file", "-", "--rpc", &f.addr, "--state-dir", st.to_str().unwrap(), "--local"])
        .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    let mut child = c.spawn().unwrap();
    std::io::Write::write_all(child.stdin.as_mut().unwrap(), format!("{SEED}\n").as_bytes()).unwrap();
    let o = child.wait_with_output().unwrap();
    let out = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    assert!(o.status.success() && out.contains("honesty check (cheque 0) sent") && !out.contains(SEED), "{out}");
    assert_eq!(cheques(&f), vec![0]);
}

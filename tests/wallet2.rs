//! The command-line wallet against a fake node RPC on 127.0.0.1 (a tiny TcpListener in the test): one cheque number is
//! never signed twice, whatever the node says, and nothing is signed for a cheque the chain would refuse.
//! Every run gets its own temporary HOME; nothing touches ~/.config or the network.
use bitcheque::{rpc::unhex, tx::{Tx, R}};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

const SEED: &str = "5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed";

/// What the fake node answers: `/id/<id>` (after `delay` ms) and `/queued/<id>`. POST /tx bodies are kept.
#[derive(Clone)]
struct Reply { nonce: &'static str, open: &'static str, unspent: String, book: &'static str, queued: String, delay: u64 }
fn reply(nonce: &'static str, unspent: &str) -> Reply { Reply { nonce, open: "none", unspent: unspent.into(), book: "256", queued: String::new(), delay: 0 } }
fn first16() -> String { (0..16).map(|i| i.to_string()).collect::<Vec<_>>().join(",") }

struct Fake { addr: String, posts: Arc<Mutex<Vec<String>>> }
fn fake(r: Reply) -> Fake {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let posts = Arc::new(Mutex::new(Vec::new()));
    let p = posts.clone();
    std::thread::spawn(move || for s in l.incoming() {
        let (mut s, r, p) = (s.unwrap(), r.clone(), p.clone());
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let mut b = [0u8; 65536];
            let (head, body) = loop {
                let n = s.read(&mut b).unwrap_or(0);
                if n == 0 { return; }
                buf.extend_from_slice(&b[..n]);
                if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..i]).to_string();
                    let len: usize = head.lines().find_map(|l| l.strip_prefix("Content-Length: ")).and_then(|v| v.trim().parse().ok()).unwrap_or(0);
                    while buf.len() < i + 4 + len { let n = s.read(&mut b).unwrap_or(0); if n == 0 { break; } buf.extend_from_slice(&b[..n]); }
                    break (head, String::from_utf8_lossy(&buf[i + 4..]).to_string());
                }
            };
            let mut w = head.split_whitespace();
            let (method, path) = (w.next().unwrap_or("").to_string(), w.next().unwrap_or("").to_string());
            let text = if method == "POST" && path == "/tx" {
                p.lock().unwrap().push(body.clone());
                body.lines().filter(|l| !l.trim().is_empty()).map(|_| "ok").collect::<Vec<_>>().join("\n")
            } else if let Some(id) = path.strip_prefix("/id/") {
                std::thread::sleep(std::time::Duration::from_millis(r.delay));
                format!("id {id}\nnumber 5\nbalance 100000000000\npending 0\nnonce {}\nbook_size {}\nunspent {}\nfunded true\nmature true\nready_at 0\nopen {}", r.nonce, r.book, r.unspent, r.open)
            } else if let Some(n) = path.strip_prefix("/account/") { format!("id 00\nnumber {n}\nbalance 0") }
            else if path.starts_with("/queued/") { r.queued.clone() }
            else if path == "/regtarget" { vec!["ffffffffffffffff"; 4].join(" ") }
            else { String::new() };
            let _ = write!(s, "HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n{text}", text.len());
        });
    });
    Fake { addr, posts }
}

/// A fresh HOME with the seed file (0600) in it.
fn home(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("bitcheque-wallet2-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let f = d.join("seed");
    std::fs::write(&f, SEED).unwrap();
    set_mode(&f, 0o600);
    d
}
fn set_mode(f: &Path, mode: u32) { use std::os::unix::fs::PermissionsExt; std::fs::set_permissions(f, std::fs::Permissions::from_mode(mode)).unwrap(); }

/// Runs `bitcheque wallet <args>` with only HOME set (unless `home` is None); returns success and stdout+stderr.
fn run(home: Option<&Path>, dir: &Path, args: &[&str], env: &[(&str, &str)]) -> (bool, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_bitcheque"));
    c.env_clear().arg("wallet").args(args).current_dir(dir);
    if let Some(h) = home { c.env("HOME", h); }
    for (k, v) in env { c.env(k, v); }
    let o = c.output().unwrap();
    (o.status.success(), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
}
fn wallet(h: &Path, f: &Fake, args: &[&str]) -> (bool, String) {
    let seed = h.join("seed");
    let mut a = args.to_vec();
    a.extend(["--seed-file", seed.to_str().unwrap(), "--rpc", &f.addr]);
    run(Some(h), h, &a, &[])
}

/// Every cheque piece posted to the fake: (cheque, column) -> the cells sent for it.
fn pieces(f: &Fake) -> Vec<(u16, u8, Vec<Vec<u8>>)> {
    f.posts.lock().unwrap().iter().flat_map(|b| b.lines().map(|l| l.to_string()).collect::<Vec<_>>()).filter_map(|l| {
        let raw = unhex(l.trim())?;
        match Tx::decode(&mut R::new(&raw)).ok()? { Tx::ChequePiece { cheque, column, shares, .. } => Some((cheque, column, shares)), _ => None }
    }).collect()
}
fn cheques(f: &Fake) -> Vec<u16> { let mut c: Vec<u16> = pieces(f).iter().map(|p| p.0).collect(); c.dedup(); c }
/// The one-time rule itself: no (cheque, column) was ever sent with two different cells (two different digits).
fn never_two_messages(fakes: &[&Fake]) {
    let mut seen: BTreeMap<(u16, u8), Vec<Vec<u8>>> = BTreeMap::new();
    for f in fakes { for (c, col, sh) in pieces(f) {
        let e = seen.entry((c, col)).or_insert_with(|| sh.clone());
        assert_eq!(*e, sh, "cheque {c} column {col} signed with two different digits");
    } }
}
fn record(h: &Path) -> Option<String> {
    std::fs::read_dir(h.join(".config/bitcheque")).ok()?.flatten()
        .find(|e| e.file_name().to_string_lossy().starts_with("used-") && !e.file_name().to_string_lossy().contains('.'))
        .map(|e| std::fs::read_to_string(e.path()).unwrap())
}

/// The audit's attack: the registration lands, its cheque 0 (honesty check) does not. A later sweep must not sign
/// cheque 0 again, or the two halves mix into "sweep everything to number 0", which pays the miner.
#[test]
fn register_records_cheque_0_and_a_sweep_never_reuses_it() {
    let h = home("cheque0");
    let f = fake(reply("none", &first16()));   // the honesty check never reaches the chain: nonce stays none
    let (ok, out) = wallet(&h, &f, &["register"]);
    assert!(ok, "{out}");
    assert_eq!(cheques(&f), vec![0]);
    assert_eq!(record(&h).as_deref(), Some("0"));
    let (ok, out) = wallet(&h, &f, &["sweep", "--to", "2"]);
    assert!(ok, "{out}");
    assert_eq!(cheques(&f), vec![0, 1]);
    never_two_messages(&[&f]);
    // without the record (lost, or never written by an older wallet) cheque 0 is still never a payment
    let h2 = home("cheque0b");
    let f2 = fake(reply("none", "0"));
    let (ok, out) = wallet(&h2, &f2, &["sweep", "--to", "2"]);
    assert!(!ok && out.contains("no unused cheques"), "{out}");
    assert!(f2.posts.lock().unwrap().is_empty());
}

/// A register run again after this machine signed real cheques does not send the honesty check again.
#[test]
fn register_again_after_cheques_does_not_resign_cheque_0() {
    let h = home("reregister");
    let f = fake(reply("none", &first16()));
    assert!(wallet(&h, &f, &["register"]).0);
    assert!(wallet(&h, &f, &["send", "--to", "7", "--amount", "1"]).0);
    let (ok, out) = wallet(&h, &f, &["register"]);
    assert!(ok && out.contains("not sent again"), "{out}");
    assert_eq!(cheques(&f), vec![0, 1]);
    never_two_messages(&[&f]);
}

/// Several runs at once (one slow node) each take their own cheque: the record is locked from reading to posting.
#[test]
fn concurrent_runs_take_different_cheques() {
    let h = home("concurrent");
    let f = fake(Reply { delay: 300, ..reply("none", &first16()) });
    let runs: Vec<_> = (0..4).map(|i| {
        let (h, a) = (h.clone(), f.addr.clone());
        std::thread::spawn(move || {
            let seed = h.join("seed");
            run(Some(&h), &h, &["send", "--to", &(10 + i).to_string(), "--amount", "1", "--seed-file", seed.to_str().unwrap(), "--rpc", &a], &[])
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
    let h = home("record");
    let f = fake(reply("none", &first16()));
    let seed = h.join("seed");
    let s = seed.to_str().unwrap();
    let (ok, out) = run(None, &h, &["send", "--to", "7", "--amount", "1", "--seed-file", s, "--rpc", &f.addr], &[]);
    assert!(!ok && out.contains("nowhere to keep"), "{out}");
    assert!(f.posts.lock().unwrap().is_empty());
    // --state-dir or BITCHEQUE_STATE stand in for HOME
    let st = h.join("state");
    let (ok, out) = run(None, &h, &["send", "--to", "7", "--amount", "1", "--seed-file", s, "--rpc", &f.addr, "--state-dir", st.to_str().unwrap()], &[]);
    assert!(ok, "{out}");
    let (ok, out) = run(None, &h, &["send", "--to", "7", "--amount", "1", "--seed-file", s, "--rpc", &f.addr], &[("BITCHEQUE_STATE", st.to_str().unwrap())]);
    assert!(ok, "{out}");
    assert_eq!(cheques(&f), vec![1, 2]);
    // an empty or garbled record is not "nothing used"
    let used = std::fs::read_dir(&st).unwrap().flatten().map(|e| e.path()).find(|p| p.file_name().unwrap().to_string_lossy().starts_with("used-") && p.extension().is_none()).unwrap();
    for bad in ["", "abc", "300", "-1"] {
        std::fs::write(&used, bad).unwrap();
        let (ok, out) = run(None, &h, &["sweep", "--to", "7", "--seed-file", s, "--rpc", &f.addr, "--state-dir", st.to_str().unwrap()], &[]);
        assert!(!ok && out.contains("not a cheque number"), "{bad:?}: {out}");
    }
    assert_eq!(cheques(&f), vec![1, 2]);
    never_two_messages(&[&f]);
}

/// A stale or lying node cannot pick the cheque: no far jumps (each burns the cheques below), nothing outside the book.
#[test]
fn a_hostile_node_cannot_steer_the_cheque() {
    let h = home("hostile");
    let f = fake(reply("0", "254"));   // only cheque 254 left, it says
    let (ok, out) = wallet(&h, &f, &["sweep", "--to", "7"]);
    assert!(!ok && out.contains("burn cheques 1-253"), "{out}");
    assert!(f.posts.lock().unwrap().is_empty() && record(&h).is_none());
    let (ok, out) = wallet(&h, &f, &["sweep", "--to", "7", "--force-skip"]);
    assert!(ok && out.contains("burned forever"), "{out}");
    assert_eq!(cheques(&f), vec![254]);
    // the same jump hidden in the queue
    let h = home("hostile2");
    let f = fake(Reply { queued: (1..=10).map(|i| i.to_string()).collect::<Vec<_>>().join(","), ..reply("none", &first16()) });
    let (ok, out) = wallet(&h, &f, &["sweep", "--to", "7"]);
    assert!(!ok && out.contains("burn cheques 1-10"), "{out}");
    // values outside the book
    for r in [reply("9999", &first16()), reply("none", "1,2,300"), Reply { book: "512", ..reply("none", &first16()) },
              Reply { open: "70000", ..reply("none", &first16()) }, Reply { queued: "x".into(), ..reply("none", &first16()) }] {
        let f = fake(r);
        let (ok, out) = wallet(&h, &f, &["sweep", "--to", "7"]);
        assert!(!ok && out.contains("try another node"), "{out}");
        assert!(f.posts.lock().unwrap().is_empty());
    }
    // a few skipped cheques are fine (a cheque of this book waiting elsewhere)
    let f = fake(Reply { queued: "1,2".into(), ..reply("none", &first16()) });
    assert!(wallet(&h, &f, &["sweep", "--to", "7"]).0);
    assert_eq!(cheques(&f), vec![3]);
}

/// With --rpc A,B the most cautious answer wins: the highest nonce, every queued cheque.
#[test]
fn a_second_rpc_cross_checks_the_cheque() {
    let h = home("two");
    let a = fake(reply("none", &first16()));
    let b = fake(Reply { queued: "3".into(), ..reply("2", &first16()) });
    let seed = h.join("seed");
    let (ok, out) = run(Some(&h), &h, &["sweep", "--to", "7", "--seed-file", seed.to_str().unwrap(), "--rpc", &format!("{},{}", a.addr, b.addr)], &[]);
    assert!(ok, "{out}");
    assert_eq!(cheques(&a), vec![4]);
    assert!(b.posts.lock().unwrap().is_empty());   // the cheque goes to the first node only
}

/// Fee tiers above 9, or tier 0 with coins, would be refused at the last piece and burn the cheque: refused up front.
#[test]
fn invalid_fee_tiers_are_refused_before_signing() {
    let h = home("fee");
    let f = fake(reply("none", &first16()));
    for args in [&["send", "--to", "7", "--amount", "1", "--fee", "10"][..], &["send", "--to", "7", "--amount", "1", "--fee", "255"],
                 &["sweep", "--to", "7", "--fee", "12"], &["send", "--to", "7", "--amount", "1", "--fee", "0"], &["sweep", "--to", "7", "--fee", "0"]] {
        let (ok, out) = wallet(&h, &f, args);
        assert!(!ok && (out.contains("tier from 0 to 9") || out.contains("fee tier 0 only")), "{args:?}: {out}");
    }
    assert!(f.posts.lock().unwrap().is_empty() && record(&h).is_none());
    let (ok, out) = wallet(&h, &f, &["send", "--to", "7", "--amount", "0", "--fee", "0"]);   // a zero cheque may go free
    assert!(ok, "{out}");
    assert_eq!(cheques(&f), vec![1]);
}

/// The seed never on the command line, never in an error, and its file kept private.
#[test]
fn the_seed_stays_private() {
    let h = home("seed");
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

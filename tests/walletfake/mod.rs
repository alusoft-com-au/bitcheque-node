//! A fake node RPC on 127.0.0.1 (a tiny TcpListener in the test) for the command-line wallet tests. It keeps a little
//! state: posted cheque pieces wait in its pool and, while `mining` is on, go straight into a "block": a cheque with
//! some columns becomes the open one, a cheque with all 18 moves the nonce (cheque numbers advance on completion).
//! POST /check answers "column already revealed" for a piece it has, else "ok" (or `refuse`). Every run gets its own
//! temporary HOME; nothing touches ~/.config or the network.
#![allow(dead_code)]
use bitcheque::{rpc::unhex, tx::{Tx, R}};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

pub const SEED: &str = "5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed";

/// What the fake node answers at first: `/id/<id>` (after `delay` ms), `/queued/<id>`, `/account/<n>`, `/regtarget`.
#[derive(Clone)]
pub struct Reply { pub nonce: &'static str, pub open: &'static str, pub unspent: String, pub book: &'static str, pub queued: String, pub delay: u64, pub regtarget: String, pub acct: Option<String> }
pub fn reply(nonce: &'static str, unspent: &str) -> Reply {
    // the local network's easiest registration target (2^240): a test registration is mined in moments
    Reply { nonce, open: "none", unspent: unspent.into(), book: "256", queued: String::new(), delay: 0,
            regtarget: "0000000000000000 0000000000000000 0000000000000000 0001000000000000".into(), acct: None }
}
pub fn first16() -> String { (0..16).map(|i| i.to_string()).collect::<Vec<_>>().join(",") }

/// The fake's chain and pool. `lose` posts are kept in `posts` but never reach the pool; `drop_replies` posts reach it
/// but get no reply; only pieces of a column below `mine_below` are mined.
pub struct St { pub nonce: String, pub open: String, pub pool: Vec<(u16, u8)>, pub chain: BTreeMap<u16, BTreeSet<u8>>, pub mining: bool,
                pub lose: usize, pub drop_replies: usize, pub refuse: Option<String>, pub mine_below: u8 }
impl St {
    fn has(&self, c: u16, col: u8) -> bool { self.pool.contains(&(c, col)) || self.chain.get(&c).is_some_and(|s| s.contains(&col)) }
    pub fn mine(&mut self) {
        let (now, keep): (Vec<_>, Vec<_>) = self.pool.drain(..).partition(|&(_, col)| col < self.mine_below);
        self.pool = keep;
        for (c, col) in now {
            let s = self.chain.entry(c).or_default();
            s.insert(col);
            if s.len() == 18 {
                if self.nonce.parse::<u16>().map_or(true, |n| n < c) { self.nonce = c.to_string(); }
                if self.open == c.to_string() { self.open = "none".into(); }
            } else { self.open = c.to_string(); }
        }
    }
}

pub struct Fake { pub addr: String, pub posts: Arc<Mutex<Vec<String>>>, pub st: Arc<Mutex<St>>, relay: Arc<Mutex<Vec<Arc<Mutex<St>>>>> }
impl Fake {
    /// Pieces posted here also reach `other` (as a real node relays them); its `posts` stay empty.
    pub fn relay_to(&self, other: &Fake) { self.relay.lock().unwrap().push(other.st.clone()); }
    pub fn set(&self, f: impl FnOnce(&mut St)) { f(&mut self.st.lock().unwrap()) }
}
pub fn fake(r: Reply) -> Fake {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let posts = Arc::new(Mutex::new(Vec::new()));
    let st = Arc::new(Mutex::new(St { nonce: r.nonce.into(), open: r.open.into(), pool: vec![], chain: BTreeMap::new(), mining: true, lose: 0, drop_replies: 0, refuse: None, mine_below: 18 }));
    let relay: Arc<Mutex<Vec<Arc<Mutex<St>>>>> = Arc::new(Mutex::new(Vec::new()));
    let (p, s0, rl) = (posts.clone(), st.clone(), relay.clone());
    std::thread::spawn(move || for s in l.incoming() {
        let (mut s, r, p, st, rl) = (s.unwrap(), r.clone(), p.clone(), s0.clone(), rl.clone());
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
            let lines: Vec<String> = body.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
            let text = if method == "POST" && path == "/tx" {
                p.lock().unwrap().push(body.clone());
                let (lost, dropped) = { let mut g = st.lock().unwrap(); let lost = g.lose > 0; if lost { g.lose -= 1; }
                    let dropped = !lost && g.drop_replies > 0; if dropped { g.drop_replies -= 1; } (lost, dropped) };
                if !lost {
                    let all: Vec<Arc<Mutex<St>>> = [st.clone()].into_iter().chain(rl.lock().unwrap().iter().cloned()).collect();
                    for n in all {
                        let mut g = n.lock().unwrap();
                        for l in &lines { if let Some((c, col, _)) = piece(l) { if !g.has(c, col) { g.pool.push((c, col)); } } }
                        if g.mining { g.mine(); }
                    }
                }
                if dropped { return; }   // accepted, but the reply never comes
                lines.iter().map(|_| "ok").collect::<Vec<_>>().join("\n")
            } else if method == "POST" && path == "/check" {
                let g = st.lock().unwrap();
                lines.iter().map(|l| match (&g.refuse, piece(l)) {
                    (Some(e), _) => e.clone(),
                    (None, Some((c, col, _))) if g.has(c, col) => "column already revealed".into(),
                    _ => "ok".into(),
                }).collect::<Vec<_>>().join("\n")
            } else if let Some(id) = path.strip_prefix("/id/") {
                std::thread::sleep(std::time::Duration::from_millis(r.delay));
                let g = st.lock().unwrap();
                format!("id {id}\nnumber 5\nbalance 100000000000\npending 0\nnonce {}\nbook_size {}\nunspent {}\nfunded true\nmature true\nready_at 0\nopen {}", g.nonce, r.book, r.unspent, g.open)
            } else if let Some(n) = path.strip_prefix("/account/") { r.acct.clone().unwrap_or(format!("id 00\nnumber {n}\nbalance 0\nfunded true")) }
            else if path.starts_with("/queued/") {
                let g = st.lock().unwrap();
                let mut q: Vec<String> = r.queued.split(',').filter(|x| !x.is_empty()).map(String::from).collect();
                for (c, _) in &g.pool { if !q.contains(&c.to_string()) { q.push(c.to_string()); } }
                q.join(",")
            }
            else if path == "/regtarget" { r.regtarget.clone() }
            else if path == "/tip" { "00".repeat(32) }
            else { String::new() };
            let _ = write!(s, "HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n{text}", text.len());
        });
    });
    Fake { addr, posts, st, relay }
}

fn piece(l: &str) -> Option<(u16, u8, Vec<Vec<u8>>)> {
    let raw = unhex(l)?;
    match Tx::decode(&mut R::new(&raw)).ok()? { Tx::ChequePiece { cheque, column, shares, .. } => Some((cheque, column, shares)), _ => None }
}

/// A fresh HOME with the seed file (0600) in it.
pub fn home(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("bitcheque-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let f = d.join("seed");
    std::fs::write(&f, SEED).unwrap();
    set_mode(&f, 0o600);
    d
}
pub fn set_mode(f: &Path, mode: u32) { use std::os::unix::fs::PermissionsExt; std::fs::set_permissions(f, std::fs::Permissions::from_mode(mode)).unwrap(); }

/// Runs `bitcheque wallet <args> --local` (the local network: quick registrations) with only HOME set (unless `home`
/// is None); returns success and stdout+stderr.
pub fn run(home: Option<&Path>, dir: &Path, args: &[&str], env: &[(&str, &str)]) -> (bool, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_bitcheque"));
    c.env_clear().arg("wallet").args(args).arg("--local").current_dir(dir);
    if let Some(h) = home { c.env("HOME", h); }
    for (k, v) in env { c.env(k, v); }
    let o = c.output().unwrap();
    (o.status.success(), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
}
pub fn wallet(h: &Path, f: &Fake, args: &[&str]) -> (bool, String) { wallet_at(h, &f.addr, args) }
pub fn wallet_at(h: &Path, rpc: &str, args: &[&str]) -> (bool, String) {
    let seed = h.join("seed");
    let mut a = args.to_vec();
    a.extend(["--seed-file", seed.to_str().unwrap(), "--rpc", rpc]);
    run(Some(h), h, &a, &[])
}

/// A recipient as printed: 11 digits, a hyphen, the Damm check digit.
pub fn num(n: u32) -> String {
    let d: Vec<u8> = format!("{n:011}").bytes().map(|c| c - b'0').collect();
    format!("{n:011}-{}", bitcheque::damm::check_digit(&d))
}

/// Every cheque piece posted to the fake: (cheque, column, the cells sent for it).
pub fn pieces(f: &Fake) -> Vec<(u16, u8, Vec<Vec<u8>>)> {
    f.posts.lock().unwrap().iter().flat_map(|b| b.lines().map(|l| l.to_string()).collect::<Vec<_>>()).filter_map(|l| piece(l.trim())).collect()
}
pub fn cheques(f: &Fake) -> Vec<u16> { let mut c: Vec<u16> = pieces(f).iter().map(|p| p.0).collect(); c.dedup(); c }
/// The one-time rule itself: no (cheque, column) was ever sent with two different cells (two different digits).
pub fn never_two_messages(fakes: &[&Fake]) {
    let mut seen: BTreeMap<(u16, u8), Vec<Vec<u8>>> = BTreeMap::new();
    for f in fakes { for (c, col, sh) in pieces(f) {
        let e = seen.entry((c, col)).or_insert_with(|| sh.clone());
        assert_eq!(*e, sh, "cheque {c} column {col} signed with two different digits");
    } }
}
/// The cheque number in the used-cheque record under HOME.
pub fn record(h: &Path) -> Option<String> {
    std::fs::read_dir(h.join(".config/bitcheque")).ok()?.flatten()
        .find(|e| e.file_name().to_string_lossy().starts_with("used-") && !e.file_name().to_string_lossy().contains('.'))
        .map(|e| std::fs::read_to_string(e.path()).unwrap().split_whitespace().next().unwrap_or("").to_string())
}

//! A fake node RPC on 127.0.0.1 (a tiny TcpListener in the test) for the command-line wallet tests. It keeps a little
//! state: posted cheque cells (openings and pieces) wait in its pool and, while `mining` is on, go straight into a
//! "block": a cheque's first cells there open it and move the nonce to it (an opening uses its number), all 18 finish
//! it. POST /check answers as a node does: "ok <rows>", "column already revealed" or "cheque already open" for cells it
//! has, "... with other digits" for other cells there (or `refuse`). Every run gets its own temporary HOME; nothing
//! touches ~/.config or the network.
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
/// but get no reply; only cells of a column below `mine_below` are mined. Every `mine` is a block (`height`); GET /height
/// answers `height + extra`, so an opening is `extra + 1` blocks deep at once; an open cheque expires `lifetime` blocks
/// after the block that opened it (`opened`, else the current height).
pub struct St { pub nonce: String, pub open: String, pub pool: Vec<(u16, u8)>, pub chain: BTreeMap<u16, BTreeSet<u8>>, pub mining: bool,
                /// the digit each revealed (cheque, column) shows, read from its cell against SEED's book
                pub digits: BTreeMap<(u16, u8), u8>,
                pub lose: usize, pub drop_replies: usize, pub refuse: Option<String>, pub mine_below: u8,
                pub height: u32, pub extra: u32, pub lifetime: u32, pub opened: BTreeMap<u16, u32>,
                /// GET /id answers "no such account" until a registration is posted (even a lost one: it lands)
                pub registered: bool,
                /// posts of cheque pieces only (an amount half) reach the pool but get no reply
                pub drop_piece_replies: usize,
                /// GET /id requests served
                pub ids: usize,
                /// cheques finished, (height, cheque): GET /sends/5 and /history/5 list them as sends, newest first, unless `history` says otherwise
                pub completed: Vec<(u32, u16)>, pub history: Option<String>,
                /// /history/5 leaves out cheques up to this one (mined rewards pushed them out of its last 50); `old`: no /sends route (an older node)
                pub pushed_out: u16, pub old: bool }
impl St {
    fn expires(&self) -> String {
        if self.open == "none" { return "none".into(); }
        self.open.split(',').map(|c| { let n: u16 = c.parse().unwrap_or(0); format!("{c}:{}", self.opened.get(&n).copied().unwrap_or(self.height) + self.lifetime) }).collect::<Vec<_>>().join(",")
    }
    /// The book's account history as a node's /history lists it: its finished cheques as sends (a payee that does not
    /// read back as a cheque is left out, as a void to a number nobody holds is).
    pub fn history(&self) -> String {
        if let Some(h) = &self.history { return h.clone(); }
        self.completed.iter().rev().filter_map(|&(h, c)| {
            let d: [u8; 18] = (0..18u8).map(|col| self.digits.get(&(c, col)).copied()).collect::<Option<Vec<u8>>>()?.try_into().ok()?;
            let m = bitcheque::message::parse(&d).ok()?;
            Some(format!("{h} send cheque={c} to={} amount={} fee={}", m.payee, m.amount().unwrap_or(1_000_000_000), m.tier as u64 * 1000))
        }).collect::<Vec<_>>().join("\n")
    }
    fn started(&self, c: u16) -> bool { self.pool.iter().any(|p| p.0 == c) || self.chain.contains_key(&c) }
    /// The node's /check answer for one line.
    fn check(&self, l: &str) -> String {
        if let Some(e) = &self.refuse { return e.clone(); }
        let Some((open, cells)) = parse(l) else { return "ok".into() };
        let c = cells[0].0;
        let mine: Vec<(u8, Option<u8>)> = cells.iter().map(|(_, col, sh)| (*col, digit(c, *col, sh))).collect();
        let other = mine.iter().any(|&(col, d)| self.has(c, col) && self.digits.get(&(c, col)).copied() != d);
        if open && self.started(c) { return if other { "cheque open with other digits" } else { "cheque already open" }.into(); }
        if open && self.nonce.parse::<u16>().is_ok_and(|n| n >= c) { return "cheque number already consumed".into(); }
        if !open && self.has(c, mine[0].0) { return if other { "column revealed with other digits" } else { "column already revealed" }.into(); }
        if !open && !self.started(c) { return "cheque not open".into(); }
        format!("ok {}", mine.iter().map(|(_, d)| d.map_or('?', |d| (b'0' + d) as char)).collect::<String>())
    }
    /// The open cheques and their digits as a node's `revealed` line shows them (only cheques on chain, not finished).
    fn revealed(&self) -> String {
        let open: Vec<String> = self.chain.iter().filter(|(_, s)| s.len() < 18).map(|(c, s)| format!("{c}:{}",
            (0..18u8).map(|col| if s.contains(&col) { self.digits.get(&(*c, col)).map_or('?', |d| (b'0' + d) as char) } else { '.' }).collect::<String>())).collect();
        if open.is_empty() { "none".into() } else { open.join(",") }
    }
    fn has(&self, c: u16, col: u8) -> bool { self.pool.contains(&(c, col)) || self.chain.get(&c).is_some_and(|s| s.contains(&col)) }
    pub fn mine(&mut self) {
        let (now, keep): (Vec<_>, Vec<_>) = self.pool.drain(..).partition(|&(_, col)| col < self.mine_below);
        self.pool = keep;
        self.height += 1;
        for (c, col) in now {
            if !self.chain.contains_key(&c) {
                // opened: its number is used at once
                self.opened.insert(c, self.height);
                if self.nonce.parse::<u16>().map_or(true, |n| n < c) { self.nonce = c.to_string(); }
            }
            let s = self.chain.entry(c).or_default();
            s.insert(col);
            if s.len() == 18 {
                self.completed.push((self.height, c));
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
    let st = Arc::new(Mutex::new(St { nonce: r.nonce.into(), open: r.open.into(), pool: vec![], chain: BTreeMap::new(), digits: BTreeMap::new(), mining: true, lose: 0, drop_replies: 0, refuse: None, mine_below: 18,
                                      height: 100, extra: 5, lifetime: 10_000, opened: BTreeMap::new(), registered: true, drop_piece_replies: 0, ids: 0, completed: vec![], history: None, pushed_out: 0, old: false }));
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
                if lines.iter().any(|l| l.starts_with("01")) { st.lock().unwrap().registered = true; }
                let (lost, dropped) = { let mut g = st.lock().unwrap(); let lost = g.lose > 0; if lost { g.lose -= 1; }
                    let mut dropped = !lost && g.drop_replies > 0; if dropped { g.drop_replies -= 1; }
                    if !lost && !dropped && g.drop_piece_replies > 0 && lines.iter().all(|l| parse(l).is_some_and(|x| !x.0)) { g.drop_piece_replies -= 1; dropped = true; }
                    (lost, dropped) };
                if !lost {
                    let all: Vec<Arc<Mutex<St>>> = [st.clone()].into_iter().chain(rl.lock().unwrap().iter().cloned()).collect();
                    for n in all {
                        let mut g = n.lock().unwrap();
                        for l in &lines { for (c, col, sh) in parse(l).map_or(vec![], |x| x.1) { if !g.has(c, col) {
                            g.pool.push((c, col));
                            if let Some(d) = digit(c, col, &sh) { g.digits.insert((c, col), d); }
                        } } }
                        if g.mining { g.mine(); }
                    }
                }
                if dropped { return; }   // accepted, but the reply never comes
                lines.iter().map(|_| "ok").collect::<Vec<_>>().join("\n")
            } else if method == "POST" && path == "/check" {
                let g = st.lock().unwrap();
                lines.iter().map(|l| g.check(l)).collect::<Vec<_>>().join("\n")
            } else if let Some(id) = path.strip_prefix("/id/") {
                std::thread::sleep(std::time::Duration::from_millis(r.delay));
                let mut g = st.lock().unwrap();
                g.ids += 1;
                if !g.registered { let _ = write!(s, "HTTP/1.0 404 Not Found\r\nContent-Length: 17\r\n\r\nno such account\r\n"); return; }
                format!("id {id}\nnumber 5\nbalance 100000000000\npending 0\nnonce {}\nbook_size {}\nunspent {}\nfunded true\nmature true\nready_at 0\nopen {}\nrevealed {}\nexpires {}", g.nonce, r.book, r.unspent, g.open, g.revealed(), g.expires())
            } else if let Some(n) = path.strip_prefix("/account/") { r.acct.clone().unwrap_or(format!("id 00\nnumber {n}\nbalance 0\nfunded true")) }
            else if path.starts_with("/queued/") {
                let g = st.lock().unwrap();
                let mut q: Vec<String> = r.queued.split(',').filter(|x| !x.is_empty()).map(String::from).collect();
                for (c, _) in &g.pool { if !q.contains(&c.to_string()) { q.push(c.to_string()); } }
                q.join(",")
            }
            else if path == "/history/5" {
                let g = st.lock().unwrap();
                g.history().lines().filter(|l| l.split("cheque=").nth(1).and_then(|x| x.split(' ').next()?.parse::<u16>().ok()).map_or(true, |c| c > g.pushed_out)).collect::<Vec<_>>().join("\n")
            }
            else if path == "/sends/5" {
                let g = st.lock().unwrap();
                if g.old { let _ = write!(s, "HTTP/1.0 400 Bad Request\r\nContent-Length: 13\r\n\r\nunknown route"); return; }
                let h = g.history(); if h.is_empty() { "none".into() } else { h }
            }
            else if path == "/regtarget" { r.regtarget.clone() }
            else if path == "/tip" { "00".repeat(32) }
            else if path == "/height" { let g = st.lock().unwrap(); (g.height + g.extra).to_string() }
            else { String::new() };
            let _ = write!(s, "HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n{text}", text.len());
        });
    });
    Fake { addr, posts, st, relay }
}

/// The row a cell of SEED's book (on the local network, as every run uses) stands for.
pub fn digit(c: u16, col: u8, shares: &[Vec<u8>]) -> Option<u8> {
    let seed: [u8; 32] = unhex(SEED)?.try_into().ok()?;
    let d = bitcheque::wallet::Domain(seed);
    (0..10u8).find(|&row| shares.first().is_some_and(|s| *s == d.cell(&bitcheque::params::Params::local().magic, 16, c, col, row)))
}

/// A cheque opening (true) or piece: its (cheque, column, cells), one per column.
fn parse(l: &str) -> Option<(bool, Vec<(u16, u8, Vec<Vec<u8>>)>)> {
    let raw = unhex(l)?;
    match Tx::decode(&mut R::new(&raw)).ok()? {
        Tx::ChequePiece { cheque, column, shares, .. } => Some((false, vec![(cheque, column, shares)])),
        Tx::ChequeOpen { cheque, pieces, .. } => Some((true, pieces.into_iter().map(|(c, sh)| (cheque, c, sh)).collect())),
        _ => None,
    }
}
/// The openings posted to the fake: (cheque, columns).
pub fn openings(f: &Fake) -> Vec<(u16, Vec<u8>)> {
    f.posts.lock().unwrap().iter().flat_map(|b| b.lines().map(|l| l.to_string()).collect::<Vec<_>>())
        .filter_map(|l| parse(l.trim()).filter(|x| x.0).map(|x| (x.1[0].0, x.1.iter().map(|p| p.1).collect()))).collect()
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
pub fn wallet_at(h: &Path, rpc: &str, args: &[&str]) -> (bool, String) { wallet_rpcs(h, &[rpc], args) }
/// With `--rpc` given once per node.
pub fn wallet_rpcs(h: &Path, rpcs: &[&str], args: &[&str]) -> (bool, String) {
    let seed = h.join("seed");
    let mut a = args.to_vec();
    a.extend(["--seed-file", seed.to_str().unwrap()]);
    for r in rpcs { a.extend(["--rpc", r]); }
    run(Some(h), h, &a, &[])
}

/// A recipient as printed: 11 digits, a hyphen, the Damm check digit.
pub fn num(n: u32) -> String {
    let d: Vec<u8> = format!("{n:011}").bytes().map(|c| c - b'0').collect();
    format!("{n:011}-{}", bitcheque::damm::check_digit(&d))
}

/// Every cheque cell posted to the fake, in openings and pieces: (cheque, column, the cells sent for it).
pub fn pieces(f: &Fake) -> Vec<(u16, u8, Vec<Vec<u8>>)> {
    f.posts.lock().unwrap().iter().flat_map(|b| b.lines().map(|l| l.to_string()).collect::<Vec<_>>()).filter_map(|l| parse(l.trim())).flat_map(|x| x.1).collect()
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

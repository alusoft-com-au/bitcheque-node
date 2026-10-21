//! Wallet-facing HTTP interface, plain text, standard library only.
//!   GET  /height   GET /peers   GET /addrs (known peer addresses)   GET /tip                GET /block/<height>   (hex)   GET /summary/<height> (text)
//!   GET  /account/<number>    GET /id/<account id hex>   GET /lookup/<code> (start of the id after its scheme byte)
//!   (account text, one "key value" line each: ... open N|none, revealed N:<18 digits or '.'>|none, expires N:<height>|none, salt)
//!   (a number appears in any output only once it is final, number_maturity blocks deep; /account/<n> of a
//!   number not final yet answers only "pending" and its ready_at)
//!   GET /commits/<account id hex>/<cheque> (a registered unspent cheque's commitments: 18 lines, one per column, of 10 hex, one per row)
//!   GET /proof/<number>   GET /regtarget (4 LE limbs, hex)   GET /queued/<account id hex> (cheque numbers of that account waiting in the mempool, comma-separated)
//!   GET  /history/<number>  (newest first, the last block::HISTORY_CAP events: height kind key=value...; a cheque to yourself is listed as receive, then send)
//!   GET  /sends/<number>  (every completed cheque of the account, newest first, as /history writes a send: height send cheque=N to=P amount=A fee=F; or "none")
//!   GET  /stats   (lifetime totals, and the reward schedule: reward of the next block, base, halving interval, next halving, maturity)
//!   GET  /mempool (count, then one line per waiting transaction in the /summary format (the first MEMPOOL_LIST), then a cheque line per waiting cheque whose recipient is readable)
//!   GET  /top[/N]  (richest N accounts, default 50: number balance book_size last_cheque unspent pending)
//!   GET  /template/<number>  (hex: the next block to mine, reward to that number (0 burns it), nonce 0)
//!   POST /tx  (body: hex-encoded tx, or several, one per line, queued together: one result per line)   POST /block (body: hex-encoded block, mined from a template)
//!   POST /check (body: one hex tx per line; dry run, nothing stored: one result per line, "ok", "ok <row>" for a
//!   cheque piece (the row its cell matched), "ok <rows>" for a cheque opening (the row of each of its columns, in
//!   order, as one string of digits), or the reason)
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use crate::crypto::hex;
use crate::net::Node;
use crate::state::Event;
use crate::tx::{Tx, R};
use std::collections::BTreeMap;
use crate::message::{self, COLS, PAYEE_DIGITS};

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 || !s.is_ascii() { return None; }   // slicing a multi-byte character would panic
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

const RPC_PER_MINUTE: u32 = 120;   // requests one address (an IPv6 /48) may make per minute
const CHECK_MAX: usize = 64;       // transactions per /check or per batched /tx
const BODY_MAX: usize = 8 << 20;   // request body bytes (16 registrations of 16 cheques, with a cheque, are under 2 MB of hex)
const HEAD_MAX: usize = 16 << 10;  // request line and headers
const RPC_THREADS: usize = 256;    // requests served at once
const RESERVE: usize = 32;         // ...the last of them only for clients holding no connection yet
const PER_IP: usize = 8;           // ...of which from one address (an IPv4 address, or an IPv6 /56: a home or a server may have that much),
const PER_48: usize = 16;          // ...from one IPv6 /48 (a site)
const PER_32: usize = 64;          // ...and from one IPv6 /32 (a provider): many /56s or /48s cost an attacker next to nothing
const HEAD_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);   // the request line and headers must arrive within this,
const DEADLINE: std::time::Duration = std::time::Duration::from_secs(20);   // the whole request within this, plus a second per 32 KB of body received
const WRITE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);   // ...and the whole reply must be taken within this
const CHECK_REGS: usize = 2;       // registrations per /check (each can cost thousands of hashes)
const MEMPOOL_LIST: usize = 500;   // waiting transactions listed by /mempool
const COSTLY_PER_SECOND: u32 = 100; // /check, /proof and /template requests served per second, from everyone together,
const COSTLY_PER_KEY: u32 = 10;     // ...and from one address (an IPv6 /48), so one cannot take the whole budget from the rest

/// The key an address is limited by: an IPv4 address, or the /48 an IPv6 address is in (a home or a server is commonly
/// given a /48, and many /64s cost nothing).
fn limit_key(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip.to_canonical() { std::net::IpAddr::V6(a) => { let s = a.segments(); std::net::IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], 0, 0, 0, 0, 0)) } x => x }
}
/// A path spelt one way: empty segments dropped ("//template/0" and "/check/" are "/template/0" and "/check"), so what
/// is routed is what is charged.
fn normal(path: &str) -> String { format!("/{}", path.split('/').filter(|s| !s.is_empty()).collect::<Vec<_>>().join("/")) }
/// The routes that cost real work whoever asks (proofs of work and hash checks, state proofs, block building).
fn costly(path: &str) -> bool { path == "/check" || path.starts_with("/proof/") || path.starts_with("/template/") }

/// The networks a connection is counted against, with the most each may hold at once: an IPv4 address, or the /56, /48
/// and /32 an IPv6 address is in. Each key is tagged with its prefix length, so a /48 and a /32 never share a count.
fn conn_keys(ip: std::net::IpAddr) -> Vec<((u8, std::net::IpAddr), usize)> {
    match ip.to_canonical() {
        std::net::IpAddr::V6(a) => [(56u8, PER_IP), (48, PER_48), (32, PER_32)].iter().map(|&(n, cap)| ((n, std::net::IpAddr::V6((u128::from(a) & !(u128::MAX >> n)).into())), cap)).collect(),
        x => vec![((32, x), PER_IP)],
    }
}
/// One RPC server's own state (a node may serve several, and tests run many in one process): connections being served
/// per network, threads busy, and this second's costly requests (second, served, served per address).
#[derive(Default)]
struct Server { open: std::sync::Mutex<std::collections::HashMap<(u8, std::net::IpAddr), usize>>, active: std::sync::atomic::AtomicUsize,
                costly: std::sync::Mutex<(u64, u32, std::collections::HashMap<std::net::IpAddr, u32>)> }
impl Server {
    /// Whether the busy threads have reached the reserve.
    fn busy(&self) -> bool { self.active.load(std::sync::atomic::Ordering::Relaxed) >= RPC_THREADS - RESERVE }
    /// One costly request from `who` (None: the operator's own tools) within this second's budget: COSTLY_PER_SECOND from
    /// everyone, COSTLY_PER_KEY of it from one address. A refused one is not counted.
    fn costly_ok(&self, who: Option<std::net::IpAddr>) -> bool {
        let sec = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let mut g = self.costly.lock().unwrap();
        let c = &mut *g;
        if c.0 != sec { *c = (sec, 0, Default::default()); }
        if c.1 >= COSTLY_PER_SECOND { return false; }
        if let Some(ip) = who { let k = c.2.entry(limit_key(ip)).or_default(); if *k >= COSTLY_PER_KEY { return false; } *k += 1; }
        c.1 += 1;
        true
    }
}
/// One connection counted against its networks while this lives (no keys: not limited).
struct Held(Arc<Server>, Vec<(u8, std::net::IpAddr)>);
impl Held {
    /// None when one of its networks already holds its cap, or when only the reserve is left (`busy`) and it already
    /// holds a connection: a flood from one place, however spread over addresses, leaves threads for everyone else.
    fn take(srv: &Arc<Server>, ip: Option<std::net::IpAddr>, busy: bool) -> Option<Held> {
        let Some(ip) = ip else { return Some(Held(srv.clone(), Vec::new())) };
        let keys = conn_keys(ip);
        let mut o = srv.open.lock().unwrap();
        if keys.iter().any(|(k, cap)| o.get(k).is_some_and(|c| *c >= *cap || busy)) { return None; }
        for (k, _) in &keys { *o.entry(*k).or_default() += 1; }
        Some(Held(srv.clone(), keys.into_iter().map(|(k, _)| k).collect()))
    }
}
impl Drop for Held { fn drop(&mut self) { let mut o = self.0.open.lock().unwrap(); for k in &self.1 { if let Some(c) = o.get_mut(k) { *c -= 1; if *c == 0 { o.remove(k); } } } } }
/// Write all of `b` within WRITE_DEADLINE in all, however slowly the client reads.
fn write_by(s: &mut TcpStream, b: &[u8]) {
    let start = std::time::Instant::now();
    let mut i = 0;
    while i < b.len() {
        let Some(left) = WRITE_DEADLINE.checked_sub(start.elapsed()).filter(|d| !d.is_zero()) else { return };
        if s.set_write_timeout(Some(left)).is_err() { return; }
        match s.write(&b[i..]) { Ok(0) | Err(_) => return, Ok(n) => i += n }
    }
}

impl Node {
    /// Simple per-address limiter: a fixed one-minute window (expired windows are swept once a minute).
    fn allow(&self, ip: std::net::IpAddr) -> bool {
        let mut g = self.rpc_limit.lock().unwrap();
        let (l, swept) = &mut *g;
        let now = std::time::Instant::now();
        if crate::net::every_minute(swept, now) { l.retain(|_, v| now.duration_since(v.1).as_secs() < 60); }
        let e = l.entry(limit_key(ip)).or_insert((0, now));
        if now.duration_since(e.1).as_secs() >= 60 { *e = (0, now); }
        e.0 += 1;
        e.0 <= RPC_PER_MINUTE
    }
    pub fn serve_rpc(self: &Arc<Self>, addr: &str) -> std::io::Result<SocketAddr> {
        let l = TcpListener::bind(addr)?;
        let local = l.local_addr()?;
        let node = self.clone();
        let srv: Arc<Server> = Arc::default();
        crate::net::spawn(move || for mut s in l.incoming().flatten() {
            use std::sync::atomic::Ordering;
            // loopback is counted once the request names its client (X-Forwarded-For from a proxy), in handle
            let ip = s.peer_addr().ok().map(|a| a.ip().to_canonical()).filter(|ip| !ip.is_loopback());
            let held = if srv.active.load(Ordering::Relaxed) >= RPC_THREADS { None } else { Held::take(&srv, ip, srv.busy()) };
            let Some(held) = held else { let _ = write!(s, "HTTP/1.0 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n"); continue };
            srv.active.fetch_add(1, Ordering::Relaxed);
            let (n, srv2) = (node.clone(), srv.clone());
            // no thread to be had: the connection is closed, not a panic that would stop the whole RPC
            if crate::net::spawn(move || {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| n.handle(s, &srv2)));
                drop(held);
                srv2.active.fetch_sub(1, Ordering::Relaxed);
            }).is_err() { srv.active.fetch_sub(1, Ordering::Relaxed); }
        })?;
        Ok(local)
    }
    fn handle(&self, mut s: TcpStream, srv: &Arc<Server>) {
        let reply = |s: &mut TcpStream, status: &str| write_by(s, format!("HTTP/1.0 {status}\r\nContent-Length: 0\r\n\r\n").as_bytes());
        // the request line and headers within HEAD_DEADLINE, the whole request within DEADLINE (a per-read timeout alone
        // lets a client trickle a byte at a time forever, and a slow head would hold a thread for nothing); a big body
        // earns a second more per 32 KB actually received, never on the strength of its Content-Length
        let start = std::time::Instant::now();
        let deadline = std::cell::Cell::new(HEAD_DEADLINE);
        let read = |s: &mut TcpStream, tmp: &mut [u8]| -> Option<usize> {
            let left = deadline.get().checked_sub(start.elapsed()).filter(|d| !d.is_zero())?;
            s.set_read_timeout(Some(left)).ok()?;
            match s.read(tmp) { Ok(0) | Err(_) => None, Ok(n) => Some(n) }
        };
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        let (head_end, body_len) = loop {
            let seen = buf.len();
            let Some(n) = read(&mut s, &mut tmp) else { return };
            buf.extend_from_slice(&tmp[..n]);
            if let Some(i) = buf[seen.saturating_sub(3)..].windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + seen.saturating_sub(3)) {
                let head = String::from_utf8_lossy(&buf[..i]).to_string();
                let lens: Vec<&str> = head.lines().filter_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("content-length")).map(|(_, v)| v.trim())).collect();
                let len = match lens.as_slice() { [] => 0, [v] => match v.parse::<usize>() { Ok(n) => n, Err(_) => return reply(&mut s, "400 Bad Request") }, _ => return reply(&mut s, "400 Bad Request") };
                if len > BODY_MAX { return reply(&mut s, "413 Payload Too Large"); }
                deadline.set(DEADLINE);
                break (i + 4, len);
            }
            if buf.len() > HEAD_MAX { return reply(&mut s, "431 Request Header Fields Too Large"); }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
        // the limits are per address; behind a reverse proxy on this machine every request comes from loopback, so the
        // proxy's X-Forwarded-For names the client. Loopback with no such header is the operator's own tools: not limited.
        // This assumes exactly one proxy, which appends the address it saw: the last entry of the last X-Forwarded-For line
        // is believed (earlier ones, and earlier lines, are whatever the client sent; a proxy that adds a line of its own
        // adds it last). Behind a chain of proxies every client would look like the last proxy but one.
        let (mut _held, mut client) = (None, None);
        if let Ok(a) = s.peer_addr() {
            let a = a.ip().to_canonical();
            // one that does not parse is limited as loopback, so a made-up header buys nothing
            let fwd = head.lines().filter_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("x-forwarded-for")).map(|(_, v)| v.to_string())).last();
            let who = if !a.is_loopback() { Some(a) } else { fwd.map(|v| v.rsplit(',').next().and_then(|x| x.trim().parse::<std::net::IpAddr>().ok()).map_or(a, |ip| ip.to_canonical())) };
            if who.is_some_and(|ip| !self.allow(ip)) { return reply(&mut s, "429 Too Many Requests"); }
            // a proxied client is held to the same connection caps (a direct one was counted when it connected)
            if a.is_loopback() { if let Some(ip) = who { match Held::take(srv, Some(ip), srv.busy()) { Some(h) => _held = Some(h), None => return reply(&mut s, "503 Service Unavailable") } } }
            client = who.filter(|ip| !ip.is_loopback());
        }
        while buf.len() < head_end + body_len {
            let Some(n) = read(&mut s, &mut tmp) else { return };
            buf.extend_from_slice(&tmp[..n]);
            deadline.set(DEADLINE + std::time::Duration::from_secs((buf.len() - head_end) as u64 / 32_768));
        }
        buf.truncate(head_end + body_len);
        // every request body is hex: anything else is refused before it is turned into text
        if !buf[head_end..].is_ascii() { return reply(&mut s, "400 Bad Request"); }
        let body = String::from_utf8_lossy(&buf[head_end..]);
        let mut words = head.split_whitespace();
        let (method, path) = (words.next().unwrap_or(""), normal(words.next().unwrap_or("")));
        // costly routes share one budget per second besides each address's own limit, so many addresses together cannot
        // take the node's whole CPU, nor one address the whole budget; a template already built is not charged
        let r = match (method, path.strip_prefix("/template/")) {
            ("GET", Some(n)) => n.parse().map_err(|_| "bad number").and_then(|n| self.template_paid(n, &mut || srv.costly_ok(client))).map(|b| hex(&b.encode())),
            _ if costly(&path) && !srv.costly_ok(client) => Err("busy"),
            _ => self.route(method, &path, &body),
        };
        if r == Err("busy") { return reply(&mut s, "503 Service Unavailable"); }
        let (status, text) = match r { Ok(t) => ("200 OK", t), Err(e) => ("400 Bad Request", e.to_string()) };
        write_by(&mut s, format!("HTTP/1.0 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\n\r\n{text}", text.len()).as_bytes());
    }
    pub fn route(&self, method: &str, path: &str, body: &str) -> Result<String, &'static str> {
        let seg: Vec<&str> = path.trim_matches('/').split('/').collect();
        if (method, path, body.trim()) == ("POST", "/check", "") { return Ok(String::new()); }   // nothing to check: not even the store lock
        let st = self.store.lock().unwrap();
        let c = &st.chain;
        match (method, seg.as_slice()) {
            ("GET", ["height"]) => Ok(c.height().to_string()),
            ("GET", ["peers"]) => { drop(st); Ok(self.peer_count().to_string()) }
            ("GET", ["addrs"]) => { drop(st); let a = self.known_addrs(); Ok(format!("count {}\n{}", a.len(), a.join("\n"))) }
            ("GET", ["tip"]) => Ok(hex(&c.tip())),
            ("GET", ["template", n]) => { drop(st); self.template(n.parse().map_err(|_| "bad number")?).map(|b| hex(&b.encode())) }
            ("POST", ["block"]) => {
                drop(st);
                let b = unhex(body).and_then(|raw| crate::block::Block::decode(&raw).ok()).ok_or("bad block")?;
                // "accepted": the main chain moved (pass it on); "side": kept off the main chain (nobody needs it yet)
                self.submit_block(&b, None).map(|main| if main { "accepted" } else { "side" }.to_string())
            }
            ("GET", ["block", h]) => c.blocks.get(h.parse::<usize>().map_err(|_| "bad height")?).map(|b| hex(&b.encode())).ok_or("no such block"),
            ("GET", ["summary", h]) => {
                let i: usize = h.parse().map_err(|_| "bad height")?;
                let b = c.blocks.get(i).ok_or("no such block")?;
                let mut out = format!("height {i}\nhash {}\nprev {}\ntime {}\nbits {:#010x}\nnonce {}\nstate_root {}\ntxs {}\n",
                    hex(&b.header.hash()), hex(&b.header.prev), b.header.time, b.header.bits, b.header.nonce, hex(&b.header.state_root), b.txs.len());
                for t in &b.txs {
                    if let Tx::Coinbase { payee, .. } = t {
                        // the subsidy is fixed by height; the full amount (subsidy + fees) comes from the payee's recent history
                        let amount = c.state.numbers.get(payee).and_then(|(id, _)| c.history.get(id))
                            .and_then(|h| h.iter().find_map(|e| match e.event { Event::Reward { amount, .. } if e.height as usize == i => Some(amount), _ => None }));
                        out += &format!("reward to={payee} subsidy={}{} mature={}\n", c.params.block_reward(i as u32), amount.map_or(String::new(), |a| format!(" amount={a}")), i as u32 + c.params.reward_maturity);
                    } else if let Tx::RegisterBook { m, n256, root, .. } = t {
                        // the number this registration was given, while the account still holds it (numbers are reused after expiry)
                        let id = crate::tx::account_id(*m, *n256, root);
                        let number = c.state.accounts.get(&id).map(|a| a.number).filter(|n| c.state.numbers.get(n).is_some_and(|(nid, at)| *nid == id && *at as usize == i) && is_final(c, *n));
                        out += &tx_line(t).replace('\n', &number.map_or("\n".into(), |n| format!(" number={n}\n")));
                    } else { out += &tx_line(t); }
                }
                // each cheque completed in this block, as written (from the sender's recent history)
                let mut seen = std::collections::BTreeSet::new();
                for t in &b.txs { if let Tx::ChequePiece { account, cheque, .. } | Tx::ChequeOpen { account, cheque, .. } = t { if seen.insert((account.clone(), *cheque)) {
                    if let Some(Event::Transfer { to, amount, fee, digits, .. }) = c.history.get(account).and_then(|h| h.iter().find(|e| e.height as usize == i && matches!(&e.event, Event::Transfer { cheque: n, .. } if n == cheque)).map(|e| e.event.clone())) {
                        let from = c.state.accounts.get(account).map(|a| a.number).filter(|n| c.state.numbers.get(n).is_some_and(|(id, _)| id == account) && is_final(c, *n));
                        out += &format!("cheque account={} cheque={cheque}{} to={to} amount={amount} fee={fee} digits={}\n", hex(account), from.map_or(String::new(), |n| format!(" from={n}")), digits.iter().map(|d| char::from(b'0' + d)).collect::<String>());
                    }
                } } }
                Ok(out)
            }
            ("GET", ["account", n]) => {
                let num: u32 = n.parse().map_err(|_| "bad number")?;
                let &(ref id, at) = c.state.numbers.get(&num).ok_or("no such number")?;
                // not final yet: only that it is pending and the block it becomes final at (public from the chain's
                // order anyway), never the account behind it, so a provisional number is not handed out
                if !is_final(c, num) { return Ok(format!("pending\nready_at {}", at + c.params.number_maturity)); }
                Ok(account_text(c, id))
            }
            ("GET", ["id", h]) => {
                let id = unhex(h).ok_or("bad hex")?;
                if !c.state.accounts.contains_key(&id) { return Err("no such account"); }
                Ok(account_text(c, &id))
            }
            ("GET", ["lookup", code]) => {
                // the lookup code printed on a cheque sheet: the start of the account id's root, without its scheme byte
                let code: String = code.chars().filter(|ch| ch.is_ascii_hexdigit()).collect::<String>().to_ascii_lowercase();
                if code.len() < 8 || code.len() > 64 { return Err("lookup code needs 8 or more hex digits"); }
                let prefix = unhex(&code[..code.len() / 2 * 2]).ok_or("bad hex")?;
                let odd = (code.len() % 2 == 1).then(|| u8::from_str_radix(&code[code.len() - 1..], 16).unwrap());
                let mut found: Vec<&Vec<u8>> = Vec::new();
                for scheme in (0..=255u8).filter(|b| b & 0x0F == 0x03) {
                    let start = [&[scheme][..], &prefix].concat();
                    for id in c.state.accounts.range(start.clone()..).map(|(k, _)| k).take_while(|k| k.starts_with(&start)) {
                        if odd.map_or(true, |d| id.get(1 + prefix.len()).is_some_and(|b| b >> 4 == d)) { found.push(id); }
                        if found.len() > 1 { return Err("ambiguous: add more of the code"); }
                    }
                }
                found.first().map(|id| account_text(c, id)).ok_or("no such account")
            }
            ("GET", ["history", n]) => {
                let num: u32 = n.parse().map_err(|_| "bad number")?;
                let (id, _) = c.state.numbers.get(&num).filter(|_| is_final(c, num)).ok_or("no such number")?;   // not final: as if unknown
                // a sender whose number is not final yet shows as its account id
                let number_of = |id: &[u8]| c.state.accounts.get(id).filter(|a| is_final(c, a.number)).map_or_else(|| hex(id), |a| a.number.to_string());
                let own = c.state.accounts.get(id).map(|a| a.number);
                let lines: Vec<String> = c.history.get(id).map(|h| h.iter().rev().flat_map(|e| match &e.event {
                    Event::Register { number, .. } => vec![format!("{} register number={number}", e.height)],
                    Event::Reward { amount, .. } => vec![format!("{} reward amount={amount}", e.height)],
                    // a cheque to yourself is both: the receive is listed first, as the newer half
                    Event::Transfer { from, cheque, to, amount, fee, .. } if from == id => {
                        let send = format!("{} send cheque={cheque} to={to} amount={amount} fee={fee}", e.height);
                        if Some(*to) == own { vec![format!("{} receive from={} cheque={cheque} amount={amount}", e.height, number_of(from)), send] } else { vec![send] }
                    }
                    Event::Transfer { from, cheque, amount, .. } => vec![format!("{} receive from={} cheque={cheque} amount={amount}", e.height, number_of(from))],
                }).collect()).unwrap_or_default();
                Ok(lines.join("\n"))
            }
            ("GET", ["sends", n]) => {
                let num: u32 = n.parse().map_err(|_| "bad number")?;
                let (id, _) = c.state.numbers.get(&num).filter(|_| is_final(c, num)).ok_or("no such number")?;
                let lines: Vec<String> = c.sends.get(id).map(|ss| ss.iter().rev().map(|(h, cheque, to, amount, fee)| format!("{h} send cheque={cheque} to={to} amount={amount} fee={fee}")).collect()).unwrap_or_default();
                Ok(if lines.is_empty() { "none".into() } else { lines.join("\n") })
            }
            ("GET", ["mempool"]) => {
                // store before mempool, the same lock order as submit_tx
                let m = self.mempool.lock().unwrap();
                // decoding every waiting piece is costly: done once per mempool version and tip
                let key = (m.version, c.tip());
                if let Some((k, text)) = self.mempool_text.lock().unwrap().as_ref() { if *k == key { return Ok(text.clone()); } }
                let mut out = format!("count {}\n{}", m.len(), m.iter().take(MEMPOOL_LIST).map(|t| tx_line(t)).collect::<String>());
                // what each waiting cheque says so far, read from the pieces against the sender's commitments
                let mut seen: BTreeMap<(Vec<u8>, u16), [Option<u8>; COLS]> = BTreeMap::new();
                for t in m.iter() {
                    let (account, cheque, cols): (_, _, Vec<(u8, &[Vec<u8>])>) = match t {
                        Tx::ChequePiece { account, cheque, column, shares } => (account, cheque, vec![(*column, shares)]),
                        Tx::ChequeOpen { account, cheque, pieces } => (account, cheque, pieces.iter().map(|(c, sh)| (*c, sh.as_slice())).collect()),
                        _ => continue,
                    };
                    let d = seen.entry((account.clone(), *cheque)).or_insert_with(|| c.state.accounts.get(account).and_then(|a| a.open.get(cheque)).map_or([None; COLS], |o| o.digits));
                    for (col, sh) in cols { if let Some(x) = c.state.piece_digit(account, *cheque, col, sh) { d[col as usize] = Some(x); } }
                }
                for ((account, cheque), d) in seen {
                    if !d[..=PAYEE_DIGITS].iter().all(|x| x.is_some()) { continue; }
                    let p: Vec<u8> = d[..=PAYEE_DIGITS].iter().map(|x| x.unwrap()).collect();
                    if !crate::damm::valid(&p) { continue; }
                    let to = p[..PAYEE_DIGITS].iter().fold(0u64, |a, &x| a * 10 + x as u64);
                    if to != 0 && !u32::try_from(to).is_ok_and(|n| is_final(c, n)) { continue; }
                    let full = d.iter().all(|x| x.is_some()).then(|| message::parse(&std::array::from_fn(|i| d[i].unwrap())).ok()).flatten();
                    let rest = full.map_or(String::new(), |msg| format!(" amount={} fee={}", msg.amount().map_or("all".into(), |a| a.to_string()), msg.tier as u64 * c.params.fee_unit));
                    out += &format!("cheque account={} cheque={cheque} to={to}{rest}\n", hex(&account));
                }
                *self.mempool_text.lock().unwrap() = Some((key, out.clone()));
                Ok(out)
            }
            ("GET", ["top"]) | ("GET", ["top", _]) => {
                // richest accounts, sorted once per block and cached
                let n: usize = seg.get(1).and_then(|x| x.parse().ok()).unwrap_or(50).min(200);
                // ranked once per block, whatever N is asked for (so alternating N cannot force a re-sort)
                if let Some((h, head, rows)) = self.top_cache.lock().unwrap().as_ref() { if *h == c.height() { return Ok(head.clone() + &rows[..n.min(rows.len())].concat()); } }
                let mut v: Vec<&crate::state::Account> = c.state.accounts.values().map(|a| &**a).collect();
                v.sort_by(|a, b| b.balance.cmp(&a.balance).then(a.number.cmp(&b.number)));
                let total: u64 = v.iter().map(|a| a.balance).sum();
                let pending: u64 = c.state.pending.values().flatten().map(|(_, amt)| amt).sum();
                let minted: u64 = (1..=c.height()).map(|h| c.params.block_reward(h)).sum();
                let max_supply = c.params.max_supply();
                let head = format!("height {}\naccounts {}\ntotal {total}\npending {pending}\nminted {minted}\nmax_supply {max_supply}\n", c.height(), v.len());
                let mut pend: BTreeMap<u32, u64> = BTreeMap::new();   // rewards not yet spendable, per number (at most reward_maturity entries)
                for (n, amt) in c.state.pending.values().flatten() { *pend.entry(*n).or_default() += amt; }
                let rows: Vec<String> = v.iter().filter(|a| is_final(c, a.number)).take(200).map(|a| format!("{} {} {} {} {} {}\n", a.number, a.balance, a.book_size, a.nonce.map_or(-1, |x| x as i64), a.commits.len(), pend.get(&a.number).copied().unwrap_or(0))).collect();
                let out = head.clone() + &rows[..n.min(rows.len())].concat();
                *self.top_cache.lock().unwrap() = Some((c.height(), head, rows));
                Ok(out)
            }
            ("GET", ["stats"]) => {
                let next = c.height() + 1;
                let p = &c.params;
                Ok(format!("height {}\naccounts {}\nregistrations {}\ntransfers {}\ntransactions {}\npieces {}\nrewards {}\nblock_target {}\nreward {}\nreward_base {}\nhalving_interval {}\nnext_halving {}\nreward_maturity {}\nlaunch_blocks {}\nlaunch_reward {}",
                    c.height(), c.state.accounts.len(), c.totals.registrations, c.totals.transfers, c.totals.txs, c.totals.pieces, c.totals.rewards, p.block_target_seconds,
                    p.block_reward(next), p.reward_base, p.halving_interval, p.next_halving(next), p.reward_maturity, p.launch_blocks, p.launch_reward))
            }
            ("GET", ["queued", h]) => {
                // a wallet must never sign a second cheque with a number already waiting: this lists them, uncapped
                let id = unhex(h).ok_or("bad hex")?;
                let m = self.mempool.lock().unwrap();
                let mut ns: Vec<u16> = m.iter().filter_map(|t| match t { Tx::ChequePiece { account, cheque, .. } | Tx::ChequeOpen { account, cheque, .. } if *account == id => Some(*cheque), _ => None }).collect();
                ns.sort_unstable(); ns.dedup();
                Ok(ns.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(","))
            }
            ("GET", ["commits", h, n]) => {
                // a registered, unspent cheque's commitments: 18 lines (columns), 10 hex each (rows), so a wallet can check its cells before revealing them
                let id = unhex(h).ok_or("bad hex")?;
                c.state.accounts.get(&id).zip(n.parse::<u16>().ok()).and_then(|(a, n)| a.commits.get(&n)).map(|x| x.lines(crate::tx::id_n(&id))).ok_or("no such cheque")
            }
            // the next block's target: a registration mined now must meet that one
            ("GET", ["regtarget"]) => Ok(c.state.next_reg_target(&c.params).0.iter().map(|l| format!("{l:016x}")).collect::<Vec<_>>().join(" ")),
            ("GET", ["proof", n]) => {
                let num: u32 = n.parse().map_err(|_| "bad number")?;
                let (id, _) = c.state.numbers.get(&num).filter(|_| is_final(c, num)).ok_or("no such number")?;   // not final: as if unknown
                let (leaf, path, root) = c.state.account_proof(id).ok_or("no proof")?;
                Ok(format!("state_root {}\nleaf {}\npath {}", hex(&root), hex(&leaf), path.iter().map(|x| hex(x)).collect::<Vec<_>>().join(" ")))
            }
            ("POST", ["tx"]) => {
                drop(st);
                // one transaction (reply "ok" or an error), or several, one per line, queued together so they land
                // in the same block (reply: one "ok" or reason per line)
                let lines: Vec<&str> = body.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
                if lines.len() > CHECK_MAX { return Err("too many transactions in one request"); }
                let mut txs = Vec::with_capacity(lines.len());
                for line in &lines { txs.push(Tx::decode(&mut R::new(&unhex(line).ok_or("bad hex")?))?); }
                if txs.len() == 1 { return self.submit_tx(txs.remove(0), None).map(|_| "ok".to_string()); }
                if txs.is_empty() { return Err("no transaction"); }
                Ok(self.submit_txs(txs, None).into_iter().map(|r| r.map_or_else(|e| e.to_string(), |_| "ok".to_string())).collect::<Vec<_>>().join("\n"))
            }
            ("POST", ["check"]) => {
                drop(st);
                let mut txs = Vec::new();
                if body.lines().filter(|l| !l.trim().is_empty()).count() > CHECK_MAX { return Err("too many transactions in one check"); }
                for line in body.lines().filter(|l| !l.trim().is_empty()) {
                    let raw = unhex(line).ok_or("bad hex")?;
                    txs.push(Tx::decode(&mut R::new(&raw))?);
                }
                if txs.iter().filter(|t| matches!(t, Tx::RegisterBook { .. } | Tx::RegisterBatch { .. })).count() > CHECK_REGS { return Err("too many registrations in one check"); }
                Ok(self.check_txs(&txs).into_iter().map(|r| match r { Ok(None) => "ok".to_string(), Ok(Some(rows)) => format!("ok {rows}"), Err(e) => e.to_string() }).collect::<Vec<_>>().join("\n"))
            }
            _ => Err("unknown route"),
        }
    }
}

/// A number is published only once it is final (number_maturity blocks deep): until then a replaced
/// block could still hand it to another book, so nobody should see it, share it or write it down.
/// Block rewards credited to `n` but not yet spendable (they join the balance reward_maturity blocks after their block).
fn pending_of(c: &crate::block::Chain, n: u32) -> u64 { c.state.pending.values().flatten().filter(|(p, _)| *p == n).map(|(_, amt)| amt).sum() }
fn is_final(c: &crate::block::Chain, n: u32) -> bool { c.state.numbers.get(&n).is_some_and(|(_, at)| at + c.params.number_maturity <= c.height()) }

fn account_text(c: &crate::block::Chain, id: &[u8]) -> String {
    let a = &c.state.accounts[id];
    // a number can receive once it is number_maturity blocks deep: ready_at is the first height that may hold such a cheque
    let ready_at = c.state.numbers.get(&a.number).map_or(0, |(_, at)| at + c.params.number_maturity);
    let mature = ready_at <= c.height();
    let number = if mature { format!("number {}\n", a.number) } else { String::new() };
    format!("id {}\n{number}balance {}\npending {}\nnonce {}\nbook_size {}\nunspent {}\nfunded {}\nmature {}\nready_at {}\nopen {}\nrevealed {}\nexpires {}\nsalt {}", hex(id), a.balance,
            pending_of(c, a.number), a.nonce.map_or("none".into(), |x| x.to_string()), a.book_size, a.commits.keys().map(|k| k.to_string()).collect::<Vec<_>>().join(","),
            a.funded, mature, ready_at, if a.open.is_empty() { "none".into() } else { a.open.keys().map(|k| k.to_string()).collect::<Vec<_>>().join(",") },
            // each open cheque's revealed digits, '.' for a column not yet on chain: a wallet checks its own cheque was
            // not pinned to someone else's digits before it shows the rest
            if a.open.is_empty() { "none".into() } else { a.open.iter().map(|(k, o)| format!("{k}:{}", o.digits.iter().map(|d| d.map_or('.', |d| (b'0' + d) as char)).collect::<String>())).collect::<Vec<_>>().join(",") },
            // the height each open cheque goes at, unfinished (its opening's block + piece_lifetime)
            if a.open.is_empty() { "none".into() } else { a.open.iter().map(|(k, o)| format!("{k}:{}", o.expiry)).collect::<Vec<_>>().join(",") },
            hex(&a.salt))
}

fn tx_line(t: &Tx) -> String {
    match t {
        Tx::Coinbase { payee, .. } => format!("reward to={payee}
"),
        Tx::RegisterBook { m, n256, book_size, root, batch, .. } => format!("register m={m} book_size={book_size} root={} cheques={} reg=pow account={}\n", hex(root), batch.cheques.len(), hex(&crate::tx::account_id(*m, *n256, root))),
        Tx::RegisterBatch { account, batch, .. } => format!("batch account={} start={} count={}\n", hex(account), batch.start, batch.count),
        Tx::ChequePiece { account, cheque, column, shares } => format!("piece account={} cheque={cheque} column={column} txid={} share={}\n", hex(account), hex(&t.txid()), shares.iter().map(|s| hex(s)).collect::<Vec<_>>().join(",")),
        Tx::Renew { account, start } => format!("renew account={} start={start}\n", hex(account)),
        Tx::ChequeOpen { account, cheque, pieces } => format!("open account={} cheque={cheque} columns={} txid={}\n", hex(account),
            pieces.iter().map(|x| x.0.to_string()).collect::<Vec<_>>().join(","), hex(&t.txid())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paths_and_connection_keys() {
        assert_eq!(normal("//template//0/"), "/template/0");
        assert_eq!(normal("/check/"), "/check");
        assert!(costly(&normal("//check")) && costly(&normal("/proof//3")) && !costly(&normal("/height/")));
        let ks = conn_keys("2001:db8:1:2ff::1".parse().unwrap());
        assert_eq!(ks.iter().map(|(k, _)| k.1.to_string()).collect::<Vec<_>>(), ["2001:db8:1:200::", "2001:db8:1::", "2001:db8::"]);
        assert_eq!(conn_keys("::ffff:10.0.0.1".parse().unwrap()), vec![((32, "10.0.0.1".parse().unwrap()), PER_IP)]);
    }
}

//! Wallet-facing HTTP interface, plain text, standard library only.
//!   GET  /height   GET /peers   GET /addrs (known peer addresses)   GET /tip                GET /block/<height>   (hex)   GET /summary/<height> (text)
//!   GET  /account/<number>    GET /id/<account id hex>   GET /lookup/<code> (start of the id after its scheme byte)
//!   (a number appears in any output only once it is final, number_maturity blocks deep; /account/<n> of a
//!   number not final yet answers only "pending" and its ready_at)
//!   GET /proof/<number>   GET /regtarget (4 LE limbs, hex)
//!   GET  /history/<number>  (newest first, the last block::HISTORY_CAP events: height kind key=value...; a cheque to yourself is listed as receive, then send)
//!   GET  /stats   (lifetime totals, and the reward schedule: reward of the next block, base, halving interval, next halving, maturity)
//!   GET  /mempool (count, then one line per waiting transaction in the /summary format, then a cheque line per waiting cheque whose recipient is readable)
//!   GET  /top[/N]  (richest N accounts, default 50: number balance book_size last_cheque unspent pending)
//!   GET  /template/<number>  (hex: the next block to mine, reward to that number (0 burns it), nonce 0)
//!   POST /tx  (body: hex-encoded tx, or several, one per line, queued together: one result per line)   POST /block (body: hex-encoded block, mined from a template)
//!   POST /check (body: one hex tx per line; dry run, nothing stored)
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

const RPC_PER_MINUTE: u32 = 120;   // requests one address may make per minute
const CHECK_MAX: usize = 64;       // transactions per /check or per batched /tx
const BODY_MAX: usize = 20 << 20;  // request body bytes (a large registration is a few MB of hex)
const RPC_THREADS: usize = 256;    // requests served at once
static ACTIVE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

impl Node {
    /// Simple per-address limiter: a fixed one-minute window.
    fn allow(&self, ip: std::net::IpAddr) -> bool {
        let mut l = self.rpc_limit.lock().unwrap();
        let now = std::time::Instant::now();
        let e = l.entry(ip).or_insert((0, now));
        if now.duration_since(e.1).as_secs() >= 60 { *e = (0, now); }
        e.0 += 1;
        if l.len() > 10_000 { l.retain(|_, v| now.duration_since(v.1).as_secs() < 60); }
        l.get(&ip).map_or(true, |e| e.0 <= RPC_PER_MINUTE)
    }
    pub fn serve_rpc(self: &Arc<Self>, addr: &str) -> std::io::Result<SocketAddr> {
        let l = TcpListener::bind(addr)?;
        let local = l.local_addr()?;
        let node = self.clone();
        std::thread::spawn(move || for mut s in l.incoming().flatten() {
            use std::sync::atomic::Ordering;
            if ACTIVE.load(Ordering::Relaxed) >= RPC_THREADS { let _ = write!(s, "HTTP/1.0 503 Busy\r\nContent-Length: 0\r\n\r\n"); continue; }
            ACTIVE.fetch_add(1, Ordering::Relaxed);
            let n = node.clone();
            std::thread::spawn(move || { let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| n.handle(s))); ACTIVE.fetch_sub(1, Ordering::Relaxed); });
        });
        Ok(local)
    }
    fn handle(&self, mut s: TcpStream) {
        // the operator's own tools on this machine are never limited
        if let Ok(a) = s.peer_addr() { if !a.ip().is_loopback() && !self.allow(a.ip()) { let _ = write!(s, "HTTP/1.0 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n"); return; } }
        let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(10)));   // a client that stops sending frees its thread
        let _ = s.set_write_timeout(Some(std::time::Duration::from_secs(10)));
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        let (head_end, body_len) = loop {
            match s.read(&mut tmp) { Ok(0) | Err(_) => return, Ok(n) => buf.extend_from_slice(&tmp[..n]) }
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..i]).to_string();
                let len = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0))).unwrap_or(0);
                if len > BODY_MAX { let _ = write!(s, "HTTP/1.0 413 Too Large\r\nContent-Length: 0\r\n\r\n"); return; }
                break (i + 4, len);
            }
            if buf.len() > 1 << 20 { return; }
        };
        while buf.len() < head_end + body_len { match s.read(&mut tmp) { Ok(0) | Err(_) => return, Ok(n) => buf.extend_from_slice(&tmp[..n]) } }
        let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
        let body = String::from_utf8_lossy(&buf[head_end..head_end + body_len]).to_string();
        let mut words = head.split_whitespace();
        let (method, path) = (words.next().unwrap_or(""), words.next().unwrap_or(""));
        let (code, text) = match self.route(method, path, &body) { Ok(t) => (200, t), Err(e) => (400, e.to_string()) };
        let _ = write!(s, "HTTP/1.0 {code} OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\n\r\n{text}", text.len());
    }
    pub fn route(&self, method: &str, path: &str, body: &str) -> Result<String, &'static str> {
        let seg: Vec<&str> = path.trim_matches('/').split('/').collect();
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
                self.submit_block(&b, None).map(|_| "accepted".to_string())
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
                for t in &b.txs { if let Tx::ChequePiece { account, cheque, .. } = t { if seen.insert((account.clone(), *cheque)) {
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
            ("GET", ["mempool"]) => {
                // store before mempool, the same lock order as submit_tx
                let m = self.mempool.lock().unwrap();
                let mut out = format!("count {}\n{}", m.len(), m.iter().map(|t| tx_line(t)).collect::<String>());
                // what each waiting cheque says so far, read from the pieces against the sender's commitments
                let mut seen: BTreeMap<(Vec<u8>, u16), [Option<u8>; COLS]> = BTreeMap::new();
                for t in m.iter() { if let Tx::ChequePiece { account, cheque, column, shares } = t {
                    let d = seen.entry((account.clone(), *cheque)).or_insert_with(|| c.state.accounts.get(account).and_then(|a| a.open.as_ref().filter(|o| o.n == *cheque)).map_or([None; COLS], |o| o.digits));
                    if let Some(x) = c.state.piece_digit(account, *cheque, *column, shares) { d[*column as usize] = Some(x); }
                } }
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
                Ok(out)
            }
            ("GET", ["top"]) | ("GET", ["top", _]) => {
                // richest accounts, sorted once per block and cached
                let n: usize = seg.get(1).and_then(|x| x.parse().ok()).unwrap_or(50).min(200);
                // ranked once per block, whatever N is asked for (so alternating N cannot force a re-sort)
                if let Some((h, head, rows)) = self.top_cache.lock().unwrap().as_ref() { if *h == c.height() { return Ok(head.clone() + &rows[..n.min(rows.len())].concat()); } }
                let mut v: Vec<&crate::state::Account> = c.state.accounts.values().collect();
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
            ("GET", ["regtarget"]) => Ok(c.state.reg_target.0.iter().map(|l| format!("{l:016x}")).collect::<Vec<_>>().join(" ")),
            ("GET", ["proof", n]) => {
                let num: u32 = n.parse().map_err(|_| "bad number")?;
                let (id, _) = c.state.numbers.get(&num).filter(|_| is_final(c, num)).ok_or("no such number")?;   // not final: as if unknown
                let (leaf, path) = c.state.account_proof(id).ok_or("no proof")?;
                Ok(format!("state_root {}\nleaf {}\npath {}", hex(&c.state.root()), hex(&leaf), path.iter().map(|x| hex(x)).collect::<Vec<_>>().join(" ")))
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
                Ok(self.check_txs(&txs).into_iter().map(|r| match r { Ok(()) => "ok".to_string(), Err(e) => e.to_string() }).collect::<Vec<_>>().join("\n"))
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
    format!("id {}\n{number}balance {}\npending {}\nnonce {}\nbook_size {}\nunspent {}\nfunded {}\nmature {}\nready_at {}\nopen {}", hex(id), a.balance,
            pending_of(c, a.number), a.nonce.map_or("none".into(), |x| x.to_string()), a.book_size, a.commits.keys().map(|k| k.to_string()).collect::<Vec<_>>().join(","),
            a.funded, mature, ready_at, a.open.as_ref().map_or("none".into(), |o| o.n.to_string()))
}

fn tx_line(t: &Tx) -> String {
    match t {
        Tx::Coinbase { payee, .. } => format!("reward to={payee}
"),
        Tx::RegisterBook { m, n256, book_size, root, batch, .. } => format!("register m={m} book_size={book_size} root={} cheques={} reg=pow account={}\n", hex(root), batch.cheques.len(), hex(&crate::tx::account_id(*m, *n256, root))),
        Tx::RegisterBatch { account, batch, .. } => format!("batch account={} start={} count={}\n", hex(account), batch.start, batch.count),
        Tx::ChequePiece { account, cheque, column, shares } => format!("piece account={} cheque={cheque} column={column} txid={} share={}\n", hex(account), hex(&t.txid()), shares.iter().map(|s| hex(s)).collect::<Vec<_>>().join(",")),
        Tx::Renew { account, start } => format!("renew account={} start={start}\n", hex(account)),
    }
}

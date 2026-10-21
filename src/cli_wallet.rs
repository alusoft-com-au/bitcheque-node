//! `bitcheque wallet`: a software wallet for one book from one seed (DESIGN.md §5, §10.12, §10.13).
use bitcheque::{crypto::{hex, sha256}, damm, message::{self, Message, COLS, PART_A, PAYEE_DIGITS}, params::{Params, COIN}, tx::Tx,
                u256::U256, wallet::{mine_registration, Book, Domain, BATCH, BOOK_SIZE}};
use std::path::Path;

/// The recipient as printed: 11 digits and the check digit (columns 0-11, printed part A).
const RECIPIENT: usize = PAYEE_DIGITS + 1;
/// How long a send waits for each half of a cheque to reach a block, unless --wait says otherwise.
const WAIT_SECONDS: u64 = 600;
/// Blocks the opening must be deep before the amount's 5 pieces leave this machine, unless --confirmations says otherwise.
const CONFIRMATIONS: u32 = 3;
/// The amount half is never released this close to the opening's expiry: it could land after the opening is gone.
const EXPIRY_MARGIN: u32 = 100;

/// A software wallet for one book from one seed: the same 256-cheque book the website prints, so a seed works in both.
/// `register` registers the first cheques (16 by default, `--cheques` for more), `more` the next ones, 16 per proof of work.
/// The book salt is derived from the seed, so the seed alone recreates the book. Talks to a node's RPC; keeps one
/// small file per book (~/.config/bitcheque/used-<id>: the last cheque number it signed, and its digits), so a number
/// never carries two messages. Cheque 0 is only ever the honesty check, sent with `register`; `send` and `sweep` never sign it.
pub fn wallet(args: &[String], opt: &dyn Fn(&str) -> Option<String>, p: &Params) -> Result<(), String> {
    let cmd = args.get(2).map(String::as_str).unwrap_or("");
    if cmd == "new" {
        let mut seed = Secret([0u8; 32]);
        std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom").map_err(|e| e.to_string())?, &mut seed.0).map_err(|e| e.to_string())?;
        println!("{}", hex(&seed.0));
        return Ok(());
    }
    let seed = read_seed(args, opt)?;
    let salt: [u8; 16] = sha256(&[b"bitcheque/salt".as_slice(), &seed.0].concat())[..16].try_into().unwrap();
    // the book holds its own copy of the seed: wiped when it is dropped, on every way out of `run`
    let book = Keys(Book { salt, n256: false, book_size: BOOK_SIZE, domains: vec![Domain(seed.0)], net: p.magic });
    drop(seed);
    run(cmd, args, opt, p, &book.0)
}

/// A completed cheque as an account's /history lists it: (height, cheque, to, amount, fee).
type Send = (u32, u16, u32, u64, u64);

/// What one node says about the book: the whole /id text, and the fields every decision rests on, which every node
/// asked must report alike (`key`).
struct View { a: Vec<(String, String)>, nonce: Option<u16>, open: Vec<u16>, expires: Vec<(u16, u32)> }
impl View {
    fn field(&self, k: &str) -> String { self.a.iter().find(|(x, _)| x == k).map(|(_, v)| v.clone()).unwrap_or_default() }
    fn key(&self) -> (Option<u16>, Vec<u16>, String, Vec<(u16, u32)>, String) { (self.nonce, self.open.clone(), self.field("revealed"), self.expires.clone(), self.field("number")) }
    /// Cheque n is over: its number is used (nonce reached it) and it is not the open one: completed, voided, or gone.
    fn done(&self, n: u16) -> bool { self.nonce.is_some_and(|x| x >= n) && !self.open.contains(&n) }
    /// The digits an open cheque shows on chain, None for a column not revealed (or a cheque not open).
    fn revealed(&self, n: u16) -> [Option<u8>; COLS] {
        let v = self.field("revealed");
        v.split(',').find_map(|e| e.strip_prefix(&format!("{n}:"))).filter(|d| d.len() == COLS)
            .map_or([None; COLS], |d| std::array::from_fn(|i| d.as_bytes()[i].checked_sub(b'0').filter(|&x| x <= 9)))
    }
    fn expiry(&self, n: u16) -> Option<u32> { self.expires.iter().find(|e| e.0 == n).map(|e| e.1) }
}

fn run(cmd: &str, args: &[String], opt: &dyn Fn(&str) -> Option<String>, p: &Params, book: &Book) -> Result<(), String> {
    let flag = |k: &str| args.iter().any(|a| a == k);
    // --rpc may be given several times, each one node or a comma list; a node named twice counts once
    let rpcs: Vec<String> = args.iter().enumerate().filter(|(_, a)| *a == "--rpc").filter_map(|(i, _)| args.get(i + 1))
        .flat_map(|v| v.split(',')).map(|r| r.trim().to_string()).filter(|r| !r.is_empty()).fold(vec![], |mut a, r| { if !a.contains(&r) { a.push(r); } a });
    let rest_only = cmd == "pieces" && flag("--rest");
    if rpcs.is_empty() && (cmd != "pieces" || rest_only) { return Err("--rpc ADDR needed".into()); }
    if rpcs.len() == 1 && (matches!(cmd, "send" | "sweep" | "void") || rest_only) {
        eprintln!("note: only one node asked (--rpc): give --rpc again with another node, reached another way, and every decision is cross-checked");
    }
    let rpc = rpcs.first().cloned().unwrap_or_default();
    let size = BOOK_SIZE;
    let cheques: u32 = opt("--cheques").map_or(Ok(BATCH), |v| v.parse()).map_err(|_| "bad --cheques")?;
    if !(1..=size).contains(&cheques) { return Err(format!("--cheques must be 1 to {size}")); }
    let confirmations: u32 = opt("--confirmations").map_or(Ok(CONFIRMATIONS), |v| v.parse()).ok().filter(|&k| k >= 1).ok_or("--confirmations takes a number of blocks, 1 or more")?;
    let wait: u64 = opt("--wait").map_or(Ok(WAIT_SECONDS), |w| w.parse()).map_err(|_| "bad --wait (seconds)")?;
    let id = hex(&book.id());
    let account_at = |rpc: &str| -> Result<Vec<(String, String)>, String> {
        Ok(http(rpc, "GET", &format!("/id/{id}"), "")?.lines().filter_map(|l| l.split_once(' ').map(|(k, v)| (clean(k), clean(v)))).collect())
    };
    let account = || account_at(&rpc);
    let record = || -> Result<Record, String> {
        let dir = opt("--state-dir").or(std::env::var("BITCHEQUE_STATE").ok()).map(std::path::PathBuf::from)
            .or(std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config/bitcheque")))
            .ok_or("nowhere to keep the used-cheque record: set HOME or BITCHEQUE_STATE, or pass --state-dir DIR")?;
        // a relative directory (or an empty HOME) would put the record wherever the command happens to run
        if !dir.is_absolute() { return Err(format!("the used-cheque record needs an absolute directory, not {:?}: check HOME, BITCHEQUE_STATE or --state-dir", dir)); }
        Record::open(&dir, &id, size)
    };
    let field = |a: &[(String, String)], k: &str| a.iter().find(|(x, _)| x == k).map(|(_, v)| v.clone()).unwrap_or_default();
    // everything a command sends goes in one request, so it all lands in the same block (a registration with its
    // cheque 0, or one half of a cheque). A batch already on the chain is refused as a duplicate, which is fine.
    let post_all = |txs: &[Tx]| -> Result<(), String> {
        let reply = http(&rpc, "POST", "/tx", &txs.iter().map(|t| hex(&t.encode())).collect::<Vec<_>>().join("\n"))?;
        match reply.lines().find(|l| !matches!(l.trim(), "ok" | "already in mempool" | "batch overlaps")) { None => Ok(()), Some(e) => Err(format!("node refused: {}", clean(e))) }
    };
    // what each node reports is only believed within this book
    let num = |v: &str, what: &str| -> Result<Option<u16>, String> {
        if v == "none" { return Ok(None); }
        v.parse::<u16>().ok().filter(|&n| (n as u32) < size).map(Some).ok_or(format!("a node reports {what} {}, not a cheque of this book: try another node", clean(v)))
    };
    let list = |v: &str, what: &str| -> Result<Vec<u16>, String> { v.split(',').filter(|x| !x.trim().is_empty()).map(|x| num(x.trim(), what).map(Option::unwrap)).collect() };
    // nonce: the last cheque used (opened); open: the cheque opened and not finished, with the digits revealed so far
    // and the height it goes at, unfinished
    let view_at = |r: &str| -> Result<View, String> {
        let a = account_at(r)?;
        if field(&a, "book_size") != size.to_string() { return Err(format!("{r} says this book has {} cheques, not {size}: try another node", clean(&field(&a, "book_size")))); }
        let open = if field(&a, "open") == "none" { vec![] } else { list(&field(&a, "open"), "open")? };
        let ex = field(&a, "expires");
        let expires = if ex == "none" { vec![] } else { ex.split(',').map(|e| e.split_once(':').and_then(|(n, h)| Some((num(n, "open").ok()??, h.parse::<u32>().ok()?))))
            .collect::<Option<Vec<_>>>().ok_or(format!("{r} gave a bad expires line: try another node"))? };
        if !open.iter().all(|n| expires.iter().any(|e| e.0 == *n)) { return Err(format!("{r} gave no expiry for an open cheque: try another node")); }
        Ok(View { nonce: num(&field(&a, "nonce"), "nonce")?, open, expires, a })
    };
    // every node's view, which must all say the same (else Err, or Ok(None) when `lenient`: a wait goes on polling)
    let agreed = |lenient: bool| -> Result<Option<View>, String> {
        let mut views = Vec::new();
        for r in &rpcs { match view_at(r) { Ok(v) => views.push(v), Err(e) if !lenient => return Err(e), Err(_) => return Ok(None) } }
        if views.windows(2).any(|w| w[0].key() != w[1].key()) {
            if lenient { return Ok(None); }
            return Err("the nodes disagree on this book (its number, last cheque, open cheque, revealed digits or expiry): wait a block and try again".into());
        }
        Ok(views.into_iter().next())
    };
    // the lowest and highest tip height among the nodes
    let heights = || -> Result<(u32, u32), String> {
        let mut hs = Vec::new();
        for r in &rpcs { hs.push(http(r, "GET", "/height", "")?.trim().parse::<u32>().map_err(|_| format!("{r} gave a bad height"))?); }
        Ok((*hs.iter().min().unwrap(), *hs.iter().max().unwrap()))
    };
    // whether the amount of an open cheque may be released: its opening `confirmations` blocks deep on every node (the
    // opening's block is its expiry less piece_lifetime), and far enough from its expiry. Err when it never may.
    let deep = |v: &View, n: u16| -> Result<bool, String> {
        let Some(exp) = v.expiry(n) else { return Ok(false) };
        let Ok((low, high)) = heights() else { return Ok(false) };   // a node not answering: not yet
        let left = exp.saturating_sub(high);
        if left < EXPIRY_MARGIN { return Err(format!("cheque {n}'s opening expires in {left} blocks: too close to send its amount (it could land after the opening is gone). Run `wallet void` to close it, then send again")); }
        Ok(low + 1 >= exp.saturating_sub(p.piece_lifetime) + confirmations)
    };
    // the account's completed cheques by one node's /history (newest first, its last block::HISTORY_CAP events); an
    // account with no final number has none
    let sends_at = |r: &str, v: &View| -> Result<Vec<Send>, String> {
        let n = v.field("number");
        if n.is_empty() { return Ok(vec![]); }
        Ok(http(r, "GET", &format!("/history/{n}"), "")?.lines().filter_map(|l| {
            let mut w = l.split_whitespace();
            let h = w.next()?.parse().ok()?;
            if w.next()? != "send" { return None; }
            let kv: Vec<(&str, &str)> = w.filter_map(|x| x.split_once('=')).collect();
            let g = |k: &str| kv.iter().find(|e| e.0 == k).map(|e| e.1);
            Some((h, g("cheque")?.parse().ok()?, g("to")?.parse().ok()?, g("amount")?.parse().ok()?, g("fee")?.parse().ok()?))
        }).collect())
    };
    // a completed cheque that is this payment: its recipient, amount (a sweep: any) and fee
    let pays = |s: &Send, m: &Message| s.2 == m.payee && s.4 == m.tier as u64 * p.fee_unit && m.amount().map_or(true, |a| a == s.3);
    // what became of cheque n by every node's history: Some((block, whether it paid `m`)) once it completed, None if no
    // node lists it (voided, overtaken by a later cheque, expired, or too old to be listed). The nodes must agree.
    let fate = |v: &View, n: u16, m: &Message| -> Result<Option<(u32, bool)>, String> {
        let mut seen = None;
        for (i, r) in rpcs.iter().enumerate() {
            let f = sends_at(r, v)?.iter().find(|s| s.1 == n).map(|s| (s.0, pays(s, m)));
            if i > 0 && f != seen { return Err(format!("the nodes' histories disagree on cheque {n}: wait a block and try again")); }
            seen = f;
        }
        Ok(seen)
    };
    let tampered = |n: u16| format!("cheque {n} shows cells this machine never sent (someone holds a printed part of it?): nothing more is sent on it. \
        Run `wallet void` to close it, and sweep to a new book: a part of this book's cheques may be exposed");
    // other digits on cheque n: from another send from this seed (another machine or state dir) when the nodes read a
    // whole recipient from its cells, on chain or waiting to be mined; else cells never sent from here (tampered)
    let taken = |n: u16| -> String {
        let to = view_at(&rpc).ok().and_then(|v| { let r = v.revealed(n); r[..=PAYEE_DIGITS].iter().copied().collect::<Option<Vec<u8>>>() })
            .filter(|d| damm::valid(d)).map(|d| d[..PAYEE_DIGITS].iter().fold(0u64, |a, &x| a * 10 + x as u64).to_string())
            .or_else(|| http(&rpc, "GET", "/mempool", "").ok()?.lines().find_map(|l| {
                let kv: Vec<(&str, &str)> = l.strip_prefix("cheque ")?.split_whitespace().filter_map(|x| x.split_once('=')).collect();
                let g = |k: &str| kv.iter().find(|e| e.0 == k).map(|e| e.1);
                (g("account")? == id && g("cheque")? == n.to_string()).then(|| g("to").map(clean)).flatten()
            }));
        match to {
            Some(to) => format!("cheque {n} was taken by another send from this seed (another machine or state dir, to {to}): nothing was sent on it here. \
                Once that one is finished or voided, run this again: it goes on a new cheque"),
            None => tampered(n),
        }
    };
    // a dry run of `txs` on every node: Ok(the txs the first node still needs) when each says "ok" with the rows of our
    // digits, or that it has the cells already; Err (tampered or refused) otherwise
    let dry_run = |n: u16, txs: &[Tx], digits: &[u8; COLS], again: &str| -> Result<Vec<Tx>, String> {
        let mut send = Vec::new();
        for r in &rpcs {
            let reply = http(r, "POST", "/check", &txs.iter().map(|t| hex(&t.encode())).collect::<Vec<_>>().join("\n")).map_err(|e| format!("{e}\ncheque {n} may still be live: {again}"))?;
            let lines: Vec<&str> = reply.lines().map(str::trim).collect();
            if lines.len() != txs.len() { return Err(format!("{r} gave a bad dry run\ncheque {n} may still be live: {again}")); }
            for (t, l) in txs.iter().zip(lines) {
                // the rows the node read from our cells must be our digits: else it holds other commitments than this book's
                let ours: String = match t { Tx::ChequePiece { column, .. } => vec![*column], Tx::ChequeOpen { pieces, .. } => pieces.iter().map(|x| x.0).collect(), _ => vec![] }
                    .iter().map(|&c| char::from(b'0' + digits[c as usize])).collect();
                if let Some(rows) = l.strip_prefix("ok ") {
                    if rows != ours { return Err(format!("{r} reads cheque {n}'s cells as {}, not {ours}: it does not hold this book as registered; nothing more is sent. Try another node", clean(rows))); }
                    if r == &rpc { send.push(t.clone()); }
                }
                else if matches!(l, "column revealed with other digits" | "cheque open with other digits") { return Err(taken(n)); }
                else if !matches!(l, "column already revealed" | "cheque already open") { return Err(format!("{r} refuses cheque {n}: {}\ncheque {n} may still be live: {again}", clean(l))); }
            }
        }
        Ok(send)
    };
    // poll every node until `ready` holds on the view they all agree on, or `wait` seconds pass (Ok(false))
    let poll = |ready: &dyn Fn(&View) -> Result<bool, String>| -> Result<bool, String> {
        let start = std::time::Instant::now();
        loop {
            if let Some(v) = agreed(true)? { if ready(&v)? { return Ok(true); } }
            if start.elapsed().as_secs() >= wait { return Ok(false); }
            std::thread::sleep(std::time::Duration::from_secs(3));
        }
    };
    let parse_digits = |d: &str| -> Result<[u8; COLS], String> {
        let digits: [u8; COLS] = d.bytes().map(|c| c.wrapping_sub(b'0')).collect::<Vec<_>>().try_into().map_err(|_| "--digits must be 18 digits")?;
        if digits.iter().any(|&x| x > 9) { return Err("--digits must be 18 digits".into()); }
        Ok(digits)
    };
    if cmd == "pieces" {
        // raw transactions as hex, for tests and hand use: first the opening alone, recorded like any cheque (so the number
        // is never signed again with other digits); the 5 remaining pieces only with --rest, for the cheque recorded here
        // and once its opening is deep enough on chain with these digits
        let cheque: u16 = opt("--cheque").ok_or("--cheque N needed")?.parse().map_err(|_| "bad --cheque")?;
        if cheque == 0 || cheque as u32 >= size { return Err(format!("--cheque must be 1 to {} (0 is the honesty check)", size - 1)); }
        let digits = parse_digits(&opt("--digits").ok_or("--digits needed")?)?;
        let rec = record()?;
        let (open, rest) = book.halves(cheque, &digits);
        if rest_only {
            if rec.read()? != Some((cheque, Some(digits))) { return Err(format!("this machine has no record of cheque {cheque} with these digits: print its opening first (without --rest)")); }
            let v = agreed(false)?.unwrap();
            if v.revealed(cheque).iter().zip(digits).any(|(r, d)| r.is_some_and(|r| r != d)) { return Err(tampered(cheque)); }
            if !v.open.contains(&cheque) || v.revealed(cheque)[..=PART_A].iter().zip(&digits).any(|(r, d)| *r != Some(*d)) { return Err(format!("cheque {cheque} is not open with these digits on chain: send its opening first, and wait for it")); }
            if !deep(&v, cheque)? { return Err(format!("cheque {cheque}'s opening is not {confirmations} blocks deep yet: wait, and ask again")); }
            for t in rest { println!("{}", hex(&t.encode())); }
            return Ok(());
        }
        if let Some((n, d)) = rec.read()? { if cheque < n || (cheque == n && d != Some(digits)) {
            return Err(format!("this machine signed cheques up to {n} already: cheque {cheque} is never signed with other digits"));
        } }
        rec.write(cheque, &digits)?;
        println!("{}", hex(&open.encode()));
        return Ok(());
    }
    match cmd {
        "info" => match account() {
            Ok(a) => { for (k, v) in a { println!("{k} {v}"); } }
            Err(_) => println!("id {id}\nnot registered"),
        },
        "register" | "more" => {
            // a rerun of a registration that went through (a lost reply, say) has nothing left to do
            if cmd == "register" && account().is_ok() { println!("id {id}\nalready registered"); return Ok(()); }
            // `more` starts after the highest cheque the chain knows (unspent or used), at a batch boundary
            let first = if cmd == "register" { 0 } else {
                let a = account()?;
                let top = field(&a, "unspent").split(',').chain([field(&a, "nonce").as_str()]).filter_map(|x| x.parse::<u32>().ok()).max().ok_or("account has no cheques")?;
                (top / BATCH).checked_add(1).and_then(|b| b.checked_mul(BATCH)).ok_or("the node reports a cheque past any book: try another node")?
            };
            if first >= size { return Err("every cheque of this book is registered already".into()); }
            let rec = if cmd == "register" { Some(record()?) } else { None };   // held until the honesty check is posted
            let limbs: Vec<u64> = http(&rpc, "GET", "/regtarget", "")?.split_whitespace().map(|w| u64::from_str_radix(w, 16).unwrap_or(0)).collect();
            let target = U256(limbs.try_into().map_err(|_| "bad regtarget")?);
            // a node can only make registration harder, never impossible (2^56 hashes would take years), and never
            // easier than consensus allows (the registration would be refused)
            if target < U256::one_shl(200) { return Err("the node's registration target is implausibly hard: try another node".into()); }
            if target > p.reg_pow_target { return Err("the node's registration target is easier than the chain allows: try another node".into()); }
            // a little below it, so registrations in the block before ours (which make the next target harder) do not void the work
            let target = target.div_u64(16).mul_u64(15);
            // the proof of work names the node's tip, so it is valid for the next reg_anchor_window blocks only
            let anchor: [u8; 32] = bitcheque::rpc::unhex(&http(&rpc, "GET", "/tip", "")?).and_then(|v| v.try_into().ok()).ok_or("bad tip")?;
            let regs = book.registrations(first, first + cheques - 1);
            let mut txs: Vec<_> = regs.iter().map(|reg| mine_registration(reg.clone(), anchor, target)).collect(); // each batch of 16 pays its own proof of work
            // honesty check: cheque 0, zero coins, to nobody, one opening of all 18 columns. Recorded before it is signed,
            // so if it never reaches the chain no later cheque takes number 0
            let mut honesty = false;
            let zero = Message::new(0, 0, 0, 0);
            if let Some(r) = &rec { match r.read()? {
                None | Some((0, _)) => { r.write(0, &zero.digits())?; txs.push(book.open_all(0, &zero.digits())); honesty = true; }
                Some((n, _)) => eprintln!("warning: this machine signed cheques up to {n} already: the honesty check (cheque 0) is not sent again"),
            } }
            post_all(&txs)?;
            let last = ((first / BATCH + regs.len() as u32) * BATCH).min(size) - 1;
            println!("id {id}\ncheques {first}-{last} registered{}", if honesty { ", honesty check (cheque 0) sent" } else { "" });
        }
        "send" | "sweep" | "void" => {
            let tier: u8 = if cmd == "void" { 0 } else { opt("--fee").map_or(Ok(1), |f| f.parse()).ok().filter(|&t| t <= 9).ok_or("--fee is a tier from 1 to 9")? };
            // tier 0 is for zero cheques, and a zero cheque is a void: `wallet void` writes it
            if tier == 0 && cmd != "void" { return Err("--fee 0 is only for a void (zero coins to nobody): use `wallet void`, or a fee tier from 1 to 9".into()); }
            // a sweep (mantissa 0000, exponent 9) moves the whole balance minus the fee: how a used-up book moves on.
            // A void is zero coins to nobody: once in a block, no lower cheque can ever complete (§10.13)
            let to = if cmd == "void" { 0 } else { payee(&opt("--to").ok_or("--to NUMBER needed: the recipient's number and check digit, as NNNNNNNNNNN-C (or N-C)")?)? };
            let (mantissa, exponent) = if cmd == "sweep" { (0, 9) } else if cmd == "void" { (0, 0) } else {
                let units = coins(&opt("--amount").ok_or("--amount COINS needed")?)?;
                (0..=9u32).find_map(|e| { let d = 10u64.pow(e); (units % d == 0 && units / d <= 9999).then(|| ((units / d) as u16, e as u8)) })
                    .ok_or("amount needs at most 4 significant digits")?
            };
            let msg = Message::new(to, mantissa, exponent, tier);
            // checked as consensus reads it before anything is recorded or signed: a cheque the chain refuses is only
            // refused at its last piece, and its number is used by then
            match message::parse(&msg.digits()) { Ok(m) if m == msg => {} Ok(_) => return Err("the cheque does not read back as written".into()), Err(e) => return Err(format!("not a valid cheque: {e}")) }
            if to == 0 && !msg.is_zero() && !flag("--burn") {
                return Err("number 0 is nobody: coins sent to it go to the block's miner. Pass --burn if that is really what you want".into());
            }
            let digits = msg.digits();
            let again_flag = flag("--again");
            // locked from here until the cheque is in a block: another run waits, then sees this cheque's number
            let rec = record()?;
            let used = rec.read()?;
            // every node asked must report the book alike (MEDIUM-4: one node could hide an open or queued cheque)
            let v = agreed(false)?.unwrap();
            // the cheque this machine signed last, if it is not over yet (cheque 0 as the honesty check moves nothing and
            // has nothing below it to void)
            let honesty = |n: u16, d: Option<[u8; COLS]>| n == 0 && d.map_or(true, |d| d == [0; COLS]);
            let live = used.filter(|&(n, d)| !honesty(n, d) && !v.done(n));
            // the same payment as the cheque recorded here (same recipient, amount and fee)
            let same = used.filter(|&(n, d)| !honesty(n, d) && d == Some(digits)).map(|u| u.0);
            if let Some(n) = same.filter(|&n| v.done(n) && cmd != "void") {
                // over: what the account's history says became of it
                match fate(&v, n, &msg)? {
                    Some((h, true)) if !again_flag => return Err(format!("payment already made (cheque {n}): this machine wrote this same cheque as cheque {n}, \
                        and it paid in block {h}. Pass --again to pay the same again on a new cheque")),
                    Some((_, false)) => eprintln!("cheque {n} carried another payment from this seed (another machine or state dir) and never this one: it goes on a new cheque"),
                    None if !again_flag => return Err(format!("payment already made (cheque {n})? This machine wrote this same cheque as cheque {n}, and it is over \
                        but not in the account's recent history: closed unpaid (voided, overtaken by a later cheque, or expired), or paid too long ago to be listed. \
                        `wallet info` and the account's history show which. Pass --again to pay it on a new cheque")),
                    _ => {}
                }
            }
            // the record's cheque may still be in flight (not over, or over but not in the account's history): one node
            // alone could hide what became of it, or a cheque sent from elsewhere, so every opening needs two that agree
            let in_flight = |n: u16| -> Result<bool, String> { Ok(!v.done(n) || fate(&v, n, &msg)?.is_none()) };
            let one_node = |n: u16| format!("cheque {n}, the last this machine signed, may still be in flight (it is not in the account's history as finished), \
                and only one node was asked: it could be hiding what became of it, or a cheque sent from another machine. Give another node too (--rpc A --rpc B)");
            // what the chain would refuse at completion, from what it says publicly, before any cell leaves this machine:
            // the balance, and a recipient every node knows as a final number (a cheque to a number nobody holds yet is void)
            let funds = |v: &View| -> Result<(), String> {
                let balance: u64 = v.field("balance").parse().map_err(|_| "the node gave no balance")?;
                let fee = tier as u64 * p.fee_unit;
                let amount = msg.amount().unwrap_or(0);
                if balance < amount + fee { return Err(format!("balance {} is less than {} coins and the fee", balance as f64 / COIN as f64, (amount + fee) as f64 / COIN as f64)); }
                if to != 0 { for r in &rpcs {
                    let t = http(r, "GET", &format!("/account/{to}"), "").unwrap_or_default();
                    if !t.lines().any(|l| l == format!("number {to}")) { return Err(format!("{r}: account {to} is not a final number yet (or does not exist)")); }
                    if !t.lines().any(|l| l == "funded true") && r == &rpc {
                        eprintln!("warning: account {to} is not permanent yet: until it holds {} coin(s) at once it expires with its balance, so smaller amounts sent to it may be burned", p.min_fund as f64 / COIN as f64);
                    }
                } }
                Ok(())
            };
            // a void again after a void that is over: nothing new is live (it would be the record's cheque), so that void stands
            let resumed = same.filter(|_| live.is_some() || cmd == "void");
            let cheque = if let Some(n) = resumed {
                // the same cheque again (a lost reply, a half-sent cheque): finished, never re-written on another number
                if live.is_some() { eprintln!("cheque {n} is this same cheque and is not finished yet: finishing it"); funds(&v)?; } else { eprintln!("cheque {n} is this same void, done already"); }
                n
            } else {
                if let Some((n, _)) = live.filter(|_| cmd != "void") {
                    return Err(format!("cheque {n} may still be live: wait for it, or run `wallet void` (a zero cheque on the next number that kills it once in a block); never re-write a payment on the next number"));
                }
                // one node could hide an open or queued cheque sent from elsewhere (another machine, the website, a restored
                // seed), so a new cheque needs two that agree, or the holder's word that this book signs here only; and
                // never one node while the record's cheque may still be in flight
                if rpcs.len() < 2 {
                    if let Some((n, _)) = used.filter(|&(n, d)| !honesty(n, d)) { if in_flight(n)? { return Err(one_node(n)); } }
                    if !flag("--fresh") { return Err(if used.map_or(true, |(n, _)| n == 0) {
                        "this machine has no record of the book's cheques: give two or more nodes that agree (--rpc A --rpc B), or pass --fresh if this book has never signed a cheque anywhere else".into()
                    } else {
                        "only one node was asked: it could be hiding a cheque sent from another machine, the website or a restored seed, and a new cheque on top of that \
                         would put a second message on its number. Give two or more nodes that agree (--rpc A --rpc B), or pass --fresh if this book signs cheques on this machine only".into()
                    }); }
                }
                // this same payment made already from anywhere (another machine, a restored seed, a new --state-dir): in
                // the account's history over about the last day, open on chain with these digits, or waiting to be mined.
                // An opening lives piece_lifetime blocks, so an older one still in flight is caught as open or waiting.
                if cmd != "void" && !again_flag {
                    let day = 86_400 / p.block_target_seconds.max(1);
                    let tip = heights()?.1;
                    for r in &rpcs { if let Some(s) = sends_at(r, &v)?.into_iter().find(|s| pays(s, &msg) && tip.saturating_sub(s.0) < day) {
                        return Err(format!("payment already made (cheque {}): the account's history shows this same payment (to {to}, same amount and fee) in block {}, \
                            sent from another machine or state dir. Pass --again to pay the same again on a new cheque", s.1, s.0));
                    } }
                    if let Some(n) = v.open.iter().copied().find(|&n| v.revealed(n)[..=PART_A].iter().zip(&digits).all(|(r, d)| *r == Some(*d))) {
                        return Err(format!("cheque {n} is open on chain with this same payment (to {to}), sent from another machine or state dir: finish it there, or wait for it. \
                            Pass --again to pay the same again on a new cheque (which ends cheque {n} unfinished)"));
                    }
                    for r in &rpcs { for l in http(r, "GET", "/mempool", "")?.lines() {
                        let kv: Vec<(&str, &str)> = l.strip_prefix("cheque ").unwrap_or("").split_whitespace().filter_map(|x| x.split_once('=')).collect();
                        let g = |k: &str| kv.iter().find(|e| e.0 == k).map(|e| e.1);
                        if g("account") == Some(id.as_str()) && g("to") == Some(to.to_string().as_str()) && g("amount").map_or(true, |a| msg.amount().map_or(true, |m| a == m.to_string())) {
                            return Err(format!("cheque {} is waiting to be mined to this same recipient ({to}), sent from another machine or state dir: wait for the next block and run \
                                this again (if it is this same payment it is then refused as made). Pass --again to pay the same again on a new cheque", clean(g("cheque").unwrap_or("?"))));
                        }
                    } }
                }
                let (mut queued, mut unspent): (Vec<u16>, Vec<Vec<u16>>) = (v.open.clone(), vec![]);
                for r in &rpcs {
                    unspent.push(list(&field(&account_at(r)?, "unspent"), "unspent")?);
                    // never two cheques with one number: skip those waiting in a node's queue (asked fresh, failing hard if a node will not say)
                    queued.extend(list(&http(r, "GET", &format!("/queued/{id}"), "")?, "queued")?);
                }
                // the lowest cheque above everything used or signed here before, neither open nor queued (a node's answers may
                // be a few seconds old), and never 0, the honesty check's number
                let floor = [used.map(|u| u.0), v.nonce].iter().flatten().map(|&n| n + 1).max().unwrap_or(1).max(1);
                let cheque = unspent[0].iter().copied().filter(|&n| n >= floor && !queued.contains(&n) && unspent.iter().all(|u| u.contains(&n))).min().ok_or("no unused cheques left")?;
                // opening a cheque burns every lower one forever: a stale or lying node must not make this wallet jump far
                if cheque - floor > 3 {
                    if !flag("--force-skip") { return Err(format!("the next free cheque looks like {cheque}, which would burn cheques {floor}-{} forever; the node may be stale or lying: try another (--rpc A --rpc B asks both), or pass --force-skip if you are sure", cheque - 1)); }
                    eprintln!("warning: --force-skip: cheques {floor}-{} are burned forever", cheque - 1);
                }
                // the remaining checks happen here, from what the chain says publicly: no cell leaves this machine before
                // the cheque is sent for real, and exactly one cheque is signed per payment
                funds(&v)?;
                // the last cheque of a book is kept for the sweep to a new book (DESIGN.md §10.11): spent on anything
                // else, whatever is left in the account can never move again
                if cmd == "send" && cheque as u32 == size - 1 && !flag("--last") {
                    return Err(format!("cheque {cheque} is the last one in this book: keep it for `wallet sweep --to <new book>`, or pass --last to spend it anyway"));
                }
                // recorded, with its digits, before anything is signed or sent: once its cells may have left this
                // machine the number is used, and only these digits may ever go out on it
                rec.write(cheque, &digits)?;
                cheque
            };
            let again = if cmd == "void" { "run `wallet void` again" } else { "run the same command again to finish it, or `wallet void` to cancel it" };
            let other = |v: &View| v.revealed(cheque).iter().zip(digits).any(|(r, d)| r.is_some_and(|r| r != d));
            // a void goes in one transaction, all 18 columns: nothing in it to protect. A payment's opening first (the
            // recipient and one amount column), and its 5 remaining pieces only once that is deep enough in a block (§10.12)
            let (open, rest) = if cmd == "void" { (book.open_all(cheque, &digits), vec![]) } else { book.halves(cheque, &digits) };
            let v = agreed(false)?.unwrap();
            if other(&v) { return Err(taken(cheque)); }
            if !v.done(cheque) && !v.open.contains(&cheque) {
                // an opening for the record's cheque from an earlier run: it may be in flight, so never on one node's word
                if resumed.is_some() && rpcs.len() < 2 { return Err(one_node(cheque)); }
                let send = dry_run(cheque, std::slice::from_ref(&open), &digits, again)?;
                // opened by someone else between the dry run and the post (two of the user's machines at once)
                if !send.is_empty() { post_all(&send).map_err(|e| if e.contains("cheque already open") || e.contains("with other digits") { taken(cheque) } else { format!("{e}\ncheque {cheque} may still be live: {again}") })?; }
            }
            // the cheque numbers waiting in some node's mempool
            let waiting = || -> Result<bool, String> { for r in &rpcs { if list(&http(r, "GET", &format!("/queued/{id}"), "")?, "queued")?.contains(&cheque) { return Ok(true); } } Ok(false) };
            let mut pending = false;
            let in_block = if cmd == "void" { poll(&|v| Ok(v.done(cheque)))? } else {
                // the opening counts once every node shows exactly our digits on this open cheque, deep enough
                let ready = poll(&|v| {
                    if other(v) { return Err(taken(cheque)); }
                    if v.done(cheque) { return Ok(true); }
                    Ok(v.open.contains(&cheque) && v.revealed(cheque)[..=PART_A].iter().zip(&digits).all(|(r, d)| *r == Some(*d)) && deep(v, cheque)?)
                })?;
                if !ready { return Err(format!("cheque {cheque} is half sent: its opening is not {confirmations} blocks deep on every node after {wait} seconds; {again}")); }
                // released only now, and only on what every node agrees on: our digits, deep enough, not near expiry
                let v = agreed(false)?.unwrap();
                if other(&v) { return Err(taken(cheque)); }
                if !v.done(cheque) {
                    if !deep(&v, cheque)? { return Err(format!("cheque {cheque}'s opening is no longer {confirmations} blocks deep on every node (a reorganisation?); {again}")); }
                    // pieces of it waiting to be mined already (a lost reply): a node's dry run reads them as finishing it
                    pending = waiting()?;
                    if pending { eprintln!("cheque {cheque}: waiting for the pieces already sent to be mined"); } else {
                        let send = dry_run(cheque, &rest, &digits, again)?;
                        if !send.is_empty() { post_all(&send).map_err(|e| format!("{e}\ncheque {cheque} may still be live: {again}"))?; }
                    }
                }
                poll(&|v| { if other(v) { return Err(taken(cheque)); } Ok(v.done(cheque)) })?
            };
            // over: a payment counts as made only when the account's history shows this cheque paying it (a void from
            // another machine, a later cheque, an expiry or a recipient not final at completion all end it unpaid)
            if in_block && cmd != "void" {
                let v = agreed(false)?.unwrap();
                match fate(&v, cheque, &msg)? {
                    Some((_, true)) => {}
                    Some(_) => return Err(format!("cheque {cheque} was finished carrying another payment from this seed (another machine or state dir): this payment was not made. \
                        Run this again to write it on a new cheque")),
                    None => return Err(format!("cheque {cheque} closed without paying {to}: {}. Nothing was paid; pass --again to write it on a new cheque",
                        match v.nonce { Some(x) if x > cheque => format!("cheque {x} went into a block after it (a void or a send from another machine with this seed), which ends every lower cheque"),
                                        _ => "it expired, or its recipient was not a final number when it completed".into() })),
                }
            }
            drop(rec);
            let what = if cmd == "sweep" { format!("{} sweeps the whole balance to {to}, fee tier {tier}", msg.display()) }
                else if cmd == "void" { format!("{} voids every lower cheque", msg.display()) }
                else { format!("{} to {to}, {} coins, fee tier {tier}", msg.display(), msg.amount().unwrap_or(0) as f64 / COIN as f64) };
            if in_block { println!("cheque {cheque} sent: {what}"); }
            else if cmd == "void" { return Err(format!("void cheque {cheque} posted but not in a block after {wait} seconds: the cheque it voids may still complete; {again}")); }
            else if pending { return Err(format!("cheque {cheque}: still waiting for the pieces already sent to be mined after {wait} seconds: {what}; run this again later")); }
            else { println!("cheque {cheque} posted, not in a block after {wait} seconds: {what}; `wallet info` shows it done when nonce reaches {cheque}"); }
        }
        _ => return Err("wallet commands: new, info, register, more, send, sweep, void, pieces".into()),
    }
    Ok(())
}

/// The seed: never from the command line (ps and shell history show it), never printed in an error, and dropped from
/// the environment once read, so nothing this process might start inherits it. (Linux still shows the environment the
/// process started with in /proc/self/environ, to its own user and root: --seed-file is better.) Every copy this
/// code makes is wiped when done; core dumps are not turned off (std alone cannot).
fn read_seed(args: &[String], opt: &dyn Fn(&str) -> Option<String>) -> Result<Secret, String> {
    if args.iter().any(|a| a == "--seed") { return Err("--seed is gone (every user of the machine can read a command line): use --seed-file FILE or BITCHEQUE_SEED".into()); }
    let env_seed = std::env::var("BITCHEQUE_SEED").ok();
    std::env::remove_var("BITCHEQUE_SEED");
    let mut text = String::with_capacity(4096);   // room enough that reading never moves it, leaving a copy behind
    let read = match (opt("--seed-file"), env_seed) {
        (Some(f), e) => {
            if let Some(e) = e { wipe_string(e); }
            if f == "-" { std::io::Read::read_to_string(&mut std::io::stdin(), &mut text).map(drop).map_err(|e| e.to_string()) }
            else { read_seed_file(&f, &mut text) }
        }
        (None, Some(t)) => { text.push_str(&t); wipe_string(t); Ok(()) }
        _ => Err("the seed is needed: --seed-file FILE (or - for standard input), or BITCHEQUE_SEED".into()),
    };
    let seed = read.and_then(|_| {
        let t = text.trim();
        let mut s = Secret([0u8; 32]);
        if t.len() != 64 || !t.is_ascii() { return Err("seed must be 32 bytes of hex".to_string()); }
        for (i, b) in s.0.iter_mut().enumerate() { *b = u8::from_str_radix(&t[2 * i..2 * i + 2], 16).map_err(|_| "seed must be 32 bytes of hex")?; }
        Ok(s)
    });
    wipe_string(text);
    seed
}

/// The seed file is opened once, checked through that handle (private to its owner, who must be this user), and
/// read from the same handle, so it cannot be swapped between the check and the read.
fn read_seed_file(f: &str, text: &mut String) -> Result<(), String> {
    let mut file = std::fs::File::open(f).map_err(|e| format!("{f}: {e}"))?;
    #[cfg(unix)] { use std::os::unix::fs::MetadataExt;
        let m = file.metadata().map_err(|e| format!("{f}: {e}"))?;
        if m.mode() & 0o077 != 0 { return Err(format!("{f}: others can read this seed file (mode {:o}): chmod 600 {f}", m.mode() & 0o777)); }
        if my_uid().is_some_and(|u| u != m.uid()) { return Err(format!("{f}: this seed file belongs to another user (uid {})", m.uid())); } }
    std::io::Read::read_to_string(&mut file, text).map(drop).map_err(|e| format!("{f}: {e}"))
}

/// --to: the recipient as printed, 11 digits and the Damm check digit (NNNNNNNNNNN-C or all 12 together), or as the
/// explorer shows it, the number without its leading zeros (N-C, the check digit still over all 11). The check digit is
/// the holder's, never computed here, so a mistyped number is caught instead of paying a stranger.
fn payee(s: &str) -> Result<u32, String> {
    let bad = || format!("--to takes the recipient's number with its check digit, as printed (NNNNNNNNNNN-C) or as the explorer shows it (N-C), not {}", clean(s));
    let all = match s.split_once('-') { Some((n, c)) if (1..=PAYEE_DIGITS).contains(&n.len()) && c.len() == 1 => format!("{n:0>PAYEE_DIGITS$}{c}"), None if s.len() == RECIPIENT => s.to_string(), _ => return Err(bad()) };
    if !all.bytes().all(|c| c.is_ascii_digit()) { return Err(bad()); }
    let d: Vec<u8> = all.bytes().map(|c| c - b'0').collect();
    if !damm::valid(&d) { return Err(format!("--to {}: the check digit does not match: the number is mistyped", clean(s))); }
    u32::try_from(d[..PAYEE_DIGITS].iter().fold(0u64, |a, &x| a * 10 + x as u64)).map_err(|_| bad())
}

/// "1.5" -> 150_000_000 base units, exact (8 decimals at most, digits only).
fn coins(s: &str) -> Result<u64, String> {
    let (w, f) = s.split_once('.').unwrap_or((s, ""));
    if f.len() > 8 || (w.is_empty() && f.is_empty()) || !w.bytes().chain(f.bytes()).all(|c| c.is_ascii_digit()) { return Err("bad amount".into()); }
    let w: u64 = if w.is_empty() { 0 } else { w.parse().map_err(|_| "amount too large")? };
    let f: u64 = if f.is_empty() { 0 } else { format!("{f:0<8}").parse().map_err(|_| "bad amount")? };
    w.checked_mul(COIN).and_then(|x| x.checked_add(f)).ok_or_else(|| "amount too large".into())
}

/// The used-cheque record of one book: `used-<id>` holds the highest cheque number this machine signed and its 18
/// digits ("N DIGITS"; an older "N" alone is read too), replaced atomically (temporary file, fsync, rename, fsync of the
/// directory) and never lowered. `used-<id>.lock` is held exclusively from reading the record until the cheque is in a
/// block, so two runs never pick the same number. The directory must be this user's alone; the lock and temporary
/// files are never opened through a symbolic link.
struct Record { dir: std::path::PathBuf, path: std::path::PathBuf, size: u32, _lock: std::fs::File }
impl Record {
    fn open(dir: &Path, id: &str, size: u32) -> Result<Record, String> {
        let err = |e: std::io::Error| format!("{}: {e}", dir.display());
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true);
        #[cfg(unix)] { use std::os::unix::fs::DirBuilderExt; b.mode(0o700); }
        b.create(dir).map_err(err)?;
        #[cfg(unix)] { use std::os::unix::fs::MetadataExt;
            let m = std::fs::metadata(dir).map_err(err)?;
            if m.mode() & 0o022 != 0 { return Err(format!("{}: others can write to this directory (mode {:o}): chmod 700 it", dir.display(), m.mode() & 0o777)); }
            if my_uid().is_some_and(|u| u != m.uid()) { return Err(format!("{}: this directory belongs to another user (uid {})", dir.display(), m.uid())); } }
        let lock = private(std::fs::OpenOptions::new().create(true).truncate(false).write(true)).open(dir.join(format!("used-{id}.lock"))).map_err(err)?;
        let t = std::time::Instant::now();
        loop { match lock.try_lock() {
            Ok(()) => break,
            Err(std::fs::TryLockError::WouldBlock) if t.elapsed().as_secs() < 60 => std::thread::sleep(std::time::Duration::from_millis(100)),
            Err(std::fs::TryLockError::WouldBlock) => return Err(format!("another wallet run holds {}/used-{id}.lock", dir.display())),
            Err(std::fs::TryLockError::Error(e)) => return Err(err(e)),
        } }
        Ok(Record { dir: dir.to_path_buf(), path: dir.join(format!("used-{id}")), size, _lock: lock })
    }
    fn read(&self) -> Result<Option<(u16, Option<[u8; COLS]>)>, String> {
        let bad = || format!("{}: not a cheque number below {}: fix it by hand (the highest cheque this machine signed) before going on", self.path.display(), self.size);
        match std::fs::read_to_string(&self.path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{}: {e}", self.path.display())),
            Ok(t) => {
                let mut w = t.split_whitespace();
                let n = w.next().and_then(|n| n.parse::<u16>().ok()).filter(|&n| (n as u32) < self.size).ok_or_else(bad)?;
                let d = match w.next() {
                    None => None,
                    Some(d) if d.bytes().all(|c| c.is_ascii_digit()) => Some(d.bytes().map(|c| c - b'0').collect::<Vec<_>>().try_into().map_err(|_| bad())?),
                    Some(_) => return Err(bad()),
                };
                if w.next().is_some() { return Err(bad()); }
                Ok(Some((n, d)))
            }
        }
    }
    fn write(&self, n: u16, digits: &[u8; COLS]) -> Result<(), String> {
        use std::io::Write;
        match self.read()? {
            Some((o, _)) if o > n => return Ok(()),
            Some((o, Some(d))) if o == n && d != *digits => return Err(format!("cheque {n} was signed here with other digits: it is never signed twice")),
            _ => {}
        }
        let tmp = self.path.with_extension("tmp");
        let err = |e: std::io::Error| format!("{}: {e}", self.path.display());
        let mut f = private(std::fs::OpenOptions::new().create(true).truncate(true).write(true)).open(&tmp).map_err(err)?;
        let text = format!("{n} {}", digits.iter().map(|d| char::from(b'0' + d)).collect::<String>());
        f.write_all(text.as_bytes()).and_then(|_| f.sync_all()).map_err(err)?;
        std::fs::rename(&tmp, &self.path).map_err(err)?;
        std::fs::File::open(&self.dir).and_then(|d| d.sync_all()).map_err(err)
    }
}

/// O_NOFOLLOW, which std does not name: its value differs between architectures.
#[cfg(all(target_os = "linux", any(target_arch = "x86", target_arch = "x86_64", target_arch = "riscv64", target_arch = "loongarch64", target_arch = "s390x")))]
const O_NOFOLLOW: i32 = 0o400000;
#[cfg(all(target_os = "linux", any(target_arch = "arm", target_arch = "aarch64", target_arch = "powerpc", target_arch = "powerpc64")))]
const O_NOFOLLOW: i32 = 0o100000;
#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
const O_NOFOLLOW: i32 = 0x100;
// anywhere else it is unknown here: no build, rather than record files opened through symbolic links
#[cfg(all(unix, not(any(all(target_os = "linux", any(target_arch = "x86", target_arch = "x86_64", target_arch = "riscv64", target_arch = "loongarch64", target_arch = "s390x",
                                                    target_arch = "arm", target_arch = "aarch64", target_arch = "powerpc", target_arch = "powerpc64")),
                       target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))))]
compile_error!("O_NOFOLLOW is not known for this target: add its value in cli_wallet.rs");

/// A file only its owner may read, never opened through a symbolic link.
fn private(o: &mut std::fs::OpenOptions) -> &mut std::fs::OpenOptions {
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; o.mode(0o600).custom_flags(O_NOFOLLOW); }
    o
}

/// The user this process runs as: the owner of /proc/self (std has no getuid). None where there is no /proc.
fn my_uid() -> Option<u32> {
    #[cfg(target_os = "linux")] { use std::os::unix::fs::MetadataExt; return std::fs::metadata("/proc/self").ok().map(|m| m.uid()); }
    #[allow(unreachable_code)] None
}

/// Zeroes memory in a way the compiler may not leave out.
fn wipe(b: &mut [u8]) { for x in b { unsafe { std::ptr::write_volatile(x, 0) } } }
fn wipe_string(mut s: String) { unsafe { wipe(s.as_bytes_mut()) } }   // zeroes are valid UTF-8
/// The seed, wiped when dropped.
struct Secret([u8; 32]);
impl Drop for Secret { fn drop(&mut self) { wipe(&mut self.0) } }
/// A book, its seed wiped when dropped.
struct Keys(Book);
impl Drop for Keys { fn drop(&mut self) { for d in &mut self.0.domains { wipe(&mut d.0) } } }

fn http(addr: &str, method: &str, path: &str, body: &str) -> Result<String, String> { bitcheque::net::http(addr, method, path, body) }
fn clean(s: &str) -> String { bitcheque::net::clean(s) }

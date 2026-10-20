//! `bitcheque wallet`: a software wallet for one book from one seed (DESIGN.md §5, §10.12, §10.13).
use bitcheque::{crypto::{hex, sha256}, damm, message::{self, Message, COLS, PAYEE_DIGITS}, params::{Params, COIN}, tx::Tx,
                u256::U256, wallet::{mine_registration, Book, Domain, BATCH, BOOK_SIZE}};
use std::path::Path;

/// The recipient columns: sent first, and in a block before the amount's 6 pieces leave this machine (§10.12).
const RECIPIENT: usize = PAYEE_DIGITS + 1;
/// How long a send waits for each half of a cheque to reach a block, unless --wait says otherwise.
const WAIT_SECONDS: u64 = 600;

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

fn run(cmd: &str, args: &[String], opt: &dyn Fn(&str) -> Option<String>, p: &Params, book: &Book) -> Result<(), String> {
    let flag = |k: &str| args.iter().any(|a| a == k);
    let rpcs: Vec<String> = opt("--rpc").unwrap_or_default().split(',').map(|r| r.trim().to_string()).filter(|r| !r.is_empty()).collect();
    if rpcs.is_empty() && cmd != "pieces" { return Err("--rpc ADDR needed".into()); }
    let rpc = rpcs.first().cloned().unwrap_or_default();
    let size = BOOK_SIZE;
    let cheques: u32 = opt("--cheques").map_or(Ok(BATCH), |v| v.parse()).map_err(|_| "bad --cheques")?;
    if !(1..=size).contains(&cheques) { return Err(format!("--cheques must be 1 to {size}")); }
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
    if cmd == "pieces" {
        // raw pieces as hex, for tests; recorded like any cheque, so the number is never signed again with other digits
        let cheque: u16 = opt("--cheque").ok_or("--cheque N needed")?.parse().map_err(|_| "bad --cheque")?;
        if cheque as u32 >= size { return Err(format!("--cheque must be below {size}")); }
        let d = opt("--digits").ok_or("--digits needed")?;
        let digits: [u8; COLS] = d.bytes().map(|c| c.wrapping_sub(b'0')).collect::<Vec<_>>().try_into().map_err(|_| "--digits must be 18 digits")?;
        if digits.iter().any(|&x| x > 9) { return Err("--digits must be 18 digits".into()); }
        let rec = record()?;
        if let Some((n, d)) = rec.read()? { if cheque < n || (cheque == n && d != Some(digits)) {
            return Err(format!("this machine signed cheques up to {n} already: cheque {cheque} is never signed with other digits"));
        } }
        rec.write(cheque, &digits)?;
        for t in book.pieces(cheque, &digits) { println!("{}", hex(&t.encode())); }
        return Ok(());
    }
    match cmd {
        "info" => match account() {
            Ok(a) => { for (k, v) in a { println!("{k} {v}"); } }
            Err(_) => println!("id {id}\nnot registered"),
        },
        "register" | "more" => {
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
            // the proof of work names the node's tip, so it is valid for the next reg_anchor_window blocks only
            let anchor: [u8; 32] = bitcheque::rpc::unhex(&http(&rpc, "GET", "/tip", "")?).and_then(|v| v.try_into().ok()).ok_or("bad tip")?;
            let regs = book.registrations(first, first + cheques - 1);
            let mut txs: Vec<_> = regs.iter().map(|reg| mine_registration(reg.clone(), anchor, target)).collect(); // each batch of 16 pays its own proof of work
            // honesty check: cheque 0, zero coins, to nobody. Recorded before it is signed, so if its pieces never reach the
            // chain no later cheque takes number 0 (mixed with the honesty check's pieces, a sweep could go to number 0)
            let mut honesty = false;
            let zero = Message::new(0, 0, 0, 0);
            if let Some(r) = &rec { match r.read()? {
                None | Some((0, _)) => { r.write(0, &zero.digits())?; txs.extend(book.sign(0, &zero)); honesty = true; }
                Some((n, _)) => eprintln!("warning: this machine signed cheques up to {n} already: the honesty check (cheque 0) is not sent again"),
            } }
            post_all(&txs)?;
            let last = ((first / BATCH + regs.len() as u32) * BATCH).min(size) - 1;
            println!("id {id}\ncheques {first}-{last} registered{}", if honesty { ", honesty check (cheque 0) sent" } else { "" });
        }
        "send" | "sweep" | "void" => {
            let wait: u64 = opt("--wait").map_or(Ok(WAIT_SECONDS), |w| w.parse()).map_err(|_| "bad --wait (seconds)")?;
            let tier: u8 = if cmd == "void" { 0 } else { opt("--fee").map_or(Ok(1), |f| f.parse()).ok().filter(|&t| t <= 9).ok_or("--fee is a tier from 0 to 9")? };
            // a sweep (mantissa 0000, exponent 9) moves the whole balance minus the fee: how a used-up book moves on.
            // A void is zero coins to nobody: once in a block, no lower cheque can ever complete (§10.13)
            let to = if cmd == "void" { 0 } else { payee(&opt("--to").ok_or("--to NUMBER needed: the recipient's 12 digits, as NNNNNNNNNNN-C")?)? };
            let (mantissa, exponent) = if cmd == "sweep" { (0, 9) } else if cmd == "void" { (0, 0) } else {
                let units = coins(&opt("--amount").ok_or("--amount COINS needed")?)?;
                (0..=9u32).find_map(|e| { let d = 10u64.pow(e); (units % d == 0 && units / d <= 9999).then(|| ((units / d) as u16, e as u8)) })
                    .ok_or("amount needs at most 4 significant digits")?
            };
            let msg = Message::new(to, mantissa, exponent, tier);
            // checked as consensus reads it before anything is recorded or signed: a cheque the chain refuses (fee tier 0
            // with coins, say) is only refused at its last piece, and its number is burned by then
            match message::parse(&msg.digits()) { Ok(m) if m == msg => {} Ok(_) => return Err("the cheque does not read back as written".into()), Err(e) => return Err(format!("not a valid cheque: {e}")) }
            if to == 0 && !msg.is_zero() && !flag("--burn") {
                return Err("number 0 is nobody: coins sent to it go to the block's miner. Pass --burn if that is really what you want".into());
            }
            let digits = msg.digits();
            // locked from here until the cheque is in a block: another run waits, then sees this cheque's number
            let rec = record()?;
            let used = rec.read()?;
            // every node asked must agree on the book; what they report is only believed within it, and the most
            // cautious answer wins (highest consumed number, every queued one, a cheque all of them list unspent)
            let num = |v: &str, what: &str| -> Result<Option<u16>, String> {
                if v == "none" { return Ok(None); }
                v.parse::<u16>().ok().filter(|&n| (n as u32) < size).map(Some).ok_or(format!("a node reports {what} {}, not a cheque of this book: try another node", clean(v)))
            };
            let list = |v: &str, what: &str| -> Result<Vec<u16>, String> { v.split(',').filter(|x| !x.trim().is_empty()).map(|x| num(x.trim(), what).map(Option::unwrap)).collect() };
            // (nonce: the last cheque completed (or opened, on chains before v11), open: the half-sent one)
            let state_at = |r: &str| -> Result<(Vec<(String, String)>, Option<u16>, Option<u16>), String> {
                let a = account_at(r)?;
                if field(&a, "book_size") != size.to_string() { return Err(format!("{r} says this book has {} cheques, not {size}: try another node", clean(&field(&a, "book_size")))); }
                let (nonce, open) = (num(&field(&a, "nonce"), "nonce")?, num(&field(&a, "open"), "open")?);
                Ok((a, nonce, open))
            };
            let mut states = Vec::new();
            for r in &rpcs { states.push(state_at(r)?); }
            // cheque n is over on a node when its nonce reached n and it is not the open one: completed, or dead
            let done = |nonce: Option<u16>, open: Option<u16>, n: u16| nonce.is_some_and(|x| x >= n) && open != Some(n);
            // the cheque this machine signed last, if some node does not show it over yet (cheque 0 as the honesty
            // check moves nothing and has nothing below it to void)
            let live = used.filter(|&(n, d)| (n > 0 || d.is_some_and(|d| d != [0; COLS])) && !states.iter().all(|(_, nonce, open)| done(*nonce, *open, n)));
            let resume = matches!(live, Some((_, Some(d))) if d == digits);
            let cheque = if let Some((n, _)) = live.filter(|_| resume) {
                // the same cheque again (a lost reply, a half-sent cheque): finished, never re-written on another number
                eprintln!("cheque {n} is this same cheque and is not finished yet: finishing it");
                n
            } else {
                if let Some((n, _)) = live.filter(|_| cmd != "void") {
                    return Err(format!("cheque {n} may still be live: wait for it, or run `wallet void` (a zero cheque on the next number that kills it once in a block); never re-write a payment on the next number"));
                }
                // no payment signed here before (a new machine, a restored seed, a new --state-dir): one node could hide
                // an open or queued cheque, so two that agree are needed, or the holder's word that the book is fresh
                if used.map_or(true, |(n, _)| n == 0) && !flag("--fresh") {
                    if rpcs.len() < 2 { return Err("this machine has no record of the book's cheques: give two or more nodes that agree (--rpc A,B), or pass --fresh if this book has never signed a cheque anywhere else".into()); }
                    if states.windows(2).any(|w| (w[0].1, w[0].2) != (w[1].1, w[1].2)) { return Err("the nodes disagree on this book's last cheque: wait a block and try again, or pass --fresh if this book has never signed a cheque anywhere else".into()); }
                }
                let (mut top, mut queued, mut unspent): (Option<u16>, Vec<u16>, Vec<Vec<u16>>) = (None, vec![], vec![]);
                for (r, (a, nonce, open)) in rpcs.iter().zip(&states) {
                    top = top.max(*nonce).max(*open);   // a half-submitted cheque is abandoned by starting a higher one
                    unspent.push(list(&field(a, "unspent"), "unspent")?);
                    // never two cheques with one number: skip those waiting in a node's queue (asked fresh, failing hard if a node will not say)
                    queued.extend(list(&http(r, "GET", &format!("/queued/{id}"), "")?, "queued")?);
                }
                // the lowest cheque above everything consumed, open, queued or signed here before (a node's answers may
                // be a few seconds old), and never 0, the honesty check's number
                let floor = [used.map(|u| u.0), top].iter().flatten().map(|&n| n + 1).max().unwrap_or(1).max(1);
                let cheque = unspent[0].iter().copied().filter(|&n| n >= floor && !queued.contains(&n) && unspent.iter().all(|u| u.contains(&n))).min().ok_or("no unused cheques left")?;
                // completing a cheque burns every lower one forever: a stale or lying node must not make this wallet jump far
                if cheque - floor > 3 {
                    if !flag("--force-skip") { return Err(format!("the next free cheque looks like {cheque}, which would burn cheques {floor}-{} forever; the node may be stale or lying: try another (--rpc A,B asks both), or pass --force-skip if you are sure", cheque - 1)); }
                    eprintln!("warning: --force-skip: cheques {floor}-{} are burned forever", cheque - 1);
                }
                // the remaining checks happen here, from what the chain says publicly: no cell leaves this machine before
                // the cheque is sent for real, and exactly one cheque is signed per payment
                let balance: u64 = field(&states[0].0, "balance").parse().map_err(|_| "the node gave no balance")?;
                let fee = tier as u64 * p.fee_unit;
                let amount = msg.amount().unwrap_or(0);
                if balance < amount + fee { return Err(format!("balance {} is less than {} coins and the fee", balance as f64 / COIN as f64, (amount + fee) as f64 / COIN as f64)); }
                // every node must know the recipient as a final number: a cheque to a number nobody holds yet would pay
                // whoever is given it later
                if to != 0 { for r in &rpcs {
                    let t = http(r, "GET", &format!("/account/{to}"), "").unwrap_or_default();
                    if !t.lines().any(|l| l == format!("number {to}")) { return Err(format!("{r}: account {to} is not a final number yet (or does not exist)")); }
                    if !t.lines().any(|l| l == "funded true") && r == &rpc {
                        eprintln!("warning: account {to} is not permanent yet: until it holds {} coin(s) at once it expires with its balance, so smaller amounts sent to it may be burned", p.min_fund as f64 / COIN as f64);
                    }
                } }
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
            let pieces = book.sign(cheque, &msg);
            let again = if cmd == "void" { "run `wallet void` again" } else { "run the same command again to finish it, or `wallet void` to cancel it" };
            // a void goes in one piece: nothing in it to protect. A payment's recipient half first, in a block before
            // its amount half is shown to anyone (§10.12)
            let halves: Vec<&[Tx]> = if cmd == "void" { vec![&pieces] } else { vec![&pieces[..RECIPIENT], &pieces[RECIPIENT..]] };
            let mut in_block = false;
            for (i, half) in halves.iter().enumerate() {
                let last = i + 1 == halves.len();
                // dry run on every node first; a piece a node already has (an earlier run sent it) is not sent again
                let mut send = Vec::new();
                for r in &rpcs {
                    let reply = http(r, "POST", "/check", &half.iter().map(|t| hex(&t.encode())).collect::<Vec<_>>().join("\n"))
                        .map_err(|e| format!("{e}\ncheque {cheque} may still be live: {again}"))?;
                    let lines: Vec<&str> = reply.lines().map(str::trim).collect();
                    if lines.len() != half.len() { return Err(format!("{r} gave a bad dry run\ncheque {cheque} may still be live: {again}")); }
                    for (t, l) in half.iter().zip(lines) {
                        if l == "ok" || l.starts_with("ok ") { if r == &rpc { send.push(t.clone()); } }
                        else if l != "column already revealed" { return Err(format!("{r} refuses cheque {cheque}: {}\ncheque {cheque} may still be live: {again}", clean(l))); }
                    }
                }
                if !send.is_empty() { post_all(&send).map_err(|e| format!("{e}\ncheque {cheque} may still be live: {again}"))?; }
                // wait for this half in a block on every node: the recipient half as the open cheque, the rest as done
                let start = std::time::Instant::now();
                in_block = loop {
                    let mut all = true;
                    for r in &rpcs {
                        let ok = state_at(r).is_ok_and(|(_, nonce, open)| done(nonce, open, cheque) || (!last && open == Some(cheque)));
                        if !ok { all = false; break; }
                    }
                    if all { break true; }
                    if start.elapsed().as_secs() >= wait { break false; }
                    std::thread::sleep(std::time::Duration::from_secs(3));
                };
                if !in_block && !last { return Err(format!("cheque {cheque} is half sent: its recipient pieces are not in a block after {wait} seconds; {again}")); }
            }
            drop(rec);
            let what = if cmd == "sweep" { format!("{} sweeps the whole balance to {to}, fee tier {tier}", msg.display()) }
                else if cmd == "void" { format!("{} voids every lower cheque", msg.display()) }
                else { format!("{} to {to}, {} coins, fee tier {tier}", msg.display(), msg.amount().unwrap_or(0) as f64 / COIN as f64) };
            if in_block { println!("cheque {cheque} sent: {what}"); }
            else if cmd == "void" { return Err(format!("void cheque {cheque} posted but not in a block after {wait} seconds: the cheque it voids may still complete; {again}")); }
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

/// --to: the recipient as printed, 11 digits and the Damm check digit (NNNNNNNNNNN-C or all 12 together). The check
/// digit is the holder's, never computed here, so a mistyped number is caught instead of paying a stranger.
fn payee(s: &str) -> Result<u32, String> {
    let bad = || format!("--to takes the recipient's 12-digit number with its check digit, as printed (NNNNNNNNNNN-C), not {}", clean(s));
    let all = match s.split_once('-') { Some((n, c)) if n.len() == PAYEE_DIGITS && c.len() == 1 => format!("{n}{c}"), None if s.len() == RECIPIENT => s.to_string(), _ => return Err(bad()) };
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
                    Some(d) => Some(d.bytes().map(|c| c.wrapping_sub(b'0')).filter(|&x| x <= 9).collect::<Vec<_>>().try_into().map_err(|_| bad())?),
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
#[cfg(not(any(all(target_os = "linux", any(target_arch = "x86", target_arch = "x86_64", target_arch = "riscv64", target_arch = "loongarch64", target_arch = "s390x",
                                           target_arch = "arm", target_arch = "aarch64", target_arch = "powerpc", target_arch = "powerpc64")),
              target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd")))]
const O_NOFOLLOW: i32 = 0;

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

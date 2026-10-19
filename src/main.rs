//! bitcheque genesis [--mainnet|--local]   (default: the public research network; --testnet is the same)
//! bitcheque node [--mainnet|--local] [--data FILE] [--listen ADDR] [--advertise ADDR] [--rpc ADDR] [--peer ADDR]... [--upstream HOST:PORT]... [--no-upstream]
//! bitcheque mine --rpc ADDR --to NUMBER [--threads N]   (mines against any node's RPC, e.g. node-ap.bitcheque.org:80; 0 burns the reward)
//!   With no --peer a node dials the compiled-in seeds, then keeps about 8 connections from the addresses peers share.
//!   On the research network it also follows the edge nodes (node-ap/us/eu/oc/sa.bitcheque.org:80, the seeds) over their
//!   HTTP RPC: pulls their blocks every minute and passes on what it accepts. --upstream picks others, --no-upstream none.
//!   --listen defaults to 0.0.0.0:8730 (mainnet) or 0.0.0.0:8731 (testnet); --advertise is the address others can reach you on.
//! bitcheque wallet new | info|register|more|send|sweep --seed-file FILE --rpc ADDR [--cheques N] [--to NUMBER --amount COINS [--fee TIER]]
//! bitcheque wallet pieces --seed-file FILE --cheque N --digits D18   (raw pieces as hex, no checks: for tests)
//!   The seed (64 hex digits) comes from --seed-file (keep it 0600), or the BITCHEQUE_SEED environment variable, or
//!   standard input with --seed-file -. --seed HEX still works, but every user of the machine can read a command line.
use bitcheque::{block::Chain, crypto::{hex, sha256}, message::Message, net::Node, params::{Params, COIN, GENESIS_MESSAGE as MESSAGE, LAUNCH_TIME, LOCAL_TIME, TESTNET_TIME}, rpc::unhex, store::Store,
                u256::U256, wallet::{mine_registration, Book, Domain, BATCH, BOOK_SIZE}};


fn main() {
    let args: Vec<String> = std::env::args().collect();
    // the public research network is the default; --mainnet is the future production network
    let local = args.iter().any(|a| a == "--local");
    let testnet = !local && !args.iter().any(|a| a == "--mainnet");
    let p = if local { Params::local() } else if testnet { Params::testnet() } else { Params::mainnet() };
    let g = Chain::genesis(&p, if local { LOCAL_TIME } else if testnet { TESTNET_TIME } else { LAUNCH_TIME }, MESSAGE);
    let opt = |k: &str| args.iter().position(|a| a == k).and_then(|i| args.get(i + 1).cloned());
    match args.get(1).map(String::as_str) {
        Some("genesis") => {
            let mut h = g.header.hash(); h.reverse();
            println!("network     {}\ntimestamp   {}\nbits        {:#010x}\nnonce       {}\nheader      {}\nblock hash  {}",
                     if local { "local" } else if testnet { "testnet" } else { "mainnet" }, g.header.time, g.header.bits, g.header.nonce, hex(&g.header.encode()), hex(&h));
        }
        Some("node") => {
            let data = opt("--data");
            let p_magic = p.magic;
            let store = Store::open(p, &g, data.as_deref().map(std::path::Path::new)).expect("open data file");
            eprintln!("height {}", store.chain.height());
            let node = Node::new(store);
            if let Some(d) = &data { node.set_book_path(std::path::PathBuf::from(format!("{d}.peers"))); }
            if let Some(a) = opt("--advertise") { node.set_advertise(&a); }
            let listen = opt("--listen").or(if local { None } else { Some(format!("0.0.0.0:{}", if testnet { 8731 } else { 8730 })) });
            if let Some(a) = listen { eprintln!("listening on {}", node.listen(&a).expect("listen")); }
            if let Some(a) = opt("--rpc") { eprintln!("rpc on {}", node.serve_rpc(&a).expect("rpc")); }
            let all = |k: &str| -> Vec<String> { args.iter().enumerate().filter(|(_, a)| *a == k).filter_map(|(i, _)| args.get(i + 1).cloned()).collect() };
            node.maintain(all("--peer"), std::time::Duration::from_secs(5));
            // the research network's seeds are the edge nodes, which speak only HTTP: follow them unless told otherwise
            let mut ups = all("--upstream");
            if ups.is_empty() && !args.iter().any(|a| a == "--no-upstream") { ups = bitcheque::net::http_seeds(&p_magic).iter().map(|s| s.to_string()).collect(); }
            if !ups.is_empty() { eprintln!("following {}", ups.join(", ")); }
            node.follow(ups, std::time::Duration::from_secs(60));
            if opt("--mine").is_some() { eprintln!("--mine is gone: the node no longer mines. Run `bitcheque mine --rpc ADDR --to NUMBER` against its RPC."); }
            loop { std::thread::sleep(std::time::Duration::from_secs(60)); }
        }
        Some("mine") => if let Err(e) = mine(&opt) { eprintln!("error: {e}"); std::process::exit(1) },
        Some("wallet") => if let Err(e) = wallet(&args, &opt) { eprintln!("error: {e}"); std::process::exit(1) },
        _ => eprintln!("usage: bitcheque genesis [--mainnet|--local] | bitcheque node [--mainnet|--local] [--data FILE] [--listen ADDR] [--advertise ADDR] [--rpc ADDR] [--peer ADDR] [--upstream HOST:PORT] [--no-upstream]\n       bitcheque mine --rpc ADDR --to NUMBER [--threads N]\n       bitcheque wallet new | info|register|more|send|sweep --seed-file FILE --rpc ADDR [--cheques N] [--to NUMBER --amount COINS [--fee TIER]]"),
    }
}

/// A software wallet for one book from one seed: the same 256-cheque book the website prints, so a seed works in both.
/// `register` registers the first cheques (16 by default, `--cheques` for more), `more` the next ones, 16 per proof of work.
/// The book salt is derived from the seed, so the seed alone recreates the book. Talks to a node's RPC; keeps no files.
fn wallet(args: &[String], opt: &dyn Fn(&str) -> Option<String>) -> Result<(), String> {
    let cmd = args.get(2).map(String::as_str).unwrap_or("");
    if cmd == "new" {
        let mut seed = [0u8; 32];
        std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom").map_err(|e| e.to_string())?, &mut seed).map_err(|e| e.to_string())?;
        println!("{}", hex(&seed));
        return Ok(());
    }
    let text = match (opt("--seed-file"), std::env::var("BITCHEQUE_SEED").ok(), opt("--seed")) {
        (Some(f), _, _) if f == "-" => { let mut t = String::new(); std::io::Read::read_to_string(&mut std::io::stdin(), &mut t).map_err(|e| e.to_string())?; t }
        (Some(f), _, _) => std::fs::read_to_string(&f).map_err(|e| format!("{f}: {e}"))?,
        (None, Some(t), _) => t,
        (None, None, Some(t)) => { eprintln!("warning: --seed puts the seed on the command line, where other users of this machine (ps) and the shell history can read it; use --seed-file or BITCHEQUE_SEED"); t }
        _ => return Err("the seed is needed: --seed-file FILE (or - for standard input), or BITCHEQUE_SEED".into()),
    };
    let seed: [u8; 32] = unhex(text.trim()).and_then(|v| v.try_into().ok()).ok_or("seed must be 32 bytes of hex")?;
    let rpc = opt("--rpc").unwrap_or_default();
    if rpc.is_empty() && cmd != "pieces" { return Err("--rpc ADDR needed".into()); }
    let salt: [u8; 16] = sha256(&[b"bitcheque/salt".as_slice(), &seed].concat())[..16].try_into().unwrap();
    let size = BOOK_SIZE;
    let cheques: u32 = opt("--cheques").map_or(Ok(BATCH), |v| v.parse()).map_err(|_| "bad --cheques")?;
    if !(1..=size).contains(&cheques) { return Err(format!("--cheques must be 1 to {size}")); }
    let book = Book { salt, n256: false, book_size: size, domains: vec![Domain(seed)] };
    let id = hex(&book.id());
    let account = || -> Result<Vec<(String, String)>, String> {
        Ok(http(&rpc, "GET", &format!("/id/{id}"), "")?.lines().filter_map(|l| l.split_once(' ').map(|(k, v)| (clean(k), clean(v)))).collect())
    };
    let field = |a: &[(String, String)], k: &str| a.iter().find(|(x, _)| x == k).map(|(_, v)| v.clone()).unwrap_or_default();
    // everything a command sends goes in one request, so it all lands in the same block (a registration with its
    // cheque 0, or a cheque's 18 pieces). A batch already on the chain is refused as a duplicate, which is fine.
    let post_all = |txs: &[bitcheque::tx::Tx]| -> Result<(), String> {
        let reply = http(&rpc, "POST", "/tx", &txs.iter().map(|t| hex(&t.encode())).collect::<Vec<_>>().join("\n"))?;
        match reply.lines().find(|l| !matches!(l.trim(), "ok" | "already in mempool" | "batch overlaps")) { None => Ok(()), Some(e) => Err(format!("node refused: {}", clean(e))) }
    };
    if cmd == "pieces" {
        let cheque: u16 = opt("--cheque").ok_or("--cheque N needed")?.parse().map_err(|_| "bad --cheque")?;
        let d = opt("--digits").ok_or("--digits needed")?;
        let digits: [u8; 18] = d.bytes().map(|c| c.wrapping_sub(b'0')).collect::<Vec<_>>().try_into().map_err(|_| "--digits must be 18 digits")?;
        if digits.iter().any(|&x| x > 9) { return Err("--digits must be 18 digits".into()); }
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
                (top / BATCH + 1) * BATCH
            };
            if first >= size { return Err("every cheque of this book is registered already".into()); }
            let limbs: Vec<u64> = http(&rpc, "GET", "/regtarget", "")?.split_whitespace().map(|w| u64::from_str_radix(w, 16).unwrap_or(0)).collect();
            let target = U256(limbs.try_into().map_err(|_| "bad regtarget")?);
            // a node can only make registration harder, never impossible: a target this low would never be met
            if target < U256::one_shl(192) { return Err("the node's registration target is implausibly hard: try another node".into()); }
            let regs = book.registrations(first, first + cheques - 1);
            let mut txs: Vec<_> = regs.iter().map(|reg| mine_registration(reg.clone(), target)).collect(); // each batch of 16 pays its own proof of work
            if cmd == "register" { txs.extend(book.sign(0, &Message::new(0, 0, 0, 0))); } // honesty check: cheque 0, zero coins, to nobody
            post_all(&txs)?;
            let last = ((first / BATCH + regs.len() as u32) * BATCH).min(size) - 1;
            println!("id {id}\ncheques {first}-{last} registered{}", if cmd == "register" { ", honesty check (cheque 0) sent" } else { "" });
        }
        "send" | "sweep" => {
            let to: u32 = opt("--to").ok_or("--to NUMBER needed")?.parse().map_err(|_| "bad --to")?;
            let tier: u8 = opt("--fee").map_or(Ok(1), |f| f.parse()).map_err(|_| "bad --fee")?;
            // a sweep (mantissa 0000, exponent 9) moves the whole balance minus the fee: how a used-up book moves on
            let (mantissa, exponent) = if cmd == "sweep" { (0, 9) } else {
                let units = coins(&opt("--amount").ok_or("--amount COINS needed")?)?;
                (0..=8u32).find_map(|e| { let d = 10u64.pow(e); (units % d == 0 && units / d <= 9999).then(|| ((units / d) as u16, e as u8)) })
                    .ok_or("amount needs at most 4 significant digits")?
            };
            let a = account()?;
            // a half-submitted cheque is abandoned by starting a higher one (consensus deletes it)
            let nonce: Option<u16> = field(&a, "open").parse().ok().or(field(&a, "nonce").parse().ok());
            let msg = Message::new(to, mantissa, exponent, tier);
            // the checks happen here, from what the chain says publicly: no cell leaves this machine before the cheque is
            // sent for real (a node shown a signed cheque in a dry run could keep it), and exactly one cheque is signed
            // per payment, so a node that lies about the result cannot collect a second one
            let balance: u64 = field(&a, "balance").parse().map_err(|_| "the node gave no balance")?;
            let fee = tier as u64 * bitcheque::params::Params::mainnet().fee_unit;
            let amount = msg.amount().unwrap_or(0);
            if balance < amount + fee { return Err(format!("balance {} is less than {} coins and the fee", balance as f64 / COIN as f64, (amount + fee) as f64 / COIN as f64)); }
            if to != 0 && !http(&rpc, "GET", &format!("/account/{to}"), "").is_ok_and(|t| t.lines().any(|l| l.starts_with("number "))) {
                return Err(format!("account {to} is not a final number yet (or does not exist)"));
            }
            // cheques already in the node's queue (an earlier send that has not been mined) are skipped
            let queued: Vec<u16> = http(&rpc, "GET", "/mempool", "").unwrap_or_default().lines()
                .filter(|l| l.starts_with("piece ") && l.contains(&format!("account={id} ")))
                .filter_map(|l| l.split_whitespace().find_map(|w| w.strip_prefix("cheque="))?.parse().ok()).collect();
            let cheque = field(&a, "unspent").split(',').filter_map(|x| x.parse::<u16>().ok()).filter(|&n| nonce.map_or(true, |k| n > k) && !queued.contains(&n)).min().ok_or("no unused cheques left")?;
            // the last cheque of a book is kept for the sweep to a new book (DESIGN.md §10.11): spent on anything
            // else, whatever is left in the account can never move again
            if cmd == "send" && cheque as u32 == size - 1 && opt("--last").is_none() {
                return Err(format!("cheque {cheque} is the last one in this book: keep it for `wallet sweep --to <new book>`, or pass --last to spend it anyway"));
            }
            let pieces = book.sign(cheque, &msg);
            post_all(&pieces)?;
            if cmd == "sweep" { println!("cheque {cheque} sent: {} sweeps the whole balance to {to}, fee tier {tier}", msg.display()); }
            else { println!("cheque {cheque} sent: {} to {to}, {} coins, fee tier {tier}", msg.display(), msg.amount().unwrap_or(0) as f64 / COIN as f64); }
        }
        _ => return Err("wallet commands: new, info, register, more, send, sweep, pieces".into()),
    }
    Ok(())
}

/// "1.5" -> 150_000_000 base units, exact (8 decimals at most).
fn coins(s: &str) -> Result<u64, String> {
    let (w, f) = s.split_once('.').unwrap_or((s, ""));
    if f.len() > 8 || (w.is_empty() && f.is_empty()) { return Err("bad amount".into()); }
    let w: u64 = if w.is_empty() { 0 } else { w.parse().map_err(|_| "bad amount")? };
    let f: u64 = if f.is_empty() { 0 } else { format!("{f:0<8}").parse().map_err(|_| "bad amount")? };
    w.checked_mul(COIN).and_then(|x| x.checked_add(f)).ok_or_else(|| "amount too large".into())
}

/// A miner that keeps no chain: fetch a template from a node's RPC, search nonces on every core, send
/// a found block back. A new template is fetched when the tip moves (checked every few seconds) and
/// every TEMPLATE_SECONDS anyway, so new transactions and a fresh time get in.
fn mine(opt: &dyn Fn(&str) -> Option<String>) -> Result<(), String> {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    const TEMPLATE_SECONDS: u64 = 20;
    let rpc = opt("--rpc").ok_or("--rpc ADDR needed (host:port of a node's RPC)")?;
    let to: u32 = opt("--to").ok_or("--to NUMBER needed (the account that gets the reward; 0 burns it)")?.parse().map_err(|_| "bad --to")?;
    let threads = opt("--threads").and_then(|t| t.parse().ok()).unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get())).max(1);
    let min = U256::from_compact(bitcheque::params::Params::testnet().min_bits.max(bitcheque::params::Params::local().min_bits));
    eprintln!("mining for account {to} on {threads} threads against {rpc}");
    loop {
        let tpl = match http(&rpc, "GET", &format!("/template/{to}"), "") {
            Ok(t) => unhex(&t).and_then(|r| bitcheque::block::Block::decode(&r).ok()).ok_or("bad template")?,
            Err(e) => { eprintln!("template: {}", clean(&e)); std::thread::sleep(std::time::Duration::from_secs(5)); continue; }
        };
        // the node builds the template, so check it pays us and asks for real work: a node (or anyone between) could
        // otherwise have our work pay someone else
        if !matches!(tpl.txs.first(), Some(bitcheque::tx::Tx::Coinbase { payee, .. }) if *payee == to) { return Err("the node's template pays someone else: use another node".into()); }
        if U256::from_compact(tpl.header.bits) > min { return Err("the node's template asks for less work than any block may have: use another node".into()); }
        let (stop, hashes, found) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicU64::new(0)), Arc::new(Mutex::new(None)));
        let workers: Vec<_> = (0..threads).map(|i| {
            let (mut b, stop, hashes, found) = (tpl.clone(), stop.clone(), hashes.clone(), found.clone());
            std::thread::spawn(move || {
                b.header.nonce = i as u32;
                while !stop.load(Ordering::Relaxed) {
                    for _ in 0..100_000 {
                        if b.header.meets_target() { *found.lock().unwrap() = Some(b.clone()); stop.store(true, Ordering::Relaxed); return; }
                        let (n, wrapped) = b.header.nonce.overflowing_add(threads as u32);
                        if wrapped { return; }   // this thread's share of the nonces is done
                        b.header.nonce = n;
                    }
                    hashes.fetch_add(100_000, Ordering::Relaxed);
                }
            })
        }).collect();
        let started = std::time::Instant::now();
        while !stop.load(Ordering::Relaxed) && started.elapsed().as_secs() < TEMPLATE_SECONDS && workers.iter().any(|w| !w.is_finished()) {
            std::thread::sleep(std::time::Duration::from_secs(3));
            if http(&rpc, "GET", "/tip", "").is_ok_and(|t| unhex(&t).is_some_and(|t| t != tpl.header.prev)) { break; }   // someone else found one
        }
        stop.store(true, Ordering::Relaxed);
        for w in workers { let _ = w.join(); }
        let rate = hashes.load(Ordering::Relaxed) as f64 / started.elapsed().as_secs_f64().max(0.001);
        let block = found.lock().unwrap().take();
        if let Some(b) = block {
            match http(&rpc, "POST", "/block", &hex(&b.encode())) {
                Ok(_) => eprintln!("mined a block on {} with {} transactions ({:.1} MH/s)", hex(&tpl.header.prev[..4]), b.txs.len() - 1, rate / 1e6),
                Err(e) => eprintln!("block refused: {}", clean(&e)),
            }
        }
    }
}

fn http(addr: &str, method: &str, path: &str, body: &str) -> Result<String, String> { bitcheque::net::http(addr, method, path, body) }
fn clean(s: &str) -> String { bitcheque::net::clean(s) }

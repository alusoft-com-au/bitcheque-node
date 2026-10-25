//! bitcheque genesis [--mainnet|--local]   (default: the public research network)
//! bitcheque node [--mainnet|--local] [--data FILE] [--listen ADDR] [--advertise ADDR] [--rpc ADDR] [--peer ADDR]... [--upstream HOST:PORT]... [--no-upstream]
//! bitcheque mine --rpc ADDR --to NUMBER [--threads N] [--light]   (mines against any node's RPC, e.g. node-ap.bitcheque.org:80; 0 burns
//!       the reward; builds the proof of work's 2 GiB table on every core, --light does without it at a thousandth of the rate)
//!   With no --peer a node dials the compiled-in seeds, then keeps about 8 connections from the addresses peers share.
//!   On the research network it also follows the edge nodes (node-ap/us/eu/oc/sa.bitcheque.org:80, the seeds) over their
//!   HTTP RPC: pulls their blocks every minute and passes on what it accepts. --upstream picks others, --no-upstream none.
//!   --listen defaults to 0.0.0.0:8730 (mainnet) or 0.0.0.0:8731 (testnet); --advertise is the address others can reach you on.
//! bitcheque wallet new   (prints a fresh seed)
//! bitcheque wallet info|register|more --seed-file FILE --rpc ADDR[,ADDR...] [--state-dir DIR] [--cheques N]
//! bitcheque wallet send --to NNNNNNNNNNN-C --amount COINS | sweep --to NNNNNNNNNNN-C | void   --seed-file FILE --rpc ADDR [--rpc ADDR...]
//!       [--state-dir DIR] [--fee TIER] [--force-skip] [--last] [--burn] [--fresh] [--again] [--confirmations K] [--wait SECONDS]
//! bitcheque wallet pieces --seed-file FILE --cheque N --digits D18 [--state-dir DIR] [--rest --rpc ADDR]   (raw txs as hex; recorded:
//!       the opening, then with --rest, once it is deep enough on chain, the 5 remaining pieces)
//!   The seed (64 hex digits) comes from --seed-file (must be 0600 and yours: no group or world access), or the BITCHEQUE_SEED
//!   environment variable (Linux keeps it readable in /proc/self/environ to you and root: prefer the file), or standard
//!   input with --seed-file -. Never on the command line, where every user can read it.
//!   The used-cheque record lives in --state-dir, else $BITCHEQUE_STATE, else ~/.config/bitcheque (absolute, yours alone).
//!   Several --rpc nodes (repeated, or a comma list): the first gets the cheque, every one dry-runs it, and every decision
//!   needs all of them to report the book alike.
//!   A new cheque needs two agreeing nodes, or --fresh: the holder's word that this book signs cheques on this machine only
//!   (one node could hide a cheque sent from elsewhere). Never one node while the last cheque signed here is not in the
//!   account's sends (/sends) as finished.
//!   --to is the recipient as printed, check digit included (never computed here), or as the explorer shows it (N-C); a
//!   non-zero amount to 0 needs --burn. "sent" only once the account's sends (/sends) show the cheque paying it.
//!   A payment goes in two halves: the opening (recipient and first amount digit), and once it is --confirmations blocks
//!   deep (3) the 5 remaining pieces. A send that fails part way says so: run the same command again (the same cheque is
//!   finished, never re-written; a payment already made, here or from another machine within about a day, or open or
//!   waiting with the same recipient, is refused unless --again), or `wallet void`, which confirms a
//!   zero cheque on the next number so the earlier one can never complete (DESIGN.md §10.13).
//!   The RPC is plain HTTP: anyone on the path can withhold or forge replies (never forge a cheque). Use --rpc A --rpc B with
//!   nodes reached over different paths.
use bitcheque::{block::Chain, crypto::hex, net::Node, params::{Params, genesis_message, LAUNCH_TIME, LOCAL_TIME, TESTNET_TIME}, rpc::unhex, store::Store,
                u256::U256};
mod cli_wallet;


fn main() {
    let args: Vec<String> = std::env::args().collect();
    // the public research network is the default; --mainnet is the future production network
    let local = args.iter().any(|a| a == "--local");
    let testnet = !local && !args.iter().any(|a| a == "--mainnet");
    let p = if local { Params::local() } else if testnet { Params::testnet() } else { Params::mainnet() };
    let g = Chain::genesis(&p, if local { LOCAL_TIME } else if testnet { TESTNET_TIME } else { LAUNCH_TIME }, &genesis_message(&p));
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
            // a damaged data file (moved aside by Store::open) or one that cannot be read: said plainly, and exit code 2
            let store = match Store::open(p, &g, data.as_deref().map(std::path::Path::new)) { Ok(s) => s, Err(e) => { eprintln!("error: data file: {e}"); std::process::exit(2) } };
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
            loop { std::thread::sleep(std::time::Duration::from_secs(60)); }
        }
        Some("mine") => if let Err(e) = mine(&opt, args.iter().any(|a| a == "--light")) { eprintln!("error: {e}"); std::process::exit(1) },
        Some("wallet") => if let Err(e) = cli_wallet::wallet(&args, &opt, &p) { eprintln!("error: {e}"); std::process::exit(1) },
        _ => eprintln!("usage: bitcheque genesis [--mainnet|--local] | bitcheque node [--mainnet|--local] [--data FILE] [--listen ADDR] [--advertise ADDR] [--rpc ADDR] [--peer ADDR] [--upstream HOST:PORT] [--no-upstream]\n       bitcheque mine --rpc ADDR --to NUMBER [--threads N] [--light]\n       bitcheque wallet new | info|register|more --seed-file FILE --rpc ADDR[,ADDR...] [--state-dir DIR] [--cheques N]\n       bitcheque wallet send --to NNNNNNNNNNN-C --amount COINS | sweep --to NNNNNNNNNNN-C | void  --seed-file FILE --rpc ADDR[,ADDR...] [--state-dir DIR] [--fee TIER] [--force-skip] [--last] [--burn] [--fresh] [--again] [--confirmations K] [--wait SECONDS]"),
    }
}

/// A miner that keeps no chain: fetch a template from a node's RPC, search nonces on every core, send
/// a found block back. A new template is fetched when the tip moves (checked every few seconds) and
/// every TEMPLATE_SECONDS anyway, so new transactions and a fresh time get in. The proof of work (pow.rs) reads a
/// 2 GiB table, built here on every core whenever the template's epoch is new (a minute or two); `--light` mines
/// without one, the way a node verifies, at about a thousandth of the rate.
fn mine(opt: &dyn Fn(&str) -> Option<String>, light: bool) -> Result<(), String> {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use bitcheque::pow::{epoch, Table};
    const TEMPLATE_SECONDS: u64 = 20;
    let rpc = opt("--rpc").ok_or("--rpc ADDR needed (host:port of a node's RPC)")?;
    let to: u32 = opt("--to").ok_or("--to NUMBER needed (the account that gets the reward; 0 burns it)")?.parse().map_err(|_| "bad --to")?;
    let threads = opt("--threads").and_then(|t| t.parse().ok()).unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get())).max(1);
    // the easiest target of any network this miner may be pointed at (a template at a mainnet target is far below it)
    let min = Params::testnet().easiest_target().max(Params::local().easiest_target());
    let rate = |r: f64| if r >= 1e6 { format!("{:.2} MH/s", r / 1e6) } else { format!("{:.1} kH/s", r / 1e3) };
    eprintln!("mining for account {to} on {threads} threads against {rpc}{}", if light { ", without the table" } else { "" });
    let mut table: Option<Arc<Table>> = None;
    loop {
        let tpl = match http(&rpc, "GET", &format!("/template/{to}"), "") {
            Ok(t) => unhex(&t).and_then(|r| bitcheque::block::Block::decode(&r).ok()).ok_or("bad template")?,
            Err(e) => { eprintln!("template: {}", clean(&e)); std::thread::sleep(std::time::Duration::from_secs(5)); continue; }
        };
        // the node builds the template, so check it pays us and asks for real work: a node (or anyone between) could
        // otherwise have our work pay someone else
        if !matches!(tpl.txs.first(), Some(bitcheque::tx::Tx::Coinbase { payee, .. }) if *payee == to) { return Err("the node's template pays someone else: use another node".into()); }
        if U256::from_compact(tpl.header.bits) > min { return Err("the node's template asks for less work than any block may have: use another node".into()); }
        if !light && table.as_ref().map_or(true, |t| t.epoch != epoch(tpl.header.height)) {
            let e = epoch(tpl.header.height);
            eprintln!("building the 2 GiB table of epoch {e} (blocks {}-{}) on {threads} threads...", e * bitcheque::pow::EPOCH, (e + 1) * bitcheque::pow::EPOCH - 1);
            let started = std::time::Instant::now();
            table = Some(Arc::new(Table::build(e, threads)));
            eprintln!("table built in {:.0} s", started.elapsed().as_secs_f64());
            continue;   // a fresh template: this one has aged
        }
        let (stop, hashes, found) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicU64::new(0)), Arc::new(Mutex::new(None)));
        let step: u32 = if light { 16 } else { 4096 };   // tries between counting (about a few milliseconds)
        let workers: Vec<_> = (0..threads).map(|i| {
            let (mut b, stop, hashes, found, table) = (tpl.clone(), stop.clone(), hashes.clone(), found.clone(), table.clone());
            std::thread::spawn(move || {
                b.header.nonce = i as u32;
                while !stop.load(Ordering::Relaxed) {
                    for _ in 0..step {
                        let pow = match &table { Some(t) => t.hash(&b.header.hash()), None => b.header.pow() };
                        if b.header.meets(&pow) { *found.lock().unwrap() = Some(b.clone()); stop.store(true, Ordering::Relaxed); return; }
                        let (n, wrapped) = b.header.nonce.overflowing_add(threads as u32);
                        if wrapped { return; }   // this thread's share of the nonces is done
                        b.header.nonce = n;
                    }
                    hashes.fetch_add(step as u64, Ordering::Relaxed);
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
        let r = hashes.load(Ordering::Relaxed) as f64 / started.elapsed().as_secs_f64().max(0.001);
        let block = found.lock().unwrap().take();
        if let Some(b) = block {
            match http(&rpc, "POST", "/block", &hex(&b.encode())) {
                Ok(_) => eprintln!("mined block {} on {} with {} transactions ({})", b.header.height, hex(&tpl.header.prev[..4]), b.txs.len() - 1, rate(r)),
                Err(e) => eprintln!("block refused: {}", clean(&e)),
            }
        }
    }
}

fn http(addr: &str, method: &str, path: &str, body: &str) -> Result<String, String> { bitcheque::net::http(addr, method, path, body) }
fn clean(s: &str) -> String { bitcheque::net::clean(s) }

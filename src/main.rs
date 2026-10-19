//! bitcheque genesis [--mainnet|--local]   (default: the public research network; --testnet is the same)
//! bitcheque node [--mainnet|--local] [--data FILE] [--listen ADDR] [--advertise ADDR] [--rpc ADDR] [--peer ADDR]... [--mine NUMBER]
//!   With no --peer a node dials the compiled-in seeds, then keeps about 8 connections from the addresses peers share.
//!   --listen defaults to 0.0.0.0:8730 (mainnet) or 0.0.0.0:8731 (testnet); --advertise is the address others can reach you on.
//! bitcheque wallet new | info|register|send|sweep --seed HEX --rpc ADDR [--size CHEQUES] [--to NUMBER --amount COINS [--fee TIER]]
//! bitcheque wallet pieces --seed HEX [--size CHEQUES] --cheque N --digits D18   (raw pieces as hex, no checks: for tests)
use bitcheque::{block::Chain, crypto::{hex, sha256}, message::Message, net::Node, params::{Params, COIN, GENESIS_MESSAGE as MESSAGE, LAUNCH_TIME, LOCAL_TIME, TESTNET_TIME}, rpc::unhex, store::Store,
                tx::Payment, u256::U256, wallet::{mine_registration, Book, Domain}};


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
            let store = Store::open(p, &g, data.as_deref().map(std::path::Path::new)).expect("open data file");
            eprintln!("height {}", store.chain.height());
            let node = Node::new(store);
            if let Some(d) = &data { node.set_book_path(std::path::PathBuf::from(format!("{d}.peers"))); }
            if let Some(a) = opt("--advertise") { node.set_advertise(&a); }
            let listen = opt("--listen").or(if local { None } else { Some(format!("0.0.0.0:{}", if testnet { 8731 } else { 8730 })) });
            if let Some(a) = listen { eprintln!("listening on {}", node.listen(&a).expect("listen")); }
            if let Some(a) = opt("--rpc") { eprintln!("rpc on {}", node.serve_rpc(&a).expect("rpc")); }
            node.maintain(args.iter().enumerate().filter(|(_, a)| *a == "--peer").filter_map(|(i, _)| args.get(i + 1).cloned()).collect(), std::time::Duration::from_secs(5));
            let mine: Option<u32> = opt("--mine").map(|s| s.parse().expect("--mine NUMBER"));   // --mine 0 mines with the reward to nobody; no --mine: a node that only validates
            loop {
                match mine {
                    Some(n) => match node.mine_once(n) { Ok(b) => eprintln!("mined block {} with {} txs", node.height(), b.txs.len() - 1), Err(e) => { eprintln!("mining: {e}"); std::thread::sleep(std::time::Duration::from_secs(1)) } },
                    None => std::thread::sleep(std::time::Duration::from_secs(5)),
                }
            }
        }
        Some("wallet") => if let Err(e) = wallet(&args, &opt) { eprintln!("error: {e}"); std::process::exit(1) },
        _ => eprintln!("usage: bitcheque genesis [--mainnet|--local] | bitcheque node [--mainnet|--local] [--data FILE] [--listen ADDR] [--advertise ADDR] [--rpc ADDR] [--peer ADDR] [--mine NUMBER]\n       bitcheque wallet new | info|register|send|sweep --seed HEX --rpc ADDR [--size CHEQUES] [--to NUMBER --amount COINS [--fee TIER]]"),
    }
}

/// A software wallet for one book from one seed: 11 cheques like a printed book, or up to 1,024 with --size
/// (miners and other busy accounts). The book salt is derived from the seed, so seed + size recreate the book. Talks to a node's RPC; keeps no files.
fn wallet(args: &[String], opt: &dyn Fn(&str) -> Option<String>) -> Result<(), String> {
    let cmd = args.get(2).map(String::as_str).unwrap_or("");
    if cmd == "new" {
        let mut seed = [0u8; 32];
        std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom").map_err(|e| e.to_string())?, &mut seed).map_err(|e| e.to_string())?;
        println!("{}", hex(&seed));
        return Ok(());
    }
    let seed: [u8; 32] = unhex(&opt("--seed").ok_or("--seed HEX needed")?).and_then(|v| v.try_into().ok()).ok_or("seed must be 32 bytes of hex")?;
    let rpc = opt("--rpc").unwrap_or_default();
    if rpc.is_empty() && cmd != "pieces" { return Err("--rpc ADDR needed".into()); }
    let salt: [u8; 16] = sha256(&[b"bitcheque/salt".as_slice(), &seed].concat())[..16].try_into().unwrap();
    let size: u32 = opt("--size").map_or(Ok(11), |v| v.parse()).map_err(|_| "bad --size")?;
    if !(11..=1024).contains(&size) { return Err("--size must be 11 to 1024".into()); }
    let book = Book { salt, n256: false, book_size: size, domains: vec![Domain(seed)] };
    let id = hex(&book.id());
    let account = || -> Result<Vec<(String, String)>, String> {
        Ok(http(&rpc, "GET", &format!("/id/{id}"), "")?.lines().filter_map(|l| l.split_once(' ').map(|(k, v)| (k.to_string(), v.to_string()))).collect())
    };
    let field = |a: &[(String, String)], k: &str| a.iter().find(|(x, _)| x == k).map(|(_, v)| v.clone()).unwrap_or_default();
    let post = |t: &bitcheque::tx::Tx| http(&rpc, "POST", "/tx", &hex(&t.encode()));
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
        "register" => {
            let limbs: Vec<u64> = http(&rpc, "GET", "/regtarget", "")?.split_whitespace().map(|w| u64::from_str_radix(w, 16).unwrap_or(0)).collect();
            let target = U256(limbs.try_into().map_err(|_| "bad regtarget")?);
            let reg = mine_registration(book.register(0, size.next_power_of_two(), Payment::Pow(0)), target); // one batch, power-of-two aligned
            post(&reg)?;
            for piece in book.sign(0, &Message::new(0, 0, 0, 0)) { post(&piece)?; } // honesty check: cheque 0, zero coins, to nobody
            println!("id {id}\nregistration and honesty check (cheque 0) sent");
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
            // dry run each candidate first: a cheque whose last piece fails would sit half-spent until it expires.
            // A cheque already in use in the node's queue (an earlier send, or a half-submitted one) is skipped;
            // writing a higher number abandons a half-submitted cheque.
            let mut chosen = None;
            for cheque in field(&a, "unspent").split(',').filter_map(|x| x.parse::<u16>().ok()).filter(|&n| nonce.map_or(true, |k| n > k)) {
                let pieces = book.sign(cheque, &msg);
                let check = http(&rpc, "POST", "/check", &pieces.iter().map(|t| hex(&t.encode())).collect::<Vec<_>>().join("\n"))?;
                match check.lines().find(|l| *l != "ok") {
                    None => { chosen = Some((cheque, pieces)); break; }
                    Some("cheque number already consumed") | Some("column already revealed") => continue, // in use in the queue
                    Some(e) => return Err(format!("node would reject this cheque: {e}")),
                }
            }
            let (cheque, pieces) = chosen.ok_or("no unused cheques left")?;
            // the last cheque of a book is kept for the sweep to a new book (DESIGN.md §10.11): spent on anything
            // else, whatever is left in the account can never move again
            if cmd == "send" && cheque as u32 == size - 1 && opt("--last").is_none() {
                return Err(format!("cheque {cheque} is the last one in this book: keep it for `wallet sweep --to <new book>`, or pass --last to spend it anyway"));
            }
            for piece in &pieces { post(piece)?; }
            if cmd == "sweep" { println!("cheque {cheque} sent: {} sweeps the whole balance to {to}, fee tier {tier}", msg.display()); }
            else { println!("cheque {cheque} sent: {} to {to}, {} coins, fee tier {tier}", msg.display(), msg.amount().unwrap_or(0) as f64 / COIN as f64); }
        }
        _ => return Err("wallet commands: new, info, register, send, sweep, pieces".into()),
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

fn http(addr: &str, method: &str, path: &str, body: &str) -> Result<String, String> {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(addr).map_err(|e| format!("{addr}: {e}"))?;
    write!(s, "{method} {path} HTTP/1.0\r\nHost: {addr}\r\nContent-Length: {}\r\n\r\n{body}", body.len()).map_err(|e| e.to_string())?;
    let mut out = String::new();
    s.read_to_string(&mut out).map_err(|e| e.to_string())?;
    let (head, text) = out.split_once("\r\n\r\n").ok_or("bad reply")?;
    if head.split_whitespace().nth(1) == Some("200") { Ok(text.to_string()) } else { Err(format!("{path}: {text}")) }
}

//! Audit 6: the command-line wallet's `register` when the node takes only some of a book's registrations (its next block
//! already holds other people's, up to the cap of 16: "registration pow cap reached" for the rest). A rerun must register
//! the missing batches, not answer "already registered" and leave them out for good; a rerun after a complete
//! registration must still do nothing. Self-contained fake node (registrations and the honesty check only).
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use bitcheque::rpc::unhex;
use bitcheque::tx::{Tx, R};

const SEED: &str = "5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed5eed";

#[derive(Default)]
struct St { regs: Vec<(u32, u32)>, honesty: usize, cap: usize, posts: Vec<String>, nonce: Option<u16> }

/// A node that takes at most `cap` registrations per POST /tx (the rest "registration pow cap reached") and lists what
/// it has as the book's unspent cheques.
fn fake(cap: usize) -> (String, Arc<Mutex<St>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let st = Arc::new(Mutex::new(St { cap, ..Default::default() }));
    let s0 = st.clone();
    std::thread::spawn(move || for s in l.incoming() {
        let (mut s, st) = (s.unwrap(), s0.clone());
        std::thread::spawn(move || {
            let mut buf = Vec::new(); let mut b = [0u8; 65536];
            let (head, body) = loop {
                let n = s.read(&mut b).unwrap_or(0); if n == 0 { return; }
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
            let mut g = st.lock().unwrap();
            let (status, text) = if method == "POST" && path == "/tx" {
                g.posts.push(body.clone());
                let mut taken = 0;
                let lines: Vec<String> = body.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
                let mut out = Vec::new();
                for l in &lines {
                    let tx = unhex(l).and_then(|r| Tx::decode(&mut R::new(&r)).ok());
                    out.push(match tx {
                        Some(Tx::RegisterBook { batch, .. }) | Some(Tx::RegisterBatch { batch, .. }) => {
                            if taken >= g.cap { "registration pow cap reached" } else { taken += 1; g.regs.push((batch.start, batch.count)); "ok" }
                        }
                        Some(Tx::ChequeOpen { cheque, .. }) => { if cheque == 0 { g.honesty += 1; g.nonce = Some(0); } "ok" }
                        _ => "ok",
                    });
                }
                ("200 OK", if lines.len() == 1 { out[0].to_string() } else { out.join("\n") })
            } else if path.starts_with("/id/") {
                if g.regs.is_empty() { ("400 Bad Request", "no such account".to_string()) } else {
                    let mut unspent: Vec<u32> = g.regs.iter().flat_map(|&(s, c)| s..s + c).filter(|&n| g.nonce.map_or(true, |x| n > x as u32)).collect();
                    unspent.sort(); unspent.dedup();
                    ("200 OK", format!("id x\nnumber 5\nbalance 0\npending 0\nnonce {}\nbook_size 256\nunspent {}\nfunded false\nmature true\nready_at 0\nopen none\nrevealed none\nexpires none\nsalt 00",
                        g.nonce.map_or("none".to_string(), |n| n.to_string()), unspent.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(",")))
                }
            } else if path == "/regtarget" { ("200 OK", "0000000000000000 0000000000000000 0000000000000000 0001000000000000".to_string()) }
            else if path == "/tip" { ("200 OK", "00".repeat(32)) }
            else if path == "/height" { ("200 OK", "100".to_string()) }
            else { ("400 Bad Request", "unknown route".to_string()) };
            let _ = write!(s, "HTTP/1.0 {status}\r\nContent-Length: {}\r\n\r\n{text}", text.len());
        });
    });
    (addr, st)
}

fn home(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("bitcheque-w6-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("seed"), SEED).unwrap();
    use std::os::unix::fs::PermissionsExt; std::fs::set_permissions(d.join("seed"), std::fs::Permissions::from_mode(0o600)).unwrap();
    d
}
fn wallet(h: &std::path::Path, rpc: &str, args: &[&str]) -> (bool, String) {
    let seed = h.join("seed");
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_bitcheque")).env_clear().env("HOME", h).arg("wallet").args(args)
        .args(["--seed-file", seed.to_str().unwrap(), "--rpc", rpc, "--local"]).current_dir(h).output().unwrap();
    (o.status.success(), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
}

#[test]
fn a_partly_taken_registration_is_completed_by_a_rerun() {
    let (addr, st) = fake(13);   // three foreign registrations already fill the next block's cap of 16
    let h = home("reg");
    let (ok, out) = wallet(&h, &addr, &["register", "--cheques", "256"]);
    assert!(!ok && out.contains("registration pow cap reached"), "the first run is refused for the last batches: {out}");
    { let g = st.lock().unwrap(); assert_eq!(g.regs.len(), 13); assert_eq!(g.honesty, 1); }
    // the rerun registers batches 13-15 (cheques 208-255) and does not send the honesty check again
    let (ok, out) = wallet(&h, &addr, &["register", "--cheques", "256"]);
    assert!(ok && out.contains("cheques 208-255 registered"), "the rerun: {out}");
    let g = st.lock().unwrap();
    let mut starts: Vec<u32> = g.regs.iter().map(|r| r.0).collect(); starts.sort();
    assert_eq!(starts, (0..16).map(|k| k * 16).collect::<Vec<u32>>(), "every batch registered after the rerun");
    assert_eq!(g.honesty, 1, "the honesty check is sent once");
    drop(g);
    // with everything registered there is nothing left to do, for that count or the default
    let (ok, out) = wallet(&h, &addr, &["register", "--cheques", "256"]);
    assert!(ok && out.contains("already registered"), "{out}");
    let (ok, out) = wallet(&h, &addr, &["register"]);
    assert!(ok && out.contains("already registered"), "{out}");
    assert_eq!(st.lock().unwrap().regs.len(), 16);
}

/// The common rerun (a lost reply after a complete registration) stays a no-op: no second batch, no second honesty check.
#[test]
fn a_rerun_of_a_complete_registration_does_nothing() {
    let (addr, st) = fake(16);
    let h = home("reg2");
    let (ok, out) = wallet(&h, &addr, &["register"]);
    assert!(ok, "{out}");
    { let g = st.lock().unwrap(); assert_eq!(g.regs.len(), 1); assert_eq!(g.honesty, 1); }
    let (ok, out) = wallet(&h, &addr, &["register"]);
    assert!(ok && out.contains("already registered"), "{out}");
    let g = st.lock().unwrap();
    assert_eq!((g.regs.len(), g.honesty, g.posts.len()), (1, 1, 1), "nothing more was posted");
    drop(g);
    // `more` still adds the next batch
    let (ok, out) = wallet(&h, &addr, &["more"]);
    assert!(ok && out.contains("cheques 16-31 registered"), "{out}");
    assert_eq!(st.lock().unwrap().regs.iter().map(|r| r.0).collect::<Vec<u32>>(), vec![0, 16]);
}

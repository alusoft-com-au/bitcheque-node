//! The onboarding page's wallet, compiled to WebAssembly from the node's own code (no second
//! implementation). The page writes inputs into `io`, calls a function, and reads `io` back.
//! A registration is prepared once, then mined in short slices so a worker can report progress.
use bitcheque::crypto::{hex, sha256};
use bitcheque::message::Message;
use bitcheque::params::Params;
use bitcheque::tx::{Payment, Tx, R};
use bitcheque::u256::U256;
use bitcheque::wallet::{Book, Domain, BOOK_SIZE};

mod qr;
mod qrread;

/// Every heap block is zeroed when it is freed, so no copy of a seed, or of anything derived from it, outlives its use
/// in the module's memory (the page's own copies are the page's business).
struct Zeroing;
unsafe impl std::alloc::GlobalAlloc for Zeroing {
    unsafe fn alloc(&self, l: std::alloc::Layout) -> *mut u8 { std::alloc::System.alloc(l) }
    unsafe fn dealloc(&self, p: *mut u8, l: std::alloc::Layout) { for i in 0..l.size() { std::ptr::write_volatile(p.add(i), 0) } std::alloc::System.dealloc(p, l) }
}
#[global_allocator]
static ALLOC: Zeroing = Zeroing;

static mut IO: Vec<u8> = Vec::new();
static mut REG: Option<(Vec<u8>, usize, [u32; 8], U256)> = None;   // encoding, split, midstate, target

#[allow(static_mut_refs)]
fn io() -> &'static mut Vec<u8> { unsafe { &mut IO } }

/// Make room for `len` input bytes and return where to write them.
#[no_mangle]
pub extern "C" fn io_reserve(len: usize) -> *mut u8 { let b = io(); *b = vec![0; len]; b.as_mut_ptr() }   // the old buffer is zeroed as it goes
#[no_mangle]
pub extern "C" fn io_ptr() -> *const u8 { io().as_ptr() }
#[no_mangle]
pub extern "C" fn io_len() -> usize { io().len() }
fn out(s: String) -> usize { let b = io(); *b = s.into_bytes(); b.len() }

/// Run `f` on the input (taken out of `io`, which then holds only `f`'s output), then zero what is left of it: the
/// input's heap copy as it is freed, and the stack the call used (where a seed or a key derived from it may sit).
fn with_seed(f: impl FnOnce(&[u8]) -> usize) -> usize {
    let i = std::mem::take(io());
    let n = f(&i);
    drop(i);
    scrub_stack();
    n
}
#[inline(never)]
fn scrub_stack() { let mut b = [0u8; 65536]; for x in b.iter_mut() { unsafe { std::ptr::write_volatile(x, 0) } } std::hint::black_box(&b); }

/// The standard book for a 32-byte seed on the research network (its magic is part of every hash): 256 cheques, salt
/// from the seed (the same book as `bitcheque wallet`).
/// Cheque 0 is the honesty check sent with the registration and is never printed. The rest are printed and
/// registered 16 at a time, whenever the holder wants more.
fn book(seed: &[u8]) -> Option<Book> {
    let mut seed: [u8; 32] = seed.try_into().ok()?;
    let salt: [u8; 16] = sha256(&[b"bitcheque/salt".as_slice(), &seed].concat())[..16].try_into().unwrap();
    let b = Book { salt, n256: false, book_size: BOOK_SIZE, domains: vec![Domain(seed)], net: Params::testnet().magic };
    for x in seed.iter_mut() { unsafe { std::ptr::write_volatile(x, 0) } }
    Some(b)
}

/// io = seed (32 bytes) -> io = account id (hex). Returns its length, 0 on bad input.
#[no_mangle]
pub extern "C" fn account_id() -> usize { with_seed(|i| book(i).map_or(0, |b| out(hex(&b.id())))) }

/// io = seed (32) || first cheque (2, LE) || last cheque (2, LE) -> io = the registrations covering those cheques,
/// unmined (anchor zero, nonce 0), hex, one per line (16 cheques each; the one holding cheque 0 registers the book).
/// They hold only public hashes, so they can be carried to an online computer and mined there without the seed.
#[no_mangle]
pub extern "C" fn reg_txs() -> usize { with_seed(|i| {
    if i.len() != 36 { return 0; }
    let (first, last) = (u16::from_le_bytes([i[32], i[33]]) as u32, u16::from_le_bytes([i[34], i[35]]) as u32);
    if first > last || last >= BOOK_SIZE { return 0; }
    book(&i[..32]).map_or(0, |b| out(b.registrations(first, last).iter().map(|t| hex(&t.encode())).collect::<Vec<_>>().join("\n")))
}) }

/// io = registration tx bytes || anchor (32: the node's tip, as GET /tip, unhexed) || target (32, little-endian, as
/// /regtarget) -> ready to mine. The anchor replaces whatever the tx held: the work then counts for the next 144 blocks
/// on that chain only, so mine and send it right away. 1 on success.
#[no_mangle]
pub extern "C" fn reg_prepare() -> usize {
    let i = io().clone();
    if i.len() < 64 + 8 { return 0; }
    let (enc, rest) = i.split_at(i.len() - 64);
    let (anchor, t) = rest.split_at(32);
    let mut tx = match Tx::decode(&mut R::new(enc)) { Ok(t @ (Tx::RegisterBook { .. } | Tx::RegisterBatch { .. })) => t, _ => return 0 };
    if let Tx::RegisterBook { pay: Payment::Pow(a, _), .. } | Tx::RegisterBatch { pay: Payment::Pow(a, _), .. } = &mut tx { *a = anchor.try_into().unwrap() }
    let enc = tx.encode();
    let split = (enc.len() - 8) / 64 * 64;
    let mid = bitcheque::sha256::midstate(&enc[..split]);
    unsafe { REG = Some((enc, split, mid, U256::from_le_bytes(t.try_into().unwrap()))) };
    1
}

/// Try nonces `start .. start + count` (the start as two 32-bit halves). Returns 1 + the offset of the
/// first nonce whose txid is below the target, leaving it in place; 0 when none in this slice.
#[no_mangle]
#[allow(static_mut_refs)]
pub extern "C" fn reg_mine(lo: u32, hi: u32, count: u32) -> u32 {
    let Some((enc, split, mid, target)) = (unsafe { REG.as_mut() }) else { return 0 };
    let at = enc.len() - 8;
    let start = (hi as u64) << 32 | lo as u64;
    for k in 0..count {
        enc[at..].copy_from_slice(&start.wrapping_add(k as u64).to_le_bytes());
        let id = sha256(&bitcheque::sha256::finish(*mid, *split, &enc[*split..]));
        if U256::from_le_bytes(&id) < *target { return k + 1; }
    }
    0
}

/// io = the mined registration, hex (its nonce is whatever the last successful `reg_mine` left in place).
#[no_mangle]
#[allow(static_mut_refs)]
pub extern "C" fn reg_result() -> usize { unsafe { REG.as_ref() }.map_or(0, |(enc, ..)| out(hex(enc))) }

/// io = seed (32) || cheque (2, little-endian) || 18 digits (one byte each) -> 6 lines of hex txs: first the cheque's
/// opening (columns 0-12: the recipient and the first amount digit), then the pieces of columns 13-17, one per line.
/// Send the opening alone, and the 5 pieces only once the opening is a few blocks deep with these digits (§10.12).
#[no_mangle]
pub extern "C" fn pieces() -> usize { with_seed(|i| {
    let Some((b, cheque, d)) = cheque_input(i) else { return 0 };
    let (open, rest) = b.halves(cheque, &d);
    out([open].iter().chain(&rest).map(|t| hex(&t.encode())).collect::<Vec<_>>().join("\n"))
}) }

/// io = as for `pieces` -> one line of hex: the whole cheque as one opening (all 18 columns), opened and completed in one
/// transaction. For a void (zero coins to number 0), which has nothing to protect.
#[no_mangle]
pub extern "C" fn open_all() -> usize { with_seed(|i| {
    let Some((b, cheque, d)) = cheque_input(i) else { return 0 };
    out(hex(&b.open_all(cheque, &d).encode()))
}) }

/// seed (32) || cheque (2, LE) || 18 digits 0-9.
fn cheque_input(i: &[u8]) -> Option<(Book, u16, [u8; 18])> {
    if i.len() != 52 { return None; }
    let d: [u8; 18] = i[34..].try_into().unwrap();
    if d.iter().any(|&x| x > 9) { return None; }
    Some((book(&i[..32])?, u16::from_le_bytes([i[32], i[33]]), d))
}

/// io = seed (32) || cheque (2, little-endian) || 18 digits (one byte each) -> the 18 cells those digits pick (column c,
/// row digit c), 32 hex digits each, one per line: the cells of `pieces` without deriving the whole book, so printing
/// a sheet can check every cheque against the wallet's own code cheaply.
#[no_mangle]
pub extern "C" fn cells() -> usize { with_seed(|i| {
    let Some((b, cheque, d)) = cheque_input(i) else { return 0 };
    out((0..18u8).map(|c| hex(&b.domains[0].cell(&b.net, b.n(), cheque, c, d[c as usize]))).collect::<Vec<_>>().join("\n"))
}) }

/// io = seed (32) || cheque (2, little-endian) -> io = that cheque's commitments in the format of the node's
/// GET /commits/<id>/<cheque>: 18 lines (columns), each 10 lowercase hex commitments (rows), space-separated. Equal to the
/// node's answer when the node holds this book's cheque as registered: check it before revealing any cell.
#[no_mangle]
pub extern "C" fn commits() -> usize { with_seed(|i| {
    if i.len() != 34 { return 0; }
    let Some(b) = book(&i[..32]) else { return 0 };
    let cheque = u16::from_le_bytes([i[32], i[33]]);
    out(bitcheque::state::Commits::new(bitcheque::book::leaf_from_shares(&b.key(), b.n(), cheque, &b.shares(cheque)).1).lines(b.n()))
}) }

/// io = book salt (16, from GET /account) || cheque (2, little-endian) || column || row || cell (16) -> io = that cell's
/// commitment in hex, as GET /commits lists it: the cheque page checks a written cell without the seed and before sending.
#[no_mangle]
pub extern "C" fn cell_commit() -> usize {
    let i = io().clone();
    if i.len() != 36 || i[18] > 17 || i[19] > 9 { return 0; }
    let k = bitcheque::crypto::key(i[..16].try_into().unwrap(), &Params::testnet().magic);
    let (q, c, r) = (u16::from_le_bytes([i[16], i[17]]), i[18], i[19]);
    out(hex(&bitcheque::book::commit(&k, 16, q, c, r, &[bitcheque::book::share_hash(&k, 16, q, c, r, 0, &i[20..])])))
}

/// io = seed (32) -> the honesty check: cheque 0, zero coins, to nobody (as `bitcheque wallet register` sends), as one
/// line of hex: one opening of all 18 columns.
#[no_mangle]
pub extern "C" fn honesty() -> usize { with_seed(|i| {
    let Some(b) = book(i) else { return 0 };
    out(hex(&b.open_all(0, &Message::new(0, 0, 0, 0).digits()).encode()))
}) }

/// io = text (a link) -> io = side length (1 byte) then one byte per module, row by row (1 = dark). 0 when too long.
#[no_mangle]
pub extern "C" fn qr() -> usize { qr_at(qr::Ecc::M) }
/// The same at the highest error correction (about 30% may be covered), for codes with a label printed in the middle.
#[no_mangle]
pub extern "C" fn qr_h() -> usize { qr_at(qr::Ecc::H) }
fn qr_at(ecc: qr::Ecc) -> usize {
    let Some((n, m)) = qr::encode(&io().clone(), ecc) else { return 0 };
    let b = io(); b.clear(); b.push(n as u8); b.extend(m.iter().map(|&d| d as u8)); b.len()
}

/// io = seed (32) -> io = the lookup code printed on the sheets: the first 12 hex digits of the account id after its scheme byte.
#[no_mangle]
pub extern "C" fn lookup_code() -> usize { with_seed(|i| book(i).map_or(0, |b| out(hex(&b.id()[1..7])))) }

/// io = width (4 bytes LE) || height (4 bytes LE) || greyscale pixels -> io = the text of a QR code found in the image. 0 when none.
#[no_mangle]
pub extern "C" fn qr_read() -> usize {
    let i = io().clone();
    if i.len() < 8 { return 0; }
    let (w, h) = (u32::from_le_bytes(i[0..4].try_into().unwrap()) as usize, u32::from_le_bytes(i[4..8].try_into().unwrap()) as usize);
    match qrread::read(&i[8..], w, h) { Some(t) => { let b = io(); *b = t; b.len() } None => 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn call(f: extern "C" fn() -> usize, input: &[u8]) -> String { *io() = input.to_vec(); let n = f(); String::from_utf8(io()[..n].to_vec()).unwrap() }
    /// (column, cell) of every piece in some lines of hex txs.
    fn cells_of(lines: &str) -> Vec<(u8, String)> {
        lines.lines().flat_map(|l| match Tx::decode(&mut R::new(&bitcheque::rpc::unhex(l).unwrap())).unwrap() {
            Tx::ChequeOpen { pieces, .. } => pieces.into_iter().map(|(c, sh)| (c, hex(&sh[0]))).collect(),
            Tx::ChequePiece { column, shares, .. } => vec![(column, hex(&shares[0]))],
            _ => panic!(),
        }).collect()
    }
    #[test]
    fn cells_match_pieces() {
        let seed = [9u8; 32];
        for (q, d) in [(1u16, [3u8; 18]), (255, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7])] {
            let input = [&seed[..], &q.to_le_bytes(), &d].concat();
            let cells_ = call(cells, &input);
            let want: Vec<(u8, String)> = cells_.lines().enumerate().map(|(c, x)| (c as u8, x.to_string())).collect();
            let two = call(pieces, &input);
            assert_eq!(two.lines().count(), 6);
            assert!(matches!(Tx::decode(&mut R::new(&bitcheque::rpc::unhex(two.lines().next().unwrap()).unwrap())), Ok(Tx::ChequeOpen { ref pieces, .. }) if pieces.len() == 13));
            assert_eq!(cells_of(&two), want);
            let one = call(open_all, &input);
            assert_eq!(one.lines().count(), 1);
            assert_eq!(cells_of(&one), want);
        }
        assert_eq!({ *io() = [&seed[..], &[1, 0], &[10u8; 18]].concat(); cells() }, 0);
        assert_eq!({ *io() = [&seed[..], &[1, 0], &[10u8; 18]].concat(); open_all() }, 0);
        assert_eq!(call(honesty, &seed).lines().count(), 1);
    }
    #[test]
    fn cell_commit_matches_the_cheque_commitments() {
        let seed = [7u8; 32];
        let b = book(&seed).unwrap();
        for q in [1u16, 200] {
            let lines = call(commits, &[&seed[..], &q.to_le_bytes()].concat());
            let cm: Vec<Vec<&str>> = lines.lines().map(|l| l.split(' ').collect()).collect();
            for c in 0..18u8 { for r in 0..10u8 {
                let cell = b.domains[0].cell(&b.net, 16, q, c, r);
                assert_eq!(call(cell_commit, &[&b.salt[..], &q.to_le_bytes(), &[c, r], &cell].concat()), cm[c as usize][r as usize]);
            } }
        }
    }
}

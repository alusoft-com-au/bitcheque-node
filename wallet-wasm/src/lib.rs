//! The onboarding page's wallet, compiled to WebAssembly from the node's own code (no second
//! implementation). The page writes inputs into `io`, calls a function, and reads `io` back.
//! A registration is prepared once, then mined in short slices so a worker can report progress.
use bitcheque::crypto::{hex, sha256};
use bitcheque::message::Message;
use bitcheque::tx::Payment;
use bitcheque::u256::U256;
use bitcheque::wallet::{Book, Domain, BOOK_SIZE};

mod qr;
mod qrread;

static mut IO: Vec<u8> = Vec::new();
static mut REG: Option<(Vec<u8>, usize, [u32; 8], U256)> = None;   // encoding, split, midstate, target

#[allow(static_mut_refs)]
fn io() -> &'static mut Vec<u8> { unsafe { &mut IO } }

/// Make room for `len` input bytes and return where to write them.
#[no_mangle]
pub extern "C" fn io_reserve(len: usize) -> *mut u8 { let b = io(); b.clear(); b.resize(len, 0); b.as_mut_ptr() }
#[no_mangle]
pub extern "C" fn io_ptr() -> *const u8 { io().as_ptr() }
#[no_mangle]
pub extern "C" fn io_len() -> usize { io().len() }
fn out(s: String) -> usize { let b = io(); *b = s.into_bytes(); b.len() }

/// The standard book for a 32-byte seed: 256 cheques, salt from the seed (the same book as `bitcheque wallet`).
/// Cheque 0 is the honesty check sent with the registration and is never printed. The rest are printed and
/// registered 16 at a time, whenever the holder wants more.
fn book(seed: &[u8]) -> Option<Book> {
    let seed: [u8; 32] = seed.try_into().ok()?;
    let salt: [u8; 16] = sha256(&[b"bitcheque/salt".as_slice(), &seed].concat())[..16].try_into().unwrap();
    Some(Book { salt, n256: false, book_size: BOOK_SIZE, domains: vec![Domain(seed)] })
}

/// io = seed (32 bytes) -> io = account id (hex). Returns its length, 0 on bad input.
#[no_mangle]
pub extern "C" fn account_id() -> usize { book(&io().clone()).map_or(0, |b| out(hex(&b.id()))) }

/// io = seed (32) || first cheque (2, LE) || last cheque (2, LE) -> io = the registrations covering those cheques,
/// nonce 0, hex, one per line (16 cheques each; the one holding cheque 0 registers the book). They hold only
/// public hashes, so they can be carried to an online computer and mined there without the seed.
#[no_mangle]
pub extern "C" fn reg_txs() -> usize {
    let i = io().clone();
    if i.len() != 36 { return 0; }
    let (first, last) = (u16::from_le_bytes([i[32], i[33]]) as u32, u16::from_le_bytes([i[34], i[35]]) as u32);
    if first > last || last >= BOOK_SIZE { return 0; }
    book(&i[..32]).map_or(0, |b| out(b.registrations(first, last).iter().map(|t| hex(&t.encode())).collect::<Vec<_>>().join("\n")))
}

/// io = registration tx bytes || target (32, little-endian, as /regtarget) -> ready to mine. 1 on success.
#[no_mangle]
pub extern "C" fn reg_prepare() -> usize {
    let i = io().clone();
    if i.len() < 64 + 8 { return 0; }
    let (enc, t) = i.split_at(i.len() - 32);
    match bitcheque::tx::Tx::decode(&mut bitcheque::tx::R::new(enc)) { Ok(bitcheque::tx::Tx::RegisterBook { pay: Payment::Pow(_), .. } | bitcheque::tx::Tx::RegisterBatch { pay: Payment::Pow(_), .. }) => {}, _ => return 0 }
    let enc = enc.to_vec();
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

/// io = seed (32) || cheque (2, little-endian) || 18 digits (one byte each) -> the 18 pieces, hex, one per line.
#[no_mangle]
pub extern "C" fn pieces() -> usize {
    let i = io().clone();
    if i.len() != 52 { return 0; }
    let Some(b) = book(&i[..32]) else { return 0 };
    let cheque = u16::from_le_bytes([i[32], i[33]]);
    let d: [u8; 18] = i[34..].try_into().unwrap();
    if d.iter().any(|&x| x > 9) { return 0; }
    out(b.pieces(cheque, &d).iter().map(|t| hex(&t.encode())).collect::<Vec<_>>().join("\n"))
}

/// io = seed (32) -> the honesty check: cheque 0, zero coins, to nobody (as `bitcheque wallet register` sends).
#[no_mangle]
pub extern "C" fn honesty() -> usize {
    let Some(b) = book(&io().clone()) else { return 0 };
    out(b.sign(0, &Message::new(0, 0, 0, 0)).iter().map(|t| hex(&t.encode())).collect::<Vec<_>>().join("\n"))
}

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
pub extern "C" fn lookup_code() -> usize { book(&io().clone()).map_or(0, |b| out(hex(&b.id()[1..7]))) }

/// io = width (4 bytes LE) || height (4 bytes LE) || greyscale pixels -> io = the text of a QR code found in the image. 0 when none.
#[no_mangle]
pub extern "C" fn qr_read() -> usize {
    let i = io().clone();
    if i.len() < 8 { return 0; }
    let (w, h) = (u32::from_le_bytes(i[0..4].try_into().unwrap()) as usize, u32::from_le_bytes(i[4..8].try_into().unwrap()) as usize);
    match qrread::read(&i[8..], w, h) { Some(t) => { let b = io(); *b = t; b.len() } None => 0 }
}

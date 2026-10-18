//! Hash primitive (DESIGN.md §3.1): `H(addr, x) = SHA256(book_salt || pad48 || addr || x)[..n]`.
//! `addr` is 8 bytes: tag, cheque (u16 LE), column, index, extra, two zero bytes.
pub use crate::sha256::sha256;

pub const TAG_SHARE: u8 = 0;
pub const TAG_COMMIT: u8 = 1;
pub const TAG_COLNODE: u8 = 2;
pub const TAG_LEAF: u8 = 3;
pub const TAG_ACCTNODE: u8 = 4;

pub fn sha256d(b: &[u8]) -> [u8; 32] { sha256(&sha256(b)) }

pub fn addr(tag: u8, cheque: u16, column: u8, index: u8, extra: u8) -> [u8; 8] {
    let c = cheque.to_le_bytes();
    [tag, c[0], c[1], column, index, extra, 0, 0]
}
pub fn h(salt: &[u8; 16], n: usize, a: &[u8; 8], x: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(72 + x.len());
    v.extend_from_slice(salt); v.extend_from_slice(&[0u8; 48]); v.extend_from_slice(a); v.extend_from_slice(x);
    sha256(&v)[..n].to_vec()
}
pub fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{:02x}", x)).collect() }

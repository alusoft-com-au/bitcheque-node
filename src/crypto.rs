//! Hash primitive (DESIGN.md §3.1): `H(key, addr, x) = SHA256(book_salt || net || pad44 || addr || x)[..n]`, where
//! `key = book_salt || net` and `net` is the network's 4-byte magic, so one book commits differently on every network.
//! `addr` is 8 bytes: tag, cheque (u16 LE), column, index, extra, two zero bytes.
pub use crate::sha256::sha256;

pub const TAG_SHARE: u8 = 0;
pub const TAG_COMMIT: u8 = 1;
pub const TAG_COLNODE: u8 = 2;
pub const TAG_LEAF: u8 = 3;
pub const TAG_ACCTNODE: u8 = 4;

/// A book's hash key on one network: its salt, then the network magic (`Params::magic`).
pub type Key = [u8; 20];
pub fn key(salt: &[u8; 16], net: &[u8; 4]) -> Key { let mut k = [0u8; 20]; k[..16].copy_from_slice(salt); k[16..].copy_from_slice(net); k }

pub fn sha256d(b: &[u8]) -> [u8; 32] { sha256(&sha256(b)) }

pub fn addr(tag: u8, cheque: u16, column: u8, index: u8, extra: u8) -> [u8; 8] {
    let c = cheque.to_le_bytes();
    [tag, c[0], c[1], column, index, extra, 0, 0]
}
pub fn h(k: &Key, n: usize, a: &[u8; 8], x: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(72 + x.len());
    v.extend_from_slice(k); v.extend_from_slice(&[0u8; 44]); v.extend_from_slice(a); v.extend_from_slice(x);
    sha256(&v)[..n].to_vec()
}
pub fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{:02x}", x)).collect() }

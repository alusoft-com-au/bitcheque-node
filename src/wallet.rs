//! Non-consensus helpers: seed derivation (DESIGN.md §4.2), building registrations and
//! cheque pieces for one or more domains. A real wallet keeps each domain on its own device.
use crate::book::{self, Bytes, ChequeShares};
use crate::crypto::sha256;
use crate::message::{Message, COLS, ROWS};
use crate::tx::{account_id, AccountId, Batch, Payment, Tx};
use crate::u256::U256;

/// One seed. A standard book has one; a split book (optional) has one per domain. Cells: `cell = SHA256("bitcheque/cell" || key[N] || col || row)[..n]`,
/// `key[N] = SHA256("bitcheque/key" || seed || N)`.
#[derive(Clone)]
pub struct Domain(pub [u8; 32]);
impl Domain {
    pub fn key(&self, cheque: u16) -> [u8; 32] { sha256(&[b"bitcheque/key".as_slice(), &self.0, &cheque.to_le_bytes()].concat()) }
    pub fn cell(&self, n: usize, cheque: u16, col: u8, row: u8) -> Bytes { sha256(&[b"bitcheque/cell".as_slice(), &self.key(cheque), &[col, row]].concat())[..n].to_vec() }
}

pub struct Book { pub salt: [u8; 16], pub n256: bool, pub book_size: u32, pub domains: Vec<Domain> }
impl Book {
    pub fn n(&self) -> usize { if self.n256 { 32 } else { 16 } }
    pub fn m(&self) -> u8 { self.domains.len() as u8 }
    /// Public share hashes of one cheque, `[col][row][k]`; a one-seed book has a single share (k = 0).
    pub fn shares(&self, cheque: u16) -> ChequeShares {
        (0..COLS as u8).map(|c| (0..ROWS as u8).map(|r| self.domains.iter().enumerate()
            .map(|(k, d)| book::share_hash(&self.salt, self.n(), cheque, c, r, k as u8, &d.cell(self.n(), cheque, c, r))).collect()).collect()).collect()
    }
    pub fn leaves(&self) -> Vec<Bytes> { (0..self.book_size).map(|i| book::leaf_from_shares(&self.salt, self.n(), i as u16, &self.shares(i as u16)).0).collect() }
    pub fn root(&self) -> Bytes { book::account_root(&self.salt, self.n(), &self.leaves(), self.book_size) }
    pub fn id(&self) -> AccountId { account_id(self.m(), self.n256, &self.root()) }
    pub fn batch(&self, start: u32, count: u32) -> Batch {
        let end = (start + count).min(self.book_size);
        Batch { start, count, cheques: (start..end).map(|i| self.shares(i as u16)).collect(),
                path: book::subtree_path(&self.salt, self.n(), start, count, &self.leaves(), self.book_size) }
    }
    pub fn register(&self, start: u32, count: u32, pay: Payment) -> Tx {
        Tx::RegisterBook { salt: self.salt, m: self.m(), n256: self.n256, book_size: self.book_size, root: self.root(), batch: self.batch(start, count), pay }
    }
    /// The 18 pieces of a cheque, payee columns first. Each carries every domain's cell.
    pub fn pieces(&self, cheque: u16, digits: &[u8; COLS]) -> Vec<Tx> {
        let id = self.id();
        (0..COLS as u8).map(|c| Tx::ChequePiece { account: id.clone(), cheque, column: c,
            shares: self.domains.iter().map(|d| d.cell(self.n(), cheque, c, digits[c as usize])).collect() }).collect()
    }
    pub fn sign(&self, cheque: u16, msg: &Message) -> Vec<Tx> { self.pieces(cheque, &msg.digits()) }
}

/// Grind the registration's PoW nonce until its txid is below `target`. The nonce is the last 8 bytes
/// of the encoding, so everything before it is hashed once (SHA-256 midstate) and each try costs a few blocks.
pub fn mine_registration(mut tx: Tx, target: U256) -> Tx {
    let mut enc = tx.encode();
    if !matches!(tx, Tx::RegisterBook { pay: Payment::Pow(_), .. }) { return tx; }
    let at = enc.len() - 8;
    let split = at / 64 * 64;
    let mid = crate::sha256::midstate(&enc[..split]);
    let mut nonce = u64::from_le_bytes(enc[at..].try_into().unwrap());
    loop {
        enc[at..].copy_from_slice(&nonce.to_le_bytes());
        let id = sha256(&crate::sha256::finish(mid, split, &enc[split..]));
        if U256::from_le_bytes(&id) < target { break; }
        nonce = nonce.wrapping_add(1);
    }
    if let Tx::RegisterBook { pay: Payment::Pow(n), .. } = &mut tx { *n = nonce }
    debug_assert!(U256::from_le_bytes(&tx.txid()) < target);
    tx
}

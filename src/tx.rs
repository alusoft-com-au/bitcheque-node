//! Transaction types (DESIGN.md §2.2) and their canonical byte form. No signatures
//! exist: a cheque piece is authorised by hash preimages, registrations are self-verifying.
use crate::book::{Bytes, ChequeShares};
use crate::crypto::sha256d;
use crate::message::{COLS, PART_A};

/// `scheme || root`; scheme = 0x03 | m<<4 | n256<<7.
pub type AccountId = Vec<u8>;

pub fn account_id(m: u8, n256: bool, root: &[u8]) -> AccountId {
    let mut v = vec![0x03 | (m << 4) | ((n256 as u8) << 7)];
    v.extend_from_slice(root);
    v
}
pub fn id_m(id: &[u8]) -> u8 { id.first().map_or(0, |b| (b >> 4) & 7) }
pub fn id_n(id: &[u8]) -> usize { if id.first().is_some_and(|b| b & 0x80 != 0) { 32 } else { 16 } }
/// A well-formed account id: scheme byte 0x03 with m in 1..=7, then a 16- or 32-byte root.
/// Checked when decoding, so nothing past the decoder ever sees a malformed one.
fn valid_id(id: &[u8]) -> bool { !id.is_empty() && id[0] & 0x0F == 0x03 && (1..=7).contains(&id_m(id)) && id.len() == 1 + id_n(id) }
fn account(r: &mut R) -> Result<AccountId, &'static str> { let a = r.bytes()?; if valid_id(&a) { Ok(a) } else { Err("bad account id") } }

#[derive(Clone, Debug, PartialEq)]
pub struct Batch {
    pub start: u32,
    pub count: u32,             // always Params::max_batch (16), aligned
    pub cheques: Vec<ChequeShares>, // cheques start.. (those below book_size)
    pub path: Vec<Bytes>,       // siblings from the subtree root to the account root
}
#[derive(Clone, Debug, PartialEq)]
/// Registrations are paid by proof of work only: (anchor, nonce). The anchor is the hash of a recent block (one of the
/// last `reg_anchor_window`), so the work is done for one place on one chain and cannot be replayed later.
pub enum Payment { Pow([u8; 32], u64) }

#[derive(Clone, Debug, PartialEq)]
pub enum Tx {
    Coinbase { height: u32, payee: u32, message: Vec<u8> },
    RegisterBook { salt: [u8; 16], m: u8, n256: bool, book_size: u32, root: Bytes, batch: Batch, pay: Payment },
    RegisterBatch { account: AccountId, batch: Batch, pay: Payment },
    /// One column of a cheque already open (§10.12).
    ChequePiece { account: AccountId, cheque: u16, column: u8, shares: Vec<Bytes> },
    Renew { account: AccountId, start: u32 },
    /// Opens a cheque: (column, shares) for every recipient column 0-11 and at least one amount column 12-17, columns
    /// strictly rising. Only a holder of both printed parts can make one; it uses the number at once (§10.12).
    ChequeOpen { account: AccountId, cheque: u16, pieces: Vec<(u8, Vec<Bytes>)> },
}

/// The columns of a cheque opening: all of part A (0-11), then one or more of part B, strictly rising, below 18.
pub fn open_columns_ok(cols: impl Iterator<Item = u8>) -> bool {
    let (mut k, mut last) = (0usize, None::<u8>);
    for c in cols {
        if (k < PART_A && c as usize != k) || c as usize >= COLS || last.is_some_and(|l| c <= l) { return false; }
        k += 1; last = Some(c);
    }
    k > PART_A
}

// ---- byte encoding: little-endian ints, length-prefixed vectors ----
pub struct W(pub Vec<u8>);
impl W {
    pub fn u8(&mut self, x: u8) { self.0.push(x) }
    pub fn u16(&mut self, x: u16) { self.0.extend_from_slice(&x.to_le_bytes()) }
    pub fn u32(&mut self, x: u32) { self.0.extend_from_slice(&x.to_le_bytes()) }
    pub fn u64(&mut self, x: u64) { self.0.extend_from_slice(&x.to_le_bytes()) }
    pub fn bytes(&mut self, b: &[u8]) { self.u32(b.len() as u32); self.0.extend_from_slice(b) }
    pub fn batch(&mut self, b: &Batch) {
        self.u32(b.start); self.u32(b.count); self.u32(b.cheques.len() as u32);
        for ch in &b.cheques { for col in ch { for row in col { for half in row { self.bytes(half) } } } }
        self.u32(b.path.len() as u32);
        for p in &b.path { self.bytes(p) }
    }
}
pub struct R<'a> { pub b: &'a [u8], pub i: usize }
impl<'a> R<'a> {
    pub fn new(b: &'a [u8]) -> R<'a> { R { b, i: 0 } }
    pub fn take(&mut self, k: usize) -> Result<&'a [u8], &'static str> {
        // checked: on a 32-bit target (the edge node's wasm) a length near u32::MAX would wrap past the bounds check
        let end = self.i.checked_add(k).filter(|&e| e <= self.b.len()).ok_or("truncated")?;
        let s = &self.b[self.i..end]; self.i = end; Ok(s)
    }
    pub fn u8(&mut self) -> Result<u8, &'static str> { Ok(self.take(1)?[0]) }
    pub fn u16(&mut self) -> Result<u16, &'static str> { Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap())) }
    pub fn u32(&mut self) -> Result<u32, &'static str> { Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap())) }
    pub fn u64(&mut self) -> Result<u64, &'static str> { Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap())) }
    pub fn bytes(&mut self) -> Result<Vec<u8>, &'static str> { let k = self.u32()? as usize; Ok(self.take(k)?.to_vec()) }
    /// A hash share of exactly `n` bytes (the book's 16 or 32), so a frame cannot decode into far more memory than it took on the wire.
    pub fn share(&mut self, n: usize) -> Result<Vec<u8>, &'static str> { let k = self.u32()? as usize; if k != n { return Err("bad share length"); } Ok(self.take(k)?.to_vec()) }
    pub fn batch(&mut self, m: usize, n: usize) -> Result<Batch, &'static str> {
        let start = self.u32()?; let count = self.u32()?; let nch = self.u32()?;
        if nch > crate::params::MAX_BATCH { return Err("batch too large"); }
        let mut cheques = Vec::with_capacity(nch as usize);
        for _ in 0..nch {
            let mut ch = Vec::with_capacity(18);
            for _ in 0..18 { let mut col = Vec::with_capacity(10);
                for _ in 0..10 { let mut row = Vec::with_capacity(m); for _ in 0..m { row.push(self.share(n)?) } col.push(row) }
                ch.push(col) }
            cheques.push(ch);
        }
        let np = self.u32()?; if np > 32 { return Err("path too long"); }
        let mut path = Vec::new(); for _ in 0..np { path.push(self.share(n)?) }
        Ok(Batch { start, count, cheques, path })
    }
}

impl Tx {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = W(Vec::new());
        match self {
            Tx::Coinbase { height, payee, message } => { w.u8(0); w.u32(*height); w.u32(*payee); w.bytes(message) }
            Tx::RegisterBook { salt, m, n256, book_size, root, batch, pay } => {
                w.u8(1); w.0.extend_from_slice(salt); w.u8(*m); w.u8(*n256 as u8); w.u32(*book_size); w.bytes(root); w.batch(batch);
                match pay { Payment::Pow(anchor, nonce) => { w.u8(0); w.0.extend_from_slice(anchor); w.u64(*nonce) } }
            }
            Tx::RegisterBatch { account, batch, pay } => {
                w.u8(2); w.bytes(account); w.batch(batch);
                match pay { Payment::Pow(anchor, nonce) => { w.u8(0); w.0.extend_from_slice(anchor); w.u64(*nonce) } }
            }
            Tx::ChequePiece { account, cheque, column, shares } => {
                w.u8(3); w.bytes(account); w.u16(*cheque); w.u8(*column); w.u8(shares.len() as u8); for h in shares { w.bytes(h) }
            }
            Tx::Renew { account, start } => { w.u8(4); w.bytes(account); w.u32(*start) }
            Tx::ChequeOpen { account, cheque, pieces } => {
                w.u8(5); w.bytes(account); w.u16(*cheque); w.u8(pieces.len() as u8);
                for (c, shares) in pieces { w.u8(*c); w.u8(shares.len() as u8); for h in shares { w.bytes(h) } }
            }
        }
        w.0
    }
    /// Decode one transaction; `r` must hold exactly its bytes (anything left over is refused, so one tx has one encoding).
    pub fn decode(r: &mut R) -> Result<Tx, &'static str> {
        let pay = |r: &mut R| -> Result<Payment, &'static str> { match r.u8()? { 0 => Ok(Payment::Pow(r.take(32)?.try_into().unwrap(), r.u64()?)), _ => Err("bad payment") } };
        let t = match r.u8()? {
            0 => Tx::Coinbase { height: r.u32()?, payee: r.u32()?, message: r.bytes()? },
            1 => {
                let salt: [u8; 16] = r.take(16)?.try_into().unwrap();
                let m = r.u8()?; let n256 = match r.u8()? { 0 => false, 1 => true, _ => return Err("bad n256") }; let book_size = r.u32()?; let root = r.bytes()?;
                if !(1..=7).contains(&m) { return Err("bad m"); }
                let n = if n256 { 32 } else { 16 };
                if root.len() != n { return Err("bad root"); }
                let batch = r.batch(m as usize, n)?;
                let pay = pay(r)?;
                Tx::RegisterBook { salt, m, n256, book_size, root, batch, pay }
            }
            2 => {
                let account = account(r)?; let batch = r.batch(id_m(&account) as usize, id_n(&account))?;
                let pay = pay(r)?;
                Tx::RegisterBatch { account, batch, pay }
            }
            3 => { let account = account(r)?; let cheque = r.u16()?; let column = r.u8()?; let k = r.u8()?; if k != id_m(&account) { return Err("bad share count"); }
                   let n = id_n(&account); let mut shares = Vec::new(); for _ in 0..k { shares.push(r.share(n)?) }
                   Tx::ChequePiece { account, cheque, column, shares } }
            4 => Tx::Renew { account: account(r)?, start: r.u32()? },
            5 => { let account = account(r)?; let cheque = r.u16()?; let k = r.u8()? as usize; if k > COLS { return Err("bad opening"); }
                   let (m, n) = (id_m(&account), id_n(&account)); let mut pieces = Vec::with_capacity(k);
                   for _ in 0..k { let c = r.u8()?; if r.u8()? != m { return Err("bad share count"); }
                                   let mut shares = Vec::new(); for _ in 0..m { shares.push(r.share(n)?) } pieces.push((c, shares)); }
                   if !open_columns_ok(pieces.iter().map(|p| p.0)) { return Err("bad opening columns"); }
                   Tx::ChequeOpen { account, cheque, pieces } }
            _ => return Err("unknown tx type"),
        };
        if r.i != r.b.len() { return Err("trailing bytes"); }
        Ok(t)
    }
    pub fn txid(&self) -> [u8; 32] { sha256d(&self.encode()) }
}

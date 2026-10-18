//! Transaction types (DESIGN.md §2.2) and their canonical byte form. No signatures
//! exist: a cheque piece is authorised by hash preimages, registrations are self-verifying.
use crate::book::{Bytes, ChequeShares};
use crate::crypto::sha256d;

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
    pub count: u32,             // power of two, aligned
    pub cheques: Vec<ChequeShares>, // cheques start.. (those below book_size)
    pub path: Vec<Bytes>,       // siblings from the subtree root to the account root
}
#[derive(Clone, Debug, PartialEq)]
pub enum Payment { Pow(u64) }   // registrations are paid by proof of work only

#[derive(Clone, Debug, PartialEq)]
pub enum Tx {
    Coinbase { height: u32, payee: u32, message: Vec<u8> },
    RegisterBook { salt: [u8; 16], m: u8, n256: bool, book_size: u32, root: Bytes, batch: Batch, pay: Payment },
    RegisterBatch { account: AccountId, batch: Batch },
    ChequePiece { account: AccountId, cheque: u16, column: u8, shares: Vec<Bytes> },
    Renew { account: AccountId, start: u32 },
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
        if self.i + k > self.b.len() { return Err("truncated"); }
        let s = &self.b[self.i..self.i + k]; self.i += k; Ok(s)
    }
    pub fn u8(&mut self) -> Result<u8, &'static str> { Ok(self.take(1)?[0]) }
    pub fn u16(&mut self) -> Result<u16, &'static str> { Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap())) }
    pub fn u32(&mut self) -> Result<u32, &'static str> { Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap())) }
    pub fn u64(&mut self) -> Result<u64, &'static str> { Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap())) }
    pub fn bytes(&mut self) -> Result<Vec<u8>, &'static str> { let k = self.u32()? as usize; Ok(self.take(k)?.to_vec()) }
    /// A hash share: at most 32 bytes (n is 16 or 32), so a frame cannot decode into far more memory than it took on the wire.
    pub fn share(&mut self) -> Result<Vec<u8>, &'static str> { let k = self.u32()? as usize; if k > 32 { return Err("share too long"); } Ok(self.take(k)?.to_vec()) }
    pub fn batch(&mut self, m: usize) -> Result<Batch, &'static str> {
        let start = self.u32()?; let count = self.u32()?; let nch = self.u32()?;
        if nch > 1024 { return Err("batch too large"); }
        let mut cheques = Vec::with_capacity(nch as usize);
        for _ in 0..nch {
            let mut ch = Vec::with_capacity(18);
            for _ in 0..18 { let mut col = Vec::with_capacity(10);
                for _ in 0..10 { let mut row = Vec::with_capacity(m); for _ in 0..m { row.push(self.share()?) } col.push(row) }
                ch.push(col) }
            cheques.push(ch);
        }
        let np = self.u32()?; if np > 32 { return Err("path too long"); }
        let mut path = Vec::new(); for _ in 0..np { path.push(self.share()?) }
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
                match pay { Payment::Pow(nonce) => { w.u8(0); w.u64(*nonce) } }
            }
            Tx::RegisterBatch { account, batch } => { w.u8(2); w.bytes(account); w.batch(batch) }
            Tx::ChequePiece { account, cheque, column, shares } => {
                w.u8(3); w.bytes(account); w.u16(*cheque); w.u8(*column); w.u8(shares.len() as u8); for h in shares { w.bytes(h) }
            }
            Tx::Renew { account, start } => { w.u8(4); w.bytes(account); w.u32(*start) }
        }
        w.0
    }
    pub fn decode(r: &mut R) -> Result<Tx, &'static str> {
        Ok(match r.u8()? {
            0 => Tx::Coinbase { height: r.u32()?, payee: r.u32()?, message: r.bytes()? },
            1 => {
                let salt: [u8; 16] = r.take(16)?.try_into().unwrap();
                let m = r.u8()?; let n256 = r.u8()? != 0; let book_size = r.u32()?; let root = r.bytes()?;
                if !(1..=7).contains(&m) { return Err("bad m"); }
                let batch = r.batch(m as usize)?;
                let pay = match r.u8()? { 0 => Payment::Pow(r.u64()?), _ => return Err("bad payment") };
                Tx::RegisterBook { salt, m, n256, book_size, root, batch, pay }
            }
            2 => { let account = account(r)?; let m = id_m(&account) as usize; Tx::RegisterBatch { account, batch: r.batch(m)? } }
            3 => { let account = account(r)?; let cheque = r.u16()?; let column = r.u8()?; let k = r.u8()?; if k > 7 { return Err("too many shares"); }
                   let mut shares = Vec::new(); for _ in 0..k { shares.push(r.share()?) }
                   Tx::ChequePiece { account, cheque, column, shares } }
            4 => Tx::Renew { account: account(r)?, start: r.u32()? },
            _ => return Err("unknown tx type"),
        })
    }
    pub fn txid(&self) -> [u8; 32] { sha256d(&self.encode()) }
}

//! Chain state and transaction rules (DESIGN.md §2.1, §3.2 rows 6-10, §10.4, §10.11, §10.12).
//! Every `apply_*` checks everything before mutating, so a rejected tx leaves no trace.
use std::collections::BTreeMap;
use std::sync::Arc;
use crate::book::{self, ChequeCommits};
use crate::crypto::sha256;
use crate::message::{self, COLS, ROWS};
use crate::params::Params;
use crate::tx::{account_id, id_m, id_n, AccountId, Batch, Payment, Tx, R, W};
use crate::u256::U256;

#[derive(Clone, Debug)]
pub struct OpenCheque { pub n: u16, pub digits: [Option<u8>; COLS], pub expiry: u32 }

/// A registered cheque's commitments. They never change after registration (only get deleted), so
/// they are shared between state copies, and their hash for the state root is computed once.
#[derive(Clone, Debug)]
pub struct Commits { pub cells: Arc<ChequeCommits>, pub digest: [u8; 32] }
impl Commits {
    fn new(c: ChequeCommits) -> Commits { let digest = sha256(&c.concat().concat()); Commits { cells: Arc::new(c), digest } }
}

#[derive(Clone, Debug)]
pub struct Account {
    pub number: u32,
    pub balance: u64,
    pub nonce: Option<u16>,
    pub book_size: u32,
    pub salt: [u8; 16],
    pub pow_paid: bool,
    pub funded: bool,
    pub batches: BTreeMap<u32, (u32, u32)>,      // start -> (count, expiry height)
    pub commits: BTreeMap<u16, Commits>,          // unspent registered cheques
    pub open: Option<OpenCheque>,
}

/// What a block did to an account, for the node's history index (not consensus, not in the root).
#[derive(Clone, Debug)]
pub enum Event {
    Register { id: AccountId, number: u32 },
    Reward { number: u32, amount: u64 },
    Transfer { from: AccountId, cheque: u16, to: u32, amount: u64, fee: u64, digits: [u8; COLS] },   // digits: the cheque as written
}

#[derive(Clone, Debug)]
pub struct State {
    pub height: u32,
    pub accounts: BTreeMap<AccountId, Account>,
    pub numbers: BTreeMap<u32, (AccountId, u32)>,   // number -> (id, assigning height)
    pub next_number: u32,
    pub free: Vec<(u32, u32)>,                      // (release height, number)
    pub pending: BTreeMap<u32, Vec<(u32, u64)>>,    // credit height -> (number, amount)
    pub expiries: BTreeMap<u32, Vec<AccountId>>,    // unfunded PoW accounts to delete
    pub reg_target: U256,
    pub reg_block_count: u32,
    pub reg_window_count: u32,
    pub log: Vec<Event>,                            // events of the block being applied; cleared by begin_block
}

type Res<T> = Result<T, &'static str>;

impl State {
    pub fn new(p: &Params) -> State {
        State { height: 0, accounts: BTreeMap::new(), numbers: BTreeMap::new(), next_number: 1, free: Vec::new(),
                pending: BTreeMap::new(), expiries: BTreeMap::new(),
                reg_target: p.reg_pow_target, reg_block_count: 0, reg_window_count: 0, log: Vec::new() }
    }

    /// Height-driven work at the start of a block: credit matured rewards, expire pieces,
    /// batches and never-funded PoW accounts.
    pub fn begin_block(&mut self, p: &Params, height: u32) {
        self.height = height;
        self.reg_block_count = 0;
        self.log.clear();
        for (num, amt) in self.pending.remove(&height).unwrap_or_default() {
            if let Some((id, _)) = self.numbers.get(&num) {
                let a = self.accounts.get_mut(id).unwrap();
                a.balance += amt;
                a.funded = true;
            }
        }
        for a in self.accounts.values_mut() {
            if a.open.as_ref().map_or(false, |o| o.expiry <= height) {
                let n = a.open.take().unwrap().n;
                a.commits.remove(&n);
            }
            let dead: Vec<u32> = a.batches.iter().filter(|(_, &(_, e))| e <= height).map(|(&s, _)| s).collect();
            for s in dead {
                let (count, _) = a.batches.remove(&s).unwrap();
                for n in s..s + count { a.commits.remove(&(n as u16)); }
            }
        }
        for id in self.expiries.remove(&height).unwrap_or_default() {
            if self.accounts.get(&id).map_or(false, |a| !a.funded) {
                let a = self.accounts.remove(&id).unwrap();
                self.numbers.remove(&a.number);
                self.free.push((height + p.number_quarantine, a.number));
            }
        }
        if height % p.reg_pow_window == 0 && height > 0 {
            // §8 item 2: scale the registration target to the observed demand, within 4x per window
            // aim for a quarter of the cap: a window at the cap quadruples the work, no demand quarters it
            let want = (p.reg_pow_per_block_cap as u64 * p.reg_pow_window as u64) / 4;
            let have = self.reg_window_count as u64;
            let (lo, hi) = (self.reg_target.div_u64(4), self.reg_target.mul_u64(4));
            let t = if have == 0 { hi } else { let scaled = self.reg_target.div_u64(have).mul_u64(want); if scaled > hi { hi } else if scaled < lo { lo } else { scaled } };
            self.reg_target = if t > p.reg_pow_target { p.reg_pow_target } else { t };
            self.reg_window_count = 0;
        }
    }

    /// Everything consensus holds, as bytes (for snapshots). `log` is transient and not included.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = W(Vec::new());
        w.u32(self.height); w.u32(self.next_number); w.u32(self.reg_block_count); w.u32(self.reg_window_count);
        for l in self.reg_target.0 { w.u64(l); }
        w.u32(self.accounts.len() as u32);
        for (id, a) in &self.accounts {
            w.bytes(id); w.u32(a.number); w.u64(a.balance); w.u8(a.nonce.is_some() as u8); w.u16(a.nonce.unwrap_or(0)); w.u32(a.book_size);
            w.0.extend_from_slice(&a.salt); w.u8(a.pow_paid as u8); w.u8(a.funded as u8);
            w.u32(a.batches.len() as u32); for (s, (c, e)) in &a.batches { w.u32(*s); w.u32(*c); w.u32(*e); }
            w.u32(a.commits.len() as u32);
            for (nn, c) in &a.commits { w.u16(*nn); w.u8(c.cells.len() as u8); for col in c.cells.iter() { w.u8(col.len() as u8); for cell in col { w.bytes(cell); } } }
            w.u8(a.open.is_some() as u8);
            if let Some(o) = &a.open { w.u16(o.n); w.u32(o.expiry); for d in o.digits { w.u8(d.unwrap_or(255)); } }
        }
        w.u32(self.numbers.len() as u32); for (n, (id, h)) in &self.numbers { w.u32(*n); w.bytes(id); w.u32(*h); }
        w.u32(self.free.len() as u32); for (r, n) in &self.free { w.u32(*r); w.u32(*n); }
        w.u32(self.pending.len() as u32); for (h, l) in &self.pending { w.u32(*h); w.u32(l.len() as u32); for (n, a) in l { w.u32(*n); w.u64(*a); } }
        w.u32(self.expiries.len() as u32); for (h, ids) in &self.expiries { w.u32(*h); w.u32(ids.len() as u32); for id in ids { w.bytes(id); } }
        w.0
    }
    pub fn decode(r: &mut R) -> Res<State> {
        let (height, next_number, reg_block_count, reg_window_count) = (r.u32()?, r.u32()?, r.u32()?, r.u32()?);
        let reg_target = U256([r.u64()?, r.u64()?, r.u64()?, r.u64()?]);
        let mut accounts = BTreeMap::new();
        for _ in 0..r.u32()? {
            let id = r.bytes()?; let number = r.u32()?; let balance = r.u64()?; let has_nonce = r.u8()? == 1; let nonce = r.u16()?; let book_size = r.u32()?;
            let salt: [u8; 16] = r.take(16)?.try_into().unwrap(); let pow_paid = r.u8()? == 1; let funded = r.u8()? == 1;
            let mut batches = BTreeMap::new(); for _ in 0..r.u32()? { let s = r.u32()?; batches.insert(s, (r.u32()?, r.u32()?)); }
            let mut commits = BTreeMap::new();
            for _ in 0..r.u32()? { let nn = r.u16()?; let mut cols = Vec::new();
                for _ in 0..r.u8()? { let mut cells = Vec::new(); for _ in 0..r.u8()? { cells.push(r.bytes()?); } cols.push(cells); }
                commits.insert(nn, Commits::new(cols)); }
            let open = if r.u8()? == 1 { let n = r.u16()?; let expiry = r.u32()?; let mut digits = [None; COLS]; for d in digits.iter_mut() { let x = r.u8()?; *d = if x == 255 { None } else { Some(x) }; } Some(OpenCheque { n, digits, expiry }) } else { None };
            accounts.insert(id, Account { number, balance, nonce: if has_nonce { Some(nonce) } else { None }, book_size, salt, pow_paid, funded, batches, commits, open });
        }
        let mut numbers = BTreeMap::new(); for _ in 0..r.u32()? { let n = r.u32()?; let id = r.bytes()?; numbers.insert(n, (id, r.u32()?)); }
        let mut free = Vec::new(); for _ in 0..r.u32()? { free.push((r.u32()?, r.u32()?)); }
        let mut pending = BTreeMap::new(); for _ in 0..r.u32()? { let h = r.u32()?; let mut l = Vec::new(); for _ in 0..r.u32()? { l.push((r.u32()?, r.u64()?)); } pending.insert(h, l); }
        let mut expiries = BTreeMap::new(); for _ in 0..r.u32()? { let h = r.u32()?; let mut ids = Vec::new(); for _ in 0..r.u32()? { ids.push(r.bytes()?); } expiries.insert(h, ids); }
        Ok(State { height, accounts, numbers, next_number, free, pending, expiries, reg_target, reg_block_count, reg_window_count, log: Vec::new() })
    }

    fn assign_number(&mut self, id: &AccountId, height: u32) -> u32 {
        let num = match self.free.iter().position(|&(rel, _)| rel <= height) {
            Some(i) => self.free.swap_remove(i).1,
            None => { let n = self.next_number; self.next_number += 1; n }
        };
        self.numbers.insert(num, (id.clone(), height));
        num
    }

    /// Verify a batch against `root` and return its (leaf index, commits) pairs. Pure.
    fn check_batch(salt: &[u8; 16], m: usize, n: usize, book_size: u32, root: &[u8], b: &Batch, p: &Params) -> Res<Vec<(u16, ChequeCommits)>> {
        if b.count == 0 || !b.count.is_power_of_two() || b.count > p.max_batch || b.start % b.count != 0 || b.start >= book_size {
            return Err("batch not aligned");
        }
        let present = (book_size - b.start).min(b.count) as usize;
        if b.cheques.len() != present { return Err("batch cheque count"); }
        let mut leaves = Vec::with_capacity(b.count as usize);
        let mut out = Vec::with_capacity(present);
        for (i, ch) in b.cheques.iter().enumerate() {
            let nn = b.start + i as u32;
            if ch.len() != COLS || ch.iter().any(|c| c.len() != ROWS || c.iter().any(|r| r.len() != m || r.iter().any(|x| x.len() != n))) {
                return Err("cheque hashes malformed");
            }
            let (leaf, commits) = book::leaf_from_shares(salt, n, nn as u16, ch);
            leaves.push(leaf);
            out.push((nn as u16, commits));
        }
        leaves.resize(b.count as usize, vec![0u8; n]);
        let sub = book::subtree_root(salt, n, b.start, &leaves);
        if book::climb(salt, n, b.start, b.count, &sub, &b.path, book_size)? != root { return Err("batch does not match root"); }
        Ok(out)
    }

    /// Apply a non-coinbase transaction. Returns the miner's income from it.
    pub fn apply(&mut self, p: &Params, tx: &Tx) -> Res<u64> {
        let height = self.height;
        match tx {
            Tx::Coinbase { .. } => Err("coinbase out of place"),
            Tx::RegisterBook { salt, m, n256, book_size, root, batch, pay } => {
                let (m, n) = (*m as usize, if *n256 { 32 } else { 16 });
                if m == 0 || m > 7 || root.len() != n || *book_size == 0 || *book_size > p.max_book_size { return Err("bad book parameters"); }
                if book_size.max(&1) <= &p.printed_book_size && *book_size != p.printed_book_size && m > 1 && batch.count < *book_size { return Err("printed books are 11 cheques"); }
                let id = account_id(m as u8, *n256, root);
                if self.accounts.contains_key(&id) { return Err("account exists"); }
                let cheques = Self::check_batch(salt, m, n, *book_size, root, batch, p)?;
                let Payment::Pow(_) = pay;
                if U256::from_le_bytes(&tx.txid()) >= self.reg_target { return Err("registration pow insufficient"); }
                if self.reg_block_count >= p.reg_pow_per_block_cap { return Err("registration pow cap reached"); }
                // ---- mutate ----
                let pow = true;
                if pow { self.reg_block_count += 1; self.reg_window_count += 1; self.expiries.entry(height + p.unfunded_pow_lifetime).or_default().push(id.clone()); }
                let number = self.assign_number(&id, height);
                self.log.push(Event::Register { id: id.clone(), number });
                let mut a = Account { number, balance: 0, nonce: None, book_size: *book_size, salt: *salt, pow_paid: pow, funded: !pow,
                                      batches: BTreeMap::new(), commits: BTreeMap::new(), open: None };
                a.batches.insert(batch.start, (batch.count, height + p.batch_lifetime));
                for (nn, c) in cheques { a.commits.insert(nn, Commits::new(c)); }
                self.accounts.insert(id, a);
                Ok(0)
            }
            Tx::RegisterBatch { account, batch, pay } => {
                // more cheques for an existing book: paid by the same proof of work as a first registration,
                // so every 16 cheques of state cost the same however they arrive
                let a = self.accounts.get(account).ok_or("no such account")?;
                if a.batches.contains_key(&batch.start) || a.batches.iter().any(|(&s, &(c, _))| batch.start < s + c && s < batch.start + batch.count) { return Err("batch overlaps"); }
                let cheques = Self::check_batch(&a.salt, id_m(account) as usize, id_n(account), a.book_size, &account[1..], batch, p)?;
                let Payment::Pow(_) = pay;
                if U256::from_le_bytes(&tx.txid()) >= self.reg_target { return Err("registration pow insufficient"); }
                if self.reg_block_count >= p.reg_pow_per_block_cap { return Err("registration pow cap reached"); }
                // ---- mutate ----
                self.reg_block_count += 1; self.reg_window_count += 1;
                let a = self.accounts.get_mut(account).unwrap();
                a.batches.insert(batch.start, (batch.count, height + p.batch_lifetime));
                for (nn, c) in cheques { if a.nonce.map_or(true, |x| nn > x) { a.commits.insert(nn, Commits::new(c)); } }
                Ok(0)
            }
            Tx::Renew { account, start } => {
                let a = self.accounts.get_mut(account).ok_or("no such account")?;
                let b = a.batches.get_mut(start).ok_or("no such batch")?;
                if a.balance < p.renew_fee { return Err("insufficient balance for renew"); }
                b.1 = height + p.batch_lifetime;
                a.balance -= p.renew_fee;
                Ok(p.renew_fee)
            }
            Tx::ChequePiece { account, cheque, column, shares } => self.apply_piece(p, account, *cheque, *column, shares),
        }
    }

    /// The digit (row) a piece reveals: the row whose stored commitment its shares match. Changes nothing.
    pub fn piece_digit(&self, account: &AccountId, nn: u16, column: u8, shares: &[Vec<u8>]) -> Option<u8> {
        let (m, n) = (id_m(account) as usize, id_n(account));
        let a = self.accounts.get(account)?;
        if column as usize >= COLS || shares.len() != m { return None; }
        let commits = a.commits.get(&nn)?;
        (0..ROWS).find(|&row| {
            let hs: Vec<Vec<u8>> = (0..m).map(|k| book::share_hash(&a.salt, n, nn, column, row as u8, k as u8, &shares[k])).collect();
            book::commit(&a.salt, n, nn, column, row as u8, &hs) == commits.cells[column as usize][row]
        }).map(|r| r as u8)
    }

    fn apply_piece(&mut self, p: &Params, account: &AccountId, nn: u16, column: u8, shares: &[Vec<u8>]) -> Res<u64> {
        let height = self.height;
        let (m, n) = (id_m(account) as usize, id_n(account));
        let a = self.accounts.get(account).ok_or("no such account")?;
        if column as usize >= COLS || shares.len() != m || shares.iter().any(|x| x.len() != n) { return Err("piece malformed"); }
        if !a.batches.iter().any(|(&s, &(c, e))| nn as u32 >= s && (nn as u32) < s + c && e > height) { return Err("cheque not registered or expired"); }
        let continuing = a.open.as_ref().map_or(false, |o| o.n == nn);
        if !continuing && a.nonce.map_or(false, |x| nn <= x) { return Err("cheque number already consumed"); }
        a.commits.get(&nn).ok_or("cheque not spendable")?;
        let mut digits = if continuing { a.open.as_ref().unwrap().digits } else { [None; COLS] };
        if digits[column as usize].is_some() { return Err("column already revealed"); }
        // row 9 of §3.2: which stored commitment does this column's preimage match?
        let row = self.piece_digit(account, nn, column, shares).ok_or("no commitment matches")?;
        digits[column as usize] = Some(row);
        // completion (row 10 of §3.2), checked before any mutation
        let mut done: Option<(u64, u64, u32, [u8; COLS])> = None; // (amount, fee, payee, digits)
        if digits.iter().all(|d| d.is_some()) {
            let d: [u8; COLS] = std::array::from_fn(|i| digits[i].unwrap());
            let msg = message::parse(&d)?;
            let fee = msg.tier as u64 * p.fee_unit;
            let amount = match msg.amount() { Some(x) => x, None => a.balance.checked_sub(fee).ok_or("sweep below fee")? };
            if msg.payee != 0 {
                let (_, assigned) = self.numbers.get(&msg.payee).ok_or("payee number unknown")?;
                if assigned + p.number_maturity > height { return Err("payee number not mature"); }
            }
            if a.balance < amount + fee { return Err("insufficient balance"); }
            done = Some((amount, fee, msg.payee, d));
        }
        // ---- mutate ----
        let a = self.accounts.get_mut(account).unwrap();
        if !continuing {
            if let Some(o) = a.open.take() { a.commits.remove(&o.n); }
            let dead: Vec<u16> = a.commits.range(..nn).map(|(&k, _)| k).collect();
            for k in dead { a.commits.remove(&k); }
            a.nonce = Some(nn);
        }
        match done {
            None => { a.open = Some(OpenCheque { n: nn, digits, expiry: height + p.piece_lifetime }); Ok(0) }
            Some((amount, fee, payee, digits)) => {
                a.open = None;
                a.commits.remove(&nn);
                a.balance -= amount + fee;
                self.log.push(Event::Transfer { from: account.clone(), cheque: nn, to: payee, amount, fee, digits });
                if payee == 0 {
                    Ok(amount + fee)   // number 0 is nobody's: the coins go to the miner with the fee
                } else {
                    let pid = self.numbers[&payee].0.clone();
                    let pa = self.accounts.get_mut(&pid).unwrap();
                    pa.balance += amount;
                    pa.funded = true;
                    Ok(fee)
                }
            }
        }
    }

    /// Coinbase (§12.2): payee must exist by the end of the block or be 0 (burn).
    pub fn apply_coinbase(&mut self, p: &Params, height: u32, payee: u32, fees: u64) -> Res<()> {
        let reward = p.block_reward(height) + fees;
        if payee == 0 { return Ok(()); }
        if !self.numbers.contains_key(&payee) { return Err("coinbase payee unknown"); }
        self.pending.entry(height + p.reward_maturity).or_default().push((payee, reward));
        self.log.push(Event::Reward { number: payee, amount: reward });
        Ok(())
    }

    /// Canonical bytes of one account record (the leaf a light client proves).
    fn account_leaf(id: &AccountId, a: &Account) -> [u8; 32] {
        let mut v = Vec::new();
        let u = |v: &mut Vec<u8>, x: u64| v.extend_from_slice(&x.to_le_bytes());
        v.extend_from_slice(id); u(&mut v, a.number as u64); u(&mut v, a.balance);
        u(&mut v, a.nonce.map_or(u64::MAX, |x| x as u64)); v.push(a.funded as u8); v.push(a.pow_paid as u8); u(&mut v, a.book_size as u64);
        for (s, (c, e)) in &a.batches { u(&mut v, *s as u64); u(&mut v, *c as u64); u(&mut v, *e as u64); }
        if let Some(o) = &a.open { u(&mut v, o.n as u64); u(&mut v, o.expiry as u64); for d in o.digits { v.push(d.unwrap_or(255)); } }
        for (nn, c) in &a.commits { u(&mut v, *nn as u64); v.extend_from_slice(&c.digest); }
        sha256(&v)
    }
    fn merkle(mut level: Vec<[u8; 32]>) -> [u8; 32] {
        if level.is_empty() { return [0u8; 32]; }
        while !level.len().is_power_of_two() { level.push([0u8; 32]); }
        while level.len() > 1 { level = level.chunks(2).map(|p| sha256(&[p[0], p[1]].concat())).collect(); }
        level[0]
    }
    /// state_root = SHA256(merkle(account leaves in id order) || SHA256(everything else)).
    pub fn root(&self) -> [u8; 32] {
        let leaves: Vec<[u8; 32]> = self.accounts.iter().map(|(id, a)| Self::account_leaf(id, a)).collect();
        let mut v = Vec::new();
        let u = |v: &mut Vec<u8>, x: u64| v.extend_from_slice(&x.to_le_bytes());
        u(&mut v, self.height as u64); u(&mut v, self.next_number as u64);
        for (num, (id, h)) in &self.numbers { u(&mut v, *num as u64); v.extend_from_slice(id); u(&mut v, *h as u64); }
        for (r, num) in &self.free { u(&mut v, *r as u64); u(&mut v, *num as u64); }
        for (h, list) in &self.pending { u(&mut v, *h as u64); for (num, amt) in list { u(&mut v, *num as u64); u(&mut v, *amt); } }
        for (h, ids) in &self.expiries { u(&mut v, *h as u64); for id in ids { v.extend_from_slice(id); } }
        for limb in self.reg_target.0 { u(&mut v, limb); }
        u(&mut v, self.reg_window_count as u64);
        self.rest_hash_cache(Self::merkle(leaves), sha256(&v))
    }
    fn rest_hash_cache(&self, accounts: [u8; 32], rest: [u8; 32]) -> [u8; 32] { sha256(&[accounts, rest].concat()) }
    /// Merkle proof of one account: (leaf, sibling path bottom-up, and the `rest` hash is the last element).
    pub fn account_proof(&self, id: &AccountId) -> Option<([u8; 32], Vec<[u8; 32]>)> {
        let pos = self.accounts.keys().position(|k| k == id)?;
        let mut level: Vec<[u8; 32]> = self.accounts.iter().map(|(id, a)| Self::account_leaf(id, a)).collect();
        while !level.len().is_power_of_two() { level.push([0u8; 32]); }
        let (leaf, mut path, mut i) = (level[pos], Vec::new(), pos);
        while level.len() > 1 {
            path.push(level[i ^ 1]);
            level = level.chunks(2).map(|p| sha256(&[p[0], p[1]].concat())).collect();
            i /= 2;
        }
        let root = self.root();
        let accounts_root = level[0];
        // the verifier needs `rest`; recover it by recomputing: root = H(accounts_root || rest)
        let mut v = Vec::new();
        let u = |v: &mut Vec<u8>, x: u64| v.extend_from_slice(&x.to_le_bytes());
        u(&mut v, self.height as u64); u(&mut v, self.next_number as u64);
        for (num, (id, h)) in &self.numbers { u(&mut v, *num as u64); v.extend_from_slice(id); u(&mut v, *h as u64); }
        for (r, num) in &self.free { u(&mut v, *r as u64); u(&mut v, *num as u64); }
        for (h, list) in &self.pending { u(&mut v, *h as u64); for (num, amt) in list { u(&mut v, *num as u64); u(&mut v, *amt); } }
        for (h, ids) in &self.expiries { u(&mut v, *h as u64); for id in ids { v.extend_from_slice(id); } }
        for limb in self.reg_target.0 { u(&mut v, limb); }
        u(&mut v, self.reg_window_count as u64);
        let rest = sha256(&v);
        debug_assert_eq!(sha256(&[accounts_root, rest].concat()), root);
        path.push(rest);
        Some((leaf, path))
    }
}

/// Light-client check: does `leaf` sit under `state_root` via `path` (last element = rest hash)?
pub fn verify_account_proof(state_root: &[u8; 32], leaf: &[u8; 32], path: &[[u8; 32]], position: usize) -> bool {
    if path.is_empty() { return false; }
    let (sibs, rest) = path.split_at(path.len() - 1);
    let mut node = *leaf;
    let mut i = position;
    for s in sibs { node = if i % 2 == 0 { sha256(&[node, *s].concat()) } else { sha256(&[*s, node].concat()) }; i /= 2; }
    sha256(&[node, rest[0]].concat()) == *state_root
}

//! Chain state and transaction rules (DESIGN.md §2.1, §3.2 rows 6-10, §10.4, §10.11, §10.12).
//! Every `apply_*` checks everything before mutating, so a rejected tx leaves no trace.
//! Accounts are shared between state copies (`Arc`, copied on write by `edit`), and each caches its leaf hash, so a
//! copy per block costs one pointer per account and the root rehashes only the accounts a block changed.
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, OnceLock};
use crate::book::{self, ChequeCommits};
use crate::crypto::{key, sha256, Key};
use crate::message::{self, COLS, ROWS};
use crate::params::Params;
use crate::tx::{account_id, id_m, id_n, open_columns_ok, AccountId, Batch, Payment, Tx, R, W};
use crate::u256::U256;

/// An open cheque (§10.12): opened by a `ChequeOpen` carrying both printed parts, so its number is used (`nonce`).
/// `expiry` is set by the opening and never moves; at expiry an unfinished cheque goes, and its number stays used.
#[derive(Clone, Debug)]
pub struct OpenCheque { pub digits: [Option<u8>; COLS], pub expiry: u32 }

/// A registered cheque's commitments, flat (`book::ChequeCommits`). They never change after registration (only get
/// deleted), so they are shared between state copies, and their hash for the state root is computed once.
#[derive(Clone, Debug)]
pub struct Commits { pub cells: Arc<[u8]>, pub digest: [u8; 32] }
impl Commits {
    pub fn new(c: ChequeCommits) -> Commits { Commits { digest: sha256(&c), cells: c.into() } }
    /// The commitment of cell (col, row) of an `n`-byte book.
    pub fn cell(&self, n: usize, col: usize, row: usize) -> &[u8] { &self.cells[(col * ROWS + row) * n..][..n] }
    /// One line per column, each its ROWS commitments in lowercase hex, space-separated (GET /commits).
    pub fn lines(&self, n: usize) -> String { (0..COLS).map(|c| (0..ROWS).map(|r| crate::crypto::hex(self.cell(n, c, r))).collect::<Vec<_>>().join(" ")).collect::<Vec<_>>().join("\n") }
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
    pub open: BTreeMap<u16, OpenCheque>,         // the open cheque, at most one: always the one at nonce
    pub leaf: OnceLock<[u8; 32]>,                 // cached account_leaf; reset by every change (State::edit)
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
    pub accounts: BTreeMap<AccountId, Arc<Account>>,
    pub numbers: BTreeMap<u32, (AccountId, u32)>,   // number -> (id, assigning height)
    pub next_number: u32,
    pub free: VecDeque<(u32, u32)>,                 // (release height, number), in release order
    pub pending: BTreeMap<u32, Vec<(u32, u64)>>,    // credit height -> (number, amount)
    pub expiries: BTreeMap<u32, Vec<AccountId>>,    // unfunded PoW accounts to delete
    pub gone: BTreeMap<AccountId, u16>,             // deleted accounts that had used cheques -> their nonce: registered again, they keep it
    pub reg_target: U256,
    pub reg_block_count: u32,                       // registrations in the current block
    pub recent: VecDeque<[u8; 32]>,                 // hashes of the last reg_anchor_window blocks, oldest first (registration anchors)
    pub wake: BTreeMap<u32, Vec<AccountId>>,        // height -> accounts whose open cheque or a batch may expire then (an index: rebuilt on decode)
    pub net: [u8; 4],                               // Params::magic: part of every book's hash key
    pub log: Vec<Event>,                            // events of the block being applied; cleared by begin_block
}

type Res<T> = Result<T, &'static str>;
/// A cheque that completes: what moves, and to whom (None: void).
struct Done { amount: u64, fee: u64, payee: Option<u32>, digits: [u8; COLS] }

/// The account to change, copied first if another state shares it, with its cached leaf cleared.
fn edit<'a>(m: &'a mut BTreeMap<AccountId, Arc<Account>>, id: &[u8]) -> &'a mut Account {
    let a = Arc::make_mut(m.get_mut(id).unwrap()); a.leaf = OnceLock::new(); a
}

impl State {
    pub fn new(p: &Params) -> State {
        State { height: 0, accounts: BTreeMap::new(), numbers: BTreeMap::new(), next_number: 1, free: VecDeque::new(),
                pending: BTreeMap::new(), expiries: BTreeMap::new(), gone: BTreeMap::new(), reg_target: p.reg_pow_target, reg_block_count: 0,
                recent: VecDeque::new(), wake: BTreeMap::new(), net: p.magic, log: Vec::new() }
    }
    /// Remember a block's hash as a registration anchor (called by the chain after each block; never for block 0, which is
    /// known before the chain starts and so would let registrations be mined ahead of it).
    pub fn push_hash(&mut self, p: &Params, h: [u8; 32]) {
        self.recent.push_back(h);
        while self.recent.len() > p.reg_anchor_window as usize { self.recent.pop_front(); }
    }
    fn key(&self, salt: &[u8; 16]) -> Key { key(salt, &self.net) }
    /// The registration target of the next block (`begin_block` moves it by this block's registrations).
    pub fn next_reg_target(&self, p: &Params) -> U256 {
        let w = p.reg_pow_window as u64;
        let t = self.reg_target.div_u64(w + p.reg_per_blocks as u64 * self.reg_block_count as u64).mul_u64(w + 1);
        if t > p.reg_pow_target { p.reg_pow_target } else { t }
    }

    /// Height-driven work at the start of a block: retarget registrations, credit matured rewards, expire pieces,
    /// batches and never-funded PoW accounts.
    pub fn begin_block(&mut self, p: &Params, height: u32) {
        self.height = height;
        // §8 item 2: the registration target follows demand every block, aiming at one registration per R = reg_per_blocks
        // blocks: each block multiplies it by (W+1)/(W+R·k) for its k registrations, W = reg_pow_window. With W a day and
        // R = 10, a block at the cap makes registering 10% harder, one registration 0.6%, an empty block 0.07% easier.
        self.reg_target = self.next_reg_target(p);
        self.reg_block_count = 0;
        self.log.clear();
        for (num, amt) in self.pending.remove(&height).unwrap_or_default() {
            if let Some((id, _)) = self.numbers.get(&num) {
                let a = edit(&mut self.accounts, id);
                a.balance += amt;
                a.funded = true;
            }
        }
        // only the accounts with something due now (the index may name some whose cheque or batch moved on: no-op)
        for id in self.wake.remove(&height).unwrap_or_default() {
            let Some(a) = self.accounts.get(&id) else { continue };
            if !a.open.values().any(|o| o.expiry <= height) && !a.batches.values().any(|&(_, e)| e <= height) { continue; }
            let a = edit(&mut self.accounts, &id);
            // an unfinished cheque goes with its commitments: its number stays used
            let stale: Vec<u16> = a.open.iter().filter(|(_, o)| o.expiry <= height).map(|(&n, _)| n).collect();
            for n in stale { a.open.remove(&n); a.commits.remove(&n); }
            let dead: Vec<u32> = a.batches.iter().filter(|(_, &(_, e))| e <= height).map(|(&s, _)| s).collect();
            for s in dead {
                let (count, _) = a.batches.remove(&s).unwrap();
                for n in s..s + count { a.commits.remove(&(n as u16)); a.open.remove(&(n as u16)); }
            }
        }
        for id in self.expiries.remove(&height).unwrap_or_default() {
            if self.accounts.get(&id).is_some_and(|a| !a.funded) {
                let a = self.accounts.remove(&id).unwrap();
                // its revealed cells stay public: a replay of its registration must not make those cheques spendable again
                if let Some(n) = a.nonce { self.gone.insert(id.clone(), n); }
                self.numbers.remove(&a.number);
                self.free.push_back((height + p.number_quarantine, a.number));
            }
        }
    }

    /// Everything consensus holds, as bytes (for snapshots). `log` is transient and `wake` is rebuilt, so neither is
    /// included. Commitments are written as flat blobs (their length follows from the account id).
    /// Not all of it is under the state root: `numbers`, `expiries`, `recent` and `net` are checked by nothing when a
    /// snapshot is loaded, so a snapshot must be the node's own (or its host's), never one taken from someone else.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = W(Vec::new());
        w.u32(self.height); w.u32(self.next_number); w.u32(self.reg_block_count); w.0.extend_from_slice(&self.net);
        for l in self.reg_target.0 { w.u64(l); }
        w.u32(self.recent.len() as u32); for h in &self.recent { w.0.extend_from_slice(h); }
        w.u32(self.accounts.len() as u32);
        for (id, a) in &self.accounts {
            w.bytes(id); w.u32(a.number); w.u64(a.balance); w.u8(a.nonce.is_some() as u8); w.u16(a.nonce.unwrap_or(0)); w.u32(a.book_size);
            w.0.extend_from_slice(&a.salt); w.u8(a.pow_paid as u8); w.u8(a.funded as u8);
            w.u32(a.batches.len() as u32); for (s, (c, e)) in &a.batches { w.u32(*s); w.u32(*c); w.u32(*e); }
            w.u32(a.commits.len() as u32);
            for (nn, c) in &a.commits { w.u16(*nn); w.0.extend_from_slice(&c.cells); }
            w.u32(a.open.len() as u32);
            for (nn, o) in &a.open { w.u16(*nn); w.u32(o.expiry); for d in o.digits { w.u8(d.unwrap_or(255)); } }
        }
        w.u32(self.numbers.len() as u32); for (n, (id, h)) in &self.numbers { w.u32(*n); w.bytes(id); w.u32(*h); }
        w.u32(self.free.len() as u32); for (r, n) in &self.free { w.u32(*r); w.u32(*n); }
        w.u32(self.pending.len() as u32); for (h, l) in &self.pending { w.u32(*h); w.u32(l.len() as u32); for (n, a) in l { w.u32(*n); w.u64(*a); } }
        w.u32(self.expiries.len() as u32); for (h, ids) in &self.expiries { w.u32(*h); w.u32(ids.len() as u32); for id in ids { w.bytes(id); } }
        w.u32(self.gone.len() as u32); for (id, n) in &self.gone { w.bytes(id); w.u16(*n); }
        w.0
    }
    pub fn decode(r: &mut R) -> Res<State> {
        let (height, next_number, reg_block_count) = (r.u32()?, r.u32()?, r.u32()?);
        let net: [u8; 4] = r.take(4)?.try_into().unwrap();
        let reg_target = U256([r.u64()?, r.u64()?, r.u64()?, r.u64()?]);
        let mut recent = VecDeque::new(); for _ in 0..r.u32()? { recent.push_back(r.take(32)?.try_into().unwrap()); }
        let (mut accounts, mut wake) = (BTreeMap::new(), BTreeMap::<u32, Vec<AccountId>>::new());
        for _ in 0..r.u32()? {
            let id = r.bytes()?; let number = r.u32()?; let balance = r.u64()?; let has_nonce = r.u8()? == 1; let nonce = r.u16()?; let book_size = r.u32()?;
            let salt: [u8; 16] = r.take(16)?.try_into().unwrap(); let pow_paid = r.u8()? == 1; let funded = r.u8()? == 1;
            let mut batches = BTreeMap::new(); for _ in 0..r.u32()? { let s = r.u32()?; batches.insert(s, (r.u32()?, r.u32()?)); }
            let mut commits = BTreeMap::new();
            for _ in 0..r.u32()? { let nn = r.u16()?; commits.insert(nn, Commits::new(r.take(COLS * ROWS * id_n(&id))?.to_vec())); }
            let mut open = BTreeMap::new();
            for _ in 0..r.u32()? { let n = r.u16()?; let expiry = r.u32()?; let mut digits = [None; COLS]; for d in digits.iter_mut() { let x = r.u8()?; *d = if x == 255 { None } else { Some(x) }; } open.insert(n, OpenCheque { digits, expiry }); }
            for e in open.values().map(|o| o.expiry).chain(batches.values().map(|&(_, e)| e)) { wake.entry(e).or_default().push(id.clone()); }
            accounts.insert(id, Arc::new(Account { number, balance, nonce: if has_nonce { Some(nonce) } else { None }, book_size, salt, pow_paid, funded, batches, commits, open, leaf: OnceLock::new() }));
        }
        let mut numbers = BTreeMap::new(); for _ in 0..r.u32()? { let n = r.u32()?; let id = r.bytes()?; numbers.insert(n, (id, r.u32()?)); }
        let mut free = VecDeque::new(); for _ in 0..r.u32()? { free.push_back((r.u32()?, r.u32()?)); }
        let mut pending = BTreeMap::new(); for _ in 0..r.u32()? { let h = r.u32()?; let mut l = Vec::new(); for _ in 0..r.u32()? { l.push((r.u32()?, r.u64()?)); } pending.insert(h, l); }
        let mut expiries = BTreeMap::new(); for _ in 0..r.u32()? { let h = r.u32()?; let mut ids = Vec::new(); for _ in 0..r.u32()? { ids.push(r.bytes()?); } expiries.insert(h, ids); }
        let mut gone = BTreeMap::new(); for _ in 0..r.u32()? { let id = r.bytes()?; gone.insert(id, r.u16()?); }
        Ok(State { height, accounts, numbers, next_number, free, pending, expiries, gone, reg_target, reg_block_count, recent, wake, net, log: Vec::new() })
    }

    /// A free number out of quarantine (the one released longest ago), else the next new one.
    fn assign_number(&mut self, id: &AccountId, height: u32) -> u32 {
        let num = match self.free.front() {
            Some(&(rel, n)) if rel <= height => { self.free.pop_front(); n }
            _ => { let n = self.next_number; self.next_number += 1; n }
        };
        self.numbers.insert(num, (id.clone(), height));
        num
    }

    /// Verify a batch against `root` and return its (leaf index, commits) pairs. Pure. Every batch is exactly
    /// `max_batch` cheques, aligned, so a book is registered in fixed pieces nobody can split differently.
    fn check_batch(k: &Key, m: usize, n: usize, book_size: u32, root: &[u8], b: &Batch, p: &Params) -> Res<Vec<(u16, ChequeCommits)>> {
        if b.count != p.max_batch || b.start % b.count != 0 || b.start >= book_size { return Err("batch not aligned"); }
        let present = (book_size - b.start).min(b.count) as usize;
        if b.cheques.len() != present { return Err("batch cheque count"); }
        let mut leaves = Vec::with_capacity(b.count as usize);
        let mut out = Vec::with_capacity(present);
        for (i, ch) in b.cheques.iter().enumerate() {
            let nn = b.start + i as u32;
            if ch.len() != COLS || ch.iter().any(|c| c.len() != ROWS || c.iter().any(|r| r.len() != m || r.iter().any(|x| x.len() != n))) {
                return Err("cheque hashes malformed");
            }
            let (leaf, commits) = book::leaf_from_shares(k, n, nn as u16, ch);
            leaves.push(leaf);
            out.push((nn as u16, commits));
        }
        leaves.resize(b.count as usize, vec![0u8; n]);
        let sub = book::subtree_root(k, n, b.start, &leaves);
        if book::climb(k, n, b.start, b.count, &sub, &b.path, book_size)? != root { return Err("batch does not match root"); }
        Ok(out)
    }
    /// A registration's proof of work: below the target, anchored to a recent block of this chain, within the block's cap.
    fn check_pow(&self, p: &Params, tx: &Tx, pay: &Payment) -> Res<()> {
        let Payment::Pow(anchor, _) = pay;
        if U256::from_le_bytes(&tx.txid()) >= self.reg_target { return Err("registration pow insufficient"); }
        if !self.recent.contains(anchor) { return Err("registration anchor not recent"); }
        if self.reg_block_count >= p.reg_pow_per_block_cap { return Err("registration pow cap reached"); }
        Ok(())
    }

    /// Apply a non-coinbase transaction. Returns the miner's income from it.
    pub fn apply(&mut self, p: &Params, tx: &Tx) -> Res<u64> {
        let height = self.height;
        match tx {
            Tx::Coinbase { .. } => Err("coinbase out of place"),
            Tx::RegisterBook { salt, m, n256, book_size, root, batch, pay } => {
                let (m, n) = (*m as usize, if *n256 { 32 } else { 16 });
                if m == 0 || m > 7 || root.len() != n || *book_size != p.book_size { return Err("bad book parameters"); }
                // a book starts at cheque 0: nobody can register a later batch of someone else's book first
                if batch.start != 0 { return Err("book must start at cheque 0"); }
                let id = account_id(m as u8, *n256, root);
                if self.accounts.contains_key(&id) { return Err("account exists"); }
                // the proof of work first: it costs one hash to check, the batch thousands
                self.check_pow(p, tx, pay)?;
                let cheques = Self::check_batch(&self.key(salt), m, n, *book_size, root, batch, p)?;
                // ---- mutate ----
                self.reg_block_count += 1;
                self.expiries.entry(height + p.unfunded_pow_lifetime).or_default().push(id.clone());
                self.wake.entry(height + p.batch_lifetime).or_default().push(id.clone());
                let number = self.assign_number(&id, height);
                self.log.push(Event::Register { id: id.clone(), number });
                // registered before and expired: the cheques it used stay used
                let nonce = self.gone.remove(&id);
                let mut a = Account { number, balance: 0, nonce, book_size: *book_size, salt: *salt, pow_paid: true, funded: false,
                                      batches: BTreeMap::new(), commits: BTreeMap::new(), open: BTreeMap::new(), leaf: OnceLock::new() };
                a.batches.insert(batch.start, (batch.count, height + p.batch_lifetime));
                for (nn, c) in cheques { if nonce.map_or(true, |x| nn > x) { a.commits.insert(nn, Commits::new(c)); } }
                self.accounts.insert(id, Arc::new(a));
                Ok(0)
            }
            Tx::RegisterBatch { account, batch, pay } => {
                // more cheques for an existing book: paid by the same proof of work as a first registration,
                // so every 16 cheques of state cost the same however they arrive
                let a = self.accounts.get(account).ok_or("no such account")?;
                // the batch's shape first, so the overlap test below adds only small, checked numbers
                if batch.count != p.max_batch || batch.start % batch.count != 0 || batch.start >= a.book_size { return Err("batch not aligned"); }
                let end = batch.start.checked_add(batch.count).ok_or("batch not aligned")?;
                if a.batches.iter().any(|(&s, &(c, _))| batch.start < s.saturating_add(c) && s < end) { return Err("batch overlaps"); }
                self.check_pow(p, tx, pay)?;
                let cheques = Self::check_batch(&self.key(&a.salt), id_m(account) as usize, id_n(account), a.book_size, &account[1..], batch, p)?;
                // ---- mutate ----
                self.reg_block_count += 1;
                self.wake.entry(height + p.batch_lifetime).or_default().push(account.clone());
                let a = edit(&mut self.accounts, account);
                a.batches.insert(batch.start, (batch.count, height + p.batch_lifetime));
                for (nn, c) in cheques { if a.nonce.map_or(true, |x| nn > x) { a.commits.insert(nn, Commits::new(c)); } }
                Ok(0)
            }
            Tx::Renew { account, start } => {
                let a = self.accounts.get(account).ok_or("no such account")?;
                let b = a.batches.get(start).ok_or("no such batch")?;
                // anyone may send a renewal (it carries no authority), so it is only valid near the end of a batch's life:
                // a renewed batch is far from expiry again, so a second one (in the same block or later) is refused
                if b.1 > height + p.renew_window { return Err("batch not near expiry"); }
                if a.balance < p.renew_fee { return Err("insufficient balance for renew"); }
                self.wake.entry(height + p.batch_lifetime).or_default().push(account.clone());
                let a = edit(&mut self.accounts, account);
                a.batches.get_mut(start).unwrap().1 = height + p.batch_lifetime;
                a.balance -= p.renew_fee;
                Ok(p.renew_fee)
            }
            Tx::ChequePiece { account, cheque, column, shares } => self.apply_piece(p, account, *cheque, *column, shares),
            Tx::ChequeOpen { account, cheque, pieces } => self.apply_open(p, account, *cheque, pieces),
        }
    }

    /// The digit (row) a piece reveals: the row whose stored commitment its shares match. Changes nothing.
    pub fn piece_digit(&self, account: &AccountId, nn: u16, column: u8, shares: &[Vec<u8>]) -> Option<u8> {
        let (m, n) = (id_m(account) as usize, id_n(account));
        let a = self.accounts.get(account)?;
        if column as usize >= COLS || shares.len() != m { return None; }
        let (commits, k) = (a.commits.get(&nn)?, self.key(&a.salt));
        (0..ROWS).find(|&row| {
            let hs: Vec<Vec<u8>> = (0..m).map(|j| book::share_hash(&k, n, nn, column, row as u8, j as u8, &shares[j])).collect();
            book::commit(&k, n, nn, column, row as u8, &hs) == commits.cell(n, column as usize, row)
        }).map(|r| r as u8)
    }

    /// Registered in a live batch, every column's shares well-formed: what any piece of cheque `nn` needs first.
    fn piece_ok(&self, account: &AccountId, nn: u16, mut columns: impl Iterator<Item = (u8, usize, bool)>) -> Res<&Account> {
        let m = id_m(account) as usize;
        let a = self.accounts.get(account).ok_or("no such account")?;
        if !columns.all(|(c, k, lens)| (c as usize) < COLS && k == m && lens) { return Err("piece malformed"); }
        if !a.batches.iter().any(|(&s, &(c, e))| nn as u32 >= s && (nn as u32) < s + c && e > self.height) { return Err("cheque not registered or expired"); }
        Ok(a)
    }

    /// One more column of an open cheque. A piece never opens a cheque: only `ChequeOpen` does, which needs both parts.
    fn apply_piece(&mut self, p: &Params, account: &AccountId, nn: u16, column: u8, shares: &[Vec<u8>]) -> Res<u64> {
        let n = id_n(account);
        let a = self.piece_ok(account, nn, std::iter::once((column, shares.len(), shares.iter().all(|x| x.len() == n))))?;
        let mut digits = a.open.get(&nn).ok_or("cheque not open")?.digits;
        if digits[column as usize].is_some() { return Err("column already revealed"); }
        // row 9 of §3.2: which stored commitment does this column's preimage match?
        digits[column as usize] = Some(self.piece_digit(account, nn, column, shares).ok_or("no commitment matches")?);
        let done = self.completion(p, a, &digits)?;
        // ---- mutate ----
        match done {
            None => { edit(&mut self.accounts, account).open.get_mut(&nn).unwrap().digits = digits; Ok(0) }
            Some(d) => Ok(self.complete(p, account, nn, d)),
        }
    }

    /// Open cheque `nn` from both printed parts at once, all or nothing: every recipient column and one or more amount
    /// columns. It uses the number at once (nonce := nn; every lower cheque, open or not, goes); with all 18 it completes.
    fn apply_open(&mut self, p: &Params, account: &AccountId, nn: u16, pieces: &[(u8, Vec<Vec<u8>>)]) -> Res<u64> {
        let (height, n) = (self.height, id_n(account));
        if !open_columns_ok(pieces.iter().map(|x| x.0)) { return Err("bad opening columns"); }
        let a = self.piece_ok(account, nn, pieces.iter().map(|(c, sh)| (*c, sh.len(), sh.iter().all(|x| x.len() == n))))?;
        if a.open.contains_key(&nn) { return Err("cheque already open"); }
        if a.nonce.is_some_and(|x| nn <= x) { return Err("cheque number already consumed"); }
        a.commits.get(&nn).ok_or("cheque not spendable")?;
        let mut digits = [None; COLS];
        for (c, sh) in pieces { digits[*c as usize] = Some(self.piece_digit(account, nn, *c, sh).ok_or("no commitment matches")?); }
        let done = self.completion(p, a, &digits)?;
        // ---- mutate ----
        let a = edit(&mut self.accounts, account);
        a.commits = a.commits.split_off(&nn);
        a.open.clear();   // a lower open cheque: the only kind there can be
        a.nonce = Some(nn);
        match done {
            None => {
                a.open.insert(nn, OpenCheque { digits, expiry: height + p.piece_lifetime });
                self.wake.entry(height + p.piece_lifetime).or_default().push(account.clone());
                Ok(0)
            }
            Some(d) => Ok(self.complete(p, account, nn, d)),
        }
    }

    /// Completion (row 10 of §3.2), checked before any mutation: None while a column is missing. A payee number nobody
    /// holds yet, or not yet final, voids the cheque (payee None): its number is used and nothing moves, so whoever gets
    /// that number later cannot collect it.
    fn completion(&self, p: &Params, a: &Account, digits: &[Option<u8>; COLS]) -> Res<Option<Done>> {
        if !digits.iter().all(|d| d.is_some()) { return Ok(None); }
        let d: [u8; COLS] = std::array::from_fn(|i| digits[i].unwrap());
        let msg = message::parse(&d)?;
        let final_payee = msg.payee == 0 || self.numbers.get(&msg.payee).is_some_and(|&(_, assigned)| assigned + p.number_maturity <= self.height);
        if !final_payee { return Ok(Some(Done { amount: 0, fee: 0, payee: None, digits: d })); }
        let fee = msg.tier as u64 * p.fee_unit;
        let amount = match msg.amount() { Some(x) => x, None => a.balance.checked_sub(fee).ok_or("sweep below fee")? };
        if a.balance < amount + fee { return Err("insufficient balance"); }
        Ok(Some(Done { amount, fee, payee: Some(msg.payee), digits: d }))
    }
    /// Finish cheque `nn`, as `completion` found it. Returns the miner's income from it.
    fn complete(&mut self, p: &Params, account: &AccountId, nn: u16, d: Done) -> u64 {
        let a = edit(&mut self.accounts, account);
        a.open.remove(&nn);
        a.commits.remove(&nn);
        let Some(payee) = d.payee else { return 0 };   // void
        a.balance -= d.amount + d.fee;
        self.log.push(Event::Transfer { from: account.clone(), cheque: nn, to: payee, amount: d.amount, fee: d.fee, digits: d.digits });
        if payee == 0 { return d.amount + d.fee; }   // number 0 is nobody's: the coins go to the miner with the fee
        let pid = self.numbers[&payee].0.clone();
        let pa = edit(&mut self.accounts, &pid);
        pa.balance += d.amount;
        // permanence needs a real balance (min_fund), so dust cannot keep an unfunded account alive
        if pa.balance >= p.min_fund { pa.funded = true; }
        d.fee
    }

    /// Coinbase (§12.2): payee must be 0 (burn) or a final number, number_maturity blocks deep, the same rule as a
    /// cheque's payee. Until then a reorg may give the number to another account, so a miner paying itself must mine to
    /// 0 (or another final number) for its first number_maturity blocks.
    pub fn apply_coinbase(&mut self, p: &Params, height: u32, payee: u32, fees: u64) -> Res<()> {
        let reward = p.block_reward(height) + fees;
        if payee == 0 { return Ok(()); }
        let (id, assigned) = self.numbers.get(&payee).ok_or("coinbase payee unknown")?;
        if assigned + p.number_maturity > height { return Err("coinbase payee not mature"); }
        // mined to: the account is kept (its reward is credited reward_maturity blocks later, and must find it there)
        if self.accounts.get(id).is_some_and(|a| !a.funded) { edit(&mut self.accounts, id).funded = true; }
        self.pending.entry(height + p.reward_maturity).or_default().push((payee, reward));
        self.log.push(Event::Reward { number: payee, amount: reward });
        Ok(())
    }

    /// Canonical bytes of one account record (the leaf a light client proves), hashed. Every list carries its length,
    /// so no two different records encode the same. `since` is the height its number was assigned: with `number` it
    /// fixes the account's entry in `numbers` and `expiries`, which are therefore not hashed separately.
    fn account_leaf(id: &AccountId, a: &Account, since: u32) -> [u8; 32] {
        let mut v = Vec::new();
        let u = |v: &mut Vec<u8>, x: u64| v.extend_from_slice(&x.to_le_bytes());
        u(&mut v, id.len() as u64); v.extend_from_slice(id); v.extend_from_slice(&a.salt); u(&mut v, a.number as u64); u(&mut v, since as u64); u(&mut v, a.balance);
        u(&mut v, a.nonce.map_or(u64::MAX, |x| x as u64)); v.push(a.funded as u8); v.push(a.pow_paid as u8); u(&mut v, a.book_size as u64);
        u(&mut v, a.batches.len() as u64);
        for (s, (c, e)) in &a.batches { u(&mut v, *s as u64); u(&mut v, *c as u64); u(&mut v, *e as u64); }
        u(&mut v, a.open.len() as u64);
        for (nn, o) in &a.open { u(&mut v, *nn as u64); u(&mut v, o.expiry as u64); for d in o.digits { v.push(d.unwrap_or(255)); } }
        u(&mut v, a.commits.len() as u64);
        for (nn, c) in &a.commits { u(&mut v, *nn as u64); v.extend_from_slice(&c.digest); }
        sha256(&v)
    }
    /// Every account's leaf, in id order: cached, so only accounts changed since they were last hashed cost a hash.
    fn leaves(&self) -> Vec<[u8; 32]> {
        self.accounts.iter().map(|(id, a)| *a.leaf.get_or_init(|| Self::account_leaf(id, a, self.numbers.get(&a.number).map_or(0, |x| x.1)))).collect()
    }
    fn pair(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] { let mut b = [0u8; 64]; b[..32].copy_from_slice(l); b[32..].copy_from_slice(r); sha256(&b) }
    fn merkle(mut level: Vec<[u8; 32]>) -> [u8; 32] {
        if level.is_empty() { return [0u8; 32]; }
        while !level.len().is_power_of_two() { level.push([0u8; 32]); }
        while level.len() > 1 { level = level.chunks(2).map(|p| Self::pair(&p[0], &p[1])).collect(); }
        level[0]
    }
    /// SHA256 of everything outside the accounts that they do not determine, each list prefixed with its length.
    fn rest_hash(&self) -> [u8; 32] {
        let mut v = Vec::new();
        let u = |v: &mut Vec<u8>, x: u64| v.extend_from_slice(&x.to_le_bytes());
        u(&mut v, self.height as u64); u(&mut v, self.next_number as u64);
        u(&mut v, self.free.len() as u64);
        for (r, num) in &self.free { u(&mut v, *r as u64); u(&mut v, *num as u64); }
        u(&mut v, self.pending.len() as u64);
        for (h, list) in &self.pending { u(&mut v, *h as u64); u(&mut v, list.len() as u64); for (num, amt) in list { u(&mut v, *num as u64); u(&mut v, *amt); } }
        u(&mut v, self.gone.len() as u64);
        for (id, n) in &self.gone { u(&mut v, id.len() as u64); v.extend_from_slice(id); u(&mut v, *n as u64); }
        for limb in self.reg_target.0 { u(&mut v, limb); }
        u(&mut v, self.reg_block_count as u64);
        sha256(&v)
    }
    /// state_root = SHA256(merkle(account leaves in id order) || rest_hash).
    pub fn root(&self) -> [u8; 32] { sha256(&[Self::merkle(self.leaves()), self.rest_hash()].concat()) }
    /// Merkle proof of one account: (leaf, sibling path bottom-up, and the `rest` hash is the last element), and the
    /// state root, computed from the same (cached) leaves.
    pub fn account_proof(&self, id: &AccountId) -> Option<([u8; 32], Vec<[u8; 32]>, [u8; 32])> {
        let pos = self.accounts.keys().position(|k| k == id)?;
        let mut level = self.leaves();
        while !level.len().is_power_of_two() { level.push([0u8; 32]); }
        let (leaf, mut path, mut i) = (level[pos], Vec::new(), pos);
        while level.len() > 1 {
            path.push(level[i ^ 1]);
            level = level.chunks(2).map(|p| Self::pair(&p[0], &p[1])).collect();
            i /= 2;
        }
        let rest = self.rest_hash();
        path.push(rest);
        Some((leaf, path, sha256(&[level[0], rest].concat())))
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

# BITCHEQUE — design notes (v0.7, 12-cheque books, 2026-10-19)

A Bitcoin-derived chain with six hard requirements:

1. **Paper seed.** The entire wallet must be recoverable from something a person
   can write on paper.
2. **Hand signing.** A transaction is signed with pen and paper, using only a
   public encoding rule and the user's printed private sheets, with no
   arithmetic, and broadcast from any untrusted computer.
3. **Quantum-safe.** No elliptic curves anywhere. Everything a node must
   trust rests on hash functions only.
4. **Stateless.** No wallet, signer or user has to remember anything but the
   seed or hold anything but the paper. No counters anywhere off-chain.
5. **One account type.** Every account is a cheque book (§10). There is no
   device-signed account. Software may drive a cheque book (§5), but the
   signature format is always the cheque.
6. **Store of value, not everyday transfers.** A printed book moves coins at
   most ten times. Throughput and convenience are not goals; exchanges and
   miners use software-driven books (§5).

Proof of work (SHA-256d), the header chain, the transaction Merkle tree, the
mempool and P2P gossip are borrowed from Bitcoin. Block timing, difficulty
adjustment and the reward schedule are adapted (§1, §12.1).

---

## 0. The standard book

Every account is a cheque book made from **one 24-word seed** (scheme byte
`0x13`, m = 1). A book has **256 cheques** on one account number: cheque 0 is the honesty
check, sent with the registration and never printed; the holder prints as many
of the rest as they like now and more later from the same seed, registering
them 16 at a time (§10.10). The printed cheques are printed in **two parts, as separate print runs**, on a
clean, offline computer with a USB-only printer that is switched off
afterwards:

- **Part A**: the 12 recipient columns P1–P12 of cheques 1–11.
- **Part B**: the amount columns D1–D4, the exponent E and the fee tier F.

Parts are kept in different places and brought together only to write a
cheque. A cheque reveals **18 cells, 216 words** (or 18 scanned QR codes,
§10.7); on chain it is 18 pieces, ≈ 900 B, and at most 360 hashes to verify
(§6).

What the part split does and does not buy: a thief who finds only part A or
only part B cannot write a cheque, because every cheque needs cells from both.
It does **not** protect against a compromised machine: the computer that holds
the seed sees every cell. Offline printing is therefore the main defence.

The split-key book of §10.6 (two seeds on two machines, every cell split,
m ≥ 2) remains in the design for large savings: one leaked machine is then
harmless, at 36 cells per cheque. Consensus is unchanged; it already accepts
any m from 1 to 7. The website does not offer split books.

## 1. What is kept from Bitcoin

| Area | Bitcoin | Bitcheque |
|---|---|---|
| Consensus | SHA-256d PoW, 10 min target | SHA-256d PoW, 60 s target (merge-mining is an open decision, §8) |
| Supply | 21M, 50 coins, halving / 210,000 blocks | ≈ 21M: a launch year of 4 coins a block (10 % of the supply), then 4.5 coins halving / 2,100,000 blocks (§12.5) |
| Difficulty | retarget every 2016 blocks | every block, LWMA over 60 blocks (§12.1); a small chain cannot survive a 2016-block window |
| Header | 80 bytes | 80 bytes + 32-byte `state_root` = 112 bytes |
| Tx Merkle tree | SHA-256d | SHA-256d over txids, zero-padded to a power of two (no duplicate-last malleability) |
| Block limit | 4M weight | 1,000,000 bytes (≈ 1,100 cheques) |

## 2. What changes, and why

### 2.1 Accounts

```
Account {
  id           scheme || root        scheme = 0x03 | m<<4 | n256<<7 ; root 16 or 32 B
  number       u32                   chain-assigned, sequential (§10.4)
  balance      u64
  nonce        u16 or none           highest cheque number consumed
  book_size    u32                   new books: 256, registered 16 at a time (cheque 0 never printed); older books 11 or 12; ≤ 256
  salt         16 B                  book salt (§3.1)
  funded       bool                  has ever received coins; an unfunded PoW account expires (§2.2)
  batches      map                   registered cheque ranges and their expiry
  commits      map                   commitments of registered, unspent cheques
  open         cheque or none        the cheque being submitted piece by piece (§10.12)
}
```

Why an account model: a cheque names its recipient by an 11-digit number
(plus check digit) and consumes a per-account cheque number; both are
account state. A UTXO model would have to smuggle the same state into
outputs.

### 2.2 Transaction types

| Type | Signed by | Fee | Purpose |
|---|---|---|---|
| `RegisterBook { salt, m, n256, book_size, root, first batch, PoW nonce }` | nobody; self-verifying | anti-spam proof of work only (§8 item 2) | creates the account, assigns its number, registers the first batch (cheques 0–15) |
| `RegisterBatch { account, batch, PoW nonce }` | nobody; self-verifying | the same proof of work as `RegisterBook` | makes the next 16 cheques of a book spendable (printing more, §10.10) |
| `ChequePiece { account, cheque, column, shares }` | the paper | encoded in the cheque (fee tier) | one column of a cheque; a cheque is 18 pieces (§10.12) |
| `Renew { account, start }` | nobody | 10,000 base units from the account balance | resets a batch's expiry (§10.11) |
| Coinbase `{ height, number, message }` | — | — | credits the block reward plus fees to an account number, 100 blocks later |

Registration transactions carry no signature because nothing in them can be
falsified: every hash must match the committed root through a Merkle path.
A third party can only register your true hashes, which helps you. A
`RegisterBook` or `RegisterBatch` is paid only by proof of work over its txid (no coins
needed), so every 16 cheques of node state cost the same work however they arrive: initial target 2^228 (≈ 2^28 hashes), at most 200 per block, the
target adjusting every 20,160 blocks (§8 item 2). A PoW account that has
received no coins after 43,200 blocks (~30 days) is deleted and its number
quarantined for 525,600 blocks (~a year) before reuse; once funded it is
permanent. A batch is a power-of-two count of cheques aligned to its start,
at most 16, and a book holds at most 256 cheques. Duplicates (an existing account, an overlapping batch) are
rejected.

Fee tier `0` (zero fee) is valid only for zero-amount cheques, so the
honesty check (§10.6) can run before the account is funded. Number 0 is
nobody's: coins and fee of a cheque to number 0 go to the block's miner.

### 2.3 The cheque message

See §10.2: 18 decimal digits, recipient number (11) + check digit, 4-digit
mantissa, exponent, fee tier.

## 3. Signature scheme: the cheque

The only signature on the chain is a Lamport-style one-time signature over
the 18 plaintext digits of the cheque. In the standard book each cell is one
secret; in a split book each is split across `m` independent domains
(§10.6). Nothing is hashed by the signer; each digit selects one pre-printed
cell per column.

### 3.1 Hash primitive

Tweakable SHA-256 in the SLH-DSA-SHA2 construction:
`H(addr, x) = SHA256(book_salt || 48 zero bytes || addr || x)` truncated to
n = 16 B (category 1, default) or 32 B (category 5, `n256` flag; cells
become 24 words, everything doubles). `book_salt` is a public 16-byte value
carried in `RegisterBook`; the reference wallets derive it from the seed
(`SHA256("bitcheque/salt" || seed)[..16]`), so seed and book size recreate
the book. `addr` is 8 bytes: (tag, cheque u16, column, index, extra, 0, 0),
the tag separating shares, commitments, column nodes, cheque leaves and
account nodes. The address prefix removes multi-target attacks. There is no
encryption anywhere in consensus: only one-way hashing and equality.

### 3.2 Life cycle of a cheque: what is hashed, compared and verified

Nothing in the protocol is encrypted. Encryption is two-way (lock, unlock);
consensus uses only one-way hashing and equality tests. Node-to-node
transport encryption (§7, not yet implemented) would hide traffic from
onlookers but plays no part in validity.

| Stage | Who | Computes | Compares / verifies | Secret? |
|---|---|---|---|---|
| 1. Seed | the offline printing computer (one per domain in a split book) | 256 random bits, shown as 24 words | — | yes, paper only |
| 2. Cheque key | the offline printing computer | `key[N] = SHA256("bitcheque/key" ‖ seed ‖ N)` | — | yes |
| 3. Cell | the offline printing computer | `cell[N][c][r] = SHA256("bitcheque/cell" ‖ key[N] ‖ c ‖ r)[..n]`; printed | — | yes, paper only |
| 4. Commitment | any computer, from the share hashes | `h_k = H(addr, cell_k)` per domain k; `commit = H(addr, h_1 ‖ … ‖ h_m)` | — | no |
| 5. Column tree, cheque leaf, root | any computer | Merkle tree over the 10 commits of a column (padded to 16); `leaf[N] = H(root_0 … root_17)`; account root over all leaves | — | no |
| 6. Registration | every node | recomputes leaves from submitted share hashes, walks Merkle paths | path must end at the root in the account id; batch aligned and not overlapping; PoW below target, per-block cap | no |
| 7. Writing | the user | nothing | reads a row per digit, copies or scans 18 × m cells | reveals exactly those cells |
| 8. Decoding | broadcasting computer | `H(addr, cell)` for each cell | finds the row whose stored commit matches; shows the decoded recipient and amount | sees only revealed cells |
| 9. Piece validation | every node | `commit' = H(addr, H(addr, cell_1) ‖ … ‖ H(addr, cell_m))` per row | some row's `commit'` == stored commit; account exists; `N > nonce` (or N is the open cheque); column not yet revealed; batch registered and unexpired; on first piece `nonce := N`, lower unspent cheques and any other open cheque are deleted | no |
| 10. Completion | every node | Damm over P1–P12; amount = mantissa × 10^E (sweep: balance − fee); fee = F × FEE_UNIT | Damm result == 0; recipient is 0 or an existing number 100 blocks old; balance ≥ amount + fee; then transfer, prune cheque N's commits | no |
| 11. Block | miner, then every node | SHA-256d over the header; tx Merkle root; state root | header meets difficulty; every piece re-validated; state root matches | no |
| 12. Afterwards | anyone, light clients | — | Merkle proofs against `state_root` for balance, nonce, number | no |

What an attacker can see: everything in rows 4–12. What they would need:
one value from row 3 that was not revealed, i.e. a preimage of a stored
commitment.

### 3.3 Security summary

- Forging any digit the signer did not choose needs a preimage of an
  unrevealed cell: 2^128 classical, 2^64 sequential quantum (category 1).
- No message hashing, so no collision surface.
- A double reveal of one cheque number (only possible by writing two
  different cheques on one number, against the rules in §10.11 and §10.12)
  lets an attacker mix revealed digits column-wise; the attacker cannot
  choose the recipient freely, and after the recipient columns are on
  chain the exposure is a larger amount to that recipient (§10.12).
- No state exists off-chain. A restore reprints from the seed and asks the
  chain which numbers are consumed.

## 4. Seed and key derivation

### 4.1 Paper formats

24 BIP-39 words per seed (256 bits, metal-backup compatible). The website
makes the seed from dice (seed = SHA-256 of the typed rolls) or from the
computer's randomness mixed with mouse movement. No passphrase.

### 4.2 Derivation (one-way, hierarchical)

```
key[N]            = SHA256("bitcheque/key"  || seed_X || N)          per seed X, per cheque N
cell[N][col][row] = SHA256("bitcheque/cell" || key[N] || col || row)[..n]
```

The seed enters the offline computer at printing, and again whenever the
holder prints more cheques of the same book (§10.10). Account discovery: a restored wallet recomputes
the root (and so the account id) from the seed and book size, or reads the
lookup code from the printed sheets (§10.4).

## 5. Software-driven books (optional, for volume)

A wallet that holds a seed can derive cells and submit a cheque without
paper: the on-chain format is unchanged (18 pieces, ≈ 900 B at m = 1). This
is how miners, pools and exchanges use the chain:

- The same 256-cheque book as the website's, from the same seed: `RegisterBook`
  carries the root and the first batch, later batches come via `RegisterBatch`.
- Batches are 16 cheques (aligned powers of two, at most 16), each with its own proof of work.
- `m = 1`, as in the standard book: the machine holding the seed is
  trusted, the ordinary hot-wallet position.
- The command-line wallet (`bitcheque wallet`) drives one book from one
  seed: `register` registers the first 16 cheques (`--cheques N` for more),
  `more` the next ones. It dry-runs every cheque against the node (`/check`)
  before sending, and refuses to spend cheque 255 on anything but `sweep`
  unless told `--last`.
- The one-time nature remains. A software wallet restored from seed must
  start above the chain's consumed number; the first-piece rule (§10.12)
  bounds any mistake to sending more to a chosen recipient.

There is no other signature type. A device that wants to sign "normally"
simply drives a cheque book.

## 6. Node and state costs

- Per account: ≈ 60 B plus the batch table.
- Per registered unspent cheque: 180 commitments × 16 B ≈ 2.9 KB (independent
  of m) until spent or expired (§10.11). The registration carrying it costs
  180 × m × 20 B ≈ 3.6 KB × m on chain.
- Per cheque: 18 pieces of ≈ 50 B, ≈ 900 B for a standard book (≈ 1.3 KB
  for a split book, m = 2). Verification: each piece is tried row by row,
  m + 1 hashes per row, so at most 18 × 10 × (m + 1) hashes (360 at m = 1).
- A 16-cheque registration is ≈ 58 KB at m = 1, so about 17 fit in a block,
  well below the PoW cap of 200. A full 256-cheque book is 16 of them and
  ≈ 740 KB of node state while unspent.
- 1 MB block ≈ 1,100 cheques a minute ≈ 18 cheques/s.
- Light clients: headers + `state_root` proofs for balance, nonce, number.

## 7. Network layer (non-consensus)

Planned: a Noise-style handshake with hybrid X25519 + ML-KEM-768,
upgradeable any time. Transport encryption is not implemented yet.

Peer discovery follows Bitcoin's model (implemented in `net.rs`): seed node names
compiled into the binary (placeholders until the project has a domain), a
`getaddr`/`addr` exchange in which every node shares the addresses it knows
(50 per reply, 1,000 remembered), an address book saved next to the data file,
and eight outbound connections kept up from that book. A node told nothing
dials the seeds; a node told one peer with `--peer` learns the rest from it.
`--advertise` is the address a node tells others it can be reached on.
Limits: 125 inbound connections, 4 per address, 3 bad messages before a
peer is dropped and its address refused for 30 minutes, 500 blocks per sync
reply, a sync source that stalls for 30 s replaced, a 64 MB mempool.

Mining: a miner fills its block from the mempool oldest first up to the
block size limit; there is no fee ordering yet. The template is rebuilt
every 10 s when the mempool has changed.

## 8. Open decisions

1. **Merge-mining.** Launch merge-mined with Bitcoin or not at all. AuxPoW
   is not implemented.
2. **Registration PoW target.** Set: initial target 2^228 (≈ 2^28 ≈ 2.7 × 10^8
   SHA-256 tries over the txid, using a midstate so each try costs a few
   blocks), a minute or two in a browser running the WebAssembly wallet on
   all cores; per-call JavaScript is far too slow, so wallets use WASM or
   native code. The target adjusts every 20,160 blocks (two weeks) toward a
   quarter of the cap of 200 PoW registrations per block (§2.2): a window
   at the cap makes the work four times harder, a window with no
   registrations four times easier, never easier than the initial target.
   Open: whether the level is right with real demand.
3. **`FEE_UNIT`** adjustment rule and whether tiers scale with a
   fee-market signal.
4. **Batch expiry period** (§10.11): set at 2,100,000 blocks (~4 years);
   revisit with real state growth.
5. **Block limit.** 1 MB ≈ 1,100 cheques a minute; revisit with real demand.
6. **Multi-recipient cheques.** Absent by design; several cheques instead.
7. **Column C.** Whether to add the optional full-message check column
   (§10.13).

## 9. Standards this leans on

- FIPS 205, SLH-DSA: only its tweakable SHA-256 hash construction.
- FIPS 180-4 (SHA-256, own implementation).
- BIP-39 (seed words and cell words).
- ISO/IEC 18004 (QR codes on the printed cells and sheets).
- FIPS 203 (ML-KEM), planned for transport only.
- Damm check digit (quasigroup of order 10) for account numbers.

---

## 10. Hand-signed cheques (scheme `0x03`)

### 10.1 What is and is not possible

- **Signing by hand with zero arithmetic: possible.** Lamport-style one-time
  signature over the *plaintext* message. Signing is "for each character of
  what you want to say, copy the secret printed in that row and column".
- **Verification by hand: not possible**, for this or any secure public-key
  scheme. But verification needs no secrets, so *any* computer, including an
  untrusted public one, can do it.
- **Computing the secrets by hand from a short seed: not possible** at real
  security levels. Hash-based security needs 128-bit secrets, and a human
  cannot evaluate a cryptographic function fast enough. So the secrets are
  *created* for you and *written down* (printed), and the thing you hold is
  the printed book: 11 cheques, each a word page and a QR page in each of
  the two parts, plus a cutting template per part (§10.10).
- **Trust.** A standard book trusts one offline computer once, at printing;
  after that, signing needs no trusted device. The split-key book (§10.6)
  removes the single printing computer: two or more devices each see only
  their own half.
- **Hashing nothing means the message must be tiny.** A full 17-byte
  account id would need ~280 secrets copied per signature. So cheques name
  a chain-assigned **sequential account number** (§10.4).
- **Every account is a cheque book.** Software-driven books (§5) cover
  volume users; the signature format never changes.

### 10.2 The cheque message (fixed by consensus)

A cheque says exactly one thing, written in 18 decimal digits:

| Field | Digits | Meaning |
|---|---|---|
| recipient | 12 | sequential account number (11 digits) + Damm check digit |
| mantissa | 4 | significant digits of the amount |
| exponent | 1 | amount = mantissa × 10^exponent base units |
| fee tier | 1 | fee = tier × FEE_UNIT (consensus constant) |

- Cheque number: printed on the sheet; must be greater than the account's
  nonce (or be the open cheque being completed), so a used cheque can never
  be replayed. Numbers are used in rising order: the first piece of a higher
  number deletes every unused lower one.
- mantissa `0000` with exponent `0` means zero coins (honesty check);
  mantissa `0000` with exponent `9` means "entire balance minus fee"
  (sweep); `0000` with any other exponent is invalid.
- The chain rejects a cheque whose recipient check digit is wrong, and a
  recipient number above 2^32 − 1.
- The website names the fee tiers 1–9 Lowest, Standard, Raised, Priority,
  Priority +, High, High +, Very high, Highest.

### 10.3 The private sheet and the signature

Each cheque (leaf) is a grid of secrets:

- 18 columns × 10 rows = **180 secrets**.
- Each secret = 128 bits, printed as a **12-word BIP-39 mnemonic**: the
  same 128 bits + 4-bit checksum as a 12-word seed phrase, from the same
  2,048-word list (the website prints English; other BIP-39 lists give the
  same bytes). The chain sees only the 16 bytes; the words are a paper
  format.
- Why words: every BIP-39 word is unique in its first four letters, so
  typing four letters with autocomplete is enough; a misspelt word is not in
  the list and is rejected on entry; a wrong word fails the checksum 15
  times in 16.
- Each cell is also printed as a **QR code**: its 32 hex digits at error
  correction H, with its position (e.g. `2·P3·1`) printed in the middle
  (§10.7).
- 2,160 words per cheque, split over the two parts (part A 1,440, part B
  720), each part's share of a cheque on one word page and one QR page.

To sign: decide the recipient number and amount, then for each of the 18
columns copy the one secret in the row matching that digit. **18 secrets,
216 words** with a standard book; **36 values, 432 words (≈ 1,700
keystrokes with four-letter autocomplete), 15–20 minutes** with the
split-key book of §10.6. Then mark the cheque as spent.

The website's cheque page: enter the recipient, amount and fee tier; the
lit box in each column is the one to copy or scan. Each box takes its 12
words (grey autocomplete suggestion, four letters complete a word) or its
QR code; "Scan cheque" scans every box in one camera session. Verify checks
all 18 cells against the chain, "In plain words" reads the cheque back, and
a pop-up warns if the recipient number is unknown or not yet final; then
the 18 pieces are sent.

The online computer needs nothing beyond those 18 secrets but the chain:
the book's commitments are registered on chain, so the computer can check
each secret the instant it is typed, and typos are caught per cell without
check digits. It sees only that cheque's cells, which fit only that
recipient and amount: it cannot change them.

On-chain structure. The book's public hash lists are registered on chain
when the account is created, so a cheque carries only the revealed secrets:

```
RegisterBook   { salt, m, n256, book_size, root, first batch, PoW nonce }   once, PoW only
RegisterBatch  { account, batch: start, count, per cheque all share hashes,
                 Merkle path from the batch subtree to the root, PoW nonce }  ≈ 3.6 KB × m per cheque,
                                                                         PoW only
ChequePiece × 18 {
  account     scheme 0x03 | m<<4 | n256<<7, root
  cheque      u16            cheque number
  column      u8             0–17
  shares      m × 16 B       the revealed cell (one per domain)
}
```

The digits themselves are not sent: each node finds the row whose
commitment a piece matches. ≈ 900 B (m = 1) or ≈ 1.3 KB (m = 2) per cheque;
nodes prune that cheque's commitments afterwards. Node state is ≈ 2.9 KB
per *unspent* cheque, paid for by the registration's proof of work.
Rationale: the broadcasting device then needs nothing but the chain and the
18 secrets, and there is no public file the user has to keep. A cheque can
be sent only after its batch is registered.

Key structure: each column has its own small Merkle tree over the 10 row
commitments; the cheque leaf = `H(addr, root_0 || … || root_17)`; the
account root is a Merkle tree over cheque leaves, padded to a power of two.
All hashes are address-tweaked (§3.1). Cells derive from the seed as in
§4.2.

Security: forging a different message on a used leaf needs a preimage for an
unrevealed secret (2^128 classical, 2^64 sequential quantum). No message
hashing means no collision surface at all. Writing a second, different
cheque on a used number leaks secrets that allow mix-and-match forgeries,
but the nonce rule makes a second use unincludable once the first has a
piece on chain, so the only exposure is a race where two different cheques
with the same number are both in the public mempool before either
confirms.

### 10.4 Sequential account numbers

Every account receives a number at its `RegisterBook`, in block and
transaction order: the oldest number out of quarantine if one is free,
otherwise the next value of a global counter (starting at 1). The mapping
`number → AccountId` is node state and is committed under `state_root`.

- Numbers cannot be chosen, so there is nothing to squat or spoof.
- **Maturity:** a number may be a cheque's recipient only once its assigning
  block is 100 deep (about 100 minutes), so a reorg cannot redirect a
  transfer; earlier the cheque fails with "payee number not mature".
- **Publication (node policy, not consensus):** no RPC output prints a
  number until it is final (100 blocks deep): `/account`, `/id` and
  `/lookup` omit the number line, `/top` leaves the account out, block
  summaries show a registration's number and a cheque's sender only once
  final, and the mempool lists a waiting cheque only when its recipient is
  final. So a provisional number is never seen, shared or written on a
  cheque book. The chain itself is public and the order can be
  recomputed; hiding is a usability rule, not a secret.
- **Lookup code:** the first 12 hex digits of the account id after its
  scheme byte (48 bits), e.g. `12CD-29D7-915E`, printed with a QR link on
  every sheet and saved in the registration file. It carries no authority
  and can never move coins. `/lookup/<code>` (8 or more hex digits) returns
  the account, with its number once final, so a holder can find their
  final number from any device without the seed. A code shared by two
  accounts is reported as ambiguous and more digits are asked for. The
  explorer's find page (`#code=XXXX-XXXX-XXXX`) shows a countdown until the
  number is final, then the account, and confirms the number with a second
  node when it can.
- **Display form:** 11 digits + 1 Damm check digit, e.g. `00000048213-5`;
  sites group the digits in fours from the left (`0000 0048 213-5`). The
  check digit is part of the cheque message and is verified by consensus;
  a mis-copied digit invalidates the cheque instead of sending to a
  stranger. The Damm quasigroup table is public and takes a minute to
  apply by hand.
- Numbers are `u32` on chain (up to ≈ 4.3 × 10^9); the 11-digit field
  leaves room to widen. Unfunded PoW accounts expire and their numbers
  return after the quarantine, so spam can hold at most about
  200 × 569,000 ≈ 1.1 × 10^8 numbers at once (fewer in practice: block size
  allows about 23 registrations per block).
- Only numbers of deleted never-funded accounts are reused, after a
  one-year quarantine. Number 0 is nobody (honesty check, fee sink).
- Numbers carry no secret and no authority: knowing all of them only lets
  you send to them.

This replaces the name registry of earlier drafts.

### 10.5 Operational notes

- A sheet is bearer paper: anyone holding an unused cheque (both parts) can
  write one cheque for any amount from that account. Keep the parts apart
  and split large holdings across several books in several places.
- Lost the book? Regenerate from the 24 words on a clean offline computer;
  the chain tells you which cheque numbers are already used. (The website's
  restore and reprint flows are not working yet.)
- Running out of printed cheques? Print the next ones from the seed on a
  clean offline computer and register them: same account number. After
  cheque 255, or if the seed may be exposed, make a new book; any unused
  cheque with mantissa `0000`, exponent `9` sweeps the balance to the new
  book's account number. Several books may be live at once.
- A written but unbroadcast cheque is a live transfer to that recipient
  only. To void it, confirm any higher-numbered cheque; lower numbers become
  invalid.
- An account gets its number at `RegisterBook` and can receive after 100
  blocks; only then is the number published. Until funded it can only run
  zero-amount cheques, and if never funded it expires after 43,200 blocks.
- Unfinished cheque: its pieces die after 10,000 blocks (~a week); the
  number stays consumed.
- Untrusted online computer: it learns 18 secrets that only authorise the
  exact cheque you wrote. It can refuse to broadcast, nothing more.

### 10.6 Split-key books (optional, for large savings): no single trusted device

Not the standard book (see §0), and not offered by the website. Use when one
compromised machine must never be able to send.

The one step that needs trust in the standard book is key generation,
because whoever hashes the secrets sees them. Split each secret instead:

```
s[p][v] = a[p][v] || b[p][v]          a from device A, b from device B
commit[p][v] = H(addr, H(addr, a) || H(addr, b))
```

- **Device A** generates every `a` value for the book from its own seed,
  prints them as "book A", and outputs the public list `H(a[p][v])` for
  every position and symbol.
- **Device B** (a second computer elsewhere) does the same for the `b`
  values, independently.
- Any device at all combines the two public hash lists into the position
  trees and the account root, because those lists contain no secrets.
- You keep book A and book B apart. Together they are your private key.
- To sign, copy both halves of each of the 18 secrets.

Security: an attacker who fully controls device A knows every `a` but no
`b`; forging any position still needs a 128-bit preimage. Only A and B
colluding, or both being the same malware, breaks it. Three or more devices
are allowed (`m`-of-`m`, m up to 7 in the account's scheme byte
`0x03 | m<<4`). With `m = 1` this is the standard book.

What a malicious device can still do is **sabotage**: print one book but
hash a different set of secrets, so your account can never send (it
cannot send either, lacking the other half). Defence, used by every book:
before funding the account, send cheque 0 for zero coins to number 0 and
let the chain verify it against the root. If it verifies, every device told
the truth about its hashes, because it cannot know which 18 secrets you
would reveal. Cheque 0 is reserved for this and sent with the registration.

Per-cheque cost at `m = 2`:

| | |
|---|---|
| Printed pages (A + B) | 2 or more per device |
| Values copied to sign | 36 |
| Words typed into the broadcast device | 432 (≈ 1,700 keystrokes) |
| On-chain size | ≈ 1.3 KB (18 pieces, 2 × 16 B secrets each) |
| Hashes to verify | ≤ 540 |

Trust domains: a printer sees everything its device sends it, so the printer
belongs to that half. Device A + printer A form one domain, device B +
printer B another; the two must share no printer, cloud print service or
vendor account. A leak of one whole domain (device, printer, screen
photographed) still cannot send. Printer-free alternatives: copy a half-book
from the screen (~2.5 h per cheque per device), or use the pre-registered
recipient mode (§10.8) where a half-cheque is 120 words.

Randomness: if you distrust a device's random number generator, each device
can mix in your own dice throws. It does not change the security argument
above; it only protects against a weak generator.

### 10.6a Threshold books (k-of-n) — design only, not in consensus

The split book is an m-of-m multisignature of one-time hash signatures.
A k-of-n variant costs only more commitments: each cell has n halves, one
per domain, and the chain stores one commitment per k-subset,
`H(addr, H(h_1 ‖ … ‖ h_k))` over the subset's half-hashes, C(n,k) per cell.
Signing reveals any k halves; a node hashes the revealed subset and checks
membership. The scheme byte would carry (k, n).

2-of-3 is the recommended store-of-value configuration: three domains at
setup, 36 cells to sign from any two books, 3 commitments per cell
(registration ≈ 3×), a thief still needs two books, and the loss of one
seed-and-book pair is recoverable by reprinting from the other two. It is
also the inheritance shape: holder, spouse, lawyer. The one-time rule is
unchanged: a cheque number is consumed by its first public piece whichever
pair signs it.

### 10.7 Machine-readable paper

Hand-drawn QR codes are impractical (Reed–Solomon error correction must be
computed by hand and scanners reject codes without it), so the printing
computer prints them:

- **Cell QR codes.** Every cell is printed both as 12 words and as a QR
  code of its 32 hex digits at error correction H (about 30 % may be
  covered), with its position (e.g. `2·P3·1`) printed in the middle. Each
  part ends with a cutting template (an empty grid marked "NO SECRETS"):
  laid over a QR page it shows one box at a time, so the camera sees only
  the cell being scanned. Never photograph a whole page: that would hand
  the device every cell of that cheque. The browser's QR reader and encoder
  are part of the WebAssembly wallet (`web/wasm`).
- **Sheet QR code.** Each sheet header carries the lookup code and a QR link
  to the explorer's find page (§10.4).
- **Tear-off tabs** (design only): each cell on a perforated tab, 18 tabs
  laid in order and photographed.
- **Dice.** The website accepts typed dice rolls for the seed
  (seed = SHA-256 of the rolls). A camera-read dice grid is design only.
- **Fallback.** Type the words; each cell is checked against the list, its
  checksum and its hash on entry, so errors are caught per cell.

### 10.8 Pre-registered recipient mode (small cheques) — design only

An account may be created with a fixed recipient list of up to 10 account
numbers, included in `RegisterBook`. A cheque in this mode has one 10-row
column (recipient) and optionally 3 amount digits + 1 exponent, i.e. 10 or
50 cells instead of 180. Per half-cheque that is 120 or 600 words, small
enough to copy by hand from a screen (no printer) or to fill from dice. The
cost is that such an account can only send to numbers registered in
advance. Consensus does not implement it.

### 10.9 Recovery and storage of a split book

- **Per-domain seeds.** (With a 2-of-3 book, §10.6a, any two seeds
  suffice.) Each device derives its half of the book from its own 24-word
  seed (§4.2), shown once for the user to write down. Restoring the book
  needs any `m` fresh devices, each given one seed: the same trust split as
  the original printing. Without this the book is unrecoverable.
- **Store halves apart.** Keep book A and book B in different places and
  bring them together only to sign. A stolen half cannot send.
- **Sabotage is bounded.** Cheque 0 samples 18 of 180 cells, so a
  dishonest device can corrupt a few cells and make specific messages
  unsignable from that book. It cannot steal, and coins can always be
  moved in other amounts.

### 10.10 Seeds, derivation and the fixed book

- A book is **256 cheques** on one account number. Number 0 is the honesty
  check, sent with the registration and never printed. The holder prints as
  many as they want now (the website offers 15, 31, 63 …) and more later from
  the same seed. Cheques are registered 16 at a time: `RegisterBook` carries
  the batch holding cheque 0 (≈ 58 KB at m = 1), each later `RegisterBatch`
  the next 16, each with its own proof of work. No cheque is kept back for a
  sweep: any cheque with amount 0000, exponent 9 sweeps (§10.11). Books
  registered before this change have 11 or 12 cheques and keep working.
- **Printing more.** On a clean, offline computer, the seed and a cheque
  range (say 16–31) give the two print files and a public registration file
  holding that range's batches; it is registered like the first one. The
  offline page that does this is a single HTML file that runs without a
  network (the `bitcheque-print` repository). A batch already registered is
  refused as a duplicate, which the website treats as done.
- Printed layout: part A (recipient columns) and part B (amount, exponent,
  fee) as separate print runs, ideally on two printers, so neither printer
  sees a whole cheque. Each part holds, for every cheque, a word page and
  then its QR page, and ends with the cutting template (§10.7). Sheet
  headers carry the lookup code and its QR link; the "Account ____" line is
  left blank, to fill in once the number is final.
- The registration and cheque 0 hold only public hashes and cells, so the
  offline computer saves them, with the lookup code, as a public
  registration file (never the seed), then the print files are deleted and
  the machines switched off. The file is opened on the website on any
  online computer, which mines the proof of work on all cores (Rust
  compiled to WebAssembly) and sends the registration and cheque 0. The
  number is not shown until final (100 blocks); the lookup code finds it
  (§10.4), and the honesty check is confirmed from the chain.
- One 24-word seed (from the computer's randomness, or made entirely from
  dice). Derivation is hierarchical and one-way (§4.2), N = 0..255.
- The seed enters an offline computer at printing: the first time, each time
  more cheques are printed, and to reprint a lost book (§10.9, §10.11).
  Keep it for as long as the book is in use.
- When all 255 printable cheques are used, or the seed may be exposed, make
  a new book and sweep the balance across with any unused cheque (mantissa
  0000, exponent 9). Several books may be live at once.

### 10.11 Statelessness of the cheque book, and state expiry

- No device keeps a counter. The paper is the state: a used cheque is
  marked, and the chain records which numbers are consumed.
- **Reprint rule.** A reprint holds the same cheques as the original. Use
  only numbers above the chain's nonce, never one the original may already
  have written, and destroy the original. Writing two different cheques on
  one number is the only way a double reveal can happen.
- **Book expiry.** Registered commitments of unspent cheques expire with
  their batch, 2,100,000 blocks (~4 years) after registration, unless
  renewed by a `Renew` (10,000 base units). Expired cheques cannot be sent
  until re-registered. This bounds node state from abandoned books.

### 10.12 Piecewise submission

Every cell is self-authenticating: its hash identifies the account, cheque
number, column and row. So a cheque is submitted as separate pieces, which
may come from different devices, places and times.

- `ChequePiece { account, cheque, column, shares (exactly m) }` is a
  transaction in its own right. Nodes verify each piece against the
  registered commitments and record the revealed digit in state. When all
  18 columns are revealed the transfer executes and the fee is charged.
- Only the paper holder can produce a valid piece, and a cheque has
  exactly 18, so pieces cannot be used for spam.
- Uses: thin channels (SMS, radio, post); several people each holding some
  columns as an approval mechanism; in a split book, cells from two
  machines.
- **Commitment rule.** Once any piece is public the cheque number is bound
  to that recipient and amount. Finish it or void it with a higher number;
  never write a different cheque with the same number.
- Pieces of an unfinished cheque expire after 10,000 blocks (~a week); the
  number stays consumed (the account nonce is advanced on first piece). A
  first piece of another number also deletes the open cheque.
- Wallets submit recipient columns first, so the recipient is fixed on
  chain before anything else is public.
- Nodes decode waiting pieces against the commitments: `/mempool` lists a
  waiting cheque's recipient once its 12 recipient digits are visible, valid
  and final, and its amount and fee once all 18 are.
- Residual risk of a double reveal (same number, two messages): an attacker
  can only mix revealed digits column-wise, cannot freely choose the
  recipient, and after the recipient columns are fixed can at most raise
  the amount within the digits revealed. No theft by a third party.

### 10.13 Operational threats and rules (after a hardware-wallet implant)

A 2026 supply-chain implant in a hardware wallet read the seed off the
device screen at setup. In a split book one implanted device learns one
half and steals nothing; in the standard book the printing computer sees
everything, so it must be clean and offline. The rules, and the threats
that remain:

- **Never buy a printed book.** A vendor who prints a book holds the key.
  Print your own from a seed only you have seen.
- **Two devices, two sources** (split books). A single device used for both
  halves is a hot wallet. Different makers, different places, different
  printers.
- **Failed broadcast rule.** If a broadcaster reports failure, it may still
  hold a live cheque. Before sending again: confirm a zero-coin cheque with
  the next number (voids the withheld one), then send with the number
  after. Never re-write the same transfer on the next number directly.
- **Signing exposure.** Both parts of one cheque are visible while
  signing. A camera over the desk captures a forgeable cheque number.
  Option: scratch-off coating over cells (print-shop only), so only the 18
  scratched cells are ever exposed and tampering is visible.
- **Amount check (optional column C).** The recipient check digit does not
  cover the amount. A 19th column carrying a Damm digit over all 18 others
  makes any single copying error invalidate the cheque, at one more cell.
  Decide before freezing; not implemented.
- **Fee unit.** Tiers are multiples of `FEE_UNIT`; an on-chain adjustment
  rule (e.g. median fee of recent blocks) is needed so tiers track demand.
- **Sampled honesty check.** 18 of 180 cells are proven; a dishonest device
  can still corrupt a few cells, which is denial of specific amounts, not
  theft.

## 11. Security relative to Bitcoin (summary)

Stronger: hash-only assumption, quantum-safe, no off-chain state, signing
needs no trusted device (a standard book trusts one offline computer once,
at printing; a split book, m ≥ 2, not even that). Weaker: a book is bearer
paper unless its parts are stored apart; one recipient per cheque; privacy
(accounts + sequential numbers) is worse than fresh-address UTXO; a young
chain has far less hashpower and no review history. Large holdings are
split across books and places rather than kept behind a single device.

## 12. Genesis and launch

Bitcheque launches as its own chain. Block 0 is deterministic from the
parameters below: anyone can rebuild it and get the same hash
(`bitcheque genesis`; `genesis.py` in this folder does so for the mainnet
parameters). There is no premine: the genesis coinbase names number 0 and
is unspendable, as in Bitcoin.

### 12.1 Consensus parameters fixed at genesis

| Parameter | Value | Note |
|---|---|---|
| Block target | 60 s | |
| Reward | blocks 1–525,000 (~1 year): 4 coins; then 4.5 coins, halving every 2,100,000 blocks (~4 years) | the launch year mines 2,100,000 coins, 10 % of the supply; the rest 18,900,000 less integer rounding, so the total stays under 21M; 10^8 base units per coin; see §12.5 |
| Reward maturity | credited to the miner's account 100 blocks later | state keeps a pending-reward queue by height |
| Difficulty | per-block LWMA over the last 60 blocks, solve times clamped to ±6 targets, result clamped ×3 / ÷3 per block | survives hashrate arriving or leaving at once |
| Stall relief (research network only) | a block more than two targets (plus the 720 s future allowance) late may use a target doubled for every further two targets of silence, up to the easiest target | a chain abandoned at a high difficulty can be restarted by whoever is left; mainnet relies on hashrate instead |
| Initial target | 2^224 (`0x1E00FFFF`), also the easiest target | adjusts within an hour of real hashrate |
| Timestamps | above the median of the last 11 blocks, at most 720 s in the future | twelve blocks, as Bitcoin's two hours are twelve of its blocks |
| Proof-of-work | SHA-256d over the 112-byte header | AuxPoW (merge-mining) not implemented, §8 item 1 |
| Header | version 4 B, prev 32 B, tx root 32 B, state root 32 B, time 4 B, bits 4 B, nonce 4 B | 112 B |
| Block limit | 1,000,000 bytes (encoded block) | §6 |
| Registration PoW | target 2^228 initially, adjusting every 20,160 blocks; at most 200 PoW registrations per block | §8 item 2 |
| Unfunded PoW account | deleted after 43,200 blocks (~30 days); number quarantined 525,600 blocks (~a year) | §2.2 |
| Batch lifetime | 2,100,000 blocks (~4 years); `Renew` costs 10,000 base units, `RegisterBatch` the registration proof of work | §10.11 |
| Piece lifetime | 10,000 blocks (~a week) | §10.12 |
| Book size | ≤ 256 cheques; batches ≤ 16, aligned powers of two, each paid by proof of work | §2.2, §10.10; a 16-cheque batch (≈ 58 KB) fits any block; `printed_book_size` is still 11 and only refuses a split book (m > 1) of fewer than 11 cheques registered in part |
| `FEE_UNIT` | 1,000 base units (0.00001 coin) initially | adjustment rule: §8 item 3 |
| Account number 0 | reserved: nobody; coins and fee of a cheque to it go to the block's miner | §2.2 |
| Account maturity | 100 blocks before a number can receive a cheque | §10.4 |
| Network magic | `0xBC 0x4E 0x51 0x00` mainnet, `…0x01` research network, `…0x02` local | non-consensus |

The public research network uses the mainnet parameters except: initial
target ≈ 2^240 (`0x1F00FFFF`), easiest later target 2^237 (`0x1E200000`,
about 2^19 hashes a block: under a second for one CPU core), the same launch year,
stall relief on. The difficulty is set by the hash power present: with one
small miner it sits at the floor, and each block can raise it up to 3× when
more join. So the chain never stalls for want of miners, the edge nodes
carry a backup miner: when no block has come for 50 seconds, one region
mines a block at the current target, paying a configured account. It is an
experimental network that may change or be reset, and at this difficulty
anyone with modest hash power can rewrite its recent history.

### 12.2 Bootstrap rules

The first blocks have no accounts, so three rules make block 1 possible:

- A coinbase names an account number that exists by the end of its own
  block (a miner may register a software book and name it in the same
  block). The 100-block maturity of §10.4 applies to cheque recipients, not
  to the coinbase; the reward itself matures 100 blocks later.
- A coinbase may name number 0, which burns the reward. The genesis
  coinbase does.
- Registration PoW in the first 20,160 blocks uses the fixed 2^228 target
  before the first adjustment, so early registrations cannot be priced out
  by a single burst.

Blocks must be timestamped after the median of the previous 11, so nobody
can mine before the genesis timestamp (the published launch time), and the
release must be public at least one week before it.

### 12.3 Launch sequence

1. Freeze §8. Every open decision becomes a line in §12.1.
2. Run the public research network (since 2026-10-17) with the same code,
   separate magic and the differences listed under §12.1, for at least 90
   days with public review of consensus bugs.
3. Publish the genesis parameters, the genesis message and the launch
   timestamp. Publish node binaries and the wallet one week ahead.
4. Block 0 is rebuilt by anyone from `genesis.py`; its hash is hard-coded
   in the release, together with nothing else.
5. At the launch timestamp mining is open to all. The project mines with
   its own hardware for continuity, not for allocation, and publishes its
   account numbers.
6. Hard-code checkpoints of every 10,000th block in later releases while
   hashrate is small; optionally anchor the chain tip into Bitcoin hourly
   (a non-consensus service, §8 item 1).
7. Offer the AuxPoW specification to mining pools. Merge-mining is the
   target state, not a launch requirement.

### 12.4 What is still open for genesis

- The genesis message text and the launch timestamp (placeholder:
  2027-01-01 00:00 UTC).

### 12.5 Early dominance

Proof-of-work cannot stop whoever brings the most hashrate from producing
most blocks, and SHA-256 means ASIC owners, so one party will likely
dominate the first days. The rules aim to make that worthless rather than
impossible:

- **A launch year at 10 %**: the first 525,000 blocks (~365 days) mine
  4 coins each, 2,100,000 coins in all, 10 % of the supply; after that each
  block mines 4.5 coins, halving every 2,100,000 blocks. Each of years two
  to four creates more coins than the first, so people who hear of the
  network late are not left behind, and mining 100 % of the first week
  earns about 0.2 % of the supply. (This replaced a Zcash-style linear slow
  start over 200,000 blocks.)
- **Per-block difficulty** (§12.1) raises the target within an hour of
  hashrate arriving, so an easy initial target cannot be ground into
  thousands of blocks.
- **Public release one week ahead and the timestamp rule** (§12.2) remove
  the insider head start. Anyone with an ASIC starts at the same second.
- **Checkpoints and Bitcoin anchoring** (§12.3) bound reorg depth, so a
  dominant miner can delay cheques but not rewrite history.
- **Merge-mining offered at launch** is the only measure that ends
  dominance rather than defusing it: one mid-size Bitcoin pool joining at
  zero marginal cost outweighs any individual.

Rejected: limiting consecutive blocks per miner (trivially evaded with
many accounts); a CPU-friendly PoW such as RandomX (forfeits
merge-mining, and botnets dominate CPU chains anyway).


## 13. Reference implementation

Rust, standard library only (`Cargo.toml` lists no dependencies). About 2,500
lines. Module map: `sha256` (own FIPS 180-4, with midstate), `u256`,
`crypto` (§3.1), `damm` and `message` (§10.2, §10.4), `book` (§3.2 rows
4–6), `tx` (§2.2), `params` (§12.1: mainnet, research network, local),
`state` (§2.1, §10.11, §10.12, Merkle state root with account proofs),
`block` (§1, §12, LWMA, stall relief, per-account history and totals for
the RPC), `store` (blocks left in the data file and read by offset, state
snapshots every 1,000 blocks, most-work chain selection, reorg by replay
from the latest snapshot), `net` (§7 discovery, connection caps,
misbehaviour strikes, mempool, mining; no transport encryption yet), `rpc`
(plain-text HTTP, 120 requests per minute per address), `wallet` (§4.2
derivation, registration mining, non-consensus), `main` (`bitcheque
genesis | node | wallet`). Tests: `tests/chain.rs` (life of the chain),
`tests/net.rs` (sync and relay), `tests/store.rs` (reorg, persistence,
proofs, RPC), `tests/hardening.rs`, plus the block 0 vector cross-checked
by `genesis.py`. P2P ports: 8730 mainnet, 8731 research network; the RPC
listens only where `--rpc` says. The research network's genesis is
2026-10-17 14:00 UTC, so blocks are mined before mainnet launch.

RPC (non-consensus): `/height`, `/tip`, `/peers`, `/addrs`,
`/block/<height>` (hex), `/summary/<height>` (rewards, registrations with
their numbers once final, completed cheques with sender and recipient),
`/account/<number>`, `/id/<account id>`, `/lookup/<code>`,
`/history/<number>` (last 50 events; a cheque to yourself is listed as
receive and send), `/proof/<number>`, `/regtarget`, `/stats`, `/top[/N]`,
`/mempool` (with decoded waiting cheques, §10.12), `POST /tx`, `POST /check`
(dry run of up to 64 transactions). Explorer addresses: `#block=N`,
`#account=N`, `#code=XXXX-XXXX-XXXX`, `#mempool`.

Browser wallet: `web/wasm` compiles the same crate to WebAssembly for the
website: the 12-cheque book from a seed, the registration (mined in slices
by workers on all cores), the honesty check, cheque pieces, the lookup
code, and a QR encoder (levels M and H) and camera reader.

Not implemented: transport encryption (§7), AuxPoW (§8), the fee-unit
adjustment rule (§8), checkpoints (§12.3), threshold books (§10.6a), the
pre-registered recipient mode (§10.8), column C (§10.13), tear-off tabs,
split books on the website, and the website's restore and reprint flows,
SIMD hashing.

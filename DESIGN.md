# BITCHEQUE — design notes (v0.8, 256-cheque books, 2026-10-20)

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
6. **Store of value, not everyday transfers.** Every move is a cheque copied
   by hand, at most 255 per book. Throughput and convenience are not goals;
   exchanges and miners use software-driven books (§5).

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

- **Part A**: the 12 recipient columns P1–P12 (columns 0–11) of every printed cheque.
- **Part B**: the amount columns D1–D4, the exponent E and the fee tier F (columns 12–17).

Parts are kept in different places and brought together only to write a
cheque. A cheque reveals **18 cells, 216 words** (or 18 scanned QR codes,
§10.7); on chain it is an opening of 13 columns and 5 pieces (or one opening
of all 18), ≈ 900 B, and at most 360 hashes to verify (§6).

What the part split does and does not buy: a thief who finds only part A or
only part B cannot write a cheque, because every cheque needs cells from both,
and cannot open, burn or freeze one either: a cheque is opened only by one
transaction carrying cells of both parts (§10.12). It does not stop a part-B
holder who sees the owner's opening from choosing the amount (§10.12).
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
  book_size    u32                   always 256, registered 16 at a time (cheque 0 never printed)
  salt         16 B                  book salt (§3.1)
  funded       bool                  has held at least min_fund (1 coin) or been mined to; an unfunded PoW account expires (§2.2)
  batches      map                   registered cheque ranges and their expiry
  commits      map                   commitments of registered, unspent cheques
  open         map                   the open cheque (at most one, at nonce), its digits so far and expiry (§10.12)
}
```

Why an account model: a cheque names its recipient by an 11-digit number
(plus check digit) and consumes a per-account cheque number; both are
account state. A UTXO model would have to smuggle the same state into
outputs.

### 2.2 Transaction types

| Type | Signed by | Fee | Purpose |
|---|---|---|---|
| `RegisterBook { salt, m, n256, book_size, root, first batch, PoW anchor + nonce }` | nobody; self-verifying | anti-spam proof of work only (§8 item 2) | creates the account, assigns its number, registers the first batch (cheques 0–15) |
| `RegisterBatch { account, batch, PoW anchor + nonce }` | nobody; self-verifying | the same proof of work as `RegisterBook` | makes the next 16 cheques of a book spendable (printing more, §10.10) |
| `ChequeOpen { account, cheque, pieces: (column, shares)… }` | the paper | encoded in the cheque (fee tier) | opens a cheque from both parts at once: all of columns 0–11 and one or more of 12–17; uses the number; with all 18 it completes (§10.12) |
| `ChequePiece { account, cheque, column, shares }` | the paper | encoded in the cheque (fee tier) | one more column of an open cheque (§10.12) |
| `Renew { account, start }` | nobody | 10,000 base units from the account balance | resets a batch's expiry (§10.11); valid only in the batch's last 43,200 blocks, so it costs its owner at most one fee per lifetime |
| Coinbase `{ height, number, message }` | — | — | credits the block reward plus fees to a final account number (or 0, nobody), 100 blocks later |

Registration transactions carry no signature because nothing in them can be
falsified: every hash must match the committed root through a Merkle path.
A third party can only register your true hashes, which helps you. A
`RegisterBook` or `RegisterBatch` is paid only by proof of work over its txid (no coins
needed), so every 16 cheques of node state cost the same work however they arrive: initial target 2^228 (≈ 2^28 hashes), at most 16 per block (about what fits), the
target adjusting every block (§8 item 2). The work is anchored: the payment is `(anchor, nonce)`, where
`anchor` is the hash of one of the last 144 blocks (`reg_anchor_window`) of the chain it is mined into (never block 0, which is
known before launch), and
the txid covers it. So the work is done at mining time for one chain and one moment: it cannot be replayed
after the account expires, on another network, or a day later. Registration files made offline carry a
zero anchor; the online wallet sets the tip as the anchor when it mines. A PoW account that has
not been funded after 1,440 blocks (~a day) is deleted and its number
quarantined for 525,600 blocks (~a year) before reuse; once funded it is
permanent. Funded means a balance of at least `min_fund` (1 coin) after a cheque arrives, or a block reward
mined to it; dust does not count. An account
deleted after using cheques leaves a record of its last cheque number, so a re-registration (with fresh work)
brings it back with those cheques still used. Every batch is exactly 16 cheques (`max_batch`) aligned to its
start, and `RegisterBook` always carries cheques 0–15: a third party who sees a registration can neither register
a fragment of it nor a later batch first. A book holds 256 cheques. Duplicates (an existing account, an
overlapping batch) are rejected.

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
`H(addr, x) = SHA256(book_salt || net || 44 zero bytes || addr || x)` truncated to
n = 16 B (category 1, default) or 32 B (category 5, `n256` flag; cells
become 24 words, everything doubles). `book_salt` is a public 16-byte value
carried in `RegisterBook`; the reference wallets derive it from the seed
(`SHA256("bitcheque/salt" || seed)[..16]`), so seed and book size recreate
the book. `net` is the network's 4-byte magic (`Params::magic`: mainnet, the research network, a local
devnet), so the same seed and salt give different commitments, roots and account ids on each network:
a registration or a piece made for one is invalid on another. Testnet books keep their ids across testnet
resets (same magic), which is intended. Caveats: (1) the paper cells are bound to the network too
(§4.2), except on the research network, whose books derive them from the seed alone; a research-network
seed reused elsewhere is still a different book there, so no cheque crosses over. (2) After a
testnet reset a re-registered book has the same commitments as before, so pieces of cheques it revealed on
the old chain can be replayed on the new one if those cheque numbers are registered and unused again; hold
such a book's old cheques as used (spend above the old nonce) or start a new book. `addr` is 8 bytes: (tag, cheque u16, column, index, extra, 0, 0),
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
| 2. Cheque key | the offline printing computer | `key[N] = SHA256("bitcheque/key" ‖ net ‖ seed ‖ N)` (no `net` on the research network, §4.2) | — | yes |
| 3. Cell | the offline printing computer | `cell[N][c][r] = SHA256("bitcheque/cell" ‖ key[N] ‖ c ‖ r)[..n]`; printed | — | yes, paper only |
| 4. Commitment | any computer, from the share hashes | `h_k = H(addr, cell_k)` per domain k; `commit = H(addr, h_1 ‖ … ‖ h_m)` | — | no |
| 5. Column tree, cheque leaf, root | any computer | Merkle tree over the 10 commits of a column (padded to 16); `leaf[N] = H(root_0 … root_17)`; account root over all leaves | — | no |
| 6. Registration | every node | recomputes leaves from submitted share hashes, walks Merkle paths | path must end at the root in the account id; batch aligned and not overlapping; PoW below target, per-block cap | no |
| 7. Writing | the user | nothing | reads a row per digit, copies or scans 18 × m cells | reveals exactly those cells |
| 8. Decoding | broadcasting computer | `H(addr, cell)` for each cell | finds the row whose stored commit matches; shows the decoded recipient and amount | sees only revealed cells |
| 9. Piece validation | every node | `commit' = H(addr, H(addr, cell_1) ‖ … ‖ H(addr, cell_m))` per row | some row's `commit'` == stored commit; account exists; batch registered and unexpired. An opening: `N > nonce`, N not open, columns 0–11 and some of 12–17, every one matching, all or nothing; then `nonce := N` and every lower cheque, open or not, is deleted. A piece: N open, column not yet revealed | no |
| 10. Completion | every node | Damm over P1–P12; amount = mantissa × 10^E (sweep: balance − fee); fee = F × FEE_UNIT | Damm result == 0; recipient is 0 or an existing number 100 blocks old, otherwise the cheque is void (nothing moves); balance ≥ amount + fee; then transfer, prune cheque N's commits | no |
| 11. Block | miner, then every node | SHA-256d over the header; tx Merkle root (leaf `SHA256d(0 ‖ txid)`, node `SHA256d(1 ‖ left ‖ right)`); state root | header meets difficulty (targets compared, not their encodings); every piece re-validated; state root matches | no |
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
  lets an attacker mix revealed digits column-wise until one of them is
  opened; the opening uses the number for good (§10.12), so after it
  nothing more can be written on that number.
- No state exists off-chain. A restore reprints from the seed and asks the
  chain which numbers are consumed.

## 4. Seed and key derivation

### 4.1 Paper formats

24 BIP-39 words per seed (256 bits, metal-backup compatible). The website
makes the seed from dice (seed = SHA-256 of the typed rolls) or from the
computer's randomness mixed with mouse movement. No passphrase.

### 4.2 Derivation (one-way, hierarchical)

```
key[N]            = SHA256("bitcheque/key"  || net || seed_X || N)   per seed X, per cheque N
cell[N][col][row] = SHA256("bitcheque/cell" || key[N] || col || row)[..n]
```

`net` is the network's 4-byte magic, so one seed on two networks gives unrelated cells and a cheque written
on one cannot be replayed on the other. The research network (magic `BC 4E 51 01`) leaves `net` out, as every
book printed for it so far was derived, so those books keep working.

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
- Batches are exactly 16 cheques, aligned, each with its own proof of work.
- `m = 1`, as in the standard book: the machine holding the seed is
  trusted, the ordinary hot-wallet position.
- The command-line wallet (`bitcheque wallet`) drives one book from one
  seed: `register` registers the first 16 cheques (`--cheques N` for more),
  `more` the next ones. It keeps a locked, fsynced record of the last
  cheque it signed and its 18 digits (written before signing, in an
  absolute directory only its user can write; cheque 0 is only ever the
  honesty check; `pieces`, the raw signer, is recorded too, prints only the
  opening, and prints the 5 remaining pieces only with `--rest`, for the
  cheque recorded there, once its opening is deep enough on chain),
  checks the message locally, never trusts a node's numbers past the book
  or more than 3 cheques ahead (`--force-skip` burns the skipped ones), and
  refuses to spend cheque 255 on anything but `sweep` unless told `--last`.
  `--to` is the recipient as printed, check digit included, verified and
  never computed (or the explorer's short form `N-C`, the check digit over
  all 11 digits); coins to number 0 need `--burn`. A new cheque needs two
  nodes that agree on the book (`--rpc A --rpc B`), or `--fresh`, the
  holder's word that the book signs cheques on this machine only: one node
  could hide a cheque sent from elsewhere, and a cheque on top of it would
  put a second message on its number. While the last cheque signed here is
  not in the account's history as finished, one node is never enough. With
  several nodes every decision (choosing a number, releasing the amount,
  deciding a cheque is done) needs all of them to report the book alike
  (number, nonce, open cheque, revealed digits, expiry), else it stops. Every node
  given dry-runs each half (`POST /check`, whose rows must be the cheque's
  own digits) and must know the recipient as final before anything is
  posted. A payment goes in two halves (§10.12): the opening (columns 0–12),
  then, once it is 3 blocks deep on every node (`--confirmations`) and more
  than 100 blocks from its expiry (else: void it), the 5 remaining pieces;
  it reports "sent" only once every node's `/sends` shows the cheque paying
  this recipient this amount (a cheque overtaken by a later one, voided or
  expired is reported as not paid, and the run fails). While the last cheque
  it signed is not shown over by every node, it only finishes that same
  cheque (the same command again, the same recorded digits) or voids it:
  `wallet void` confirms a zero-coin, fee tier 0 cheque to number 0 on the
  next number, as one opening of all 18 columns, and waits for its block
  (§10.13, failed-broadcast rule). The same payment again (same recipient,
  amount and fee as the recorded cheque, now over and paid; or in the
  account's `/sends` within about a day (every completed cheque: `/history`
  keeps only the last 50 events, and an account that mines pushes its sends
  out of it; an older node without `/sends` is read by its `/history`, and
  the wallet warns that the check is limited), or open on chain with these digits,
  or waiting to be mined to the same recipient, sent from another machine)
  is refused as "payment already made" unless `--again`. A fee tier 0 is refused but for a void.
  The RPC is plain HTTP, so anyone on the path can withhold or forge replies
  (never a cheque): give nodes reached over different paths.
- The one-time nature remains. A software wallet restored from seed must
  start above the chain's consumed number; an opening uses its number at once
  (§10.12), so a number once opened can never carry a second message.

There is no other signature type. A device that wants to sign "normally"
simply drives a cheque book.

## 6. Node and state costs

- Per account: ≈ 60 B plus the batch table.
- Per registered unspent cheque: 180 commitments × 16 B ≈ 2.9 KB (independent
  of m) until spent or expired (§10.11). The registration carrying it costs
  180 × m × 20 B ≈ 3.6 KB × m on chain.
- Per cheque: 18 cells of ≈ 50 B in one opening and 5 pieces, ≈ 900 B for a
  standard book (≈ 1.3 KB for a split book, m = 2). Verification: each cell
  is tried row by row, m + 1 hashes per row, so at most 18 × 10 × (m + 1)
  hashes (360 at m = 1); an opening of 13 columns at most 260.
- A 16-cheque registration is ≈ 58 KB at m = 1, so about 17 fit in a block,
  about the PoW cap of 16. A full 256-cheque book is 16 of them and
  ≈ 740 KB of node state while unspent.
- 1 MB block ≈ 1,100 cheques a minute ≈ 18 cheques/s.
- Light clients: headers + `state_root` proofs for balance, nonce, number.
- Unfunded registrations: ≈ 6.6 MB at the one per 10 blocks the target
  settles at (§8 item 2).
- In memory a registered cheque's 180 commitments are one flat 2,880-byte blob shared between state copies
  (≈ 3.1 KB per cheque all told); snapshots write them as raw blobs. Accounts are shared between the
  per-block state copies (copy on write) and each caches its leaf hash, so a block copies one pointer per
  account and rehashes only the accounts it changed (100,000 accounts × 16 cheques: copy ≈ 50 ms, root
  ≈ 80 ms, against ≈ 350 ms and ≈ 930 ms before). Expiries of open cheques and batches are kept in an
  index by height, so `begin_block` touches only what is due.
- State root: `SHA256(merkle(account leaves in id order) || rest)`. An account leaf hashes its record and
  the height its number was assigned (which fixes its entries in `numbers` and the unfunded-expiry list, so
  those are not hashed again); `rest` hashes the height, the next new number, the free-number queue, pending
  rewards, deleted accounts' nonces, the registration target and this block's registration count. The last
  144 block hashes (registration anchors) are state too, but follow from the header chain and are not hashed.
  Snapshots therefore carry some state (`numbers`, the expiry list, those hashes, the magic) that the root does
  not check when one is loaded: a node loads only its own (or its host's) snapshots, never one from elsewhere.

## 7. Network layer (non-consensus)

Planned: a Noise-style handshake with hybrid X25519 + ML-KEM-768,
upgradeable any time. Transport encryption is not implemented yet.

**Seeds and upstreams.** The research network's seed nodes are the edge
nodes on Cloudflare (`node-ap`, `node-us`, `node-eu`, `node-oc`, `node-sa`.bitcheque.org),
which cannot speak this TCP protocol: Workers neither open nor accept raw
connections. So a node also follows *upstreams* over the HTTP RPC: every
minute it pulls the blocks an upstream has above its own tip (`/height`,
`/block/<n>`, walking back up to 200 blocks on a fork; every upstream's
height is asked and the highest pulled from, the next if that brings nothing
new) and it posts every transaction and block it accepts, from its RPC or
from its TCP peers, to all of them (`POST /tx` and `POST /block`; a block
from a peer only if its time is within the last hour, so an initial sync is
not posted block by block). A `POST /tx` carries at most 64 transactions, 16
registrations among them (an edge node refuses a whole post with more) and
about 2 MB of hex; posts waiting for one upstream are joined while they fit
and go at least 2.5 s apart (an edge node takes about 30 heavy posts a
minute), and one answered 429 or 5xx, or not answered, is sent again, waiting
twice as long each time up to a minute, so nothing is dropped for being sent
too fast. Our own transactions (from our RPC) not yet mined are offered to
peers and upstreams again every 10 minutes. With no
`--upstream` it follows the four seeds; `--no-upstream` turns this off. A
node following them and talking TCP to others bridges the two. The edge
nodes do not pull from it, so its own blocks reach them only by that push.
The RPC is plain HTTP (no TLS dependency): blocks and transactions check
themselves, so a party in between can withhold them but not forge them.

The edge nodes form a mesh among themselves: each pushes what it accepts to
the other four and pulls only as a safety net (not while pushed blocks keep
arriving). Their calls carry a shared secret and the chain version; a peer
on another version (an old node after a reset) is neither pulled from nor
pushed to, and without the secret nobody counts as a peer. A peer that
times out is left alone for three minutes; one that sends a refused block,
or claims a greater height but sends nothing that moves the chain, is not
pulled from for ten. A fork is found by comparing block hashes, stepping
back 1, 2, 4… blocks and then halving the gap. Only transactions a node had
from the public are offered to the others again, after a wake, at most
twice. Their RPC answers only paths spelt one way (no leading zeros, no
trailing slash), so each has one cache key.

Peer discovery over TCP follows Bitcoin's model (implemented in `net.rs`): seed node names
compiled into the binary (none on the research network, whose seeds are the
edge nodes above; placeholders on mainnet until the project has a domain), a
`getaddr`/`addr` exchange in which every node shares the addresses it knows
(50 per reply, once per connection, 1,000 remembered, at most 100 taken per
sending /16 or /32 per 10 minutes), an address book saved next to the data file,
and eight outbound connections kept up from that book. A node told nothing
dials the seeds; a node told one peer with `--peer` learns the rest from it.
`--advertise` is the address a node tells others it can be reached on.
The book keeps one entry per IP (eight per /16), so one host on many ports
cannot fill it. Outbound peers are chosen at random, addresses that
answered a HELLO before ("tried", marked in the saved book) taking turns with
new ones, at most one per /16 (/32 for IPv6), dialled in parallel with a 3 s
timeout. An address is forgotten after 3 failed dials in a row, a tried one
after 10; a dial we refuse ourselves (the address is banned or shunned for a
while) is no failure. Gossip never pushes a tried address out of a full book.
The book is saved by writing a new file, flushing it and renaming it over the
old one, so a crash never leaves half a book. Addresses
that carry an IPv4 address inside (NAT64, 6to4, Teredo, IPv4-compatible) are
not taken from gossip. The reply to our own `getaddr` is read whenever it
comes; other `addr` messages at most every 10 s. What a node shares (`addr`,
`/addrs`) leaves out a built-in seed that never answered it and, off a devnet,
loopback and private addresses. An address an inbound peer advertises is
only its claim: it never counts as that address being connected, nor is it
what gets shunned.

Limits: 125 inbound connections, 4 per address and 8 per /24 (/48 for IPv6:
a site, so a provider's /32 of customers is not held to 8). When all are
taken a newcomer is let in by dropping the newest connection of the netgroup
(/16, /32 for IPv6, Bitcoin's grouping) holding the most, never one of the 8
longest-connected or of the 8 that last brought new blocks. A new connection must send
its whole HELLO (at most 200 bytes, and the first frame must be one) within
10 s of connecting; after that a frame may take at most 120 s once it has
started, and none may be longer than the largest block (plus 4 KB). A
block's header and proof of work are checked, and a block already stored is
recognised, before its transactions are decoded. A block our rules reject
for good (one remembered as invalid, below, or built on one) ends the
connection at once: the peer is on other consensus rules or lying, nothing
it has from there on is any use, and its height claim would otherwise hold
templates back for as long as it mines. Its address is not dialled again,
and one off loopback is refused, for 30 minutes. 3 bad messages (a block
failing a cheaper check, such as its proof of work or transaction root, a
repeated `getaddr`, a transaction that can never be valid, such
as a cheque piece matching no commitment) drop a peer and refuse its
address for 30 minutes; strikes and bans are counted per address (an IPv6
/48) across connections, each map of them holds at most 10,000 entries, and
loopback is dropped but never refused (devnets run
many nodes on one machine). A transaction refused only against our state or
mempool is never a strike (honest nodes disagree like this all the time, as
when two conflicting cheque pieces reach different nodes); past 200 refused
in a minute the rest of that minute's are ignored. A sync reply is 500
blocks or about 8 MB of them, whichever comes first; the asker counts only
the block of the height it waits for next (a block sent twice, or from an
earlier ask, is not counted), both ways, and asks on from there, or again
when the source has been quiet for 10 s (a reply cut short by a full send
queue, 16 MB per peer). A block with an unknown parent makes the asker step
back to find the fork, twice as far each time and at most 12 times until
that peer gives it a new block; one sent again before the next ask is dropped
undecoded. Every block a peer sends also tells its height (HELLO is said only
once), so a peer shown to be ahead is asked even after its claim was reset to
ours. The sync source is
a random peer that is ahead, one we dialled if there is one (a claimed height
is not trusted to choose by); it must give us 50 blocks we did not have
(main chain or side), or all it has left, every 30 s, or it is replaced and
its address barred as a source for 10 minutes (not banned: it may be honest
and slow), so a block now and then cannot hold the slot. Templates are
refused ("syncing") only while a peer that has sent us a block new to us in
the last 10 s is more than 6 blocks ahead: a claim alone, from a peer we
dialled or one that called us, holds nothing back. After a reorg the
abandoned transactions go to every peer, the sender of the winning branch
too. A 64 MB mempool, with a txid set and a running byte count beside it.

The RPC serves 256 requests at once; the last 32 threads only for clients
holding no connection yet. One address holds at most 8 connections (an IPv4
address or an IPv6 /56), one IPv6 /48 16 and one /32 64, and a request's
line and headers must arrive within 5 s (the whole request within 20 s), so a
slow client from one place cannot hold the threads. It limits each address
(an IPv6 /48) to 120 requests a minute, and `/check`, `/proof` and
`/template` to 100 a second from everyone together, 10 of them from one
address; a template already built for that tip, mempool, second and payee is
not charged. A path is routed and charged spelt one way (empty segments
dropped). Behind a proxy the last entry of the last `X-Forwarded-For` line is
the client. The data file is flushed to the disk within about 10 s of a
block being written, and before each snapshot; a tail of zeros after a crash
is cut off like a torn record, and other damage moves the file aside and
stops the node with a plain error (exit code 2).

A block that fails validation after its proof of work and transaction root
have checked out is remembered (the last 4,096), with any block built on
it, so sending it again costs a lookup, not another validation or reorg
replay. A tip block's header (difficulty, time) is checked before the
block is written to the data file. After a reorg the new blocks are relayed
first; the mempool is rebuilt from the abandoned blocks' transactions and
what was waiting, and only the abandoned ones are relayed again. A
registration's proof of work and batch (which need no chain state) are
checked before the store lock is taken, and a txid that failed them is
refused at once next time.

Mining: a miner fills its block from the mempool oldest first up to the
block size limit; there is no fee ordering yet. The template is rebuilt
every 10 s when the mempool has changed. The node chooses a template's
transactions once per tip, mempool and second, and keeps the blocks built
from them for up to 16 payees, so miners with different payees cost one
build each.

## 8. Open decisions

1. **Merge-mining.** Launch merge-mined with Bitcoin or not at all. AuxPoW
   is not implemented.
2. **Registration PoW target.** Set: initial target 2^228 (≈ 2^28 ≈ 2.7 × 10^8
   SHA-256 tries over the txid, using a midstate so each try costs a few
   blocks), a minute or two in a browser running the WebAssembly wallet on
   all cores; per-call JavaScript is far too slow, so wallets use WASM or
   native code. The target adjusts every block toward one registration per
   R = 10 blocks on average (the cap is 16 per block, §2.2): a block with k
   registrations multiplies it by (W+1)/(W+R·k), W = 1,440 (a day). A block
   at the cap makes registering about 10% harder (twice as hard in 7 blocks),
   one registration 0.6% harder, so a burst hardens within minutes; an empty
   block makes it 0.07% easier (about e times easier per quiet day); never
   easier than the initial target.
   Memory: a registration holds 16 × 2,880 B ≈ 46 KB of commitments until
   funded or deleted. At the floor target one costs only ~2^28 hashes, so an
   unfunded account lives 1,440 blocks (~a day): at the equilibrium of one
   per 10 blocks that is 144 accounts, ≈ 6.6 MB (the edge node's Durable
   Object has 128 MB; one a block for 4,320 blocks was ≈ 200 MB). More within
   one lifetime needs more work: every further 144 registrations (6.6 MB)
   make each one e ≈ 2.7 times harder, so filling 128 MB would need the last
   registrations to cost ~10^8 floor registrations each.
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
  the printed book: the cheques printed so far (up to 255), each a word page
  and a QR page in each of the two parts, plus a cutting template per part
  (§10.10).
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

- Cheque number: printed on the sheet; an opening must name a number greater
  than the account's nonce, a piece the open cheque, so a used cheque can
  never be replayed. Numbers are used in rising order: an opening (cells of
  both parts, §10.12) uses its number, and every unused lower one is deleted.
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
all 18 cells against the chain (`GET /commits/<id>/<cheque>` gives the cheque's 180 commitments, so the
page checks each cell locally before revealing any), "In plain words" reads the cheque back, and
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
RegisterBook   { salt, m, n256, book_size, root, first batch, PoW anchor + nonce }   once, PoW only
RegisterBatch  { account, batch: start, count, per cheque all share hashes,
                 Merkle path from the batch subtree to the root, PoW anchor + nonce }  ≈ 3.6 KB × m per cheque,
                                                                         PoW only
ChequeOpen {                 one, then ChequePiece × (18 − its columns)
  account     scheme 0x03 | m<<4 | n256<<7, root
  cheque      u16            cheque number
  pieces      (column u8, shares m × 16 B)…   columns 0–11 and one or more of 12–17, rising
}
ChequePiece {
  account, cheque
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
cheque on a used number leaks secrets that allow mix-and-match forgeries.
The chain makes a second message on one number impossible once the first is
opened (the opening uses the number, for good); before that, two written
cheques on one number are two ways to open it, and whichever opening lands
first fixes its columns, the rest still mixable from the revealed cells.
Never write a number twice.

### 10.4 Sequential account numbers

Every account receives a number at its `RegisterBook`, in block and
transaction order: the oldest number out of quarantine if one is free (freed
numbers queue in release order),
otherwise the next value of a global counter (starting at 1). The mapping
`number → AccountId` is node state and is committed under `state_root`.

- Numbers cannot be chosen, so there is nothing to squat or spoof.
- **Maturity:** a number may be a cheque's recipient, or a block reward's,
  only once its assigning block is 100 deep (about 100 minutes), so a reorg
  cannot redirect a transfer or a reward to whoever holds the number on
  another branch; earlier the cheque fails with "payee number not mature"
  and the block with "coinbase payee not mature".
- **Publication (node policy, not consensus):** no RPC output prints a
  number until it is final (100 blocks deep): `/id` and `/lookup` omit the
  number line, `/account/<n>` of a number not yet final answers only
  `pending` and its `ready_at` block (the explorer counts down to it), never
  the account behind it, `/history/<n>` and `/proof/<n>` answer it as an
  unknown number, a sender not yet final appears in a
  history as its account id, `/top` leaves the account out, block
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
  return after the quarantine, so spam can hold at most
  16 × (1,440 + 525,600) ≈ 8.4 × 10^6 numbers at once at the per-block cap,
  and about 52,700 at the one registration per 10 blocks the target settles
  at (§8 item 2).
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
  blocks; only then is the number published. Until funded (1 coin held, or
  a block reward) it is temporary: if never funded it is deleted after
  1,440 blocks (~a day). It can send whatever it holds meanwhile.
- Unfinished cheque: it dies 10,000 blocks (~a week) after its opening,
  and its number stays consumed.
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
cannot send either, lacking the other half). Cheque 0 for zero coins to
number 0 is sent with the registration and verified by the chain, but it
proves little: it always reveals row 0 of every column of cheque 0, a cheque
that is never printed, so it shows only that the device can compute cheque 0,
not that the printed cheques match what was registered. The check that does:
before funding, the wallet compares cells picked at random from the printed
sheets against the registered commitments (`GET /commits/<id>/<cheque>`),
which a device cannot predict at printing.

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
unchanged: a cheque number is consumed once cells of both parts are public,
whichever pair signs it.

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
- **Sabotage.** Cheque 0 alone proves nothing about the paper (§10.6);
  random printed cells checked against `GET /commits` before funding catch
  a device that hashed something else. A device that corrupts only a few
  cells can still make specific messages unsignable from that book; it
  cannot steal, and coins can be moved in other amounts.

### 10.10 Seeds, derivation and the fixed book

- A book is **256 cheques** on one account number. Number 0 is the honesty
  check, sent with the registration and never printed. The holder prints as
  many as they want now (the website offers 15, 31, 63 …) and more later from
  the same seed. Cheques are registered 16 at a time: `RegisterBook` carries
  the batch holding cheque 0 (≈ 58 KB at m = 1), each later `RegisterBatch`
  the next 16, each with its own proof of work. No cheque is kept back for a
  sweep: any cheque with amount 0000, exponent 9 sweeps (§10.11). A book of
  any other size is refused.
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
  online computer, which takes the node's tip as the registration's anchor,
  mines the proof of work on all cores (Rust compiled to WebAssembly) and
  sends the registration and cheque 0 (the work is good for 144 blocks). The
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

- `ChequeOpen { account, cheque, pieces }` opens a cheque (below);
  `ChequePiece { account, cheque, column, shares (exactly m) }` adds one
  column to the open cheque, a transaction in its own right. Nodes verify
  each cell against the registered commitments and record the revealed digit
  in state. When all 18 columns are revealed the transfer executes and the
  fee is charged.
- Only the paper holder can produce a valid piece, and a cheque has
  exactly 18, so pieces cannot be used for spam.
- Uses: thin channels (SMS, radio, post); several people each holding some
  columns as an approval mechanism; in a split book, cells from two
  machines.
- **Opening (consensus).** A cheque is opened only by a `ChequeOpen`: one
  transaction carrying every recipient column (0–11) and one or more amount
  columns (12–17), columns strictly rising, one encoding. It applies all or
  nothing: the cheque registered and unexpired, not open, N > nonce, and
  every column's cell matching a row. It uses the number at once:
  `nonce := N`, and every lower cheque, open or not, is deleted; so at most
  one cheque is open, the one at nonce. With all 18 columns it completes at
  once (a void, the honesty check). A `ChequePiece` is valid only for the
  open cheque: no piece, nor any number of pieces, opens anything.
- **Expiry.** An open cheque expires 10,000 blocks (~a week) after its
  opening; later pieces do not move that. It is then removed, and its
  number stays used: nothing can be written on it again.
- So a holder of only part A, only part B, or a few leaked cells can neither
  open, burn nor freeze anything: every opening needs cells of both parts,
  and a piece needs an open cheque. (Audit 3's rule let a single piece open
  a cheque without binding it: a one-part holder could pin every unused
  cheque, re-pinning at expiry, for free; and an expired unbound opening let
  a wallet without its record sign that number again with other digits.)
- **Commitment rule.** Once any piece is public, its digit is fixed for
  that cheque while it is open, and its cell is public for good. Finish the
  cheque or void it with a higher number; never write a different cheque
  with the same number.
- Wallets send the opening first with columns 0–12 (the recipient and the
  first amount digit), and the 5 remaining amount pieces only once the
  opening is a few blocks deep (3 by default), far from its expiry (100
  blocks or more left, else void it), and the chain shows that cheque open
  with exactly their digits. A cheque open with someone else's digits is
  spoiled: nothing more is sent on it.
- **Residuals.** The amount is not protected by the split into parts: a
  part-B holder who sees the owner's opening (in the mempool, or once in a
  block) can choose the amount. Racing the opening it can copy the owner's
  recipient cells into its own opening and pick any amount, a sweep of the
  whole balance included, to the owner's recipient (the fee tier to the
  miner); after the opening is in a block it can still write columns 13–17
  for the largest amount the balance allows under the owner's first digit.
  The recipient cannot be changed by anyone holding only part B. A part-A
  holder who sees the owner's opening and gets its own opening mined first
  (a miner, or a race won) can open that cheque to its own recipient with
  the owner's column-12 cell; it cannot finish it (the rest of part B is the
  owner's), so it spoils one cheque and steals nothing. Only a split book
  (§10.6), where no single part or machine holds a whole column, really
  defends the amount; after any theft of a part, sweep to a new book.
- **Unknown recipient.** A completing piece whose payee number does not
  exist or is not yet final (100 blocks) is accepted and voids the cheque:
  the number is used, no coins move and no fee is charged. So nobody who
  gets that number later can collect it.
- Nodes decode waiting openings and pieces against the commitments:
  `/mempool` lists a waiting cheque's recipient once its 12 recipient digits
  are visible, valid and final, and its amount and fee once all 18 are. Two
  openings of one cheque conflict: the second is refused ("cheque already
  open"); `POST /check` answers "cheque open with other digits" when the open
  cheque shows other digits than an opening, "column revealed with other
  digits" for such a piece, and "ok <rows>" with the rows its cells matched.
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
  The command-line wallet enforces this: it refuses a new payment while
  its last cheque is not completed, and `wallet void` sends the zero
  cheque (§5).
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
- **Honesty check.** Cheque 0 always reveals row 0 of an unprinted cheque,
  so it shows only that the device computes cheque 0; random printed cells
  compared with `GET /commits` before funding are the real check. A
  dishonest device can still corrupt a few cells, which is denial of
  specific amounts, not theft.

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
| Registration PoW | target 2^228 initially, adjusting every block toward one registration per 10 blocks (time constant 1,440 blocks); anchored to one of the last 144 block hashes (not block 0's); at most 16 PoW registrations per block | §8 item 2 |
| Funding | an account becomes permanent once it holds 1 coin (`min_fund`) after a cheque, or is mined to | §2.2 |
| Unfunded PoW account | deleted after 1,440 blocks (~a day); number quarantined 525,600 blocks (~a year) | §2.2, §8 item 2 |
| Batch lifetime | 2,100,000 blocks (~4 years); `Renew` costs 10,000 base units, `RegisterBatch` the registration proof of work | §10.11 |
| Piece lifetime | 10,000 blocks (~a week) from a cheque's opening | §10.12 |
| Book size | exactly 256 cheques; every batch exactly 16, aligned, the first (`RegisterBook`) at cheque 0, each paid by proof of work | §2.2, §10.10; a 16-cheque batch (≈ 58 KB) fits any block |
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

- A coinbase names a final account number (100 blocks deep, §10.4), as a
  cheque's recipient does, or number 0. A new miner therefore mines to 0
  (or to another final number) for its first 100 blocks; a reorg can never
  hand its rewards to whoever holds the number on another branch. The
  reward itself then matures 100 blocks later. (The edge nodes' backup
  miner falls back to 0 until its configured number is final.)
- A coinbase may name number 0, which burns the reward. The genesis
  coinbase does.
- Registration PoW starts at the fixed 2^228 target and never gets easier;
  a burst at the cap hardens it about 1% a block, quiet blocks ease it back.

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
the RPC), `store` (blocks left in the data file and read by offset; at
startup the file is scanned header by header and only blocks after the
snapshot are read and checked; a torn last record is cut off, but a record
length no block can have stops the node and moves the file aside to
`<data>.corrupt` rather than cutting off every block after it; state
snapshots every 1,000 blocks to disk and, on a node, one in memory every
`max_reorg` blocks (as many kept as a reorg of `max_reorg` could need), so
an ordinary reorg replays at most about 2 × `max_reorg` blocks; with no
usable snapshot a fork more than 2 × `max_reorg` blocks back is refused
rather than replayed from genesis (on the edge node, whose snapshots are
the host's, this bounds how deep a reorg it follows); most-work chain
selection (a fork deeper than 100 blocks, `max_reorg`, needs twice the
work of what it replaces, and its side blocks are kept only while the
branch has at least half the main chain's work over the same heights;
none forking more than 2,000 blocks back); side-branch work summed from
headers; reorg by replay from the latest snapshot at or below the fork),
`net` (§7 discovery, connection caps,
misbehaviour strikes, mempool, mining; no transport encryption yet), `rpc`
(plain-text HTTP, 120 requests per minute per address (an IPv6 /64), 8
connections at once per address (an IPv6 /56) and 256 in all; behind a
reverse proxy on the same machine the client is the last
`X-Forwarded-For` entry, which assumes exactly one proxy hop; a request
must arrive within 20 s, plus a second per 32 KB of body actually
received, and its reply be taken within 60 s; bodies must be ASCII;
`/mempool` is cached per mempool version and tip), `wallet` (§4.2
derivation, registration mining, non-consensus), `main` (`bitcheque
genesis | node | wallet`). Tests: `tests/chain.rs` (life of the chain),
`tests/net.rs` (sync and relay), `tests/store.rs` (reorg, persistence,
proofs, RPC), `tests/hardening.rs`, `tests/net2.rs` (network, storage and RPC abuse), `tests/consensus2.rs` and
`tests/consensus3.rs` (consensus audits), `tests/wallet2.rs` and `tests/wallet3.rs` (the command-line wallet against a
fake RPC), plus the block 0 vector cross-checked
by `genesis.py`. P2P ports: 8730 mainnet, 8731 research network; the RPC
listens only where `--rpc` says. The research network's genesis is
2026-10-17 14:00 UTC, so blocks are mined before mainnet launch.

RPC (non-consensus): `/height`, `/tip`, `/peers`, `/addrs`,
`/block/<height>` (hex), `/summary/<height>` (rewards, registrations with
their numbers once final, completed cheques with sender and recipient),
`/account/<number>`, `/id/<account id>`, `/lookup/<code>`,
`/history/<number>` (last 50 events; a cheque to yourself is listed as
receive and send), `/sends/<number>` (every completed cheque of the account,
newest first, one `HEIGHT send cheque=N to=P amount=A fee=F` line each, as
`/history` writes a send, or `none`; at most a book's 256, kept for the
account's lifetime in the node's index and its snapshots, rebuilt on a
reorg), `/proof/<number>`, `/regtarget`, `/stats`, `/top[/N]`,
`/mempool` (with decoded waiting cheques, §10.12), `POST /tx`, `POST /check`
(dry run of up to 64 transactions, at most 2 of them registrations; a
repeated line is answered "duplicate transaction"; an empty body answers
at once). Explorer addresses: `#block=N`,
`#account=N`, `#code=XXXX-XXXX-XXXX`, `#mempool`.

Browser wallet: `web/wasm` compiles the same crate to WebAssembly for the
website: the 256-cheque book from a seed, the registration (mined in slices
by workers on all cores), the honesty check, cheque pieces, the lookup
code, and a QR encoder (levels M and H) and camera reader.

Not implemented: transport encryption (§7), AuxPoW (§8), the fee-unit
adjustment rule (§8), checkpoints (§12.3), threshold books (§10.6a), the
pre-registered recipient mode (§10.8), column C (§10.13), tear-off tabs,
split books on the website, and the website's restore and reprint flows,
SIMD hashing.

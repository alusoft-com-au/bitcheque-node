# Bitcheque GPU miner

A CUDA miner for the node's proof of work (DESIGN.md §1.1, `src/pow.rs`): every card holds the 2 GiB table of the
current epoch and tries nonces against templates from any node's RPC, exactly as `bitcheque mine` does on the processor.
It is a separate program on purpose: the node stays dependency-free Rust, and this needs the CUDA toolkit.

```
./build.sh                                   # nvcc -O3 -std=c++17 -arch=sm_80 (edit for other cards)
./bitcheque-miner --selftest                 # the card's hashes against the vectors in tests/pow.rs and genesis.py
./bitcheque-miner --rpc node-ap.bitcheque.org:80 --to NUMBER [--devices 0,1]
```

`--to` is the account number the reward goes to (0 burns it). A new template is taken when the node's tip moves and every
20 seconds anyway. Each card checks three table elements against the processor's after building, and every block it finds
is verified on the processor without the table before it is sent; a table that disagrees stops the miner and a find the
processor does not confirm is not sent, so a wrong kernel can never send a bad block. Past its share of a template's 2^32
nonces a card moves the header's time on by a second and starts over (a block's time may run up to 12 minutes ahead of a
node's clock), so a node is asked for a template a few times a minute, not once per share; while the chain is in stall
relief (silent for over 14 minutes), when the header's time sets its target, the card takes a fresh template instead. A
node that gives no template (busy, restarting, another chain) leaves the cards idle until it gives one: no work is redone.

The table (2^26 elements of 512 chained SHA-256s) takes about six seconds to build on a card and is rebuilt every 1,024
blocks. One GA100-class card (CMP 170HX) does 0.3-0.45 billion tries a second (these passive cards throttle when hot: keep
air moving over them); the processor without the table does about 250 a second per core, with it a few million.

Conventions a port must match bit for bit (see `tests/pow.rs` for the vectors): the block id is SHA-256d of the 112-byte
header; the table seed is SHA-256("bitcheque table" ‖ epoch as u32 LE), epoch = height / 1024; element i is
SHA-256(seed ‖ i as u32 LE) hashed 511 more times; the 32 indices are the little-endian u32 words of SHA-256(id ‖ c) for
c = 0..3, each masked to 26 bits; the elements are added as little-endian 256-bit numbers (wrapping); the proof-of-work
hash is SHA-256(id ‖ sum as 32 LE bytes), read little-endian and compared below the compact target in the header's bits.

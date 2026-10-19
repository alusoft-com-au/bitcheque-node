# Bitcheque node

Bitcheque is an experimental proof-of-work blockchain (SHA-256d, 60-second blocks) where coins move with
hand-copied cheques printed offline from a hash-based cheque book (up to 256 cheques, printed as needed). Rust, no dependencies.

- `DESIGN.md`: every rule and parameter, and why.
- `src/`: the node, wallet and RPC (`cargo build --release`, binary `target/release/bitcheque`).
- `tests/`: `cargo test`.
- `wallet-wasm/`: the same Rust book and registration code compiled to WebAssembly for the website:
  `cd wallet-wasm && cargo build --release --target wasm32-unknown-unknown`.
- `edge/`: the edge node, the node's chain, mempool and RPC compiled to WebAssembly and run by Cloudflare
  Durable Objects in three regions (`node-ap`, `node-us`, `node-eu`.bitcheque.org). No sockets and no miner:
  each wakes every minute, pulls new blocks from upstream nodes' RPC, keeps them in SQLite, and forwards
  posted transactions upstream. `edge/build.sh`, then `npx wrangler deploy` in `edge/`.

The official website lives in [bitcheque-website](https://github.com/alusoft-com-au/bitcheque-website); the offline
page for printing more cheques of a book in [bitcheque-print](https://github.com/alusoft-com-au/bitcheque-print).

This is an experimental research network that may change or be reset. MIT licence.

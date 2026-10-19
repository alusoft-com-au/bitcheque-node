# Bitcheque node

Bitcheque is an experimental proof-of-work blockchain (SHA-256d, 60-second blocks) where coins move with
hand-copied cheques printed offline from a hash-based cheque book (up to 256 cheques, printed as needed). Rust, no dependencies.

- `DESIGN.md`: every rule and parameter, and why.
- `src/`: the node, wallet and RPC (`cargo build --release`, binary `target/release/bitcheque`). `bitcheque node`
  joins the research network by following the edge nodes (its seeds) over their HTTP RPC; add `--rpc 0.0.0.0:8732` to
  serve wallets and miners, and `--peer HOST:8731` to also talk TCP to other nodes.
- `tests/`: `cargo test`.
- `wallet-wasm/`: the same Rust book and registration code compiled to WebAssembly for the website:
  `cd wallet-wasm && cargo build --release --target wasm32-unknown-unknown`.
- `edge/`: the edge node, the node's chain, mempool and RPC compiled to WebAssembly and run by Cloudflare
  Durable Objects in three regions (`node-ap`, `node-us`, `node-eu`.bitcheque.org). No sockets and no miner:
  each wakes every minute, pulls new blocks from upstream nodes' RPC, keeps them in SQLite, and forwards
  posted transactions upstream. Each keeps only the last 2,000 block headers in memory (older blocks stay in
  SQLite), so memory stays flat however long the chain grows. `edge/build.sh`, then `npx wrangler deploy` in `edge/`.
  Two more, `node-oc` (Oceania) and `node-sa` (South America), run as their own Workers (`edge/wrangler.oc.jsonc`,
  `edge/wrangler.sa.jsonc`): they follow the three as upstreams through a service binding every 30 seconds and do not
  mine; deploy one with `npx wrangler deploy -c wrangler.oc.jsonc`.

The official website lives in [bitcheque-website](https://github.com/alusoft-com-au/bitcheque-website); the offline
page for printing more cheques of a book in [bitcheque-print](https://github.com/alusoft-com-au/bitcheque-print).

This is an experimental research network that may change or be reset. MIT licence.

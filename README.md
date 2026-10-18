# Bitcheque node

Bitcheque is an experimental proof-of-work blockchain (SHA-256d, 60-second blocks) where coins move with
hand-copied cheques printed once, offline, from a hash-based cheque book. Rust, no dependencies.

- `DESIGN.md`: every rule and parameter, and why.
- `src/`: the node, wallet and RPC (`cargo build --release`, binary `target/release/bitcheque`).
- `tests/`: `cargo test`.
- `wallet-wasm/`: the same Rust book and registration code compiled to WebAssembly for the website:
  `cd wallet-wasm && cargo build --release --target wasm32-unknown-unknown`.

The official website lives in [bitcheque-website](https://github.com/alusoft-com-au/bitcheque-website).

This is an experimental research network that may change or be reset. MIT licence.

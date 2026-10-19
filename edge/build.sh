#!/bin/sh
# Build the edge node's WebAssembly next to worker.js (wrangler bundles it from there).
set -e; cd "$(dirname "$0")"
cargo build --release --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/release/bitcheque_edge.wasm bitcheque_edge.wasm

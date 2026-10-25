#!/bin/sh
# Build the edge node's WebAssembly next to worker.js (wrangler bundles it from there).
set -e; cd "$(dirname "$0")"
# the chain version block 0 names (src/params.rs) and the one this worker resets by must be the same number
v=$(sed -n 's/^pub const CHAIN_VERSION: u32 = \([0-9]*\);.*/\1/p' ../src/params.rs); w=$(sed -n "s/^const CHAIN_VERSION = '\([0-9]*\)';.*/\1/p" worker.js)
[ -n "$v" ] && [ "$v" = "$w" ] || { echo "CHAIN_VERSION differs: src/params.rs '$v', worker.js '$w'"; exit 1; }
cargo build --release --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/release/bitcheque_edge.wasm bitcheque_edge.wasm

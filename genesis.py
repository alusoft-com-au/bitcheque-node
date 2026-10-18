#!/usr/bin/env python3
"""Bitcheque block 0. Deterministic from the parameters in DESIGN.md §12.
Run: python3 genesis.py            -> prints the header fields and hash
     python3 genesis.py --testnet  -> same with testnet parameters
"""
import calendar, hashlib, struct, sys, time

MESSAGE   = b"Bitcheque genesis. Message text and launch timestamp to be set (DESIGN.md 12.4)."
TIMESTAMP = calendar.timegm(time.strptime("2027-01-01 00:00:00", "%Y-%m-%d %H:%M:%S"))  # placeholder launch time, UTC
VERSION   = 1
INITIAL_BITS = {"mainnet": 0x1e00ffff, "testnet": 0x1f00ffff}   # ~2^224 and ~2^240 targets, compact form
REWARD_PAYEE = 0                                                   # account number 0: burned (12.2)

def sha256d(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def target_from_bits(bits):
    exp, mant = bits >> 24, bits & 0xffffff
    return mant << (8 * (exp - 3))

def coinbase_tx(height, payee, message):
    # type 0x00 = coinbase: height u32, payee u32, message (u32 length prefix), as src/tx.rs encodes it
    return b"\x00" + struct.pack("<II", height, payee) + struct.pack("<I", len(message)) + message

def header(prev, txroot, stateroot, t, bits, nonce):
    return struct.pack("<I", VERSION) + prev + txroot + stateroot + struct.pack("<III", t, bits, nonce)

def main():
    net = "testnet" if "--testnet" in sys.argv else "mainnet"
    bits = INITIAL_BITS[net]
    cb = coinbase_tx(0, REWARD_PAYEE, MESSAGE)
    txroot = sha256d(cb)                         # single-tx Merkle tree
    stateroot = bytes(32)                        # empty state
    prev = bytes(32)
    target = target_from_bits(bits)
    nonce = 0
    while True:
        h = header(prev, txroot, stateroot, TIMESTAMP, bits, nonce)
        hsh = sha256d(h)
        if int.from_bytes(hsh, "little") < target: break
        nonce += 1
    print(f"network     {net}")
    print(f"timestamp   {TIMESTAMP}")
    print(f"bits        {bits:#010x}")
    print(f"nonce       {nonce}")
    print(f"coinbase    {cb.hex()}")
    print(f"tx root     {txroot.hex()}")
    print(f"state root  {stateroot.hex()}")
    print(f"header      {h.hex()}")
    print(f"block hash  {hsh[::-1].hex()}")

if __name__ == "__main__":
    main()

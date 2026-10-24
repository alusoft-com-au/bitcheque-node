#!/usr/bin/env python3
"""Bitcheque block 0. Deterministic from the parameters in DESIGN.md §12.
Run: python3 genesis.py            -> prints the header fields and hash (mainnet parameters)
     python3 genesis.py --testnet  -> same with the research network's parameters
The timestamp is the mainnet placeholder; the node's `bitcheque genesis` prints the live research network's block 0.
"""
import calendar, hashlib, struct, sys, time

MESSAGE   = b"Bitcheque genesis. Message text and launch timestamp to be set (DESIGN.md 12.4)."
TIMESTAMP = calendar.timegm(time.strptime("2027-01-01 00:00:00", "%Y-%m-%d %H:%M:%S"))  # placeholder launch time, UTC
HEIGHT    = 0
INITIAL_BITS = {"mainnet": 0x20040000, "testnet": 0x20040000}   # 2^250 targets (about 2^6 tries), compact form
# the proof of work (DESIGN.md 1.1, src/pow.rs): a table of N elements per EPOCH blocks, K of them summed per try
N, K, ROUNDS, EPOCH = 1 << 26, 32, 512, 1024
REWARD_PAYEE = 0                                                   # account number 0: burned (12.2)

def sha256(b): return hashlib.sha256(b).digest()
def sha256d(b): return sha256(sha256(b))

def table_seed(epoch): return sha256(b"bitcheque table" + struct.pack("<I", epoch))

def element(seed, i):
    x = sha256(seed + struct.pack("<I", i))
    for _ in range(ROUNDS - 1): x = sha256(x)
    return x

def pow_hash(block_id, height):
    seed = table_seed(height // EPOCH)
    f = 0
    for c in range(K // 8):
        w = sha256(block_id + bytes([c]))
        for j in range(8):
            f += int.from_bytes(element(seed, struct.unpack_from("<I", w, 4 * j)[0] & (N - 1)), "little")
    return sha256(block_id + (f % 2**256).to_bytes(32, "little"))

def target_from_bits(bits):
    exp, mant = bits >> 24, bits & 0xffffff
    return mant << (8 * (exp - 3))

def coinbase_tx(height, payee, message):
    # type 0x00 = coinbase: height u32, payee u32, message (u32 length prefix), as src/tx.rs encodes it
    return b"\x00" + struct.pack("<II", height, payee) + struct.pack("<I", len(message)) + message

def header(prev, txroot, stateroot, t, bits, nonce):
    return struct.pack("<I", HEIGHT) + prev + txroot + stateroot + struct.pack("<III", t, bits, nonce)

def main():
    net = "testnet" if "--testnet" in sys.argv else "mainnet"
    bits = INITIAL_BITS[net]
    cb = coinbase_tx(0, REWARD_PAYEE, MESSAGE)
    txroot = sha256d(b"\x00" + sha256d(cb))     # single-tx Merkle tree: the leaf, SHA256d(0 || txid)
    stateroot = bytes(32)                        # empty state
    prev = bytes(32)
    target = target_from_bits(bits)
    nonce = 0
    while True:
        h = header(prev, txroot, stateroot, TIMESTAMP, bits, nonce)
        hsh = sha256d(h)
        if int.from_bytes(pow_hash(hsh, HEIGHT), "little") < target: break
        nonce += 1
    print(f"network     {net}")
    print(f"timestamp   {TIMESTAMP}")
    print(f"bits        {bits:#010x}")
    print(f"nonce       {nonce}")
    print(f"coinbase    {cb.hex()}")
    print(f"tx root     {txroot.hex()}")
    print(f"state root  {stateroot.hex()}")
    print(f"header      {h.hex()}")
    print(f"pow hash    {pow_hash(hsh, HEIGHT).hex()}")
    print(f"block hash  {hsh[::-1].hex()}")

if __name__ == "__main__":
    main()

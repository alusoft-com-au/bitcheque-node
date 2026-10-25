// Bitcheque GPU miner (CUDA) for the table proof of work of DESIGN.md §1.1 / src/pow.rs. It holds the 2 GiB table of the
// current epoch on every card and tries nonces (and, past 2^32 of them, the header's time) against templates from any
// node's RPC, the same way `bitcheque mine` does: GET /template/<number>, GET /tip, POST /block. The cards share a
// template's 2^32 nonces; a card that has used its share moves the header's time on by a second (while the chain is not
// in stall relief, when only the node can stamp a time and target that agree; then it takes a fresh template). A found
// block is checked on the processor, without the table, before it is sent. Nothing here is consensus: the node decides.
//
// Build: ./build.sh   (nvcc -O3 -std=c++17 -arch=sm_80; the CUDA toolkit and an NVIDIA driver, nothing else)
// Run:   ./bitcheque-miner --rpc node-ap.bitcheque.org:80 --to NUMBER [--devices 0,2] [--selftest]
#include <cuda_runtime.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>

// ---- the proof of work's constants (src/pow.rs) ----
static const uint32_t N = 1u << 26, K = 32, ROUNDS = 512, EPOCH = 1024;
static const uint32_t TEMPLATE_SECONDS = 20;   // a fresh template this often (new transactions, a fresh time)
static const uint32_t RELIEF_S = 720 + 2 * 60;  // max_future_seconds + two block targets (src/params.rs): a header time past the latest recent
                                               // block's by more may set its own target (stall relief, src/block.rs relieved_bits), so a card moves
                                               // its time on its own only while it stays within RELIEF_S of the parent's
static const uint32_t LAUNCH = 1u << 24;        // nonces per kernel launch (about 40 ms on one card)

#define CK(x) do { cudaError_t e_ = (x); if (e_ != cudaSuccess) { fprintf(stderr, "cuda: %s at %s:%d\n", cudaGetErrorString(e_), __FILE__, __LINE__); exit(2); } } while (0)

// ---- SHA-256, on the card and on the processor (the same code, so the self-test and the check before sending agree) ----
__constant__ uint32_t KD[64];
static const uint32_t KH[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
__host__ __device__ static inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
__host__ __device__ static inline uint32_t bswap(uint32_t x) { return (x >> 24) | ((x >> 8) & 0xff00) | ((x << 8) & 0xff0000) | (x << 24); }
__host__ __device__ static inline const uint32_t* kk() {
#ifdef __CUDA_ARCH__
    return KD;
#else
    return KH;
#endif
}
/// One compression of the 16 big-endian words `w` into state `h`.
__host__ __device__ static void compress(uint32_t h[8], const uint32_t w0[16]) {
    uint32_t w[16];
    for (int i = 0; i < 16; i++) w[i] = w0[i];
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    const uint32_t* k = kk();
#pragma unroll
    for (int i = 0; i < 64; i++) {
        if (i >= 16) {   // the schedule, 16 words at a time
            uint32_t x = w[(i + 1) & 15], y = w[(i + 14) & 15];
            w[i & 15] += (rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)) + w[(i + 9) & 15] + (rotr(y, 17) ^ rotr(y, 19) ^ (y >> 10));
        }
        uint32_t t1 = hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + k[i] + w[i & 15];
        uint32_t t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}
__host__ __device__ static inline void iv(uint32_t h[8]) { h[0] = 0x6a09e667; h[1] = 0xbb67ae85; h[2] = 0x3c6ef372; h[3] = 0xa54ff53a; h[4] = 0x510e527f; h[5] = 0x9b05688c; h[6] = 0x1f83d9ab; h[7] = 0x5be0cd19; }
/// SHA-256 of 32 bytes given as 8 big-endian words (a digest), as 8 big-endian words.
__host__ __device__ static void sha_words32(const uint32_t in[8], uint32_t out[8]) {
    uint32_t w[16] = {in[0], in[1], in[2], in[3], in[4], in[5], in[6], in[7], 0x80000000u, 0, 0, 0, 0, 0, 0, 256};
    iv(out); compress(out, w);
}
/// SHA-256 of a digest followed by one byte `c` (33 bytes).
__host__ __device__ static void sha_words33(const uint32_t in[8], uint32_t c, uint32_t out[8]) {
    uint32_t w[16] = {in[0], in[1], in[2], in[3], in[4], in[5], in[6], in[7], (c << 24) | 0x00800000u, 0, 0, 0, 0, 0, 0, 264};
    iv(out); compress(out, w);
}
/// SHA-256 of a digest followed by a little-endian u32 (36 bytes).
__host__ __device__ static void sha_words36(const uint32_t in[8], uint32_t i, uint32_t out[8]) {
    uint32_t w[16] = {in[0], in[1], in[2], in[3], in[4], in[5], in[6], in[7], bswap(i), 0x80000000u, 0, 0, 0, 0, 0, 288};
    iv(out); compress(out, w);
}
/// SHA-256 of two digests (64 bytes): the second block is padding only.
__host__ __device__ static void sha_words64(const uint32_t a[8], const uint32_t b[8], uint32_t out[8]) {
    uint32_t w[16] = {a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]};
    iv(out); compress(out, w);
    uint32_t p[16] = {0x80000000u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 512};
    compress(out, p);
}
/// Table element `i` of the epoch with `seed`: ROUNDS chained hashes (src/pow.rs element).
__host__ __device__ static void element(const uint32_t seed[8], uint32_t i, uint32_t out[8]) {
    uint32_t x[8]; sha_words36(seed, i, x);
    for (uint32_t r = 1; r < ROUNDS; r++) { uint32_t y[8]; sha_words32(x, y); for (int k = 0; k < 8; k++) x[k] = y[k]; }
    for (int k = 0; k < 8; k++) out[k] = x[k];
}
/// Add a digest, read as a little-endian 256-bit number, to the little-endian limbs `f` (wrapping).
__host__ __device__ static inline void add_le(uint32_t f[8], const uint32_t e[8]) {
    uint64_t carry = 0;
    for (int k = 0; k < 8; k++) { uint64_t s = (uint64_t)f[k] + bswap(e[k]) + carry; f[k] = (uint32_t)s; carry = s >> 32; }
}
/// Elements recomputed from the seed (the node's way; the self-test and the check before sending).
struct Light { const uint32_t* seed; __host__ __device__ void operator()(uint32_t i, uint32_t e[8]) const { element(seed, i, e); } };
/// The proof-of-work hash of block id `id`, `get(i, out)` supplying elements: SHA-256(id ‖ sum of the K elements, LE).
template <class Get> __host__ __device__ static void pow_hash(const uint32_t id[8], const Get& get, uint32_t out[8]) {
    uint32_t f[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    for (uint32_t c = 0; c < K / 8; c++) {
        uint32_t w[8]; sha_words33(id, c, w);
        for (int j = 0; j < 8; j++) { uint32_t e[8]; get(bswap(w[j]) & (N - 1), e); add_le(f, e); }
    }
    uint32_t fw[8]; for (int k = 0; k < 8; k++) fw[k] = bswap(f[k]);   // the sum's little-endian bytes as message words
    sha_words64(id, fw, out);
}
/// True if the hash, read little-endian, is below the target (8 little-endian limbs).
__host__ __device__ static inline bool below(const uint32_t pow[8], const uint32_t target[8]) {
    for (int k = 7; k >= 0; k--) { uint32_t v = bswap(pow[k]); if (v != target[k]) return v < target[k]; }
    return false;
}

// ---- kernels ----
__global__ void build_table(const uint32_t* __restrict__ seed, uint4* __restrict__ table) {
    uint32_t s[8]; for (int k = 0; k < 8; k++) s[k] = seed[k];
    for (uint32_t i = blockIdx.x * blockDim.x + threadIdx.x; i < N; i += gridDim.x * blockDim.x) {
        uint32_t e[8]; element(s, i, e);
        table[2 * (size_t)i] = make_uint4(e[0], e[1], e[2], e[3]); table[2 * (size_t)i + 1] = make_uint4(e[4], e[5], e[6], e[7]);
    }
}
struct Job { uint32_t mid[8]; uint32_t tail[12]; uint32_t target[8]; };   // midstate of header bytes 0..64; bytes 64..112 as words; target limbs
__constant__ Job JOB;
__global__ void __launch_bounds__(256) mine(uint32_t nonce_base, uint32_t time, const uint4* __restrict__ table, uint32_t* __restrict__ found) {
    uint32_t nonce = nonce_base + blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t w[16];
    for (int k = 0; k < 12; k++) w[k] = JOB.tail[k];
    w[9] = bswap(time); w[11] = bswap(nonce); w[12] = 0x80000000u; w[13] = 0; w[14] = 0; w[15] = 896;
    uint32_t h[8]; for (int k = 0; k < 8; k++) h[k] = JOB.mid[k];
    compress(h, w);
    uint32_t id[8]; sha_words32(h, id);   // the block id: SHA-256d of the header
    // pow_hash with the table: eight elements' loads issued together, then summed (the same arithmetic as pow_hash)
    uint32_t f[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    for (uint32_t c = 0; c < K / 8; c++) {
        uint32_t iw[8]; sha_words33(id, c, iw);
        uint4 ea[8], eb[8];
#pragma unroll
        for (int j = 0; j < 8; j++) { size_t at = 2 * (size_t)(bswap(iw[j]) & (N - 1)); ea[j] = __ldg(table + at); eb[j] = __ldg(table + at + 1); }
#pragma unroll
        for (int j = 0; j < 8; j++) { uint32_t e[8] = {ea[j].x, ea[j].y, ea[j].z, ea[j].w, eb[j].x, eb[j].y, eb[j].z, eb[j].w}; add_le(f, e); }
    }
    uint32_t fw[8]; for (int k = 0; k < 8; k++) fw[k] = bswap(f[k]);
    uint32_t pow[8]; sha_words64(id, fw, pow);
    if (below(pow, JOB.target)) { if (atomicCAS(found, 0xFFFFFFFFu, nonce) == 0xFFFFFFFFu) found[1] = time; }
}
__global__ void selftest_kernel(uint32_t* out) {   // elements, indices and hashes the Rust tests fix (tests/pow.rs)
    uint32_t seed0[8], seed1[8], e[8], x[8], id[8];
    uint32_t m0[16] = {0x62697463u, 0x68657175u, 0x65207461u, 0x626c6500u, 0x00000080u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 152};   // "bitcheque table" + epoch 0 LE
    iv(seed0); compress(seed0, m0);
    uint32_t m1[16] = {0x62697463u, 0x68657175u, 0x65207461u, 0x626c6501u, 0x00000080u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 152};   // epoch 1
    iv(seed1); compress(seed1, m1);
    for (int k = 0; k < 8; k++) out[k] = seed0[k];
    element(seed0, 0, e); for (int k = 0; k < 8; k++) out[8 + k] = e[k];
    element(seed1, 12345, e); for (int k = 0; k < 8; k++) out[16 + k] = e[k];
    uint32_t mx[16] = {0x78800000u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8}; iv(id); compress(id, mx);   // sha256("x")
    pow_hash(id, Light{seed0}, x); for (int k = 0; k < 8; k++) out[24 + k] = x[k];
    pow_hash(id, Light{seed1}, x); for (int k = 0; k < 8; k++) out[32 + k] = x[k];
}

// ---- host side ----
static std::string hexs(const uint32_t* w, int n) { static const char* d = "0123456789abcdef"; std::string s; for (int i = 0; i < n; i++) for (int b = 3; b >= 0; b--) { uint32_t v = (w[i] >> (8 * b)) & 0xff; s += d[v >> 4]; s += d[v & 15]; } return s; }
static std::string hexb(const std::vector<uint8_t>& v) { static const char* d = "0123456789abcdef"; std::string s; for (uint8_t b : v) { s += d[b >> 4]; s += d[b & 15]; } return s; }
static bool unhex(const std::string& s, std::vector<uint8_t>& out) {
    out.clear(); if (s.size() % 2) return false;
    auto nib = [](char c) -> int { if (c >= '0' && c <= '9') return c - '0'; if (c >= 'a' && c <= 'f') return c - 'a' + 10; if (c >= 'A' && c <= 'F') return c - 'A' + 10; return -1; };
    for (size_t i = 0; i < s.size(); i += 2) { int a = nib(s[i]), b = nib(s[i + 1]); if (a < 0 || b < 0) return false; out.push_back((uint8_t)(a * 16 + b)); }
    return true;
}
static inline uint32_t le32(const uint8_t* p) { return p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24); }
static inline uint32_t be32(const uint8_t* p) { return ((uint32_t)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]; }
static inline void put_le32(uint8_t* p, uint32_t v) { p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }
/// Bitcoin's compact target as 8 little-endian limbs (src/u256.rs from_compact).
static void target_limbs(uint32_t bits, uint32_t t[8]) {
    uint8_t b[32] = {0}; uint32_t exp = bits >> 24, mant = bits & 0x007FFFFF;
    if (exp <= 3) { uint32_t v = mant >> (8 * (3 - exp)); b[0] = v; b[1] = v >> 8; b[2] = v >> 16; }
    else for (int k = 0; k < 3; k++) { size_t at = exp - 3 + k; if (at < 32) b[at] = (mant >> (8 * k)) & 0xff; }
    for (int k = 0; k < 8; k++) t[k] = le32(b + 4 * k);
}
static bool target_gt(const uint32_t a[8], const uint32_t b[8]) { for (int k = 7; k >= 0; k--) if (a[k] != b[k]) return a[k] > b[k]; return false; }
/// The epoch's table seed: SHA-256("bitcheque table" ‖ epoch LE), as words.
static void table_seed(uint32_t epoch, uint32_t out[8]) {
    uint8_t m[19] = {'b','i','t','c','h','e','q','u','e',' ','t','a','b','l','e'}; put_le32(m + 15, epoch);
    uint32_t w[16] = {0}; uint8_t blk[64] = {0}; memcpy(blk, m, 19); blk[19] = 0x80; blk[62] = 0; blk[63] = 19 * 8;
    for (int k = 0; k < 16; k++) w[k] = be32(blk + 4 * k);
    iv(out); compress(out, w);
}
/// A header's proof-of-work hash without the table (the node's way), for checking a card's find before it is sent.
static void pow_light(const uint8_t header[112], uint32_t out[8]) {
    uint32_t h[8]; iv(h);
    uint32_t w[16]; for (int k = 0; k < 16; k++) w[k] = be32(header + 4 * k); compress(h, w);
    for (int k = 0; k < 12; k++) w[k] = be32(header + 64 + 4 * k); w[12] = 0x80000000u; w[13] = 0; w[14] = 0; w[15] = 896; compress(h, w);
    uint32_t id[8]; sha_words32(h, id);
    uint32_t seed[8]; table_seed(le32(header) / EPOCH, seed);
    pow_hash(id, Light{seed}, out);
}
/// HTTP/1.0 to a node's RPC: the reply body, or "" with `status` set to 0 on a connection failure.
static std::string http(const std::string& host, const std::string& port, const char* method, const std::string& path, const std::string& body, int& status) {
    status = 0;
    addrinfo hints = {}, *res = nullptr; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0) return "";
    int fd = -1;
    for (addrinfo* a = res; a; a = a->ai_next) { fd = socket(a->ai_family, a->ai_socktype, 0); if (fd < 0) continue; timeval tv = {10, 0}; setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv); setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv); if (connect(fd, a->ai_addr, a->ai_addrlen) == 0) break; close(fd); fd = -1; }
    freeaddrinfo(res);
    if (fd < 0) return "";
    std::string req = std::string(method) + " " + path + " HTTP/1.0\r\nHost: " + host + "\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
    size_t sent = 0; while (sent < req.size()) { ssize_t n = send(fd, req.data() + sent, req.size() - sent, 0); if (n <= 0) { close(fd); return ""; } sent += n; }
    std::string reply; char buf[65536]; ssize_t n; while ((n = recv(fd, buf, sizeof buf, 0)) > 0) reply.append(buf, n);
    close(fd);
    if (reply.compare(0, 5, "HTTP/") != 0) return "";
    status = atoi(reply.c_str() + 9);
    size_t at = reply.find("\r\n\r\n"); return at == std::string::npos ? "" : reply.substr(at + 4);
}
struct Template { std::vector<uint8_t> block; uint32_t height = 0, time = 0, bits = 0, parent_time = 0, generation = 0; };   // parent_time 0: unknown (no roll)
static std::mutex g_mu; static Template g_tpl; static std::atomic<bool> g_stop{false};
static std::string g_host, g_port; static uint32_t g_to = 0;

static void selftest() {
    CK(cudaMemcpyToSymbol(KD, KH, sizeof KH));
    uint32_t* d; CK(cudaMalloc(&d, 40 * 4)); selftest_kernel<<<1, 1>>>(d); CK(cudaDeviceSynchronize());
    uint32_t v[40]; CK(cudaMemcpy(v, d, sizeof v, cudaMemcpyDeviceToHost)); CK(cudaFree(d));
    const char* want[5] = {"586ed6dff289102f1527e5648afa39758018f46c7aa76d874d946f8cee510d53", "0a5cfa9ca9dfdc070f30cf50c98222e2ce461364e31e998549bc72eb8276318f",
                           "05ef8b66d9f9d3241c2b66b3470a5f9bc9ef2eaa164a2c7fe30b78e7c19f802b", "9f8f3809e9c27beffacf0ce76f72544d59bb0274ef1d842bff9ec477da368b4f",
                           "6712403938fd011a452e0e3a6d9a7df8d373671e2050f281beed887f5372bd6b"};
    const char* names[5] = {"seed(0)", "element(seed(0), 0)", "element(seed(1), 12345)", "pow(sha256(\"x\"), epoch 0)", "pow(sha256(\"x\"), epoch 1)"};
    bool ok = true;
    for (int k = 0; k < 5; k++) { std::string got = hexs(v + 8 * k, 8); bool same = got == want[k]; ok &= same; printf("%-28s %s %s\n", names[k], got.c_str(), same ? "ok" : "MISMATCH"); }
    // the processor's copy of the code too, and the mainnet block 0 of genesis.py (nonce 60)
    uint32_t s0[8]; table_seed(0, s0); ok &= hexs(s0, 8) == want[0];
    std::vector<uint8_t> g; unhex("000000000000000000000000000000000000000000000000000000000000000000000000da3770257ad9b6b575d76282b4551fe6c5cbed267f7b9109848b970876b826dc000000000000000000000000000000000000000000000000000000000000000080ec366b000004203c000000", g);
    uint32_t p[8]; pow_light(g.data(), p); std::string gp = hexs(p, 8);
    bool gok = gp == "b90c85cd6874ea35cb76009c43cca25dd95fa1d5f7b4da2964e3929241c76100"; ok &= gok;
    printf("%-28s %s %s\n", "block 0 pow (processor)", gp.c_str(), gok ? "ok" : "MISMATCH");
    printf(ok ? "self-test passed\n" : "SELF-TEST FAILED\n"); exit(ok ? 0 : 1);
}
/// Fetch a template; false if the node gave none that can be mined for `to` (with a message), or the same one again.
static bool fetch_template() {
    int st; std::string hex = http(g_host, g_port, "GET", "/template/" + std::to_string(g_to), "", st);
    while (!hex.empty() && (hex.back() == '\n' || hex.back() == '\r')) hex.pop_back();
    std::vector<uint8_t> b;
    if (st != 200 || !unhex(hex, b) || b.size() < 129) { fprintf(stderr, "template: %s\n", st == 0 ? "no answer" : hex.substr(0, 120).c_str()); return false; }
    // the node builds the template: check it pays us and asks for real work (a node, or anyone between, could otherwise
    // have our work pay someone else), as bitcheque mine does
    if (b[120] != 0 || le32(&b[125]) != g_to) { fprintf(stderr, "the node's template pays someone else: use another node\n"); exit(1); }
    uint32_t t[8], easiest[8]; target_limbs(le32(&b[104]), t); target_limbs(0x207FFFFF, easiest);
    if (target_gt(t, easiest)) { fprintf(stderr, "the node's template asks for less work than any block may have: use another node\n"); exit(1); }
    // the parent's time (the latest recent block's is at least it): how far a card may move the header's time on its own
    uint32_t parent_time = 0;
    { int ps; std::string ph = http(g_host, g_port, "GET", "/block/" + std::to_string(le32(&b[0]) - 1), "", ps); std::vector<uint8_t> pb;
      while (!ph.empty() && (ph.back() == '\n' || ph.back() == '\r')) ph.pop_back();
      if (ps == 200 && unhex(ph, pb) && pb.size() >= 112) parent_time = le32(&pb[96]); }
    std::lock_guard<std::mutex> lk(g_mu);
    // the same template again (a cache in front of the node, for a second or two after a block): not fresh, so the cards
    // idle rather than do the same work and send the same block twice; the main thread asks again on its next poll
    if (b == g_tpl.block) return false;
    g_tpl.block = b; g_tpl.height = le32(&b[0]); g_tpl.time = le32(&b[100]); g_tpl.bits = le32(&b[104]); g_tpl.parent_time = parent_time; g_tpl.generation++;
    return true;
}
static std::string tip() { int st; std::string s = http(g_host, g_port, "GET", "/tip", "", st); while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back(); return st == 200 ? s : ""; }

static void device_loop(int dev, uint32_t ordinal, uint32_t ndev, std::atomic<uint64_t>* tries) {
    CK(cudaSetDevice(dev));
    cudaDeviceProp prop; CK(cudaGetDeviceProperties(&prop, dev));
    size_t fr = 0, tot = 0; CK(cudaMemGetInfo(&fr, &tot));
    if (fr < (size_t)N * 32 + (64u << 20)) { fprintf(stderr, "GPU %d (%s): %.1f GiB free, the table needs 2 GiB\n", dev, prop.name, fr / 1073741824.0); return; }
    CK(cudaMemcpyToSymbol(KD, KH, sizeof KH));
    uint4* table; CK(cudaMalloc(&table, (size_t)N * 32));
    uint32_t *found, *dseed; CK(cudaMalloc(&found, 8)); CK(cudaMalloc(&dseed, 32));
    uint32_t table_epoch = 0xFFFFFFFFu, gen = 0;
    const uint64_t share = (1ull << 32) / ndev; const uint32_t first = (uint32_t)(ordinal * share);   // this card's nonces of every template (all 2^32 for one card)
    Template tpl; uint32_t nonce = 0; uint64_t done = 0;   // nonces tried at this header time
    // no fresh template from the node: this one is dropped, and the card idles until the main thread's next (never the same work twice)
    auto fresh = [&] { if (!fetch_template()) tpl.block.clear(); };
    while (!g_stop) {
        { std::lock_guard<std::mutex> lk(g_mu); if (g_tpl.generation != gen) { tpl = g_tpl; gen = tpl.generation; nonce = first; done = 0; } }
        if (tpl.block.empty()) { std::this_thread::sleep_for(std::chrono::milliseconds(100)); continue; }
        uint32_t epoch = tpl.height / EPOCH;
        if (epoch != table_epoch) {
            uint32_t seed[8]; table_seed(epoch, seed); CK(cudaMemcpy(dseed, seed, 32, cudaMemcpyHostToDevice));
            fprintf(stderr, "GPU %d: building the table of epoch %u (blocks %u-%u)...\n", dev, epoch, epoch * EPOCH, (epoch + 1) * EPOCH - 1);
            auto t0 = std::chrono::steady_clock::now();
            build_table<<<prop.multiProcessorCount * 8, 256>>>(dseed, table); CK(cudaDeviceSynchronize());
            // two elements read back and recomputed here: the table on the card is the one the node expects
            for (uint32_t i : {0u, 12345u, N - 1}) { uint32_t got[8], want[8]; CK(cudaMemcpy(got, table + 2 * (size_t)i, 32, cudaMemcpyDeviceToHost)); element(seed, i, want); if (memcmp(got, want, 32)) { fprintf(stderr, "GPU %d: table element %u differs from the processor's: stopping\n", dev, i); exit(2); } }
            fprintf(stderr, "GPU %d: table built in %.1f s\n", dev, std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
            table_epoch = epoch;
        }
        Job job;
        { uint32_t h[8]; iv(h); uint32_t w[16]; for (int k = 0; k < 16; k++) w[k] = be32(&tpl.block[4 * k]); compress(h, w); memcpy(job.mid, h, 32);
          for (int k = 0; k < 12; k++) job.tail[k] = be32(&tpl.block[64 + 4 * k]); target_limbs(tpl.bits, job.target); }
        CK(cudaMemcpyToSymbol(JOB, &job, sizeof job));
        const uint32_t none[2] = {0xFFFFFFFFu, 0};
        // this card's share of the template's nonces, LAUNCH at a time, until the main thread takes a fresh template
        while (!g_stop) {
            { std::lock_guard<std::mutex> lk(g_mu); if (g_tpl.generation != gen) break; }
            if (done >= share) {
                // this card's nonces are used up: the next second of the same template (a block's time may run twelve minutes
                // ahead of the node's clock), unless that second could set its own target (stall relief): then a fresh template
                if (tpl.parent_time && tpl.time + 1 <= tpl.parent_time + RELIEF_S) { tpl.time++; nonce = first; done = 0; }
                else { fresh(); break; }
            }
            CK(cudaMemcpy(found, none, 8, cudaMemcpyHostToDevice));
            mine<<<LAUNCH / 256, 256>>>(nonce, tpl.time, table, found); CK(cudaDeviceSynchronize());
            tries->fetch_add(LAUNCH);
            uint32_t got[2]; CK(cudaMemcpy(got, found, 8, cudaMemcpyDeviceToHost));
            if (got[0] != 0xFFFFFFFFu) {
                std::vector<uint8_t> b = tpl.block; put_le32(&b[100], got[1]); put_le32(&b[108], got[0]);
                uint32_t p[8], t[8]; pow_light(b.data(), p); target_limbs(tpl.bits, t);
                if (!below(p, t)) { fprintf(stderr, "GPU %d: a find the processor does not confirm (nonce %u): not sent\n", dev, got[0]); }
                else {
                    int st; std::string r = http(g_host, g_port, "POST", "/block", hexb(b), st);
                    while (!r.empty() && (r.back() == '\n' || r.back() == '\r')) r.pop_back();
                    if (st == 200 && r == "accepted") fprintf(stderr, "GPU %d: mined block %u (nonce %u)\n", dev, tpl.height, got[0]);
                    else if (st == 200) fprintf(stderr, "GPU %d: block %u found, but another came first (%s)\n", dev, tpl.height, r.c_str());
                    else fprintf(stderr, "GPU %d: block %u refused: %s\n", dev, tpl.height, st == 0 ? "no answer" : r.c_str());
                    fresh();   // a fresh template either way (the tip moved, or this one is no good)
                    break;
                }
            }
            nonce += LAUNCH; done += LAUNCH;
        }
    }
}

int main(int argc, char** argv) {
    std::string rpc, devs; bool self = false;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--rpc" && i + 1 < argc) rpc = argv[++i]; else if (a == "--to" && i + 1 < argc) g_to = strtoul(argv[++i], nullptr, 10);
        else if (a == "--devices" && i + 1 < argc) devs = argv[++i]; else if (a == "--selftest") self = true;
        else { fprintf(stderr, "usage: bitcheque-miner --rpc HOST:PORT --to NUMBER [--devices 0,1,...] [--selftest]\n"); return 1; }
    }
    if (self) selftest();
    if (rpc.empty()) { fprintf(stderr, "--rpc HOST:PORT needed (a node's RPC, e.g. node-ap.bitcheque.org:80)\n"); return 1; }
    size_t colon = rpc.rfind(':'); if (colon == std::string::npos) { fprintf(stderr, "--rpc wants HOST:PORT\n"); return 1; }
    g_host = rpc.substr(0, colon); g_port = rpc.substr(colon + 1);
    int count = 0; CK(cudaGetDeviceCount(&count));
    std::vector<int> use;
    if (devs.empty()) for (int d = 0; d < count; d++) use.push_back(d);
    else { size_t at = 0; while (at < devs.size()) { size_t e = devs.find(',', at); if (e == std::string::npos) e = devs.size(); int d = atoi(devs.substr(at, e - at).c_str()); if (d < 0 || d >= count) { fprintf(stderr, "no GPU %d\n", d); return 1; } use.push_back(d); at = e + 1; } }
    if (use.empty()) { fprintf(stderr, "no CUDA device\n"); return 1; }
    // no template yet (the node is down, restarting, or the account is not registered yet): asked again every few seconds,
    // as `bitcheque mine` does; the message above says why
    while (!fetch_template() && !g_stop) std::this_thread::sleep_for(std::chrono::seconds(5));
    if (g_stop) return 0;
    fprintf(stderr, "mining for account %u on %zu GPU(s) against %s (next block %u, epoch %u)\n", g_to, use.size(), rpc.c_str(), g_tpl.height, g_tpl.height / EPOCH);
    std::vector<std::atomic<uint64_t>> tries(use.size()); for (auto& t : tries) t = 0;
    std::vector<std::thread> threads;
    for (size_t k = 0; k < use.size(); k++) threads.emplace_back(device_loop, use[k], (uint32_t)k, (uint32_t)use.size(), &tries[k]);
    // the template is replaced when the tip moves and every TEMPLATE_SECONDS anyway
    std::string last_tip = tip(); auto fetched = std::chrono::steady_clock::now(), reported = fetched; std::vector<uint64_t> seen(use.size(), 0);
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        std::string t = tip(); auto now = std::chrono::steady_clock::now();
        if ((!t.empty() && t != last_tip) || now - fetched > std::chrono::seconds(TEMPLATE_SECONDS)) { if (fetch_template()) { fetched = now; if (!t.empty()) last_tip = t; } }
        if (now - reported > std::chrono::seconds(30)) {
            double secs = std::chrono::duration<double>(now - reported).count(); std::string line = "rate:";
            for (size_t k = 0; k < use.size(); k++) { uint64_t n = tries[k].load(); line += " GPU " + std::to_string(use[k]) + " " + std::to_string((long)((n - seen[k]) / secs / 1e6)) + " MH/s"; seen[k] = n; }
            fprintf(stderr, "%s\n", line.c_str()); reported = now;
        }
    }
}

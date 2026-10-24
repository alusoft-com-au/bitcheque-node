// Bitcheque edge node: three Durable Objects (one per region) running the node's own chain code
// (bitcheque_edge.wasm, built from edge/src) with no sockets. Miners anywhere fetch GET /template/<number>
// and send mined blocks to POST /block; transactions arrive at POST /tx. Whatever one region accepts it
// passes straight to the others (and to any upstream nodes); each also wakes every minute and pulls what
// it missed (GET /height, GET /block/<n>). Blocks live in its SQLite database. Cost: it sleeps between
// wakes (no duration billed). The regions in MINE_REGIONS are also backup miners: when no block has come for
// QUIET_S (the first region), QUIET_S + FALLBACK_S (the second) and so on, one mines for up to MINE_MS at the
// current target, paying the account whose id is MINER_ID (hex; nobody while it has no final number). Changing
// CHAIN_VERSION wipes every region's database once, on its next wake: a network reset. Peers prove themselves to each
// other with the secret EDGE_SECRET (wrangler secret) in X-Edge-Peer and name their chain version in X-Edge-Chain (a
// peer on another one, such as an old node after a reset, is neither pulled from nor pushed to); without the secret
// nobody is a peer. The public's requests are rate limited per address (RL; RL_HEAVY too for /check, /tx and /template,
// where a registration in a /tx counts once more), and all of a region's together (RL_REGION, keyed by the region), in
// two tiers: each address's first RL_FAIR requests a minute draw on a pool of their own (see `limited`). Posts (/tx,
// /block, /check) have budgets of their own, so a flood of reads never starves them.
import { DurableObject } from 'cloudflare:workers';
import WASM from './bitcheque_edge.wasm';

const REGIONS = { ap: 'apac', us: 'enam', eu: 'weur' };   // node-<key>.bitcheque.org -> location hint
// a deployment may run other regions (env REGIONS, JSON like {"oc":"oc"}): a further node that follows these as upstreams
const regions = env => env.REGIONS ? JSON.parse(env.REGIONS) : REGIONS;
const SYNC_MS = 60_000;          // between wakes (env SYNC_S overrides, in seconds: the follower nodes use 180)
const SNAP_EVERY = 100;          // blocks between state snapshots (a cold start replays fewer than this)
const MAX_PER_WAKE = 500;        // blocks fetched in one wake
const HDR_CHUNK = 100;           // headers per database row (a cold start reads ~20 rows; a new block rewrites one of 11 KB)
const HDR_KEEP = 2000;           // headers handed to the node on a cold start (it keeps this many: store::HOST_KEEP)
const PART = 1_000_000;          // snapshot bytes per row (rows hold at most 2 MB)
const QUIET_S = 50;              // the backup miner mines when no block has come for this long: with nobody else
                                 // mining it finds one each wake, about one a minute (the block target)
const MINE_MS = 4000;            // at most this long per wake (the floor is ~2^8 tries, each ~16,000 hashes without the
                                 // table, src/pow.rs: about two seconds here)
const MINE_TRIES = 50;           // nonces per call into the wasm, between clock checks (~0.3 s)
const RETRY_MS = 10_000;         // a quiet wake that mined nothing tries again after this, not after SYNC_MS
const CHAIN_VERSION = '12';        // bump to reset the network: each region forgets its chain and starts from block 0
const FALLBACK_S = 120;          // each further region in MINE_REGIONS waits this much longer (if the first is down)
const RERELAY_MAX = 50;          // waiting transactions offered again to each other region per wake
const RERELAY_TIMES = 2;         // ...each only if the public sent it here, after it waited a wake, and at most this often
const POOL_MAX = 1000;           // waiting transactions kept in the database across unloads (all offered again on load)
const POOL_BYTES = 16 << 20;     // ...and at most this many bytes of them (past either, the newest rows of whoever holds most go)
const BODY_MAX = 4 << 20;        // request body bytes (16 registrations of 16 cheques and a cheque are under 2 MB of hex)
const ROW_MAX = 1_900_000;       // a SQLite row holds at most 2 MB: a bigger pool batch is kept a line per row
const PEER_MS = 10_000;          // a peer that has not answered by then is given up on
const BUSY_MS = 30_000;          // ...and left alone this long (it may only be busy)
const DOWN_MS = 180_000;         // one on another chain version (it said so: its X-Edge-Chain, or a 409) is left alone this long
const SKIP_MS = 600_000;         // an upstream that sent a refused block, or nothing that moved the chain, is not pulled from this long
const START_TRIES = 5;           // starts again after a stored block or waiting transaction trapped the node (it is dropped)
const FRESH = new Set(['height', 'tip', 'template']);   // miners and the status page need these nearly fresh
const FRESH_S = 2;               // ...but a short cache still collapses a flood of them into one request per colo
const CACHE_S = 15;              // seconds the front worker caches a GET reply (status pages poll every 10 s)
// the RPC's paths, spelt one way only (numbers without sign or leading zeros, ids of the right length, no trailing slash:
// /proof/7, /proof/07 and /proof/+7 would be three cache keys). Anything else is refused here, without waking a Durable Object.
const N = '(?:0|[1-9]\\d{0,9})', ID = '[0-9a-f]{34}(?:[0-9a-f]{32})?';
const GETS = new RegExp(`^/(?:height|peers|addrs|tip|regtarget|stats|mempool|edge|top(?:/${N})?|(?:block|summary|account|proof|history|sends|template)/${N}|(?:id|queued)/${ID}|lookup/[0-9a-f]{8,64}|commits/${ID}/${N})$`);
const POSTS = /^\/(?:tx|check|block)$/;
const HEAVY = /^\/(?:check$|tx$|block$|template\/)/;   // the public's costlier requests: RL_HEAVY's lower limit applies too
const TOP_MAX = 200;             // the most accounts /top/N lists (rpc.rs)
const TX_REGS = 16;              // registrations taken from one of the public's /tx (a whole book: 16 batches of 16, sent with
                                 // cheque 0); the rest of its registrations are answered 429, to be sent again
const STATE_MAX = 40 << 20;      // past this many bytes of serialized state (the last snapshot, plus registrations taken since)
const MEM_MAX = 88 << 20;        // ...or of wasm memory, no new registration is taken (503 "edge full"): a Durable Object has
                                 // 128 MB in all, and a snapshot is serialized beside the live state (so ~2x it at the peak)
const CORS = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' };
// every reply: plain text, never sniffed as anything else, loading nothing; and the chain version this node is on
const HDRS = { ...CORS, 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'none'", 'X-Edge-Chain': CHAIN_VERSION };
const enc = new TextEncoder(), dec = new TextDecoder();
const timeout = (p, ms) => Promise.race([p, new Promise((_, no) => setTimeout(() => no(new Error('timeout')), ms))]);
// the peer secret; without one nobody counts as a peer and no peer is called (said once per isolate)
let unset = false;
const secret = env => { if (!env.EDGE_SECRET && !unset) { unset = true; console.error('EDGE_SECRET is not set: nobody is a peer and no peer is called'); } return env.EDGE_SECRET || ''; };
const isPeer = (env, v) => { const s = enc.encode(secret(env)), g = enc.encode(v || ''); return s.length > 0 && g.length === s.length && crypto.subtle.timingSafeEqual(g, s); };
// the body, refused (null) past `max` bytes: by its Content-Length at once, else while it streams in
async function readBody(req, max = BODY_MAX) {
  if (+(req.headers.get('content-length') || 0) > max) return null;
  if (!req.body) return '';
  const parts = [], rd = req.body.getReader(); let n = 0;
  for (;;) { const { done, value } = await rd.read(); if (done) break; n += value.length; if (n > max) { rd.cancel(); return null; } parts.push(value); }
  const all = new Uint8Array(n); let o = 0; for (const p of parts) { all.set(p, o); o += p.length; }
  return dec.decode(all);
}
// the rate-limit key: an IPv4 address, or the /48 of an IPv6 one (one machine has a whole /64, and anyone can get a /48),
// spelt one way only: lowercase, :: expanded, each group four digits (2001:DB8::1, 2001:db8:0:0::1 and 2001:0db8::1 are
// one key). An IPv4-mapped address (::ffff:1.2.3.4, or in hex) is that IPv4 address. Anything unparsable is its own key.
const limitKey = ip => {
  ip = ip.trim().toLowerCase().replace(/%.*$/, '');   // a zone id (fe80::1%eth0) is no part of the address
  if (!ip.includes(':')) return ip;
  const v4 = ip.match(/^(.*:)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);   // a dotted tail is the last two groups
  if (v4) ip = v4[1] + ((v4[2] << 8 | v4[3]) & 0xffff).toString(16) + ':' + ((v4[4] << 8 | v4[5]) & 0xffff).toString(16);
  const halves = ip.split('::'); if (halves.length > 2) return ip;
  const l = halves[0] ? halves[0].split(':') : [], r = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const g = [...l, ...Array(Math.max(0, 8 - l.length - r.length)).fill('0'), ...r].map(x => x.padStart(4, '0'));
  if (g.length !== 8 || (halves.length === 1 && l.length !== 8) || !g.every(x => /^[0-9a-f]{4}$/.test(x))) return ip;
  if (g.slice(0, 5).every(x => x === '0000') && g[5] === 'ffff') return [g[6].slice(0, 2), g[6].slice(2), g[7].slice(0, 2), g[7].slice(2)].map(x => parseInt(x, 16)).join('.');
  return g.slice(0, 3).join(':') + '::/48';
};
const text = (body, status = 200, extra = {}) => new Response(body, { status, headers: { 'Content-Type': 'text/plain; charset=utf-8', ...HDRS, ...extra } });
const unhex = s => { s = s.trim(); if (!/^([0-9a-f]{2})*$/i.test(s)) return null; const b = new Uint8Array(s.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(s.substr(2 * i, 2), 16); return b; };
const hashOf = s => s.match(/^hash ([0-9a-f]+)$/m)?.[1];
const linesOf = s => s.split('\n').map(l => l.trim()).filter(Boolean);   // a /tx body's transactions, as the RPC reads them
const isReg = l => /^0[12]/.test(l);   // a registration (its tag, 1 or 2, is its first byte)
// the answer to all of a /tx body's lines when only `kept` (their indices) went to the node, which answered `reply` (one
// line each, or for one line alone its single answer); the rest are answered `why`
const merge = (all, kept, reply, why) => { const rs = kept.length === 1 ? [reply.trim()] : reply.trim().split('\n'), m = new Map(kept.map((i, k) => [i, rs[k] ?? '']));
  return all.map((_, i) => m.has(i) ? m.get(i) : why).join('\n'); };
const FULL = 'edge full: this node takes no new registrations for now (its state is at its limit); try another node, or again later';

export class EdgeNode extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec(`CREATE TABLE IF NOT EXISTS blocks (h INTEGER PRIMARY KEY, data BLOB NOT NULL);
                   CREATE TABLE IF NOT EXISTS hdr (chunk INTEGER PRIMARY KEY, data BLOB NOT NULL);
                   CREATE TABLE IF NOT EXISTS snap (part INTEGER PRIMARY KEY, data BLOB NOT NULL);
                   CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
                   CREATE TABLE IF NOT EXISTS pool (id INTEGER PRIMARY KEY AUTOINCREMENT, tx TEXT NOT NULL UNIQUE, own INTEGER NOT NULL DEFAULT 0, age INTEGER NOT NULL DEFAULT 0, src TEXT NOT NULL DEFAULT '')`);
    this.x = null; this.ready = false; this.starting = null; this.replaying = false;
    this.relayed = Promise.resolve();   // forwards go out one after another, in the order they were accepted
    this.pushed = 0;                    // when a block sent here last moved the chain
    this.pool = null;                   // the pool's rows and bytes, at most (poolTrim)
    this.from = null;                   // a peer that pushed a block on a branch we do not have: the next wake pulls from it first
    this.state = 0;                     // bytes of serialized state: the last snapshot's, plus registrations taken since (full)
    if (this.meta('chain_version') !== CHAIN_VERSION) {   // a network reset: start again from block 0
      this.sql.exec('DELETE FROM blocks; DELETE FROM hdr; DELETE FROM snap; DELETE FROM pool');
      this.sql.exec('DELETE FROM meta WHERE k != ?', 'region');   // keep the region: an alarm may wake it before any request
      this.meta('chain_version', CHAIN_VERSION);
    }
    this.down = JSON.parse(this.meta('down') || '{}');   // peer -> until when it is left alone (ms)
  }
  meta(k, v) { if (v === undefined) return this.sql.exec('SELECT v FROM meta WHERE k = ?', k).toArray()[0]?.v; this.sql.exec('INSERT OR REPLACE INTO meta VALUES (?, ?)', k, String(v)); }
  put(b) { const p = this.x.io_reserve(b.length); new Uint8Array(this.x.memory.buffer, p, b.length).set(b); }
  out(n) { return dec.decode(new Uint8Array(this.x.memory.buffer, this.x.io_ptr(), n)); }
  now() { this.x.set_now(Math.floor(Date.now() / 1000)); }
  every() { return this.env.SYNC_S ? +this.env.SYNC_S * 1000 : SYNC_MS; }

  // ---- the wasm node and its storage ----
  async node() {
    if (this.ready) return this.x;
    if (!this.starting) this.starting = this.start().finally(() => { this.starting = null; });
    return this.starting;
  }
  // the instance is published (this.x) only once it has fully started; a failure leaves nothing half-made behind
  async start(tries = START_TRIES) {
    this.ready = false;
    // the callbacks use their own instance (x), not this.x: that may be a newer one by the time they run
    let x;
    const bytes = (p, n) => new Uint8Array(x.memory.buffer, p, n).slice(), view = (p, n) => new Uint8Array(x.memory.buffer, p, n);
    const env = {
      host_get: h => { const r = this.sql.exec('SELECT data FROM blocks WHERE h = ?', h).toArray()[0]; if (!r) return 0;
                       const b = new Uint8Array(r.data), p = x.buf_reserve(b.length); new Uint8Array(x.memory.buffer, p, b.length).set(b); return b.length; },
      // a replayed block is stored already: nothing to write
      host_put: (h, p, n) => { if (this.replaying) return; const b = bytes(p, n); this.sql.exec('INSERT OR REPLACE INTO blocks VALUES (?, ?)', h, b); this.header(h, b.subarray(0, 112)); },
      // nor while replaying: the snapshot was taken when the block first came (if that was lost, the next one is at
      // most SNAP_EVERY blocks on, and a cold start replays from the one before). Stored straight from wasm memory, a
      // part at a time (no copy of the whole: it may be tens of MB, beside the state it was serialized from)
      host_snap: (p, n) => { this.state = n; if (this.replaying) return; this.sql.exec('DELETE FROM snap');
                             for (let i = 0; i * PART < n; i++) this.sql.exec('INSERT INTO snap VALUES (?, ?)', i, view(p + i * PART, Math.min(PART, n - i * PART))); },
    };
    x = this.x = (await WebAssembly.instantiate(WASM, { env })).exports;
    let at = null;   // the stored block ({ h }) or pool row ({ id }) being fed in
    try {
    this.now();
    // restore: the snapshot, the headers up to it, then every stored block above it. The snapshot goes straight into the
    // node's input buffer a row at a time (not gathered in JavaScript first: that was three more copies of it)
    const sn = this.sql.exec('SELECT COALESCE(SUM(length(data)), 0) AS n FROM snap').toArray()[0].n;
    const top = sn >= 8 ? new Uint8Array(this.sql.exec('SELECT substr(data, 1, 8) AS d FROM snap WHERE part = 0').toArray()[0]?.d ?? new ArrayBuffer(0)) : null;
    const sh = top?.length === 8 ? new DataView(top.buffer, top.byteOffset).getUint32(4, true) : 0;
    const hdr = this.headers(sh, HDR_KEEP);
    const io = x.io_reserve(4 + sn + hdr.length), mem = new Uint8Array(x.memory.buffer);   // after the reserve: it may grow memory
    new DataView(x.memory.buffer).setUint32(io, sn, true);
    let o = io + 4; for (const r of this.sql.exec('SELECT data FROM snap ORDER BY part')) { const d = new Uint8Array(r.data); mem.set(d, o); o += d.length; }
    mem.set(hdr, io + 4 + sn); this.state = sn;
    if (!x.open(+(this.env.NET ?? 0), SNAP_EVERY)) throw new Error('edge node failed to start');
    this.replaying = true;
    for (const r of this.sql.exec('SELECT h, data FROM blocks WHERE h > ? ORDER BY h', x.height())) { at = { h: r.h }; this.put(new Uint8Array(r.data)); this.now(); if (x.add_block() !== 1) break; }
    this.replaying = false;
    this.trim();
    // the mempool: Cloudflare unloads an idle object between wakes, so waiting transactions are kept in the database
    // and offered again, oldest first. One the chain now refuses (mined, or no longer valid) is dropped.
    // A row may hold a batch (one transaction per line, sent together so they share a block): it is offered again
    // as a batch, and kept while any of it is still accepted. Within its limits first (an older version kept more).
    this.poolTrim();
    for (const r of this.sql.exec('SELECT id, tx FROM pool ORDER BY id')) {   // a row at a time, not all of them at once
      at = { id: r.id };
      const [code, why] = this.rpc('POST', '/tx', r.tx);
      for (const l of linesOf(r.tx)) if (isReg(l)) this.state += l.length / 2;
      const live = why.trim().split('\n').some(x => x === 'ok' || x === 'already in mempool');
      if (!(code === 200 && live) && why.trim() !== 'already in mempool') this.sql.exec('DELETE FROM pool WHERE id = ?', r.id);
    }
    } catch (e) {
      this.x = null; this.replaying = false;
      // a stored block or waiting transaction that traps the node would fail every start: drop it (a block, and every
      // one stored above it) and start again
      if (!(e instanceof WebAssembly.RuntimeError) || !at || tries < 1) throw e;
      console.error(`edge node start: ${at.h ? 'block ' + at.h : 'pool row ' + at.id} trapped (${e.message}): dropped`);
      if (at.h) this.sql.exec('DELETE FROM blocks WHERE h >= ?', at.h); else this.sql.exec('DELETE FROM pool WHERE id = ?', at.id);
      return this.start(tries - 1);
    }
    this.ready = true;
    return x;
  }
  // any exception out of the wasm (a trap, or a host callback's error unwinding through it with a lock held) leaves
  // its state unusable: drop the instance so the next call starts a fresh one from the database
  guard(f) { try { return f(); } catch (e) { this.x = null; this.ready = false; throw e; } }
  header(h, b) {   // keep block h's header in its chunk row
    const c = Math.floor((h - 1) / HDR_CHUNK), at = ((h - 1) % HDR_CHUNK) * 112;
    const old = this.sql.exec('SELECT data FROM hdr WHERE chunk = ?', c).toArray()[0];
    const row = new Uint8Array(Math.max(old ? old.data.byteLength : 0, at + 112));
    if (old) row.set(new Uint8Array(old.data)); row.set(b, at);
    this.sql.exec('INSERT OR REPLACE INTO hdr VALUES (?, ?)', c, row);
  }
  headers(k, n) {  // the headers of the last n blocks up to k (blocks max(1, k-n+1) ..= k), concatenated
    if (k < 1) return new Uint8Array(0);
    const from = Math.max(1, k - n + 1), out = new Uint8Array((k - from + 1) * 112);
    for (const r of this.sql.exec('SELECT chunk, data FROM hdr WHERE chunk >= ? AND chunk <= ? ORDER BY chunk', Math.floor((from - 1) / HDR_CHUNK), Math.floor((k - 1) / HDR_CHUNK))) {
      const d = new Uint8Array(r.data), at = (r.chunk * HDR_CHUNK - (from - 1)) * 112;   // where this row starts, relative to block `from`
      const src = Math.max(0, -at), dst = Math.max(0, at), len = Math.min(d.length - src, out.length - dst);
      if (len > 0) out.set(d.subarray(src, src + len), dst);
    }
    return out;
  }
  trim() {         // after a reorg onto a shorter branch: forget blocks (and header rows wholly) above the tip
    const h = this.x.height();
    this.sql.exec('DELETE FROM blocks WHERE h > ?', h);
    this.sql.exec('DELETE FROM hdr WHERE chunk > ?', Math.floor((h - 1) / HDR_CHUNK));
  }
  // the pool within POOL_MAX rows and POOL_BYTES bytes. Past either, rows go from the sender (src) holding the largest
  // share of them (of rows or of bytes, whichever is the larger fraction of its limit), its newest first: a flood of cheap
  // valid transactions pushes out only its own, not everyone else's older ones (nor what the flood's own early rows
  // depend on). this.pool is an upper bound on its size (inserts add to it, deletes do not take away; null: not counted
  // yet): only past a limit are the rows counted again
  poolTrim() {
    if (this.pool && this.pool.n <= POOL_MAX && this.pool.bytes <= POOL_BYTES) return;
    let n = 0, bytes = 0; const by = new Map(), cut = [];   // src -> { n, bytes, rows: [[id, len]] oldest first }
    for (const r of this.sql.exec('SELECT id, src, length(tx) AS len FROM pool ORDER BY id')) {
      const s = by.get(r.src) || by.set(r.src, { n: 0, bytes: 0, rows: [] }).get(r.src); s.n++; s.bytes += r.len; s.rows.push([r.id, r.len]); n++; bytes += r.len; }
    const share = s => Math.max(s.n / POOL_MAX, s.bytes / POOL_BYTES);
    while (n > POOL_MAX || bytes > POOL_BYTES) {
      let top = null; for (const s of by.values()) if (s.n && (!top || share(s) > share(top))) top = s;
      const [id, len] = top.rows.pop(); top.n--; top.bytes -= len; n--; bytes -= len; cut.push(id);
    }
    for (let i = 0; i < cut.length; i += 100) { const ids = cut.slice(i, i + 100); this.sql.exec(`DELETE FROM pool WHERE id IN (${ids.map(() => '?').join(',')})`, ...ids); }
    this.pool = { n, bytes };
  }
  // no new registration is taken past STATE_MAX bytes of state or MEM_MAX of wasm memory (blocks still are: that is consensus)
  full() { return this.state > STATE_MAX || !!this.x && this.x.memory.buffer.byteLength > MEM_MAX; }
  add(b) { return this.guard(() => { this.put(b); this.now(); const r = this.x.add_block(); return r ? { r } : { r, why: this.out(this.x.io_len()) }; }); }
  rpc(method, path, body = '') { return this.guard(() => { this.put(enc.encode(`${method} ${path}\n${body}`)); this.now(); const s = this.out(this.x.rpc()); const i = s.indexOf('\n'); return [+s.slice(0, i), s.slice(i + 1)]; }); }

  // ---- upstreams: other nodes' RPC ("https://host"), or another region ("do:eu"); never this object itself ----
  upstreams() {
    const list = (this.env.UPSTREAMS || '').split(',').map(s => s.trim()).filter(Boolean);
    return [...Object.keys(regions(this.env)).filter(r => !this.ctx.id.equals(this.env.NODE.idFromName(r))).map(r => 'do:' + r), ...list];
  }
  leave(up, ms) { this.down[up] = Date.now() + ms; this.meta('down', JSON.stringify(this.down)); }
  // a peer in this Worker ("do:eu", made in its own region if this call creates it), or another node's RPC ("https://host"),
  // reached through the service binding SERVICES names for its host (a Worker may not fetch another on its own zone).
  // X-Edge-Peer tells it not to pass this on, X-Edge-From who sent it (and X-Edge-Src, extra, whose transactions they
  // are). A peer on another chain says so (an X-Edge-Chain not ours, or a 409): left alone for DOWN_MS. Anything else that
  // fails is left alone for BUSY_MS: a timeout, a network error, or a reply with no X-Edge-Chain at all (a 5xx from Cloudflare
  // or the service binding is no node's answer: it may only be busy, and a pull a moment later should not be blocked).
  // With no binding for its host (and not on this machine) it is not called: the secret never crosses the public internet.
  async call(up, path, init, extra = {}) {
    if (!secret(this.env)) throw new Error('no EDGE_SECRET');
    if ((this.down[up] || 0) > Date.now()) throw new Error('left alone for now');
    const via = up.startsWith('do:') ? null : this.env[JSON.parse(this.env.SERVICES || '{}')[new URL(up).host]]
      || (/^http:\/\/(?:localhost|127\.0\.0\.1)[:/]/.test(up + '/') ? globalThis : null);   // wrangler dev with a local devnet node
    if (!up.startsWith('do:') && !via) throw new Error(`${up}: no service binding`);
    const peer = { ...init, headers: { ...extra, 'X-Edge-Peer': this.env.EDGE_SECRET, 'X-Edge-Chain': CHAIN_VERSION, 'X-Edge-From': this.meta('region') || '' } };
    let r, t, ms = BUSY_MS;
    try {
      if (up.startsWith('do:')) { const g = up.slice(3);
        r = await timeout(this.env.NODE.get(this.env.NODE.idFromName(g), { locationHint: regions(this.env)[g] }).fetch(`https://edge${path}?region=${g}`, peer), PEER_MS); }
      else r = await via.fetch(up.replace(/\/$/, '') + path, { ...peer, signal: AbortSignal.timeout(PEER_MS) });
      const chain = r.headers.get('X-Edge-Chain');
      if (r.status === 409 || chain !== null && chain !== CHAIN_VERSION) { ms = DOWN_MS; throw new Error(`${up}: chain version ${chain} (${r.status})`); }
      if (chain === null) throw new Error(`${up}${path}: ${r.status}, not a node's reply`);
      t = await timeout(r.text(), PEER_MS);
    } catch (e) { this.leave(up, ms); throw e; }
    if (!r.ok) throw new Error(`${up}${path}: ${r.status}`);
    return t;
  }
  // the highest height at or below `top` where `up`'s chain and ours hold the same block: step back 1, 2, 4... until they
  // agree, then halve the gap. Each step compares block hashes from /summary (ours from our own database).
  async fork(up, top) {
    const same = async h => { if (h < 1) return true; const m = hashOf(this.rpc('GET', `/summary/${h}`)[1]); return !!m && m === hashOf(await this.call(up, `/summary/${h}`)); };
    let bad = top + 1, good = top, step = 1;
    while (!(await same(good))) { bad = good; good = Math.max(0, good - step); step *= 2; }
    while (bad - good > 1) { const m = (good + bad) >> 1; if (await same(m)) good = m; else bad = m; }
    return good;
  }
  // -> { rose: the height went up, fetched: blocks fetched }
  async sync() {
    const x = await this.node(), h0 = x.height(), every = this.every();
    let fetched = 0, log = [];
    // one source per wake: peers in order, stopping at the first that is not behind us (pushes do the real work;
    // this catches whatever a push missed). None while pushes keep the chain moving, unless a peer pushed a block on a
    // branch we do not have (this.from): then that peer first, whatever its height.
    this.now();
    const from = this.from; this.from = null;
    const pushed = !from && Date.now() - this.pushed < every && x.quiet() * 1000 < 2 * every;
    const ups = this.upstreams(); if (from) ups.sort((a, b) => (b === from) - (a === from));
    for (const up of pushed ? [] : ups) {
      if (!this.ready || fetched >= MAX_PER_WAKE) break;   // a block trapped the node (it starts afresh below), or enough for one wake
      if ((this.down[up] || 0) > Date.now()) { log.push({ up, skipped: true }); continue; }
      try {
        const theirs = +(await this.call(up, '/height')), mine = this.x.height();
        if (!Number.isInteger(theirs)) throw new Error('bad height');
        // heights alone do not tell which chain has more work: at the same height (or from the peer that pushed a block on
        // another branch) a different tip is followed back to where the chains part, and their branch fetched from there
        // (the node takes it only if it has more work)
        const split = (theirs === mine || up === from) && mine > 0 && theirs > 0 && (await this.call(up, '/tip')).trim() !== this.rpc('GET', '/tip')[1].trim();
        if (theirs < mine && !split) { log.push({ up, ok: true, height: theirs, behind: true }); continue; }
        let h = mine + 1, forked = false;
        if (split) { forked = true; h = await this.fork(up, Math.min(theirs, mine)) + 1; }
        while (h <= theirs && fetched < MAX_PER_WAKE) {
          const b = unhex(await this.call(up, `/block/${h}`)); fetched++;
          const a = b ? this.add(b) : { r: 0, why: 'bad hex' };
          // the tip moved (1: extended or reorganised): carry on above it; a side block (3) or one we had (2): from h + 1
          if (a.r === 1) { h = this.x.height() + 1; continue; }
          if (a.r) { h++; continue; }
          // a fork: fetch their branch from where we agree
          if (a.why === 'prev unknown' && !forked && h > 1) { forked = true; h = await this.fork(up, h - 1) + 1; continue; }
          this.leave(up, SKIP_MS);
          throw new Error(`block ${h} refused: ${a.why}`);
        }
        this.trim();
        log.push({ up, ok: true, height: theirs });
        // taller, yet nothing it sent moved our chain (blocks we had, or a branch with less work): leave it be a while, try the next
        if (theirs <= mine || this.x.height() > mine) break;
        this.leave(up, SKIP_MS);
      } catch (e) { log.push({ up, ok: false, error: String(e.message || e) }); }
    }
    const y = await this.node();
    this.meta('last_sync', JSON.stringify({ at: new Date().toISOString(), height: y.height(), fetched, pushed, log }));
    const rose = y.height() > h0;
    await this.rerelay();
    return { rose, fetched };
  }
  // ---- the backup miner: so the chain never stalls for want of miners. Only the regions in MINE_REGIONS, only
  // after QUIET_S without a block (later regions wait longer, so they step in only if the first is down);
  // real miners keep the tip fresh, so it stays idle while anyone else is mining ----
  async backup() {
    const x = this.x;
    const rank = (this.env.MINE_REGIONS || '').split(',').map(s => s.trim()).indexOf(this.meta('region'));
    if (rank < 0) return;
    this.now(); if (x.quiet() < QUIET_S + rank * FALLBACK_S) return;
    // the payee is pinned by account id, not number: a number goes to whoever registers first after a reset (or
    // takes it over once it expires), an id only to the holder of that book. No final number yet: mine to nobody.
    const [code, acct] = this.env.MINER_ID ? this.rpc('GET', '/id/' + this.env.MINER_ID) : [0, ''];
    let payee = code === 200 ? +(acct.match(/^number (\d+)$/m)?.[1] || 0) : 0, start = (Math.random() * 2 ** 32) >>> 0;
    const end = Date.now() + MINE_MS, note = o => this.meta('last_mined', JSON.stringify({ at: new Date().toISOString(), height: x.height(), payee, ...o }));
    while (Date.now() < end) {
      this.now();
      const r = this.guard(() => x.mine(payee, start, MINE_TRIES)); start = (start + MINE_TRIES) >>> 0;
      // hand the block to the other regions before the alarm returns: background work started in an alarm is
      // cut off when it ends, which left the others a minute behind until their own sync
      if (r === 1) { const body = this.out(x.io_len()); note({ found: true });
        await Promise.allSettled(this.upstreams().map(up => this.call(up, '/block', { method: 'POST', body }))); return true; }
      if (r === 2) { const why = this.out(x.io_len());
        if (payee && /payee/.test(why)) { payee = 0; continue; }   // the account does not exist yet: mine to nobody
        note({ error: why }); return; }
    }
    note({ found: false });
    return false;
  }
  // offer what the public sent here to the other regions again, oldest first: one lost on the way (or refused there
  // because it overtook the transaction it depends on) gets through. Only after it has waited a wake (the push went out
  // when it came), at most RERELAY_TIMES times; what peers forwarded is theirs to offer. They answer "already in mempool"
  // for the rest; a peer header stops them passing it on.
  async rerelay() {
    // first against our own chain: a row the chain now refuses (mined, or no longer valid) is dropped, not re-sent
    const live = [];
    for (const r of this.sql.exec('SELECT id, tx, own, age, src FROM pool ORDER BY id')) {   // a row at a time
      let why;
      // a trap here means this row broke the node: never again (any other error is not the row's doing)
      try { why = this.rpc('POST', '/tx', r.tx)[1]; } catch (e) { if (e instanceof WebAssembly.RuntimeError) this.sql.exec('DELETE FROM pool WHERE id = ?', r.id); throw e; }
      if (!why.trim().split('\n').some(x => x === 'ok' || x === 'already in mempool')) this.sql.exec('DELETE FROM pool WHERE id = ?', r.id);
      else if (r.own && r.age >= 1 && r.age <= RERELAY_TIMES && live.length < RERELAY_MAX) live.push(r);
    }
    this.sql.exec('UPDATE pool SET age = 1 WHERE own = 1 AND age = 0');
    for (const r of live) this.sql.exec('UPDATE pool SET age = age + 1 WHERE id = ?', r.id);
    // each peer gets them as batched requests (at most 64 transactions each, the RPC's limit), a sender's apart from
    // another's (X-Edge-Src: the peer keeps them as that sender's), all peers at once
    const by = new Map(), batches = [];
    for (const r of live) by.set(r.src, [...(by.get(r.src) || []), ...r.tx.split('\n')]);
    for (const [src, lines] of by) for (let i = 0; i < lines.length; i += 64) batches.push([src, lines.slice(i, i + 64).join('\n')]);
    if (batches.length) await Promise.allSettled(this.upstreams().map(async up => { for (const [src, body] of batches) { try { await this.call(up, '/tx', { method: 'POST', body }, { 'X-Edge-Src': src }); } catch (_) {} } }));
  }
  // every SYNC_S; straight away again while catching up (a wake that fetched its fill and raised the height) or when a
  // peer pushed a block on another branch meanwhile. A failure is logged, not thrown: a thrown alarm is retried at once.
  async alarm() {
    let s = { fetched: 0 }, mined;
    try { s = await this.sync(); if (s.fetched < MAX_PER_WAKE) mined = await this.backup(); } catch (e) { console.error(`edge node wake: ${e.stack || e}`); }
    // a quiet chain whose wake found no block (about one wake in twelve at the floor) is tried again soon, not next minute
    await this.ctx.storage.setAlarm(Date.now() + (this.from || s.rose && s.fetched >= MAX_PER_WAKE ? 1000 : mined === false ? RETRY_MS : this.every()));
  }

  async fetch(req) {
    const url = new URL(req.url);
    const region = url.searchParams.get('region');
    if (region && region !== this.region) { this.region = region; if (this.meta('region') !== region) this.meta('region', region); }
    // the front worker passes X-Edge-Peer on only from a real peer (the regions here send the secret themselves), and its
    // X-Edge-Chain: one on another chain version is refused
    const peer = !!req.headers.get('X-Edge-Peer');
    if (peer && req.headers.get('X-Edge-Chain') !== CHAIN_VERSION) return text('another chain version', 409);
    if (!(await this.ctx.storage.getAlarm())) await this.ctx.storage.setAlarm(Date.now() + 1000);
    await this.node();
    // the sync and mining details help nobody but the operator (and an attacker timing a fork): peers only. Block bodies
    // are never pruned (they are what peers and new nodes sync from): db_bytes shows how far the database has grown;
    // state_bytes and wasm_bytes how near the node is to full (STATE_MAX, MEM_MAX)
    if (url.pathname === '/edge') return text(`region ${this.meta('region')}\nchain ${CHAIN_VERSION}\nheight ${this.x.height()}\nupstreams ${this.upstreams().join(' ')}\n` +
      (peer ? `last_sync ${this.meta('last_sync') ?? 'never'}\nlast_mined ${this.meta('last_mined') ?? 'never'}\ndb_bytes ${this.sql.databaseSize}\n` +
              `state_bytes ${Math.round(this.state)}${this.full() ? ' (full)' : ''}\nwasm_bytes ${this.x.memory.buffer.byteLength}\ndown ${JSON.stringify(this.down)}\n` : ''));
    let body = req.method === 'POST' ? await readBody(req) : '';
    if (body === null) return text('request too large', 413);
    // whose transactions these are (the front worker's limitKey of the sender, or what the peer passing them on said)
    const src = (req.headers.get('X-Edge-Src') || '').slice(0, 64);
    // past its state limit the node takes no new registration (from anyone: they would all grow the state): a request of
    // nothing else is refused, 503; of a batch, the rest goes in and its registrations are answered FULL
    let all = null, kept = null;
    if (req.method === 'POST' && url.pathname === '/tx' && this.full()) {
      const ls = linesOf(body), k = ls.flatMap((l, i) => isReg(l) ? [] : [i]);
      if (!k.length && ls.length) return text(FULL, 503, { 'Retry-After': '3600' });
      if (k.length < ls.length) { all = ls; kept = k; body = k.map(i => ls[i]).join('\n'); }
    }
    let [code, reply] = this.rpc(req.method, url.pathname, body);
    if (req.method === 'POST' && url.pathname === '/tx' && code === 200) {
      // keep what was accepted (for a batch, the lines whose result is "ok"), together, as one row (a line per row if too big),
      // marked as the public's (own) or a peer's
      const lines = body.trim().split(/\s*\n\s*/), res = reply.trim().split('\n');
      const ok = lines.length === 1 ? lines : lines.filter((_, i) => res[i] === 'ok');
      const rows = ok.join('\n').length > ROW_MAX ? ok : ok.length ? [ok.join('\n')] : [];
      for (const row of rows) { try { this.sql.exec('INSERT OR IGNORE INTO pool (tx, own, src) VALUES (?, ?, ?)', row, peer ? 0 : 1, src); if (this.pool) { this.pool.n++; this.pool.bytes += row.length; } } catch (_) {} }
      for (const l of ok) if (isReg(l)) this.state += l.length / 2;   // the state grows by about each registration taken
      this.poolTrim();
    }
    if (req.method === 'POST' && url.pathname === '/block' && reply.trim() === 'accepted') this.pushed = Date.now();
    // a peer pushed a block on a branch we do not have (a push carries only the tip): pull from that peer now
    if (req.method === 'POST' && url.pathname === '/block' && peer && reply.trim() === 'prev unknown') {
      const f = req.headers.get('X-Edge-From') || '', up = this.upstreams().find(u => u === 'do:' + f || u.startsWith(`https://node-${f}.`));
      // it just reached us, on our chain: a busy or chain-version breaker on it is lifted, so the pull is not skipped
      // (not one for a refused block)
      if (up && this.down[up] && this.down[up] - Date.now() <= DOWN_MS) { delete this.down[up]; this.meta('down', JSON.stringify(this.down)); }
      if (f && up && !this.from) { this.from = up; const a = await this.ctx.storage.getAlarm(); if (!a || a > Date.now() + 1000) await this.ctx.storage.setAlarm(Date.now() + 1000); }
    }
    // a new transaction or a block that moved the main chain goes on to the other regions and upstream nodes at once
    // (not back to the region that sent it, and not a side block: nobody needs it unless it wins); polling is only the
    // safety net
    const moved = url.pathname === '/tx' || reply.trim() === 'accepted';
    // of a batch, only the lines this node accepted go on (the peers would refuse the rest too)
    const fwd = url.pathname !== '/tx' ? body : (() => { const ls = body.trim().split(/\s*\n\s*/), rs = reply.trim().split('\n'); return ls.length === 1 ? body : ls.filter((_, i) => rs[i] === 'ok').join('\n'); })();
    // in the background, one after another in the order accepted: the reply does not wait for a slow peer
    if (req.method === 'POST' && (url.pathname === '/tx' || url.pathname === '/block') && code === 200 && moved && fwd && !peer) {
      this.relayed = this.relayed.then(() => Promise.allSettled(this.upstreams().map(up => this.call(up, url.pathname, { method: 'POST', body: fwd }, src ? { 'X-Edge-Src': src } : {}))));
      this.ctx.waitUntil?.(this.relayed);
    }
    if (req.method === 'POST' && url.pathname === '/block') this.trim();
    if (all) { reply = merge(all, kept, reply, FULL); code = 200; }
    return text(reply, code, { 'X-Edge-Height': String(this.x.height()) });   // for the front worker (what of a 400 it may cache)
  }
}

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const local = url.hostname === 'localhost' || url.hostname === '127.0.0.1';   // wrangler dev: ?node=ap
    const region = local ? url.searchParams.get('node') || 'ap' : url.hostname.match(/^node-([a-z]+)\./)?.[1];
    const R = regions(env);
    if (!R[region]) return text('unknown node', 404);
    if (req.method === 'OPTIONS') return new Response(null, { headers: HDRS });
    if (!['GET', 'HEAD', 'POST'].includes(req.method)) return text('method not allowed', 405);
    // hex in an id or a lookup code may come in either case: the lowercase path is the one used (and the cache key)
    let path = /^\/(?:id|queued|lookup|commits)\//.test(url.pathname) ? url.pathname.toLowerCase() : url.pathname;
    if (!(req.method === 'POST' ? POSTS : GETS).test(path)) return text('unknown route', 404);
    path = path.replace(/^\/top\/(\d+)$/, (p, n) => +n > TOP_MAX ? `/top/${TOP_MAX}` : p);   // the node lists at most TOP_MAX: one cache key for more
    // X-Edge-Peer from a peer carries the shared secret; anyone else's is dropped (it would stop their transactions
    // being passed on at once). Its X-Edge-Chain goes on for the Durable Object to check, and X-Edge-From (its region).
    const peer = isPeer(env, req.headers.get('X-Edge-Peer'));
    // whether a block is there only the region knows: this isolate's idea of its height may be minutes old (a region
    // catching up climbs hundreds a minute), so /block/<n> above it is asked of the region like anything else
    const key = limitKey(req.headers.get('CF-Connecting-IP') || '');
    // X-Edge-Src: whose transactions they are (the Durable Object keeps its pool fair between senders)
    const fwd = peer ? { 'X-Edge-Peer': '1', 'X-Edge-Chain': req.headers.get('X-Edge-Chain') || '', 'X-Edge-From': req.headers.get('X-Edge-From') || '', 'X-Edge-Src': req.headers.get('X-Edge-Src') || '' }
                     : { 'X-Edge-Src': key };
    // the public's uncached requests are rate limited per address (cache hits cost nothing and are not counted), and all
    // of them together per region (RL_REGION, generous): a farm of addresses cannot swamp one Durable Object either.
    // (Cloudflare counts each limit per location, so this caps what one location sends it.) Reads and posts are counted
    // apart (keys get: and post:), so a flood of reads never locks out a miner's block or anyone's transaction. And the
    // region's budget is in two tiers: an address's first RL_FAIR requests a minute draw on a pool of their own
    // (<region>:<kind>:fair), the rest on the main one; a farm of addresses that drains the main pool (6000 a minute is
    // 20 /48s at RL's limit) leaves everyone else their fair share, unless it has some 200 /48s at one location.
    const kind = req.method === 'POST' ? 'post' : 'get';
    const limited = async () => { if (peer) return false; const k = `${kind}:${key}`;
      if (env.RL && !(await env.RL.limit({ key: k })).success || HEAVY.test(path) && env.RL_HEAVY && !(await env.RL_HEAVY.limit({ key })).success) return true;
      if (!env.RL_REGION) return false;
      const fair = !!env.RL_FAIR && (await env.RL_FAIR.limit({ key: k })).success;
      return !(await env.RL_REGION.limit({ key: `${region}:${kind}${fair ? ':fair' : ''}` })).success; };
    const heavy = async n => !env.RL_HEAVY ? n : (await Promise.all(Array.from({ length: n }, () => env.RL_HEAVY.limit({ key })))).filter(r => r.success).length;   // of n units, those granted
    const busy = () => text('too many requests', 429, { 'Retry-After': '60' });
    // an edge node has no TCP peers: its peers are the other regions and the upstream nodes it syncs with
    if (path === '/peers') return text(String(Object.keys(R).length - 1 + (env.UPSTREAMS || '').split(',').filter(s => s.trim()).length));
    const stub = env.NODE.get(env.NODE.idFromName(region), { locationHint: R[region] });
    // a reply from the Durable Object, its X-Edge-Height (for the cache below) taken off
    const seen = res => { const out = new Response(res.body, res); out.headers.delete('X-Edge-Height'); return out; };
    const inner = new URL(path + `?region=${region}`, 'https://edge');
    if (req.method === 'POST') {
      if (await limited()) return busy();
      const body = await readBody(req);
      if (body === null) return text('request too large', 413);
      // each registration in the public's /tx (its line starts with tag 1 or 2) costs work to check, like one in /check:
      // each is counted once more against RL_HEAVY, and at most TX_REGS of a request are taken. The rest of the request goes
      // in; registrations past either limit are answered 429 (Retry-After; X-Edge-Taken and the body say how many lines
      // were taken, one answer per line), for the sender to send again. So a native node relaying 64 transactions a post
      // loses none: from one address its posts plus their registrations may come to 30 a minute (RL_HEAVY), so 30 posts
      // of 64 (1,920 transactions) without registrations, or two carrying 28 (the chain itself takes far fewer)
      const ls = !peer && path === '/tx' ? linesOf(body) : [], regs = ls.flatMap((l, i) => isReg(l) ? [i] : []);
      const most = Math.min(regs.length, TX_REGS), take = most ? await heavy(most) : 0, skip = new Set(regs.slice(take));
      if (!skip.size) return seen(await stub.fetch(inner, { method: 'POST', body, headers: fwd }));   // a peer's forward is not passed on again
      const kept = ls.flatMap((_, i) => skip.has(i) ? [] : [i]), wait = take < most ? 60 : 1;
      const why = `not taken, send it again: ${kept.length} of ${ls.length} lines taken (at most ${TX_REGS} registrations in one request` +
        (wait > 1 ? ', and this address has sent its registrations for the minute)' : ')');
      const extra = { 'Retry-After': String(wait), 'X-Edge-Taken': String(kept.length) };
      if (!kept.length) return text(merge(ls, [], '', why), 429, extra);
      const res = await stub.fetch(inner, { method: 'POST', body: kept.map(i => ls[i]).join('\n'), headers: fwd }), reply = await res.text();
      // a refusal of the whole request (edge full, a bad line in a batch) stands as it is
      if (res.status >= 500 || res.status !== 200 && kept.length > 1) return seen(new Response(reply, res));
      return text(merge(ls, kept, reply, why), 429, extra);
    }
    // GET and HEAD share the cache (HEAD answers with the headers only)
    const head = r => req.method === 'HEAD' ? new Response(null, r) : r;
    // peers skip the cache: after a reorg a cached /block/<h> would be the abandoned one for a few seconds. /edge differs
    // for peers and the public, and a wallet asks /queued right before it signs: never cached
    const fresh = FRESH.has(path.split('/')[1]), cache = caches.default, ck = new Request(url.origin + path);
    const cached = !peer && path !== '/edge' && !path.startsWith('/queued/');
    const hit = cached ? await cache.match(ck) : null;
    if (hit) return head(hit);
    if (await limited()) return busy();
    const res = await stub.fetch(inner, { headers: fwd }), out = seen(res), h = +(res.headers.get('X-Edge-Height') ?? NaN);
    // a refusal (400: no account...) is kept briefly too, so asking again and again costs nothing; but not "no such block"
    // for one above the region's height (as it answered just now): that one is due within minutes, and is not kept at all
    const soon = res.status === 400 && +(path.match(/^\/(?:block|summary)\/(\d+)$/)?.[1] ?? -1) > (Number.isFinite(h) ? h : -1);
    if (soon) out.headers.set('Cache-Control', 'no-store');
    else if ((res.ok || res.status === 400) && cached) { out.headers.set('Cache-Control', `public, max-age=${fresh || !res.ok ? FRESH_S : CACHE_S}`); ctx.waitUntil(cache.put(ck, out.clone())); }
    return head(out);
  },
  // a watchdog: wake each region so its alarm keeps running even if nothing has called it
  async scheduled(_ev, env) {
    await Promise.allSettled(Object.entries(regions(env)).map(([r, hint]) => env.NODE.get(env.NODE.idFromName(r), { locationHint: hint }).fetch(`https://edge/edge?region=${r}`)));
  },
};

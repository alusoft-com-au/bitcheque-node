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
// nobody is a peer. The public's requests are rate limited (RL, and RL_HEAVY too for /check and /template).
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
const MINE_MS = 3000;            // at most this long per wake (the floor is ~2^19 hashes: about a second here)
const MINE_TRIES = 50_000;       // nonces per call into the wasm, between clock checks
const CHAIN_VERSION = '10';        // bump to reset the network: each region forgets its chain and starts from block 0
const FALLBACK_S = 120;          // each further region in MINE_REGIONS waits this much longer (if the first is down)
const RERELAY_MAX = 50;          // waiting transactions offered again to each other region per wake
const RERELAY_TIMES = 2;         // ...each only if the public sent it here, after it waited a wake, and at most this often
const POOL_MAX = 1000;           // waiting transactions kept in the database across unloads (all offered again on load)
const BODY_MAX = 4 << 20;        // request body bytes (16 registrations of 16 cheques and a cheque are under 2 MB of hex)
const ROW_MAX = 1_900_000;       // a SQLite row holds at most 2 MB: a bigger pool batch is kept a line per row
const PEER_MS = 10_000;          // a peer that has not answered by then is given up on
const DOWN_MS = 180_000;         // ...and left alone this long (so is one on another chain version)
const SKIP_MS = 600_000;         // an upstream that sent a refused block, or nothing that moved the chain, is not pulled from this long
const START_TRIES = 5;           // starts again after a stored block or waiting transaction trapped the node (it is dropped)
const FRESH = new Set(['height', 'tip', 'template', 'queued']);   // miners and the status page need these nearly fresh
const FRESH_S = 2;               // ...but a short cache still collapses a flood of them into one request per colo
const CACHE_S = 15;              // seconds the front worker caches a GET reply (status pages poll every 10 s)
// the RPC's paths, spelt one way only (numbers without sign or leading zeros, ids of the right length, no trailing slash:
// /proof/7, /proof/07 and /proof/+7 would be three cache keys). Anything else is refused here, without waking a Durable Object.
const N = '(?:0|[1-9]\\d{0,9})', ID = '[0-9a-f]{34}(?:[0-9a-f]{32})?';
const GETS = new RegExp(`^/(?:height|peers|addrs|tip|regtarget|stats|mempool|edge|top(?:/${N})?|(?:block|summary|account|proof|history|template)/${N}|(?:id|queued)/${ID}|lookup/[0-9a-f]{8,64}|commits/${ID}/${N})$`);
const POSTS = /^\/(?:tx|check|block)$/;
const HEAVY = /^\/(?:check$|template\/)/;   // the public's costlier requests: RL_HEAVY's lower limit applies too
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
// the rate-limit key: an IPv4 address, or the /64 of an IPv6 one (one machine has a whole /64)
const limitKey = ip => { if (!ip.includes(':')) return ip; const [a, b = ''] = ip.split('::'); const l = a ? a.split(':') : [], r = b ? b.split(':') : [];
  return [...l, ...Array(8 - l.length - r.length).fill('0'), ...r].slice(0, 4).join(':') + '::/64'; };
const text = (body, status = 200, extra = {}) => new Response(body, { status, headers: { 'Content-Type': 'text/plain; charset=utf-8', ...HDRS, ...extra } });
const unhex = s => { s = s.trim(); if (!/^([0-9a-f]{2})*$/i.test(s)) return null; const b = new Uint8Array(s.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(s.substr(2 * i, 2), 16); return b; };
const hashOf = s => s.match(/^hash ([0-9a-f]+)$/m)?.[1];

export class EdgeNode extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec(`CREATE TABLE IF NOT EXISTS blocks (h INTEGER PRIMARY KEY, data BLOB NOT NULL);
                   CREATE TABLE IF NOT EXISTS hdr (chunk INTEGER PRIMARY KEY, data BLOB NOT NULL);
                   CREATE TABLE IF NOT EXISTS snap (part INTEGER PRIMARY KEY, data BLOB NOT NULL);
                   CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
                   CREATE TABLE IF NOT EXISTS pool (id INTEGER PRIMARY KEY AUTOINCREMENT, tx TEXT NOT NULL UNIQUE, own INTEGER NOT NULL DEFAULT 0, age INTEGER NOT NULL DEFAULT 0)`);
    // older layouts: pool rows without their origin (own: from the public) and wakes waited (age); headers 1000 to a row
    // in `headers` (split into rows of HDR_CHUNK in `hdr`)
    const cols = this.sql.exec("SELECT name FROM pragma_table_info('pool')").toArray().map(r => r.name);
    for (const c of ['own', 'age']) if (!cols.includes(c)) this.sql.exec(`ALTER TABLE pool ADD COLUMN ${c} INTEGER NOT NULL DEFAULT 0`);
    if (this.sql.exec("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'headers'").toArray().length) {
      for (const r of this.sql.exec('SELECT chunk, data FROM headers').toArray()) { const d = new Uint8Array(r.data), n = HDR_CHUNK * 112;
        for (let i = 0; i * n < d.length; i++) this.sql.exec('INSERT OR REPLACE INTO hdr VALUES (?, ?)', r.chunk * (1000 / HDR_CHUNK) + i, d.subarray(i * n, (i + 1) * n)); }
      this.sql.exec('DROP TABLE headers');
    }
    this.x = null; this.ready = false; this.starting = null; this.replaying = false;
    this.relayed = Promise.resolve();   // forwards go out one after another, in the order they were accepted
    this.pushed = 0;                    // when a block sent here last moved the chain
    if (this.meta('chain_version') !== CHAIN_VERSION) {   // a network reset: start again from block 0
      this.sql.exec('DELETE FROM blocks; DELETE FROM hdr; DELETE FROM snap; DELETE FROM pool');
      this.sql.exec('DELETE FROM meta WHERE k != ?', 'region');   // keep the region: an alarm may wake it before any request
      this.meta('chain_version', CHAIN_VERSION);
    }
    this.down = JSON.parse(this.meta('down') || '{}');   // peer -> until when it is left alone (ms)
  }
  meta(k, v) { if (v === undefined) return this.sql.exec('SELECT v FROM meta WHERE k = ?', k).toArray()[0]?.v; this.sql.exec('INSERT OR REPLACE INTO meta VALUES (?, ?)', k, String(v)); }
  bytes(p, n) { return new Uint8Array(this.x.memory.buffer, p, n).slice(); }
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
    const env = {
      host_get: h => { const r = this.sql.exec('SELECT data FROM blocks WHERE h = ?', h).toArray()[0]; if (!r) return 0;
                       const b = new Uint8Array(r.data), p = this.x.buf_reserve(b.length); new Uint8Array(this.x.memory.buffer, p, b.length).set(b); return b.length; },
      // a replayed block is stored already: nothing to write
      host_put: (h, p, n) => { if (this.replaying) return; const b = this.bytes(p, n); this.sql.exec('INSERT OR REPLACE INTO blocks VALUES (?, ?)', h, b); this.header(h, b.subarray(0, 112)); },
      host_snap: (p, n) => { const b = this.bytes(p, n); this.sql.exec('DELETE FROM snap');
                             for (let i = 0; i * PART < b.length; i++) this.sql.exec('INSERT INTO snap VALUES (?, ?)', i, b.subarray(i * PART, (i + 1) * PART)); },
    };
    const x = this.x = (await WebAssembly.instantiate(WASM, { env })).exports;
    let at = null;   // the stored block ({ h }) or pool row ({ id }) being fed in
    try {
    this.now();
    // restore: the snapshot, the headers up to it, then every stored block above it
    const parts = this.sql.exec('SELECT data FROM snap ORDER BY part').toArray().map(r => new Uint8Array(r.data));
    const snap = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); parts.reduce((o, p) => (snap.set(p, o), o + p.length), 0);
    const sh = snap.length >= 8 ? new DataView(snap.buffer).getUint32(4, true) : 0;
    const hdr = this.headers(sh, HDR_KEEP);
    const io = new Uint8Array(4 + snap.length + hdr.length);
    new DataView(io.buffer).setUint32(0, snap.length, true); io.set(snap, 4); io.set(hdr, 4 + snap.length);
    this.put(io);
    if (!x.open(+(this.env.NET ?? 0), SNAP_EVERY)) throw new Error('edge node failed to start');
    this.replaying = true;
    for (const r of this.sql.exec('SELECT h, data FROM blocks WHERE h > ? ORDER BY h', x.height())) { at = { h: r.h }; this.put(new Uint8Array(r.data)); this.now(); if (x.add_block() !== 1) break; }
    this.replaying = false;
    this.trim();
    // the mempool: Cloudflare unloads an idle object between wakes, so waiting transactions are kept in the database
    // and offered again, oldest first. One the chain now refuses (mined, or no longer valid) is dropped.
    // A row may hold a batch (one transaction per line, sent together so they share a block): it is offered again
    // as a batch, and kept while any of it is still accepted.
    for (const r of this.sql.exec('SELECT id, tx FROM pool ORDER BY id').toArray()) {
      at = { id: r.id };
      const [code, why] = this.rpc('POST', '/tx', r.tx);
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
  // X-Edge-Peer tells it not to pass this on; a reply without our X-Edge-Chain is from another chain. One that times out,
  // or is on another chain, is left alone for DOWN_MS.
  async call(up, path, init) {
    if (!secret(this.env)) throw new Error('no EDGE_SECRET');
    if ((this.down[up] || 0) > Date.now()) throw new Error('left alone for now');
    const peer = { ...init, headers: { 'X-Edge-Peer': this.env.EDGE_SECRET, 'X-Edge-Chain': CHAIN_VERSION } };
    let r, t;
    try {
      if (up.startsWith('do:')) { const g = up.slice(3);
        r = await timeout(this.env.NODE.get(this.env.NODE.idFromName(g), { locationHint: regions(this.env)[g] }).fetch(`https://edge${path}?region=${g}`, peer), PEER_MS); }
      else {
        const via = this.env[JSON.parse(this.env.SERVICES || '{}')[new URL(up).host]] || this.env.UPSTREAM_SVC || globalThis;
        r = await via.fetch(up.replace(/\/$/, '') + path, { ...peer, signal: AbortSignal.timeout(PEER_MS) });
      }
      if (r.headers.get('X-Edge-Chain') !== CHAIN_VERSION) throw new Error(`${up}: chain version ${r.headers.get('X-Edge-Chain')}`);
      t = await timeout(r.text(), PEER_MS);
    } catch (e) { this.leave(up, DOWN_MS); throw e; }
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
    // this catches whatever a push missed). None while pushes keep the chain moving.
    this.now();
    const pushed = Date.now() - this.pushed < every && x.quiet() * 1000 < 2 * every;
    for (const up of pushed ? [] : this.upstreams()) {
      if (!this.ready || fetched >= MAX_PER_WAKE) break;   // a block trapped the node (it starts afresh below), or enough for one wake
      if ((this.down[up] || 0) > Date.now()) { log.push({ up, skipped: true }); continue; }
      try {
        const theirs = +(await this.call(up, '/height')), mine = this.x.height();
        if (!Number.isInteger(theirs)) throw new Error('bad height');
        if (theirs < mine) { log.push({ up, ok: true, height: theirs, behind: true }); continue; }
        let h = mine + 1, forked = false;
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
        if (theirs === mine || this.x.height() > mine) break;
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
        await Promise.allSettled(this.upstreams().map(up => this.call(up, '/block', { method: 'POST', body }))); return; }
      if (r === 2) { const why = this.out(x.io_len());
        if (payee && /payee/.test(why)) { payee = 0; continue; }   // the account does not exist yet: mine to nobody
        note({ error: why }); return; }
    }
    note({ found: false });
  }
  // offer what the public sent here to the other regions again, oldest first: one lost on the way (or refused there
  // because it overtook the transaction it depends on) gets through. Only after it has waited a wake (the push went out
  // when it came), at most RERELAY_TIMES times; what peers forwarded is theirs to offer. They answer "already in mempool"
  // for the rest; a peer header stops them passing it on.
  async rerelay() {
    // first against our own chain: a row the chain now refuses (mined, or no longer valid) is dropped, not re-sent
    const live = [];
    for (const r of this.sql.exec('SELECT id, tx, own, age FROM pool ORDER BY id').toArray()) {
      let why;
      try { why = this.rpc('POST', '/tx', r.tx)[1]; } catch (e) { this.sql.exec('DELETE FROM pool WHERE id = ?', r.id); throw e; }   // it broke the node: never again
      if (!why.trim().split('\n').some(x => x === 'ok' || x === 'already in mempool')) this.sql.exec('DELETE FROM pool WHERE id = ?', r.id);
      else if (r.own && r.age >= 1 && r.age <= RERELAY_TIMES && live.length < RERELAY_MAX) live.push(r);
    }
    this.sql.exec('UPDATE pool SET age = 1 WHERE own = 1 AND age = 0');
    for (const r of live) this.sql.exec('UPDATE pool SET age = age + 1 WHERE id = ?', r.id);
    // each peer gets them as batched requests (at most 64 transactions each, the RPC's limit), all peers at once
    const lines = live.flatMap(r => r.tx.split('\n')), batches = [];
    for (let i = 0; i < lines.length; i += 64) batches.push(lines.slice(i, i + 64).join('\n'));
    if (batches.length) await Promise.allSettled(this.upstreams().map(async up => { for (const body of batches) { try { await this.call(up, '/tx', { method: 'POST', body }); } catch (_) {} } }));
  }
  // every SYNC_S; straight away again while catching up (a wake that fetched its fill and raised the height)
  async alarm() { let s = { fetched: 0 }; try { s = await this.sync(); if (s.fetched < MAX_PER_WAKE) await this.backup(); } finally { await this.ctx.storage.setAlarm(Date.now() + (s.rose && s.fetched >= MAX_PER_WAKE ? 1000 : this.every())); } }

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
    // the sync and mining details help nobody but the operator (and an attacker timing a fork): peers only
    if (url.pathname === '/edge') return text(`region ${this.meta('region')}\nchain ${CHAIN_VERSION}\nheight ${this.x.height()}\nupstreams ${this.upstreams().join(' ')}\n` +
      (peer ? `last_sync ${this.meta('last_sync') ?? 'never'}\nlast_mined ${this.meta('last_mined') ?? 'never'}\ndown ${JSON.stringify(this.down)}\n` : ''));
    const body = req.method === 'POST' ? await readBody(req) : '';
    if (body === null) return text('request too large', 413);
    const [code, reply] = this.rpc(req.method, url.pathname, body);
    if (req.method === 'POST' && url.pathname === '/tx' && code === 200) {
      // keep what was accepted (for a batch, the lines whose result is "ok"), together, as one row (a line per row if too big),
      // marked as the public's (own) or a peer's
      const lines = body.trim().split(/\s*\n\s*/), res = reply.trim().split('\n');
      const ok = lines.length === 1 ? lines : lines.filter((_, i) => res[i] === 'ok');
      const rows = ok.join('\n').length > ROW_MAX ? ok : ok.length ? [ok.join('\n')] : [];
      for (const row of rows) { try { this.sql.exec('INSERT OR IGNORE INTO pool (tx, own) VALUES (?, ?)', row, peer ? 0 : 1); } catch (_) {} }
      this.sql.exec('DELETE FROM pool WHERE id <= (SELECT MAX(id) FROM pool) - ?', POOL_MAX);
    }
    if (req.method === 'POST' && url.pathname === '/block' && reply.trim() === 'accepted') this.pushed = Date.now();
    // a new transaction or a block that moved the main chain goes on to the other regions and upstream nodes at once
    // (not back to the region that sent it, and not a side block: nobody needs it unless it wins); polling is only the
    // safety net
    const moved = url.pathname === '/tx' || reply.trim() === 'accepted';
    // of a batch, only the lines this node accepted go on (the peers would refuse the rest too)
    const fwd = url.pathname !== '/tx' ? body : (() => { const ls = body.trim().split(/\s*\n\s*/), rs = reply.trim().split('\n'); return ls.length === 1 ? body : ls.filter((_, i) => rs[i] === 'ok').join('\n'); })();
    // in the background, one after another in the order accepted: the reply does not wait for a slow peer
    if (req.method === 'POST' && (url.pathname === '/tx' || url.pathname === '/block') && code === 200 && moved && fwd && !peer) {
      this.relayed = this.relayed.then(() => Promise.allSettled(this.upstreams().map(up => this.call(up, url.pathname, { method: 'POST', body: fwd }))));
      this.ctx.waitUntil?.(this.relayed);
    }
    if (req.method === 'POST' && url.pathname === '/block') this.trim();
    return text(reply, code);
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
    const path = /^\/(?:id|queued|lookup|commits)\//.test(url.pathname) ? url.pathname.toLowerCase() : url.pathname;
    if (!(req.method === 'POST' ? POSTS : GETS).test(path)) return text('unknown route', 404);
    // X-Edge-Peer from a peer carries the shared secret; anyone else's is dropped (it would stop their transactions
    // being passed on at once). Its X-Edge-Chain goes on for the Durable Object to check.
    const peer = isPeer(env, req.headers.get('X-Edge-Peer'));
    const fwd = peer ? { 'X-Edge-Peer': '1', 'X-Edge-Chain': req.headers.get('X-Edge-Chain') || '' } : {};
    // the public's uncached requests are rate limited per address (cache hits cost nothing and are not counted)
    const key = limitKey(req.headers.get('CF-Connecting-IP') || '');
    const limited = async () => !peer && (env.RL && !(await env.RL.limit({ key })).success || HEAVY.test(path) && env.RL_HEAVY && !(await env.RL_HEAVY.limit({ key })).success);
    // an edge node has no TCP peers: its peers are the other regions and the upstream nodes it syncs with
    if (path === '/peers') return text(String(Object.keys(R).length - 1 + (env.UPSTREAMS || '').split(',').filter(s => s.trim()).length));
    const stub = env.NODE.get(env.NODE.idFromName(region), { locationHint: R[region] });
    const inner = new URL(path + `?region=${region}`, 'https://edge');
    if (req.method === 'POST') {
      if (await limited()) return text('too many requests', 429);
      const body = await readBody(req);
      if (body === null) return text('request too large', 413);
      return stub.fetch(inner, { method: 'POST', body, headers: fwd });   // a peer's forward is not passed on again
    }
    // GET and HEAD share the cache (HEAD answers with the headers only)
    const head = r => req.method === 'HEAD' ? new Response(null, r) : r;
    // peers skip the cache: after a reorg a cached /block/<h> would be the abandoned one for a few seconds
    const fresh = FRESH.has(path.split('/')[1]), cache = caches.default, ck = new Request(url.origin + path);
    const hit = peer ? null : await cache.match(ck);
    if (hit) return head(hit);
    if (await limited()) return text('too many requests', 429);
    const res = await stub.fetch(inner, { headers: fwd });
    const out = new Response(res.body, res);
    // /edge differs for peers and the public: never cached
    if (res.ok && path !== '/edge' && !peer) { out.headers.set('Cache-Control', `public, max-age=${fresh ? FRESH_S : CACHE_S}`); ctx.waitUntil(cache.put(ck, out.clone())); }
    return head(out);
  },
  // a watchdog: wake each region so its alarm keeps running even if nothing has called it
  async scheduled(_ev, env) {
    await Promise.allSettled(Object.entries(regions(env)).map(([r, hint]) => env.NODE.get(env.NODE.idFromName(r), { locationHint: hint }).fetch(`https://edge/edge?region=${r}`)));
  },
};

// Bitcheque edge node: three Durable Objects (one per region) running the node's own chain code
// (bitcheque_edge.wasm, built from edge/src) with no sockets. Miners anywhere fetch GET /template/<number>
// and send mined blocks to POST /block; transactions arrive at POST /tx. Whatever one region accepts it
// passes straight to the others (and to any upstream nodes); each also wakes every minute and pulls what
// it missed (GET /height, GET /block/<n>). Blocks live in its SQLite database. Cost: it sleeps between
// wakes (no duration billed).
import { DurableObject } from 'cloudflare:workers';
import WASM from './bitcheque_edge.wasm';

const REGIONS = { ap: 'apac', us: 'enam', eu: 'weur' };   // node-<key>.bitcheque.org -> location hint
const SYNC_MS = 60_000;          // between wakes
const SNAP_EVERY = 100;          // blocks between state snapshots (a cold start replays fewer than this)
const MAX_PER_WAKE = 500;        // blocks fetched in one wake
const HDR_CHUNK = 1000;          // headers per database row (fewer rows read on a cold start)
const PART = 1_000_000;          // snapshot bytes per row (rows hold at most 2 MB)
const CACHE_S = 15;              // seconds the front worker caches a GET reply (status pages poll every 10 s)
// the RPC's first path segments: anything else is refused here, without waking a Durable Object
const ROUTES = new Set(['height', 'peers', 'addrs', 'tip', 'block', 'summary', 'account', 'id', 'lookup', 'proof', 'regtarget', 'history', 'stats', 'mempool', 'top', 'template', 'tx', 'check', 'edge']);
const CORS = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' };
const enc = new TextEncoder(), dec = new TextDecoder();
const text = (body, status = 200, extra = {}) => new Response(body, { status, headers: { 'Content-Type': 'text/plain; charset=utf-8', ...CORS, ...extra } });
const unhex = s => { s = s.trim(); if (!/^([0-9a-f]{2})*$/i.test(s)) return null; const b = new Uint8Array(s.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(s.substr(2 * i, 2), 16); return b; };

export class EdgeNode extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec(`CREATE TABLE IF NOT EXISTS blocks (h INTEGER PRIMARY KEY, data BLOB NOT NULL);
                   CREATE TABLE IF NOT EXISTS headers (chunk INTEGER PRIMARY KEY, data BLOB NOT NULL);
                   CREATE TABLE IF NOT EXISTS snap (part INTEGER PRIMARY KEY, data BLOB NOT NULL);
                   CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)`);
    this.x = null;
  }
  meta(k, v) { if (v === undefined) return this.sql.exec('SELECT v FROM meta WHERE k = ?', k).toArray()[0]?.v; this.sql.exec('INSERT OR REPLACE INTO meta VALUES (?, ?)', k, String(v)); }
  bytes(p, n) { return new Uint8Array(this.x.memory.buffer, p, n).slice(); }
  put(b) { const p = this.x.io_reserve(b.length); new Uint8Array(this.x.memory.buffer, p, b.length).set(b); }
  out(n) { return dec.decode(new Uint8Array(this.x.memory.buffer, this.x.io_ptr(), n)); }
  now() { this.x.set_now(Math.floor(Date.now() / 1000)); }

  // ---- the wasm node and its storage ----
  async node() {
    if (this.x) return this.x;
    const env = {
      host_get: h => { const r = this.sql.exec('SELECT data FROM blocks WHERE h = ?', h).toArray()[0]; if (!r) return 0;
                       const b = new Uint8Array(r.data), p = this.x.buf_reserve(b.length); new Uint8Array(this.x.memory.buffer, p, b.length).set(b); return b.length; },
      host_put: (h, p, n) => { const b = this.bytes(p, n); this.sql.exec('INSERT OR REPLACE INTO blocks VALUES (?, ?)', h, b); this.header(h, b.subarray(0, 112)); },
      host_snap: (p, n) => { const b = this.bytes(p, n); this.sql.exec('DELETE FROM snap');
                             for (let i = 0; i * PART < b.length; i++) this.sql.exec('INSERT INTO snap VALUES (?, ?)', i, b.subarray(i * PART, (i + 1) * PART)); },
    };
    const x = this.x = (await WebAssembly.instantiate(WASM, { env })).exports;
    this.now();
    // restore: the snapshot, the headers up to it, then every stored block above it
    const parts = this.sql.exec('SELECT data FROM snap ORDER BY part').toArray().map(r => new Uint8Array(r.data));
    const snap = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); parts.reduce((o, p) => (snap.set(p, o), o + p.length), 0);
    const sh = snap.length >= 8 ? new DataView(snap.buffer).getUint32(4, true) : 0;
    const hdr = this.headers(sh);
    const io = new Uint8Array(4 + snap.length + hdr.length);
    new DataView(io.buffer).setUint32(0, snap.length, true); io.set(snap, 4); io.set(hdr, 4 + snap.length);
    this.put(io);
    if (!x.open(+(this.env.NET ?? 0), SNAP_EVERY)) throw new Error('edge node failed to start');
    for (const r of this.sql.exec('SELECT data FROM blocks WHERE h > ? ORDER BY h', x.height())) { this.put(new Uint8Array(r.data)); this.now(); if (x.add_block() !== 1) break; }
    this.trim();
    return x;
  }
  header(h, b) {   // keep block h's header in its chunk row
    const c = Math.floor((h - 1) / HDR_CHUNK), at = ((h - 1) % HDR_CHUNK) * 112;
    const old = this.sql.exec('SELECT data FROM headers WHERE chunk = ?', c).toArray()[0];
    const row = new Uint8Array(Math.max(old ? old.data.byteLength : 0, at + 112));
    if (old) row.set(new Uint8Array(old.data)); row.set(b, at);
    this.sql.exec('INSERT OR REPLACE INTO headers VALUES (?, ?)', c, row);
  }
  headers(k) {     // the headers of blocks 1..k, concatenated
    const out = new Uint8Array(k * 112);
    for (const r of this.sql.exec('SELECT chunk, data FROM headers WHERE chunk <= ? ORDER BY chunk', Math.floor((k - 1) / HDR_CHUNK))) {
      const d = new Uint8Array(r.data), at = r.chunk * HDR_CHUNK * 112;
      out.set(d.subarray(0, Math.min(d.length, out.length - at)), at);
    }
    return out;
  }
  trim() {         // after a reorg onto a shorter branch: forget blocks above the tip
    const h = this.x.height();
    this.sql.exec('DELETE FROM blocks WHERE h > ?', h);
  }
  add(b) { this.put(b); this.now(); const r = this.x.add_block(); return r ? { r } : { r, why: this.out(this.x.io_len()) }; }
  rpc(method, path, body = '') { this.put(enc.encode(`${method} ${path}\n${body}`)); this.now(); const s = this.out(this.x.rpc()); const i = s.indexOf('\n'); return [+s.slice(0, i), s.slice(i + 1)]; }

  // ---- upstreams: other nodes' RPC ("https://host"), or another region ("do:eu") ----
  upstreams() {
    const list = (this.env.UPSTREAMS || '').split(',').map(s => s.trim()).filter(Boolean);
    const me = this.meta('region');
    return [...list, ...Object.keys(REGIONS).filter(r => r !== me).map(r => 'do:' + r)];
  }
  async call(up, path, init) {
    const r = up.startsWith('do:')
      ? await this.env.NODE.get(this.env.NODE.idFromName(up.slice(3))).fetch('https://edge' + path, { ...init, headers: { 'X-Edge-Peer': '1' } })
      : await fetch(up.replace(/\/$/, '') + path, { ...init, signal: AbortSignal.timeout(10_000) });
    if (!r.ok) throw new Error(`${up}${path}: ${r.status}`);
    return r.text();
  }
  async sync() {
    const x = await this.node();
    let fetched = 0, log = [];
    for (const up of this.upstreams()) {
      if (up.startsWith('do:') && log.some(l => l.ok)) break;   // other regions only when no upstream answered
      try {
        const theirs = +(await this.call(up, '/height'));
        let h = x.height() + 1, back = 0;
        while (h <= theirs && fetched < MAX_PER_WAKE) {
          const b = unhex(await this.call(up, `/block/${h}`)); fetched++;
          const a = b ? this.add(b) : { r: 0, why: 'bad hex' };
          // accepted: carry on from the tip if it moved past h, else (a side block, or one we had) from h + 1
          if (a.r) { h = x.height() >= h ? x.height() + 1 : h + 1; continue; }
          if (a.why === 'prev unknown' && back < 200 && h > 1) { back++; h--; continue; }   // a fork: walk back to where we agree
          throw new Error(`block ${h} refused: ${a.why}`);
        }
        this.trim();
        log.push({ up, ok: true, height: theirs });
      } catch (e) { log.push({ up, ok: false, error: String(e.message || e) }); }
    }
    this.meta('last_sync', JSON.stringify({ at: new Date().toISOString(), height: x.height(), fetched, log }));
    return fetched;
  }
  // every minute; straight away again while catching up
  async alarm() { let n = 0; try { n = await this.sync(); } finally { await this.ctx.storage.setAlarm(Date.now() + (n >= MAX_PER_WAKE ? 1000 : SYNC_MS)); } }

  async fetch(req) {
    const url = new URL(req.url);
    const region = url.searchParams.get('region');
    if (region && region !== this.region) { this.region = region; if (this.meta('region') !== region) this.meta('region', region); }
    if (!(await this.ctx.storage.getAlarm())) await this.ctx.storage.setAlarm(Date.now() + 1000);
    await this.node();
    if (url.pathname === '/edge') return text(`region ${this.meta('region')}\nheight ${this.x.height()}\nupstreams ${this.upstreams().join(' ')}\nlast_sync ${this.meta('last_sync') ?? 'never'}\n`);
    const body = req.method === 'POST' ? await req.text() : '';
    const [code, reply] = this.rpc(req.method, url.pathname, body);
    // a new transaction or a newly mined block goes on to the other regions and upstream nodes at once
    // (not back to the region that sent it); polling every minute is only the safety net
    if (req.method === 'POST' && (url.pathname === '/tx' || url.pathname === '/block') && code === 200 && !req.headers.get('X-Edge-Peer'))
      this.ctx.waitUntil(Promise.allSettled(this.upstreams().map(up => this.call(up, url.pathname, { method: 'POST', body }))));
    if (req.method === 'POST' && url.pathname === '/block') this.trim();
    return text(reply, code);
  }
}

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const local = url.hostname === 'localhost' || url.hostname === '127.0.0.1';   // wrangler dev: ?node=ap
    const region = local ? url.searchParams.get('node') || 'ap' : url.hostname.match(/^node-([a-z]+)\./)?.[1];
    if (!REGIONS[region]) return text('unknown node', 404);
    if (req.method === 'OPTIONS') return new Response(null, { headers: CORS });
    if (!ROUTES.has(url.pathname.split('/')[1])) return text('unknown route', 404);
    // an edge node has no TCP peers: its peers are the other regions and the upstream nodes it syncs with
    if (url.pathname === '/peers') return text(String(Object.keys(REGIONS).length - 1 + (env.UPSTREAMS || '').split(',').filter(s => s.trim()).length));
    const stub = env.NODE.get(env.NODE.idFromName(region), { locationHint: REGIONS[region] });
    const inner = new URL(url.pathname + `?region=${region}`, 'https://edge');
    if (req.method !== 'GET') return stub.fetch(inner, { method: req.method, body: await req.text() });
    const cache = caches.default, key = new Request(url.origin + url.pathname);
    const hit = await cache.match(key);
    if (hit) return hit;
    const res = await stub.fetch(inner);
    const out = new Response(res.body, res);
    if (res.ok) { out.headers.set('Cache-Control', `public, max-age=${CACHE_S}`); ctx.waitUntil(cache.put(key, out.clone())); }
    return out;
  },
  // a watchdog: wake each region so its alarm keeps running even if nothing has called it
  async scheduled(_ev, env) {
    await Promise.allSettled(Object.entries(REGIONS).map(([r, hint]) => env.NODE.get(env.NODE.idFromName(r), { locationHint: hint }).fetch(`https://edge/edge?region=${r}`)));
  },
};

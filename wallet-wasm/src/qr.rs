//! A small QR code encoder (ISO/IEC 18004): byte or alphanumeric mode, error correction level M or H,
//! versions 1-10 (up to 213 bytes, plenty for a link). Follows the structure of Project Nayuki's reference encoder.

#[derive(Clone, Copy, PartialEq)]
pub enum Ecc { L, M, Q, H }
impl Ecc {
    pub fn per_block(self, v: usize) -> usize { match self {
        Ecc::L => [0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18][v], Ecc::M => [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26][v],
        Ecc::Q => [0, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24][v], Ecc::H => [0, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28][v] } }
    pub fn blocks(self, v: usize) -> usize { match self {
        Ecc::L => [0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4][v], Ecc::M => [0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5][v],
        Ecc::Q => [0, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8][v], Ecc::H => [0, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8][v] } }
    fn format(self) -> u32 { match self { Ecc::L => 0b01, Ecc::M => 0b00, Ecc::Q => 0b11, Ecc::H => 0b10 } }
}
pub const ALNUM: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

pub fn raw_modules(v: usize) -> usize {
    let mut r = (16 * v + 128) * v + 64;
    if v >= 2 { let n = v / 7 + 2; r -= (25 * n - 10) * n - 55; if v >= 7 { r -= 36; } }
    r
}
fn data_codewords(v: usize, e: Ecc) -> usize { raw_modules(v) / 8 - e.per_block(v) * e.blocks(v) }

pub fn gf_mul(x: u8, y: u8) -> u8 {
    let mut z: u32 = 0;
    for i in (0..8).rev() { z = (z << 1) ^ ((z >> 7) * 0x11D); z ^= ((y as u32 >> i) & 1) * x as u32; }
    z as u8
}
fn rs_divisor(degree: usize) -> Vec<u8> {
    let mut r = vec![0u8; degree]; r[degree - 1] = 1;
    let mut root = 1u8;
    for _ in 0..degree {
        for j in 0..degree { r[j] = gf_mul(r[j], root); if j + 1 < degree { r[j] ^= r[j + 1]; } }
        root = gf_mul(root, 2);
    }
    r
}
fn rs_remainder(data: &[u8], div: &[u8]) -> Vec<u8> {
    let mut r = vec![0u8; div.len()];
    for &b in data {
        let f = b ^ r[0]; r.remove(0); r.push(0);
        for (x, &d) in r.iter_mut().zip(div) { *x ^= gf_mul(d, f); }
    }
    r
}

pub struct Grid { pub n: usize, pub m: Vec<bool>, pub f: Vec<bool> }
impl Grid {
    fn set(&mut self, x: usize, y: usize, dark: bool) { self.m[y * self.n + x] = dark; self.f[y * self.n + x] = true; }
    fn finder(&mut self, cx: i32, cy: i32) {
        for dy in -4..=4i32 { for dx in -4..=4i32 {
            let (x, y) = (cx + dx, cy + dy);
            if x >= 0 && y >= 0 && (x as usize) < self.n && (y as usize) < self.n { let d = dx.abs().max(dy.abs()); self.set(x as usize, y as usize, d != 2 && d != 4); }
        } }
    }
    fn align(&mut self, cx: usize, cy: usize) {
        for dy in -2..=2i32 { for dx in -2..=2i32 { self.set((cx as i32 + dx) as usize, (cy as i32 + dy) as usize, dx.abs().max(dy.abs()) != 1); } }
    }
    fn format(&mut self, ecc: Ecc, mask: u32) {
        let data = ecc.format() << 3 | mask;
        let mut rem = data;
        for _ in 0..10 { rem = (rem << 1) ^ ((rem >> 9) * 0x537); }
        let bits = (data << 10 | rem) ^ 0x5412;
        let b = |i: u32| (bits >> i) & 1 != 0;
        let n = self.n;
        for i in 0..6 { self.set(8, i, b(i as u32)); }
        self.set(8, 7, b(6)); self.set(8, 8, b(7)); self.set(7, 8, b(8));
        for i in 9..15 { self.set(14 - i, 8, b(i as u32)); }
        for i in 0..8 { self.set(n - 1 - i, 8, b(i as u32)); }
        for i in 8..15 { self.set(8, n - 15 + i, b(i as u32)); }
        self.set(8, n - 8, true);
    }
}

pub fn masked(mask: u8, x: usize, y: usize) -> bool {
    match mask {
        0 => (x + y) % 2 == 0, 1 => y % 2 == 0, 2 => x % 3 == 0, 3 => (x + y) % 3 == 0,
        4 => (x / 3 + y / 2) % 2 == 0, 5 => x * y % 2 + x * y % 3 == 0,
        6 => (x * y % 2 + x * y % 3) % 2 == 0, _ => ((x + y) % 2 + x * y % 3) % 2 == 0,
    }
}

fn penalty(g: &Grid) -> usize {
    let n = g.n; let at = |x: usize, y: usize| g.m[y * n + x];
    let mut p = 0;
    for pass in 0..2 {                                     // rows, then columns
        for a in 0..n {
            let line: Vec<bool> = (0..n).map(|b| if pass == 0 { at(b, a) } else { at(a, b) }).collect();
            let mut run = 1;
            for b in 1..=n {
                if b < n && line[b] == line[b - 1] { run += 1; } else { if run >= 5 { p += run - 2; } run = 1; }
            }
            // finder-like 1:1:3:1:1 with four light modules on one side
            for b in 0..n.saturating_sub(10) {
                let w: Vec<bool> = line[b..b + 11].to_vec();
                let core = [true, false, true, true, true, false, true];
                if (w[..7] == core && w[7..].iter().all(|x| !x)) || (w[4..] == core && w[..4].iter().all(|x| !x)) { p += 40; }
            }
        }
    }
    for y in 0..n - 1 { for x in 0..n - 1 { let c = at(x, y); if at(x + 1, y) == c && at(x, y + 1) == c && at(x + 1, y + 1) == c { p += 3; } } }
    let dark = g.m.iter().filter(|&&d| d).count() as i64; let total = (n * n) as i64;
    p + (((dark * 20 - total * 10).abs() + total - 1) / total - 1) as usize * 10
}

/// Timing, finder, alignment, format and version areas of version `v`, marked in `f` (format bits for mask 0).
pub fn layout(v: usize, ecc: Ecc) -> Grid {
    let n = v * 4 + 17;
    let mut g = Grid { n, m: vec![false; n * n], f: vec![false; n * n] };
    for i in 0..n { g.set(6, i, i % 2 == 0); g.set(i, 6, i % 2 == 0); }
    g.finder(3, 3); g.finder(n as i32 - 4, 3); g.finder(3, n as i32 - 4);
    if v >= 2 {
        let na = v / 7 + 2; let step = (v * 8 + na * 3 + 5) / (na * 4 - 4) * 2;
        let mut pos = vec![6usize; na]; let mut p = n - 7;
        for i in (1..na).rev() { pos[i] = p; p -= step; }
        for (i, &x) in pos.iter().enumerate() { for (j, &y) in pos.iter().enumerate() {
            if !((i == 0 && j == 0) || (i == 0 && j == na - 1) || (i == na - 1 && j == 0)) { g.align(x, y); }
        } }
    }
    g.format(ecc, 0);
    if v >= 7 {
        let mut rem = v as u32; for _ in 0..12 { rem = (rem << 1) ^ ((rem >> 11) * 0x1F25); }
        let bits = (v as u32) << 12 | rem;
        for i in 0..18 { let bit = (bits >> i) & 1 != 0; let (a, b) = (n - 11 + i % 3, i / 3); g.set(a, b, bit); g.set(b, a, bit); }
    }
    g
}

/// The order codeword bits are placed in: up and down two-module columns from the right, skipping column 6.
pub fn zigzag(g: &Grid) -> Vec<usize> {
    let n = g.n; let mut out = Vec::new(); let mut right = n as i32 - 1;
    while right >= 1 {
        if right == 6 { right = 5; }
        for vert in 0..n { for j in 0..2 {
            let x = (right - j) as usize; let up = (right + 1) & 2 == 0;
            let y = if up { n - 1 - vert } else { vert };
            if !g.f[y * n + x] { out.push(y * n + x); }
        } }
        right -= 2;
    }
    out
}

/// The symbol for `text`: (side length, modules row by row, true = dark). None when it is too long.
/// Text made only of QR's 45 alphanumeric characters (digits, capitals, a few symbols) is packed in alphanumeric mode.
pub fn encode(text: &[u8], ecc: Ecc) -> Option<(usize, Vec<bool>)> {
    let alnum = text.iter().all(|c| ALNUM.contains(c));
    let need = |v: usize| if alnum { 4 + if v < 10 { 9 } else { 11 } + text.len() / 2 * 11 + text.len() % 2 * 6 } else { 4 + if v < 10 { 8 } else { 16 } + text.len() * 8 };
    let v = (1..=10).find(|&v| need(v) <= data_codewords(v, ecc) * 8)?;
    // data bits: mode, length, data, terminator, padding
    let mut bits: Vec<bool> = Vec::new();
    let push = |val: u32, len: usize, bits: &mut Vec<bool>| for i in (0..len).rev() { bits.push((val >> i) & 1 != 0); };
    if alnum {
        push(0b0010, 4, &mut bits);
        push(text.len() as u32, if v < 10 { 9 } else { 11 }, &mut bits);
        let ix = |c: u8| ALNUM.iter().position(|&a| a == c).unwrap() as u32;
        for pair in text.chunks(2) { if pair.len() == 2 { push(ix(pair[0]) * 45 + ix(pair[1]), 11, &mut bits) } else { push(ix(pair[0]), 6, &mut bits) } }
    } else {
        push(0b0100, 4, &mut bits);
        push(text.len() as u32, if v < 10 { 8 } else { 16 }, &mut bits);
        for &b in text { push(b as u32, 8, &mut bits); }
    }
    let cap = data_codewords(v, ecc) * 8;
    let t = 4.min(cap - bits.len()); push(0, t, &mut bits);
    let pad = (8 - bits.len() % 8) % 8; push(0, pad, &mut bits);
    let mut data: Vec<u8> = bits.chunks(8).map(|c| c.iter().fold(0u8, |a, &b| a << 1 | b as u8)).collect();
    let mut k = 0; while data.len() < data_codewords(v, ecc) { data.push(if k % 2 == 0 { 0xEC } else { 0x11 }); k += 1; }
    // split into blocks, add error correction, interleave
    let (nb, eccw) = (ecc.blocks(v), ecc.per_block(v));
    let raw = raw_modules(v) / 8;
    let short = nb - raw % nb; let short_len = raw / nb;
    let div = rs_divisor(eccw);
    let mut blocks: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut at = 0;
    for i in 0..nb {
        let len = short_len - eccw + if i < short { 0 } else { 1 };
        let d = data[at..at + len].to_vec(); at += len;
        let e = rs_remainder(&d, &div);
        blocks.push((d, e));
    }
    let mut cw: Vec<u8> = Vec::new();
    for i in 0..=short_len - eccw { for (d, _) in &blocks { if i < d.len() { cw.push(d[i]); } } }
    for i in 0..eccw { for (_, e) in &blocks { cw.push(e[i]); } }
    let n = v * 4 + 17;
    let mut g = layout(v, ecc);
    // codewords in the zigzag
    for (i, at) in zigzag(&g).into_iter().enumerate() { if i < cw.len() * 8 { g.m[at] = (cw[i >> 3] >> (7 - (i & 7))) & 1 != 0; } }
    // the mask with the lowest penalty
    let mut best: Option<(usize, Grid)> = None;
    for mask in 0..8u8 {
        let mut t = Grid { n, m: g.m.clone(), f: g.f.clone() };
        for y in 0..n { for x in 0..n { if !t.f[y * n + x] && masked(mask, x, y) { t.m[y * n + x] ^= true; } } }
        t.format(ecc, mask as u32);
        let s = penalty(&t);
        if best.as_ref().map_or(true, |(b, _)| s < *b) { best = Some((s, t)); }
    }
    let g = best.unwrap().1;
    Some((n, g.m))
}

//! A small QR code reader for camera frames: versions 1-10, any error correction level, numeric,
//! alphanumeric and byte segments. It finds the three finder patterns, maps the grid through a
//! perspective transform (refined with the alignment pattern when there is one), samples the
//! modules, reads the format, unmasks, and repairs each block with Reed-Solomon decoding.
use crate::qr::{self, gf_mul, Ecc, ALNUM};

// ---- binarize: dark where a pixel is clearly below its neighbourhood's mean ----
fn binarize(g: &[u8], w: usize, h: usize) -> Vec<bool> {
    let mut sum = vec![0u32; (w + 1) * (h + 1)];
    for y in 0..h { let mut row = 0u32; for x in 0..w { row += g[y * w + x] as u32; sum[(y + 1) * (w + 1) + x + 1] = sum[y * (w + 1) + x + 1] + row; } }
    let r = (w.min(h) / 16).max(6);
    let mut out = vec![false; w * h];
    for y in 0..h { for x in 0..w {
        let (x0, y0, x1, y1) = (x.saturating_sub(r), y.saturating_sub(r), (x + r + 1).min(w), (y + r + 1).min(h));
        let s = sum[y1 * (w + 1) + x1] + sum[y0 * (w + 1) + x0] - sum[y0 * (w + 1) + x1] - sum[y1 * (w + 1) + x0];
        let mean = s as f32 / ((x1 - x0) * (y1 - y0)) as f32;
        out[y * w + x] = (g[y * w + x] as f32) < mean * 0.9 - 2.0;
    } }
    out
}

struct Img { w: usize, h: usize, b: Vec<bool> }
impl Img {
    fn at(&self, x: i32, y: i32) -> Option<bool> { (x >= 0 && y >= 0 && (x as usize) < self.w && (y as usize) < self.h).then(|| self.b[y as usize * self.w + x as usize]) }
}

// ---- finder patterns: runs of dark/light/dark/light/dark in 1:1:3:1:1 ----
fn ratio_ok(c: &[i32; 5]) -> bool {
    let total: i32 = c.iter().sum();
    if total < 7 || c.iter().any(|&v| v == 0) { return false; }
    let m = total as f32 / 7.0; let v = m / 1.6;
    ((c[0] as f32 - m).abs() < v) && ((c[1] as f32 - m).abs() < v) && ((c[2] as f32 - 3.0 * m).abs() < 3.0 * v)
        && ((c[3] as f32 - m).abs() < v) && ((c[4] as f32 - m).abs() < v)
}

/// From pixel (x, y) inside a pattern's centre run, count the five runs along one axis. Returns the centre of the
/// middle run along that axis (continuous coordinates: pixel i spans [i, i+1)) and the pattern's total length.
fn cross(img: &Img, x: i32, y: i32, dx: i32, dy: i32, max: i32) -> Option<(f32, i32)> {
    if img.at(x, y) != Some(true) { return None; }
    let p = if dx != 0 { x } else { y };
    let mut c = [0i32; 5];
    let mut k = 0;
    while img.at(x - k * dx, y - k * dy) == Some(true) { c[2] += 1; k += 1; if c[2] > max { return None; } }
    let back = c[2];
    while img.at(x - k * dx, y - k * dy) == Some(false) { c[1] += 1; k += 1; if c[1] > max { return None; } }
    while img.at(x - k * dx, y - k * dy) == Some(true) { c[0] += 1; k += 1; if c[0] > max { return None; } }
    let mut k = 1;
    while img.at(x + k * dx, y + k * dy) == Some(true) { c[2] += 1; k += 1; if c[2] > max { return None; } }
    while img.at(x + k * dx, y + k * dy) == Some(false) { c[3] += 1; k += 1; if c[3] > max { return None; } }
    while img.at(x + k * dx, y + k * dy) == Some(true) { c[4] += 1; k += 1; if c[4] > max { return None; } }
    if !ratio_ok(&c) { return None; }
    Some(((p - back + 1) as f32 + c[2] as f32 / 2.0, c.iter().sum()))
}

#[derive(Clone, Copy)]
struct Pt { x: f32, y: f32, m: f32, n: u32 }

fn finders(img: &Img) -> Vec<Pt> {
    let mut found: Vec<Pt> = Vec::new();
    let check = |c: &[i32; 5], end: usize, y: usize, found: &mut Vec<Pt>| {
        let total: i32 = c.iter().sum();
        let cx = end as f32 - c[4] as f32 - c[3] as f32 - c[2] as f32 / 2.0;
        let Some((cy, ty)) = cross(img, cx as i32, y as i32, 0, 1, total) else { return };
        let Some((cx2, tx)) = cross(img, cx as i32, cy as i32, 1, 0, total) else { return };
        let m = (tx + ty) as f32 / 14.0;
        match found.iter_mut().find(|p| (p.x - cx2).abs() < p.m * 2.0 && (p.y - cy).abs() < p.m * 2.0 && (p.m - m).abs() < p.m.max(m) * 0.5) {
            Some(p) => { let n = p.n as f32; p.x = (p.x * n + cx2) / (n + 1.0); p.y = (p.y * n + cy) / (n + 1.0); p.m = (p.m * n + m) / (n + 1.0); p.n += 1; }
            None => found.push(Pt { x: cx2, y: cy, m, n: 1 }),
        }
    };
    for y in 0..img.h {
        // states 0, 2, 4 count dark runs and 1, 3 light runs
        let (mut c, mut st) = ([0i32; 5], 0usize);
        for x in 0..img.w {
            if img.b[y * img.w + x] {
                if st & 1 == 1 { st += 1; }
                c[st] += 1;
            } else if st & 1 == 0 {
                if st == 4 {
                    if ratio_ok(&c) { check(&c, x, y, &mut found); c = [0; 5]; st = 0; }
                    else { c = [c[2], c[3], c[4], 1, 0]; st = 3; }
                } else { st += 1; c[st] += 1; }
            } else { c[st] += 1; }
        }
        if st == 4 && ratio_ok(&c) { check(&c, img.w, y, &mut found); }
    }
    found
}

// ---- perspective transform from module coordinates to image coordinates ----
fn solve(mut a: [[f64; 9]; 8]) -> Option<[f64; 8]> {
    for col in 0..8 {
        let piv = (col..8).max_by(|&i, &j| a[i][col].abs().partial_cmp(&a[j][col].abs()).unwrap())?;
        if a[piv][col].abs() < 1e-12 { return None; }
        a.swap(col, piv);
        for r in 0..8 { if r != col { let f = a[r][col] / a[col][col]; for k in col..9 { a[r][k] -= f * a[col][k]; } } }
    }
    let mut x = [0f64; 8]; for i in 0..8 { x[i] = a[i][8] / a[i][i]; } Some(x)
}
fn homography(src: [(f64, f64); 4], dst: [(f64, f64); 4]) -> Option<[f64; 8]> {
    let mut a = [[0f64; 9]; 8];
    for i in 0..4 {
        let ((x, y), (u, v)) = (src[i], dst[i]);
        a[2 * i] = [x, y, 1.0, 0.0, 0.0, 0.0, -u * x, -u * y, u];
        a[2 * i + 1] = [0.0, 0.0, 0.0, x, y, 1.0, -v * x, -v * y, v];
    }
    solve(a)
}
fn map(h: &[f64; 8], x: f64, y: f64) -> (f64, f64) {
    let d = h[6] * x + h[7] * y + 1.0;
    ((h[0] * x + h[1] * y + h[2]) / d, (h[3] * x + h[4] * y + h[5]) / d)
}

/// Look for an alignment pattern (dark centre, light ring, dark ring) near an estimate.
fn alignment(img: &Img, ex: f32, ey: f32, m: f32) -> Option<(f32, f32)> {
    let r = (m * 5.0) as i32; let mut best: Option<(f32, f32, f32)> = None;
    for dy in -r..=r { for dx in -r..=r {
        let (x, y) = (ex as i32 + dx, ey as i32 + dy);
        if img.at(x, y) != Some(true) { continue; }
        // light ring one module out, dark ring two modules out, in four directions
        let ok = [(1, 0), (-1, 0), (0, 1), (0, -1)].iter().all(|&(ux, uy)| {
            img.at(x + (ux as f32 * m) as i32, y + (uy as f32 * m) as i32) == Some(false)
                && img.at(x + (ux as f32 * 2.0 * m) as i32, y + (uy as f32 * 2.0 * m) as i32) == Some(true)
        });
        if ok { let d = (dx * dx + dy * dy) as f32; if best.map_or(true, |b| d < b.2) { best = Some((x as f32 + 0.5, y as f32 + 0.5, d)); } }
    } }
    // centre of the dark middle module: middle of its dark run across, then down, twice
    let (mut x, mut y) = best.map(|b| (b.0 as i32, b.1 as i32))?;
    let lim = (m * 1.6) as i32 + 1;
    let mut fx = x as f32 + 0.5; let mut fy = y as f32 + 0.5;
    for _ in 0..2 {
        let (mut a, mut b) = (0, 0);
        while a < lim && img.at(x - a - 1, y) == Some(true) { a += 1; }
        while b < lim && img.at(x + b + 1, y) == Some(true) { b += 1; }
        fx = x as f32 + 0.5 + (b - a) as f32 / 2.0; x = fx as i32;
        let (mut a, mut b) = (0, 0);
        while a < lim && img.at(x, y - a - 1) == Some(true) { a += 1; }
        while b < lim && img.at(x, y + b + 1) == Some(true) { b += 1; }
        fy = y as f32 + 0.5 + (b - a) as f32 / 2.0; y = fy as i32;
    }
    Some((fx, fy))
}

// ---- Reed-Solomon decoding over GF(256), generator roots alpha^0 .. alpha^(n-1) ----
fn gf_pow2(e: usize) -> u8 { let mut x = 1u8; for _ in 0..e % 255 { x = gf_mul(x, 2); } x }
fn gf_inv(x: u8) -> u8 { (1..=255u16).map(|y| y as u8).find(|&y| gf_mul(x, y) == 1).unwrap_or(0) }
fn poly_eval(p: &[u8], x: u8) -> u8 { p.iter().rev().fold(0u8, |acc, &c| gf_mul(acc, x) ^ c) }   // p[i] = coefficient of x^i

fn rs_correct(cw: &mut [u8], nsym: usize) -> bool {
    let n = cw.len();
    let syn: Vec<u8> = (0..nsym).map(|j| { let a = gf_pow2(j); cw.iter().fold(0u8, |s, &b| gf_mul(s, a) ^ b) }).collect();
    if syn.iter().all(|&s| s == 0) { return true; }
    // Berlekamp-Massey: error locator lambda
    let (mut c, mut b) = (vec![1u8], vec![1u8]);
    let (mut l, mut m, mut bb) = (0usize, 1usize, 1u8);
    for i in 0..nsym {
        let mut d = syn[i];
        for j in 1..=l { if j < c.len() { d ^= gf_mul(c[j], syn[i - j]); } }
        if d == 0 { m += 1; continue; }
        let coef = gf_mul(d, gf_inv(bb));
        let mut nc = c.clone(); if nc.len() < b.len() + m { nc.resize(b.len() + m, 0); }
        for (k, &bv) in b.iter().enumerate() { nc[k + m] ^= gf_mul(coef, bv); }
        if 2 * l <= i { b = c; l = i + 1 - l; bb = d; m = 1; } else { m += 1; }
        c = nc;
    }
    if l * 2 > nsym { return false; }
    // Chien search: error at codeword index n-1-k when lambda(alpha^-k) = 0
    let mut pos = Vec::new();
    for k in 0..n { if poly_eval(&c, gf_pow2(255 - k % 255)) == 0 { pos.push(k); } }
    if pos.len() != l { return false; }
    // Forney: omega = S(x) * lambda(x) mod x^nsym; e = X * omega(X^-1) / lambda'(X^-1)
    let mut omega = vec![0u8; nsym];
    for (i, &s) in syn.iter().enumerate() { for (j, &cv) in c.iter().enumerate() { if i + j < nsym { omega[i + j] ^= gf_mul(s, cv); } } }
    let deriv: Vec<u8> = (1..c.len()).map(|i| if i % 2 == 1 { c[i] } else { 0 }).collect();
    for &k in &pos {
        let x = gf_pow2(k); let xi = gf_inv(x);
        let den = poly_eval(&deriv, xi);
        if den == 0 { return false; }
        let e = gf_mul(gf_mul(x, poly_eval(&omega, xi)), gf_inv(den));
        cw[n - 1 - k] ^= e;
    }
    (0..nsym).all(|j| { let a = gf_pow2(j); cw.iter().fold(0u8, |s, &b| gf_mul(s, a) ^ b) == 0 })
}

// ---- format information ----
fn format_code(data: u32) -> u32 { let mut rem = data; for _ in 0..10 { rem = (rem << 1) ^ ((rem >> 9) * 0x537); } (data << 10 | rem) ^ 0x5412 }

/// Read a sampled module grid (true = dark) of side n: the decoded text, if it is a valid symbol.
fn read_grid(n: usize, m: &[bool]) -> Option<Vec<u8>> {
    if n < 21 || (n - 17) % 4 != 0 || (n - 17) / 4 > 10 { return None; }
    let v = (n - 17) / 4;
    let at = |x: usize, y: usize| m[y * n + x];
    let mut f1 = 0u32; let mut f2 = 0u32;
    let p1: Vec<(usize, usize)> = (0..6).map(|i| (8, i)).chain([(8, 7), (8, 8), (7, 8)]).chain((9..15).map(|i| (14 - i, 8))).collect();
    let p2: Vec<(usize, usize)> = (0..8).map(|i| (n - 1 - i, 8)).chain((8..15).map(|i| (8, n - 15 + i))).collect();
    for (i, &(x, y)) in p1.iter().enumerate() { if at(x, y) { f1 |= 1 << i; } }
    for (i, &(x, y)) in p2.iter().enumerate() { if at(x, y) { f2 |= 1 << i; } }
    let (data, dist) = (0..32u32).map(|d| (d, (format_code(d) ^ f1).count_ones().min((format_code(d) ^ f2).count_ones()))).min_by_key(|&(_, e)| e)?;
    if dist > 3 { return None; }
    let ecc = match data >> 3 { 0b00 => Ecc::M, 0b10 => Ecc::H, 0b01 => Ecc::L, _ => Ecc::Q };
    let mask = (data & 7) as u8;
    let g = qr::layout(v, ecc);
    let order = qr::zigzag(&g);
    let raw = qr::raw_modules(v) / 8;
    let mut cw = vec![0u8; raw];
    for (i, &p) in order.iter().enumerate().take(raw * 8) {
        let (x, y) = (p % n, p / n);
        let bit = m[p] ^ qr::masked(mask, x, y);
        if bit { cw[i >> 3] |= 0x80 >> (i & 7); }
    }
    // undo the interleaving, repair each block, join the data
    let (nb, eccw) = (ecc.blocks(v), ecc.per_block(v));
    let short = nb - raw % nb; let short_len = raw / nb;
    let lens: Vec<usize> = (0..nb).map(|i| short_len - eccw + if i < short { 0 } else { 1 }).collect();
    let mut blocks: Vec<Vec<u8>> = lens.iter().map(|&l| Vec::with_capacity(l + eccw)).collect();
    let mut k = 0;
    for i in 0..=short_len - eccw { for (bi, b) in blocks.iter_mut().enumerate() { if i < lens[bi] { b.push(cw[k]); k += 1; } } }
    for _ in 0..eccw { for b in blocks.iter_mut() { b.push(cw[k]); k += 1; } }
    let mut data_bytes = Vec::new();
    for (bi, b) in blocks.iter_mut().enumerate() { if !rs_correct(b, eccw) { return None; } data_bytes.extend_from_slice(&b[..lens[bi]]); }
    // segments
    let mut pos = 0usize;
    let mut read = |len: usize| -> Option<u32> { if pos + len > data_bytes.len() * 8 { return None; } let mut r = 0u32; for _ in 0..len { r = r << 1 | ((data_bytes[pos >> 3] >> (7 - (pos & 7))) & 1) as u32; pos += 1; } Some(r) };
    let mut out = Vec::new();
    loop {
        let mode = match read(4) { Some(x) => x, None => break };
        match mode {
            0 => break,
            1 => { let mut cnt = read(if v < 10 { 10 } else { 12 })?; while cnt >= 3 { let d = read(10)?; out.extend(format!("{d:03}").bytes()); cnt -= 3; }
                   if cnt == 2 { let d = read(7)?; out.extend(format!("{d:02}").bytes()); } else if cnt == 1 { let d = read(4)?; out.extend(format!("{d}").bytes()); } }
            2 => { let mut cnt = read(if v < 10 { 9 } else { 11 })?; while cnt >= 2 { let d = read(11)?; out.push(*ALNUM.get((d / 45) as usize)?); out.push(*ALNUM.get((d % 45) as usize)?); cnt -= 2; }
                   if cnt == 1 { let d = read(6)?; out.push(*ALNUM.get(d as usize)?); } }
            4 => { let cnt = read(if v < 10 { 8 } else { 16 })?; for _ in 0..cnt { out.push(read(8)? as u8); } }
            7 => { read(8)?; }
            _ => break,
        }
    }
    Some(out)
}

/// Read a QR code from an 8-bit greyscale image, row by row.
pub fn read(gray: &[u8], w: usize, h: usize) -> Option<Vec<u8>> {
    if gray.len() < w * h || w < 21 || h < 21 { return None; }
    let img = Img { w, h, b: binarize(gray, w, h) };
    let mut f = finders(&img);
    f.sort_by(|a, b| b.n.cmp(&a.n));
    f.truncate(8);
    if f.len() < 3 { return None; }
    // best triple: similar module sizes and a right angle at the corner
    let mut best: Option<(f32, [Pt; 3])> = None;
    for i in 0..f.len() { for j in i + 1..f.len() { for k in j + 1..f.len() {
        let t = [f[i], f[j], f[k]];
        let ms = (t[0].m + t[1].m + t[2].m) / 3.0;
        if t.iter().any(|p| (p.m - ms).abs() > ms * 0.5) { continue; }
        let d = |a: &Pt, b: &Pt| (a.x - b.x).powi(2) + (a.y - b.y).powi(2);
        let sides = [d(&t[1], &t[2]), d(&t[0], &t[2]), d(&t[0], &t[1])];
        let c = (0..3).max_by(|&a, &b| sides[a].partial_cmp(&sides[b]).unwrap()).unwrap();   // the corner faces the longest side
        let (o1, o2) = ((c + 1) % 3, (c + 2) % 3);
        let score = (sides[o1] + sides[o2] - sides[c]).abs() / sides[c] + (sides[o1] - sides[o2]).abs() / sides[c];
        if best.as_ref().map_or(true, |b| score < b.0) { best = Some((score, [t[c], t[o1], t[o2]])); }
    } } }
    let (_, [tl, mut tr, mut bl]) = best?;
    // orientation: with y pointing down, top-right x bottom-left (relative to top-left) is positive
    if (tr.x - tl.x) * (bl.y - tl.y) - (tr.y - tl.y) * (bl.x - tl.x) < 0.0 { std::mem::swap(&mut tr, &mut bl); }
    let ms = (tl.m + tr.m + bl.m) / 3.0;
    let dist = |a: &Pt, b: &Pt| ((a.x - b.x).powi(2) + (a.y - b.y).powi(2)).sqrt();
    let est = ((dist(&tl, &tr) + dist(&tl, &bl)) / 2.0 / ms).round() as i32 + 7;
    let mut dims: Vec<i32> = Vec::new();
    for d in [est, est + 1, est - 1, est + 2, est - 2, est + 4, est - 4] { let d = d - ((d - 17).rem_euclid(4)) ; if !dims.contains(&d) && (21..=57).contains(&d) { dims.push(d); } }
    let try_grid = |n: usize, p4: (f64, f64), dst4: (f64, f64)| -> Option<Vec<u8>> {
        let c3 = n as f64 - 3.5;
        let h = homography([(3.5, 3.5), (c3, 3.5), (3.5, c3), p4], [(tl.x as f64, tl.y as f64), (tr.x as f64, tr.y as f64), (bl.x as f64, bl.y as f64), dst4])?;
        let mut grid = vec![false; n * n];
        for y in 0..n { for x in 0..n {
            let (px, py) = map(&h, x as f64 + 0.5, y as f64 + 0.5);
            grid[y * n + x] = img.at(px.floor() as i32, py.floor() as i32).unwrap_or(false);
        } }
        read_grid(n, &grid)
    };
    for dim in dims {
        let n = dim as usize;
        let brx = tr.x - tl.x + bl.x; let bry = tr.y - tl.y + bl.y;
        // fourth point: the bottom-right alignment pattern when the version has one, else the corner finder-centre position
        let (p4, ex, ey) = if n > 21 {
            let corr = 1.0 - 3.0 / (n as f32 - 7.0);
            ((n as f64 - 6.5, n as f64 - 6.5), tl.x + corr * (brx - tl.x), tl.y + corr * (bry - tl.y))
        } else { ((n as f64 - 3.5, n as f64 - 3.5), brx, bry) };
        if n > 21 { if let Some((ax, ay)) = alignment(&img, ex, ey, ms) { if let Some(t) = try_grid(n, p4, (ax as f64, ay as f64)) { return Some(t); } } }
        for r in 0..=4i32 { for dy in -r..=r { for dx in -r..=r {
            if dx.abs() != r && dy.abs() != r { continue; }   // rings outward from the estimate, half a module apart
            let (qx, qy) = (ex as f64 + dx as f64 * ms as f64 * 0.5, ey as f64 + dy as f64 * ms as f64 * 0.5);
            if let Some(t) = try_grid(n, p4, (qx, qy)) { return Some(t); }
        } } }
    }
    None
}

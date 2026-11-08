// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! QR codes (ISO/IEC 18004) for invites: byte mode at error correction level M, versions 1 to 10
//! (up to 213 bytes).

pub const MAX_VERSION: usize = 10;
pub const MAX_SIZE: usize = MAX_VERSION * 4 + 17;

/// Level M: each version's error correction bytes per block, and its blocks.
const ECC_PER_BLOCK: [usize; MAX_VERSION + 1] = [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26];
const BLOCKS: [usize; MAX_VERSION + 1] = [0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5];
const GF_POLY: u32 = 0x11d;
const FORMAT_GEN: i64 = 0x537;
const FORMAT_ECC: u32 = 10;
const FORMAT_BITS: usize = 15;
const FORMAT_MASK: i64 = 0x5412;
const VERSION_GEN: i64 = 0x1f25;
const VERSION_ECC: u32 = 12;
const VERSION_BITS: usize = 18;
/// From this version on, the version is drawn twice beside the finders.
const VERSION_SHOWN: usize = 7;
/// The row and column the timing patterns run along, and the format's, past the top left
/// finder and its separator.
const TIMING: usize = 6;
const FORMAT_LINE: usize = 8;
const MODE_BYTE: u32 = 4;
const PAD_A: u32 = 0xec;
const PAD_B: u32 = 0x11;

/// A QR code: `size` modules a side, each dark or light. A scanner also needs 4 light modules
/// around it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Qr {
    pub size: usize,
    dark: Vec<bool>,
}

impl Qr {
    pub fn dark(&self, x: usize, y: usize) -> bool {
        self.dark[y * self.size + x]
    }

    /// Row by row from the top, "1" for dark, as the JSON interface gives it.
    pub fn rows(&self) -> Vec<String> {
        (0..self.size)
            .map(|y| (0..self.size).map(|x| if self.dark(x, y) { '1' } else { '0' }).collect())
            .collect()
    }
}

struct Grid {
    size: usize,
    dark: Vec<bool>,
    /// Finders, timing, alignment, format and version: not data.
    func: Vec<bool>,
}

/// The modules left for data and error correction once the function patterns are drawn.
fn raw_modules(ver: usize) -> usize {
    let mut n = (16 * ver + 128) * ver + 64;
    if ver >= 2 {
        let align = ver / 7 + 2;
        n -= (25 * align - 10) * align - 55;
        if ver >= VERSION_SHOWN {
            n -= 2 * VERSION_BITS;
        }
    }
    n
}

/// The bits a byte mode segment's length takes.
fn length_bits(ver: usize) -> u32 {
    if ver < 10 { 8 } else { 16 }
}

/// GF(256) with the polynomial 0x11d.
fn gf_mul(x: u8, y: u8) -> u8 {
    let mut z: u32 = 0;
    for i in (0..8).rev() {
        z = (z << 1) ^ ((z >> 7) * GF_POLY);
        z ^= u32::from((y >> i) & 1) * u32::from(x);
    }
    z as u8
}

/// The Reed-Solomon generator of this degree, highest power first and without its leading 1.
fn rs_divisor(degree: usize) -> Vec<u8> {
    let mut out = vec![0u8; degree];
    out[degree - 1] = 1;
    let mut root = 1u8;
    for _ in 0..degree {
        for j in 0..degree {
            out[j] = gf_mul(out[j], root);
            if j + 1 < degree {
                out[j] ^= out[j + 1];
            }
        }
        root = gf_mul(root, 2);
    }
    out
}

fn rs_remainder(data: &[u8], div: &[u8]) -> Vec<u8> {
    let degree = div.len();
    let mut out = vec![0u8; degree];
    for &d in data {
        let factor = d ^ out[0];
        out.remove(0);
        out.push(0);
        for j in 0..degree {
            out[j] ^= gf_mul(div[j], factor);
        }
    }
    out
}

/// data, then the remainder of it divided by generator, which is ecc bits long.
fn bch(data: i64, generator: i64, ecc: u32) -> i64 {
    let mut rem = data;
    for _ in 0..ecc {
        rem = (rem << 1) ^ ((rem >> (ecc - 1)) * generator);
    }
    data << ecc | rem
}

fn append(buf: &mut [u8], bit: &mut usize, v: u32, n: u32) {
    for k in (0..n).rev() {
        buf[*bit >> 3] |= (((v >> k) & 1) << (7 - (*bit & 7))) as u8;
        *bit += 1;
    }
}

impl Grid {
    fn put(&mut self, x: usize, y: usize, dark: bool) {
        self.dark[y * self.size + x] = dark;
        self.func[y * self.size + x] = true;
    }

    fn draw_format(&mut self, mask: i64) {
        // Level M's two bits are 00.
        let bits = bch(mask, FORMAT_GEN, FORMAT_ECC) ^ FORMAT_MASK;
        let b = |i: usize| (bits >> i) & 1 != 0;
        let s = self.size;
        for i in 0..=5 {
            self.put(FORMAT_LINE, i, b(i));
        }
        self.put(FORMAT_LINE, 7, b(6));
        self.put(FORMAT_LINE, FORMAT_LINE, b(7));
        self.put(7, FORMAT_LINE, b(8));
        for i in 9..FORMAT_BITS {
            self.put(FORMAT_BITS - 1 - i, FORMAT_LINE, b(i));
        }
        for i in 0..8 {
            self.put(s - 1 - i, FORMAT_LINE, b(i));
        }
        for i in 8..FORMAT_BITS {
            self.put(FORMAT_LINE, s - FORMAT_BITS + i, b(i));
        }
        self.put(FORMAT_LINE, s - 8, true);
    }

    fn draw_version(&mut self, ver: usize) {
        let bits = bch(ver as i64, VERSION_GEN, VERSION_ECC);
        for i in 0..VERSION_BITS {
            let bit = (bits >> i) & 1 != 0;
            let (a, b) = (self.size - 11 + i % 3, i / 3);
            self.put(a, b, bit);
            self.put(b, a, bit);
        }
    }

    fn draw_functions(&mut self, ver: usize) {
        let s = self.size as i64;
        for i in 0..self.size {
            self.put(TIMING, i, i % 2 == 0);
            self.put(i, TIMING, i % 2 == 0);
        }
        // The finders, with the light separator around each.
        let dist = |dx: i64, dy: i64| dx.abs().max(dy.abs());
        for (cx, cy) in [(3, 3), (s - 4, 3), (3, s - 4)] {
            for dy in -4..=4 {
                for dx in -4..=4 {
                    let (x, y, d) = (cx + dx, cy + dy, dist(dx, dy));
                    if (0..s).contains(&x) && (0..s).contains(&y) {
                        self.put(x as usize, y as usize, d != 2 && d != 4);
                    }
                }
            }
        }
        let mut pos = [0i64; 7];
        let mut n = 0;
        if ver > 1 {
            n = ver / 7 + 2;
            let step = ((ver * 4 + n * 2 + 1) / (n * 2 - 2) * 2) as i64;
            pos[0] = TIMING as i64;
            let mut p = s - 7;
            for i in (1..n).rev() {
                pos[i] = p;
                p -= step;
            }
        }
        for i in 0..n {
            for j in 0..n {
                if (i == 0 && j == 0) || (i == 0 && j == n - 1) || (i == n - 1 && j == 0) {
                    continue;
                }
                for dy in -2..=2 {
                    for dx in -2..=2 {
                        self.put((pos[i] + dx) as usize, (pos[j] + dy) as usize, dist(dx, dy) != 1);
                    }
                }
            }
        }
        // Reserved here, and drawn again once the mask is chosen.
        self.draw_format(0);
        if ver >= VERSION_SHOWN {
            self.draw_version(ver);
        }
    }

    fn apply_mask(&mut self, m: usize) {
        let s = self.size;
        for y in 0..s {
            for x in 0..s {
                if self.func[y * s + x] {
                    continue;
                }
                let inv = match m {
                    0 => (x + y) % 2 == 0,
                    1 => y % 2 == 0,
                    2 => x % 3 == 0,
                    3 => (x + y) % 3 == 0,
                    4 => (x / 3 + y / 2) % 2 == 0,
                    5 => x * y % 2 + x * y % 3 == 0,
                    6 => (x * y % 2 + x * y % 3) % 2 == 0,
                    _ => ((x + y) % 2 + x * y % 3) % 2 == 0,
                };
                self.dark[y * s + x] ^= inv;
            }
        }
    }

    /// The standard's penalties: long runs, 2x2 blocks, shapes like a finder, and an uneven
    /// balance of dark and light. The mask with the least is the easiest to scan.
    fn penalty(&self) -> i64 {
        const FINDER_A: [bool; 11] = [true, false, true, true, true, false, true, false, false, false, false];
        const FINDER_B: [bool; 11] = [false, false, false, false, true, false, true, true, true, false, true];
        let s = self.size;
        let mut score: i64 = 0;
        for pass in 0..2 {
            for a in 0..s {
                let line: Vec<bool> = (0..s)
                    .map(|b| if pass == 1 { self.dark[b * s + a] } else { self.dark[a * s + b] })
                    .collect();
                let mut run = 1i64;
                for b in 1..=s {
                    if b < s && line[b] == line[b - 1] {
                        run += 1;
                        continue;
                    }
                    if run >= 5 {
                        score += 3 + run - 5;
                    }
                    run = 1;
                }
                for w in line.windows(11) {
                    if w == FINDER_A || w == FINDER_B {
                        score += 40;
                    }
                }
            }
        }
        let mut dark: i64 = 0;
        for y in 0..s {
            for x in 0..s {
                let c = self.dark[y * s + x];
                dark += i64::from(c);
                if x + 1 < s
                    && y + 1 < s
                    && c == self.dark[y * s + x + 1]
                    && c == self.dark[(y + 1) * s + x]
                    && c == self.dark[(y + 1) * s + x + 1]
                {
                    score += 3;
                }
            }
        }
        let total = (s * s) as i64;
        let k = ((dark * 20 - total * 10).abs() + total - 1) / total - 1;
        score + k * 10
    }
}

/// The QR code for text, or None if it doesn't fit in version 10.
pub fn encode(text: &str) -> Option<Qr> {
    let t = text.as_bytes();
    let len = t.len();
    let (ver, cap) = (1..=MAX_VERSION).find_map(|ver| {
        let cap = raw_modules(ver) / 8 - ECC_PER_BLOCK[ver] * BLOCKS[ver];
        (len <= cap && 4 + length_bits(ver) as usize + 8 * len <= cap * 8).then_some((ver, cap))
    })?;

    // Byte mode, the length, the bytes, a terminator, then 0xec 0x11 ... to fill it.
    let raw = raw_modules(ver) / 8;
    let mut data = vec![0u8; raw];
    let mut bit = 0usize;
    append(&mut data, &mut bit, MODE_BYTE, 4);
    append(&mut data, &mut bit, len as u32, length_bits(ver));
    for &c in t {
        append(&mut data, &mut bit, u32::from(c), 8);
    }
    bit += (cap * 8 - bit).min(4);
    bit = (bit + 7) & !7;
    let mut pad = PAD_A;
    while bit < cap * 8 {
        append(&mut data, &mut bit, pad, 8);
        pad ^= PAD_A ^ PAD_B;
    }

    // Split into blocks, each with its error correction, then interleaved a byte at a time.
    let (nb, ecc_len) = (BLOCKS[ver], ECC_PER_BLOCK[ver]);
    let short_n = nb - raw % nb;
    let short_len = raw / nb - ecc_len;
    let div = rs_divisor(ecc_len);
    let mut blocks = Vec::new();
    let mut off = 0;
    for b in 0..nb {
        let blen = short_len + usize::from(b >= short_n);
        let blk = &data[off..off + blen];
        blocks.push((blk, rs_remainder(blk, &div)));
        off += blen;
    }
    let mut all = Vec::with_capacity(raw);
    for c in 0..=short_len {
        for (blk, _) in &blocks {
            if c < blk.len() {
                all.push(blk[c]);
            }
        }
    }
    for c in 0..ecc_len {
        for (_, ecc) in &blocks {
            all.push(ecc[c]);
        }
    }

    let s = ver * 4 + 17;
    let mut g = Grid {
        size: s,
        dark: vec![false; s * s],
        func: vec![false; s * s],
    };
    g.draw_functions(ver);
    // Up and down two columns at a time from the right, skipping the vertical timing pattern.
    let mut i = 0;
    let mut right = s as i64 - 1;
    while right >= 1 {
        if right == TIMING as i64 {
            right = TIMING as i64 - 1;
        }
        let r = right as usize;
        for v in 0..s {
            for j in 0..2 {
                let x = r - j;
                let up = (r + 1) & 2 == 0;
                let y = if up { s - 1 - v } else { v };
                if g.func[y * s + x] || i >= raw * 8 {
                    continue;
                }
                g.dark[y * s + x] = (all[i >> 3] >> (7 - (i & 7))) & 1 != 0;
                i += 1;
            }
        }
        right -= 2;
    }
    let mut best = (0, i64::MAX);
    for m in 0..8 {
        g.apply_mask(m);
        g.draw_format(m as i64);
        let score = g.penalty();
        if score < best.1 {
            best = (m, score);
        }
        g.apply_mask(m);
    }
    g.apply_mask(best.0);
    g.draw_format(best.0 as i64);
    Some(Qr { size: s, dark: g.dark })
}

// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Pictures cleaned before they're offered: a PNG, JPEG or GIF without what could tell where,
//! when or with what it was made.
//!
//! Whatever is in a picture is the sender's own, but it's still read as untrusted: every length is
//! checked before it's used, and anything that doesn't add up fails the clean rather than being
//! copied through.

/// Exif's GPS: where it was taken.
pub const CLEAN_LOCATION: u32 = 1;
/// The rest of the Exif: make, model, settings, serial numbers, when.
pub const CLEAN_CAMERA: u32 = 2;
/// XMP: editing history, and sometimes the place.
pub const CLEAN_XMP: u32 = 4;
/// IPTC and Photoshop's: captions, names, places.
pub const CLEAN_IPTC: u32 = 8;
/// Comments, and PNG's text.
pub const CLEAN_COMMENT: u32 = 16;
/// More pictures or a video in it or after it: thumbnails, MPF, motion photos.
pub const CLEAN_EXTRA: u32 = 32;
/// PNG's tIME: when it was last changed.
pub const CLEAN_TIME: u32 = 64;
/// Other segments, chunks or extensions.
pub const CLEAN_OTHER: u32 = 128;
/// Noise added (a baseline JPEG).
pub const CLEAN_NOISE: u32 = 256;
pub const CLEAN_SEED_LEN: usize = 16;
/// [`cannot`] needs this many bytes of a file's start.
pub const CLEAN_HEAD: usize = 16;

/// The largest picture chat takes, in pixels.
pub const IMAGE_MAX_PIXELS: u64 = 120_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Png,
    Jpeg,
    Gif,
}

/// What a file is from its first bytes, if it's a picture chat can clean and show.
pub fn kind(data: &[u8]) -> Option<Kind> {
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some(Kind::Png)
    } else if data.starts_with(b"\xff\xd8\xff") {
        Some(Kind::Jpeg)
    } else if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        Some(Kind::Gif)
    } else {
        None
    }
}

impl Kind {
    /// The name a picture whose own name tells too much is offered under.
    pub fn plain_name(self) -> &'static str {
        match self {
            Kind::Jpeg => "photo.jpg",
            Kind::Png => "image.png",
            Kind::Gif => "image.gif",
        }
    }
}

/// What [`clean`] took out of a picture, as the user is told it.
pub fn describe(took: u32) -> Vec<&'static str> {
    [
        (CLEAN_LOCATION, "where it was taken"),
        (CLEAN_CAMERA, "camera details and when"),
        (CLEAN_XMP, "editing details"),
        (CLEAN_IPTC, "captions and names"),
        (CLEAN_COMMENT, "comments"),
        (CLEAN_EXTRA, "a picture or video tucked in with it"),
        (CLEAN_TIME, "when it was saved"),
        (CLEAN_OTHER, "other hidden data"),
    ]
    .into_iter()
    .filter(|(f, _)| took & f != 0)
    .map(|(_, w)| w)
    .collect()
}

/// A PNG, JPEG or GIF without what could tell where, when or with what it was made. Only what
/// drawing it needs is kept: in a JPEG its tables and scans, a JFIF header, an ICC colour profile
/// and Adobe's colour marker, and an Orientation other than 1, alone, so a portrait photo still
/// shows upright. With noise, a baseline JPEG also has some of its coefficients moved one step
/// within their size class, chosen from seed: the same symbols, so the same tables encode them,
/// and nothing a viewer can see, but no two copies are the same bytes or pixels.
///
/// The cleaned picture and what was taken out or done (`CLEAN_` flags), or None if it isn't a
/// picture chat can clean, or is damaged.
pub fn clean(input: &[u8], noise: bool, seed: &[u8; CLEAN_SEED_LEN]) -> Option<(Vec<u8>, u32)> {
    let mut o = Vec::with_capacity(input.len() + input.len() / 8 + 64);
    let took = match kind(input)? {
        Kind::Jpeg => clean_jpeg(input, noise, seed, &mut o)?,
        Kind::Png => clean_png(input, &mut o)?,
        Kind::Gif => clean_gif(input, &mut o)?,
    };
    Some((o, took))
}

// ---- showing one ----

/// A picture made small enough to show: `w` × `h` pixels of red, green and blue, row by row from
/// the top. `src_w` and `src_h` are the picture's own size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Thumb {
    pub w: u32,
    pub h: u32,
    pub src_w: u32,
    pub src_h: u32,
    pub rgb: Vec<u8>,
}

/// The most memory a picture may take while it's decoded.
const DECODE_MAX_ALLOC: u64 = 512 * 1024 * 1024;

/// Decodes a PNG, JPEG or GIF (its first frame) from a peer and scales it to fit in `max_w` by
/// `max_h`, keeping its shape and turning it upright, with transparency drawn over `bg`. The
/// decoders are memory-safe Rust (image-rs), told the format from the picture's first bytes and
/// limited in size, so a picture made to attack them can at worst fail to show.
pub fn decode(data: &[u8], max_w: u32, max_h: u32, bg: [u8; 3]) -> Result<Thumb, String> {
    use image::{ImageDecoder, ImageFormat, ImageReader};
    let format = match kind(data) {
        Some(Kind::Png) => ImageFormat::Png,
        Some(Kind::Jpeg) => ImageFormat::Jpeg,
        Some(Kind::Gif) => ImageFormat::Gif,
        None => return Err("not a PNG, JPEG or GIF image".into()),
    };
    let mut reader = ImageReader::with_format(std::io::Cursor::new(data), format);
    let mut limits = image::Limits::default();
    limits.max_alloc = Some(DECODE_MAX_ALLOC);
    reader.limits(limits);
    let mut dec = reader.into_decoder().map_err(|e| format!("damaged: {e}"))?;
    let (src_w, src_h) = dec.dimensions();
    if src_w == 0 || src_h == 0 || u64::from(src_w) * u64::from(src_h) > IMAGE_MAX_PIXELS {
        return Err("too big to show".into());
    }
    let orientation = dec.orientation().unwrap_or(image::metadata::Orientation::NoTransforms);
    let mut img = image::DynamicImage::from_decoder(dec).map_err(|e| format!("damaged: {e}"))?;
    img.apply_orientation(orientation);
    let (w, h) = (img.width(), img.height());
    let (max_w, max_h) = (max_w.max(1), max_h.max(1));
    if w > max_w || h > max_h {
        img = img.thumbnail(max_w, max_h);
    }
    let rgba = img.to_rgba8();
    let mut rgb = Vec::with_capacity(rgba.len() / 4 * 3);
    for px in rgba.pixels() {
        let a = u32::from(px[3]);
        for c in 0..3 {
            rgb.push(((u32::from(px[c]) * a + u32::from(bg[c]) * (255 - a) + 127) / 255) as u8);
        }
    }
    Ok(Thumb {
        w: rgba.width(),
        h: rgba.height(),
        src_w,
        src_h,
        rgb,
    })
}

// ---- JPEG ----

const M_TEM: u8 = 0x01;
const M_SOF0: u8 = 0xC0;
const M_SOF1: u8 = 0xC1;
const M_DHT: u8 = 0xC4;
const M_DAC: u8 = 0xCC;
const M_SOF15: u8 = 0xCF;
const M_RST0: u8 = 0xD0;
const M_RST7: u8 = 0xD7;
const M_EOI: u8 = 0xD9;
const M_SOS: u8 = 0xDA;
const M_DQT: u8 = 0xDB;
const M_DNL: u8 = 0xDC;
const M_DRI: u8 = 0xDD;
const M_DHP: u8 = 0xDE;
const M_EXP: u8 = 0xDF;
const M_APP0: u8 = 0xE0;
const M_APP1: u8 = 0xE1;
const M_APP2: u8 = 0xE2;
const M_APP13: u8 = 0xED;
const M_APP14: u8 = 0xEE;
const M_COM: u8 = 0xFE;
const COEFS: usize = 64;
const EXIF_HEAD: usize = 6;
const TIFF_HEAD: usize = 8;
const IFD_ENTRY: usize = 12;
const TAG_ORIENTATION: u32 = 0x0112;
const TAG_GPS: u32 = 0x8825;
const TIFF_SHORT: u32 = 3;
const ORIENT_MAX: u32 = 8;
/// One in this many coefficients that can move does.
const NOISE_EVERY: u32 = 8;
/// More blocks than the largest picture chat takes could have mean a damaged header.
const BLOCKS_MAX: u64 = IMAGE_MAX_PIXELS / 16;

/// The next marker at *i, past any fill bytes, with *i after it.
fn next_marker(p: &[u8], i: &mut usize) -> Option<u8> {
    if *i + 1 >= p.len() || p[*i] != 0xFF {
        return None;
    }
    while *i + 1 < p.len() && p[*i + 1] == 0xFF {
        *i += 1;
    }
    if *i + 1 >= p.len() {
        return None;
    }
    let m = p[*i + 1];
    *i += 2;
    Some(m)
}

/// The length of the segment at `at` (its two length bytes included), if it's all there.
fn seg_len(p: &[u8], at: usize) -> Option<usize> {
    if p.len() - at < 2 {
        return None;
    }
    let l = usize::from(p[at]) << 8 | usize::from(p[at + 1]);
    (l >= 2 && l <= p.len() - at).then_some(l)
}

/// Where the entropy-coded data starting at i ends: at the first marker that isn't a restart or
/// a stuffed byte.
fn ecs_end(p: &[u8], mut i: usize) -> usize {
    while i < p.len() {
        if p[i] != 0xFF || i + 1 >= p.len() {
            i += 1;
            continue;
        }
        let nx = p[i + 1];
        if nx == 0x00 || (M_RST0..=M_RST7).contains(&nx) {
            i += 2;
            continue;
        }
        if nx == 0xFF {
            i += 1;
            continue;
        }
        return i;
    }
    p.len()
}

fn rd16(q: &[u8], le: bool) -> u32 {
    if le {
        u32::from(q[0]) | u32::from(q[1]) << 8
    } else {
        u32::from(q[0]) << 8 | u32::from(q[1])
    }
}

fn rd32(q: &[u8], le: bool) -> u32 {
    let b = [q[0], q[1], q[2], q[3]];
    if le { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) }
}

/// The Orientation in the first IFD of an Exif segment (1 if it has none), and whether it has GPS.
fn exif_orientation(d: &[u8], gps: &mut bool) -> u32 {
    if d.len() < EXIF_HEAD + TIFF_HEAD || &d[..EXIF_HEAD] != b"Exif\0\0" {
        return 1;
    }
    let t = &d[EXIF_HEAD..];
    let tn = t.len();
    let le = &t[..2] == b"II";
    if !le && &t[..2] != b"MM" {
        return 1;
    }
    if rd16(&t[2..], le) != 42 {
        return 1;
    }
    let ifd = rd32(&t[4..], le) as usize;
    if ifd > tn - 2 {
        return 1;
    }
    let count = rd16(&t[ifd..], le) as usize;
    let mut orient = 1;
    for k in 0..count {
        let e = ifd + 2 + k * IFD_ENTRY;
        if e + IFD_ENTRY > tn {
            break;
        }
        let (tag, ty) = (rd16(&t[e..], le), rd16(&t[e + 2..], le));
        if tag == TAG_GPS {
            *gps = true;
        }
        if tag == TAG_ORIENTATION && ty == TIFF_SHORT && rd32(&t[e + 4..], le) == 1 {
            let v = rd16(&t[e + 8..], le);
            if (1..=ORIENT_MAX).contains(&v) {
                orient = v;
            }
        }
    }
    orient
}

/// An Exif segment with nothing in it but the Orientation.
fn put_orientation(o: &mut Vec<u8>, orient: u32) {
    #[rustfmt::skip]
    const HEAD: [u8; 28] = [
        0xFF, M_APP1, 0x00, 0x22, b'E', b'x', b'i', b'f', 0, 0, // length 34
        b'I', b'I', 42, 0, 8, 0, 0, 0,                          // little-endian, the IFD at 8
        1, 0,                                                   // one entry
        0x12, 0x01, TIFF_SHORT as u8, 0, 1, 0, 0, 0,            // Orientation, a SHORT, one of it
    ];
    o.extend_from_slice(&HEAD);
    // Its value, then no next IFD.
    o.extend_from_slice(&[orient as u8, 0, 0, 0, 0, 0, 0, 0]);
}

/// Whether a segment before the scans is kept, and if not, what it was.
fn jpeg_keep(m: u8, d: &[u8], took: &mut u32) -> bool {
    match m {
        M_DQT | M_DHT | M_DRI | M_DAC | M_DNL | M_DHP | M_EXP => true,
        M_APP0 => {
            // JFXX holds a thumbnail.
            if d.starts_with(b"JFIF\0") {
                return true;
            }
            *took |= CLEAN_EXTRA;
            false
        }
        M_APP1 => {
            *took |= if d.starts_with(b"Exif\0\0") { CLEAN_CAMERA } else { CLEAN_XMP };
            false
        }
        M_APP2 => {
            // MPF: more pictures in the file, each with Exif of its own.
            if d.starts_with(b"ICC_PROFILE\0") {
                return true;
            }
            *took |= CLEAN_EXTRA;
            false
        }
        M_APP13 => {
            *took |= CLEAN_IPTC;
            false
        }
        M_APP14 => {
            // Adobe's, which says how CMYK and YCCK colours are stored.
            if d.starts_with(b"Adobe") {
                return true;
            }
            *took |= CLEAN_OTHER;
            false
        }
        M_COM => {
            *took |= CLEAN_COMMENT;
            false
        }
        _ if (M_SOF0..=M_SOF15).contains(&m) => true,
        _ => {
            *took |= CLEAN_OTHER;
            false
        }
    }
}

#[derive(Clone)]
struct Huff {
    code: [u16; 256],
    size: [u8; 256],
    vals: [u8; 256],
    mincode: [i32; 17],
    maxcode: [i32; 17],
    valptr: [i32; 17],
    ok: bool,
}

impl Default for Huff {
    fn default() -> Self {
        Huff {
            code: [0; 256],
            size: [0; 256],
            vals: [0; 256],
            mincode: [0; 17],
            maxcode: [0; 17],
            valptr: [0; 17],
            ok: false,
        }
    }
}

impl Huff {
    /// Codes are given out shortest first, in the order the values are listed, so the same table
    /// decodes a value and encodes it again.
    fn build(bits: &[u8], vals: &[u8]) -> Huff {
        let mut h = Huff::default();
        let (mut code, mut k) = (0i32, 0usize);
        for len in 1..=16 {
            h.valptr[len] = k as i32;
            h.mincode[len] = code;
            for _ in 0..bits[len - 1] {
                let v = vals[k];
                h.vals[k] = v;
                h.code[usize::from(v)] = code as u16;
                h.size[usize::from(v)] = len as u8;
                k += 1;
                code += 1;
            }
            h.maxcode[len] = if bits[len - 1] != 0 { code - 1 } else { -1 };
            if code > (1 << len) {
                return h;
            }
            code <<= 1;
        }
        h.ok = true;
        h
    }
}

#[derive(Clone, Copy, Default)]
struct Comp {
    id: u8,
    h: u32,
    v: u32,
}

#[derive(Default)]
struct Noise {
    /// SOF0 or SOF1: one pass, Huffman coded.
    sequential: bool,
    width: u64,
    height: u64,
    ncomp: usize,
    hmax: u32,
    vmax: u32,
    restart: u64,
    comp: [Comp; 4],
    dc: [Huff; 4],
    ac: [Huff; 4],
    rng: u64,
    changed: u32,
}

impl Noise {
    fn rnd(&mut self) -> u32 {
        self.rng ^= self.rng >> 12;
        self.rng ^= self.rng << 25;
        self.rng ^= self.rng >> 27;
        (self.rng.wrapping_mul(2_685_821_657_736_338_717) >> 32) as u32
    }

    fn parse_dht(&mut self, d: &[u8]) {
        let mut i = 0;
        while d.len() - i >= 17 {
            let (tc, th) = (d[i] >> 4, usize::from(d[i] & 15));
            let total: usize = d[i + 1..i + 17].iter().map(|&b| usize::from(b)).sum();
            if tc > 1 || th > 3 || total > 256 || total > d.len() - i - 17 {
                return;
            }
            let h = Huff::build(&d[i + 1..i + 17], &d[i + 17..i + 17 + total]);
            if tc == 1 {
                self.ac[th] = h;
            } else {
                self.dc[th] = h;
            }
            i += 17 + total;
        }
    }

    fn parse_sof(&mut self, m: u8, d: &[u8]) {
        self.sequential = false;
        if (m != M_SOF0 && m != M_SOF1) || d.len() < 6 {
            return;
        }
        self.height = u64::from(d[1]) << 8 | u64::from(d[2]);
        self.width = u64::from(d[3]) << 8 | u64::from(d[4]);
        self.ncomp = usize::from(d[5]);
        if (d[0] != 8 && d[0] != 12) || !(1..=4).contains(&self.ncomp) || d.len() < 6 + 3 * self.ncomp {
            return;
        }
        self.hmax = 1;
        self.vmax = 1;
        for c in 0..self.ncomp {
            let comp = Comp {
                id: d[6 + 3 * c],
                h: u32::from(d[7 + 3 * c] >> 4),
                v: u32::from(d[7 + 3 * c] & 15),
            };
            if !(1..=4).contains(&comp.h) || !(1..=4).contains(&comp.v) {
                return;
            }
            self.hmax = self.hmax.max(comp.h);
            self.vmax = self.vmax.max(comp.v);
            self.comp[c] = comp;
        }
        self.sequential = true;
    }

    /// A step up or down within the coefficient's size class: the top bit of its amplitude bits
    /// stays, so its size, and with it the Huffman symbol before it, doesn't change.
    fn nudge(&mut self, bits: u32, size: u32) -> u32 {
        let top = 1 << (size - 1);
        let mut low = bits & (top - 1);
        if low == 0 {
            low += 1;
        } else if low == top - 1 {
            low -= 1;
        } else if self.rnd() & 1 != 0 {
            low += 1;
        } else {
            low -= 1;
        }
        self.changed += 1;
        (bits & top) | low
    }

    /// One block, copied symbol for symbol, but for the amplitudes that move. The DC coefficient
    /// never does, so a block's overall brightness stays.
    fn block(&mut self, b: &mut Bits, w: &mut Put, dc: usize, ac: usize) -> Option<()> {
        let t = b.sym(&self.dc[dc])?;
        if t > 15 {
            return None;
        }
        w.bits(
            u32::from(self.dc[dc].code[usize::from(t)]),
            u32::from(self.dc[dc].size[usize::from(t)]),
        );
        if t != 0 {
            let bits = b.bits(u32::from(t))?;
            w.bits(bits, u32::from(t));
        }
        let mut k = 1;
        while k < COEFS {
            let rs = b.sym(&self.ac[ac])?;
            w.bits(
                u32::from(self.ac[ac].code[usize::from(rs)]),
                u32::from(self.ac[ac].size[usize::from(rs)]),
            );
            let (run, size) = (usize::from(rs >> 4), u32::from(rs & 15));
            if size == 0 {
                if run != 15 {
                    break;
                }
                k += 16;
                continue;
            }
            k += run;
            if k >= COEFS {
                return None;
            }
            let mut bits = b.bits(size)?;
            if size >= 2 && self.rnd().is_multiple_of(NOISE_EVERY) {
                bits = self.nudge(bits, size);
            }
            w.bits(bits, size);
            k += 1;
        }
        Some(())
    }

    fn blocks(&mut self, b: &mut Bits, w: &mut Put, sc: &[(u32, u32, usize, usize)], mcus: u64) -> Option<()> {
        let mut rst = 0u8;
        for m in 0..mcus {
            if self.restart != 0 && m > 0 && m % self.restart == 0 {
                b.restart(rst)?;
                w.flush();
                w.o.extend_from_slice(&[0xFF, M_RST0 + (rst & 7)]);
                rst = rst.wrapping_add(1);
            }
            for &(h, v, dc, ac) in sc {
                let blocks = if sc.len() == 1 { 1 } else { h * v };
                for _ in 0..blocks {
                    self.block(b, w, dc, ac)?;
                }
            }
        }
        w.flush();
        Some(())
    }

    /// One scan of a sequential JPEG, written again with noise. False if the scan is to be copied
    /// as it is: progressive, arithmetic coded, or anything this can't follow.
    fn scan(&mut self, hdr: &[u8], ecs: &[u8], o: &mut Vec<u8>) -> bool {
        if !self.sequential || self.width == 0 || self.height == 0 || hdr.is_empty() {
            return false;
        }
        let ns = usize::from(hdr[0]);
        if !(1..=4).contains(&ns) || hdr.len() < 1 + 2 * ns + 3 {
            return false;
        }
        let mut sc = [(0u32, 0u32, 0usize, 0usize); 4];
        for (k, s) in sc.iter_mut().enumerate().take(ns) {
            let (id, td, ta) = (hdr[1 + 2 * k], usize::from(hdr[2 + 2 * k] >> 4), usize::from(hdr[2 + 2 * k] & 15));
            let Some(c) = self.comp[..self.ncomp].iter().rev().find(|c| c.id == id) else {
                return false;
            };
            if td > 3 || ta > 3 || !self.dc[td].ok || !self.ac[ta].ok {
                return false;
            }
            *s = (c.h, c.v, td, ta);
        }
        if hdr[1 + 2 * ns] != 0 || usize::from(hdr[2 + 2 * ns]) != COEFS - 1 || hdr[3 + 2 * ns] != 0 {
            return false;
        }
        let (hmax, vmax) = (u64::from(self.hmax), u64::from(self.vmax));
        let mcus = if ns == 1 {
            // Not interleaved: a block at a time, over the component's own size.
            let cw = (self.width * u64::from(sc[0].0)).div_ceil(hmax);
            let ch = (self.height * u64::from(sc[0].1)).div_ceil(vmax);
            cw.div_ceil(8) * ch.div_ceil(8)
        } else {
            self.width.div_ceil(8 * hmax) * self.height.div_ceil(8 * vmax)
        };
        if mcus == 0 || mcus > BLOCKS_MAX {
            return false;
        }
        let start = o.len();
        let changed = self.changed;
        let mut b = Bits {
            p: ecs,
            i: 0,
            acc: 0,
            nbits: 0,
        };
        let mut w = Put {
            o: &mut *o,
            acc: 0,
            nbits: 0,
        };
        if self.blocks(&mut b, &mut w, &sc[..ns], mcus).is_some() {
            return true;
        }
        o.truncate(start);
        self.changed = changed;
        false
    }
}

struct Bits<'a> {
    p: &'a [u8],
    i: usize,
    acc: u32,
    nbits: u32,
}

impl Bits<'_> {
    /// No bits are read past a marker.
    fn bit(&mut self) -> Option<u32> {
        if self.nbits == 0 {
            let byte = *self.p.get(self.i)?;
            if byte == 0xFF {
                if self.p.get(self.i + 1) != Some(&0) {
                    return None;
                }
                self.i += 2;
            } else {
                self.i += 1;
            }
            self.acc = u32::from(byte);
            self.nbits = 8;
        }
        self.nbits -= 1;
        Some(self.acc >> self.nbits & 1)
    }

    fn bits(&mut self, n: u32) -> Option<u32> {
        let mut v = 0;
        for _ in 0..n {
            v = v << 1 | self.bit()?;
        }
        Some(v)
    }

    fn sym(&mut self, h: &Huff) -> Option<u8> {
        let mut code = 0i32;
        for len in 1..=16 {
            code = code << 1 | self.bit()? as i32;
            if h.maxcode[len] >= 0 && code >= h.mincode[len] && code <= h.maxcode[len] {
                return Some(h.vals[(h.valptr[len] + code - h.mincode[len]) as usize]);
            }
        }
        None
    }

    /// The rest of the byte is padding, then restart marker number n.
    fn restart(&mut self, n: u8) -> Option<()> {
        self.nbits = 0;
        while self.i + 1 < self.p.len() && self.p[self.i] == 0xFF && self.p[self.i + 1] == 0xFF {
            self.i += 1;
        }
        if self.i + 1 >= self.p.len() || self.p[self.i] != 0xFF || self.p[self.i + 1] != M_RST0 + (n & 7) {
            return None;
        }
        self.i += 2;
        Some(())
    }
}

struct Put<'a> {
    o: &'a mut Vec<u8>,
    acc: u32,
    nbits: u32,
}

impl Put<'_> {
    /// A byte of 0xFF in the data is followed by a 0, so it can't be taken for a marker.
    fn bits(&mut self, v: u32, n: u32) {
        for k in (0..n).rev() {
            self.acc = self.acc << 1 | (v >> k & 1);
            self.nbits += 1;
            if self.nbits == 8 {
                let byte = self.acc as u8;
                self.o.push(byte);
                if byte == 0xFF {
                    self.o.push(0);
                }
                self.acc = 0;
                self.nbits = 0;
            }
        }
    }

    /// The last byte is padded with 1s, before a restart marker or at the end of a scan.
    fn flush(&mut self) {
        if self.nbits != 0 {
            let n = 8 - self.nbits;
            self.bits((1 << n) - 1, n);
        }
    }
}

fn clean_jpeg(p: &[u8], noise: bool, seed: &[u8; CLEAN_SEED_LEN], o: &mut Vec<u8>) -> Option<u32> {
    let mut took = 0;
    // The Orientation first, wherever its Exif is, so it goes right after the JFIF header.
    let (mut orient, mut gps) = (1, false);
    let mut i = 2;
    while let Some(m) = next_marker(p, &mut i) {
        if m == M_SOS || m == M_EOI {
            break;
        }
        if m == M_TEM || (M_RST0..=M_RST7).contains(&m) {
            continue;
        }
        let n = seg_len(p, i)?;
        if m == M_APP1 {
            let x = exif_orientation(&p[i + 2..i + n], &mut gps);
            if x != 1 {
                orient = x;
            }
        }
        i += n;
    }
    if gps {
        took |= CLEAN_LOCATION;
    }
    let mut s = Noise::default();
    for &b in seed {
        s.rng = s.rng << 8 ^ s.rng >> 56 ^ u64::from(b);
    }
    if s.rng == 0 {
        s.rng = 1;
    }
    o.extend_from_slice(&p[..2]);
    let mut wrote_orient = orient == 1;
    let mut scans = 0;
    i = 2;
    loop {
        let Some(m) = next_marker(p, &mut i) else {
            // Cut off after its scans: it's finished as a whole file would be.
            if scans == 0 {
                return None;
            }
            o.extend_from_slice(b"\xFF\xD9");
            break;
        };
        if m == M_EOI {
            o.extend_from_slice(b"\xFF\xD9");
            // A motion photo's video, or another picture.
            if i < p.len() {
                took |= CLEAN_EXTRA;
            }
            break;
        }
        if m == M_TEM || (M_RST0..=M_RST7).contains(&m) {
            continue;
        }
        let n = seg_len(p, i)?;
        let d = &p[i + 2..i + n];
        if !wrote_orient && m != M_APP0 {
            put_orientation(o, orient);
            wrote_orient = true;
        }
        if m == M_SOS {
            o.extend_from_slice(&[0xFF, m]);
            o.extend_from_slice(&p[i..i + n]);
            let ecs = i + n;
            let end = ecs_end(p, ecs);
            if !noise || !s.scan(d, &p[ecs..end], o) {
                o.extend_from_slice(&p[ecs..end]);
            }
            scans += 1;
            i = end;
            continue;
        }
        if jpeg_keep(m, d, &mut took) {
            o.extend_from_slice(&[0xFF, m]);
            o.extend_from_slice(&p[i..i + n]);
            if m == M_DHT {
                s.parse_dht(d);
            } else if m == M_DRI && d.len() == 2 {
                s.restart = u64::from(d[0]) << 8 | u64::from(d[1]);
            } else if (M_SOF0..=M_SOF15).contains(&m) && m != M_DAC {
                s.parse_sof(m, d);
            }
        }
        i += n;
    }
    if s.changed != 0 {
        took |= CLEAN_NOISE;
    }
    Some(took)
}

// ---- PNG ----

const PNG_SIG: usize = 8;
const CHUNK_HEAD: usize = 8;
const CHUNK_CRC: usize = 4;

fn clean_png(p: &[u8], o: &mut Vec<u8>) -> Option<u32> {
    // What drawing it needs, including colour (iCCP, cICP and the rest) and animation.
    const KEEP: [&[u8; 4]; 16] = [
        b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"gAMA", b"cHRM", b"sRGB", b"iCCP", b"cICP", b"sBIT", b"bKGD", b"pHYs", b"acTL",
        b"fcTL", b"fdAT",
    ];
    const XMP_KEY: &[u8] = b"XML:com.adobe.xmp\0";
    let mut took = 0;
    o.extend_from_slice(&p[..PNG_SIG]);
    let mut i = PNG_SIG;
    while p.len() - i >= CHUNK_HEAD + CHUNK_CRC {
        let n = u32::from_be_bytes([p[i], p[i + 1], p[i + 2], p[i + 3]]) as usize;
        if n > p.len() - i - CHUNK_HEAD - CHUNK_CRC {
            return None;
        }
        let ty: &[u8] = &p[i + 4..i + 8];
        let d = &p[i + CHUNK_HEAD..i + CHUNK_HEAD + n];
        let whole = CHUNK_HEAD + n + CHUNK_CRC;
        if KEEP.iter().any(|k| ty == *k) {
            o.extend_from_slice(&p[i..i + whole]);
        } else if ty == b"iTXt" && d.starts_with(XMP_KEY) {
            took |= CLEAN_XMP;
        } else if ty == b"tEXt" || ty == b"zTXt" || ty == b"iTXt" {
            took |= CLEAN_COMMENT;
        } else if ty == b"eXIf" {
            took |= CLEAN_CAMERA;
        } else if ty == b"tIME" {
            took |= CLEAN_TIME;
        } else {
            took |= CLEAN_OTHER;
        }
        i += whole;
        if ty == b"IEND" {
            if i < p.len() {
                took |= CLEAN_EXTRA;
            }
            return Some(took);
        }
    }
    None
}

// ---- GIF ----

const GIF_HEAD: usize = 13;
const GIF_FLAGS_AT: usize = 10;
const GIF_TABLE: u8 = 0x80;
const GIF_IMAGE: u8 = 0x2C;
const GIF_EXT: u8 = 0x21;
const GIF_END: u8 = 0x3B;
const GIF_IMAGE_HEAD: usize = 10;
const GIF_APP_ID: usize = 11;
const EXT_GRAPHIC: u8 = 0xF9;
const EXT_TEXT: u8 = 0x01;
const EXT_COMMENT: u8 = 0xFE;
const EXT_APP: u8 = 0xFF;

fn skip_blocks(p: &[u8], i: &mut usize) -> Option<()> {
    while *i < p.len() {
        let n = usize::from(p[*i]);
        *i += 1;
        if n == 0 {
            return Some(());
        }
        if n > p.len() - *i {
            return None;
        }
        *i += n;
    }
    None
}

fn colour_table(flags: u8) -> usize {
    if flags & GIF_TABLE != 0 { 3 << ((flags & 7) + 1) } else { 0 }
}

fn clean_gif(p: &[u8], o: &mut Vec<u8>) -> Option<u32> {
    if p.len() < GIF_HEAD {
        return None;
    }
    let mut took = 0;
    let mut i = GIF_HEAD + colour_table(p[GIF_FLAGS_AT]);
    if i > p.len() {
        return None;
    }
    o.extend_from_slice(&p[..i]);
    while i < p.len() {
        let start = i;
        if p[i] == GIF_END {
            o.push(GIF_END);
            if i + 1 < p.len() {
                took |= CLEAN_EXTRA;
            }
            return Some(took);
        }
        if p[i] == GIF_IMAGE {
            if p.len() - i < GIF_IMAGE_HEAD + 1 {
                return None;
            }
            i += GIF_IMAGE_HEAD + colour_table(p[i + GIF_IMAGE_HEAD - 1]);
            // The LZW code size, then the data.
            if i >= p.len() {
                return None;
            }
            i += 1;
            skip_blocks(p, &mut i)?;
            o.extend_from_slice(&p[start..i]);
            continue;
        }
        if p[i] != GIF_EXT || p.len() - i < 2 {
            return None;
        }
        let label = p[i + 1];
        let mut keep = label == EXT_GRAPHIC || label == EXT_TEXT;
        i += 2;
        if label == EXT_APP {
            // Only the ones that say how an animation loops.
            let app = p.len() - i > GIF_APP_ID && usize::from(p[i]) == GIF_APP_ID;
            let id = if app { &p[i + 1..i + 1 + GIF_APP_ID] } else { &[][..] };
            if app && (id == b"NETSCAPE2.0" || id == b"ANIMEXTS1.0") {
                keep = true;
            } else {
                took |= if app && id == b"XMP DataXMP" { CLEAN_XMP } else { CLEAN_OTHER };
            }
        } else if label == EXT_COMMENT {
            took |= CLEAN_COMMENT;
        } else if !keep {
            took |= CLEAN_OTHER;
        }
        skip_blocks(p, &mut i)?;
        if keep {
            o.extend_from_slice(&p[start..i]);
        }
    }
    // No trailer: it gets one.
    o.push(GIF_END);
    Some(took)
}

// ---- what chat can't clean, and names ----

/// For a file chat can't clean that usually says where and when it was made (photos and videos
/// in other formats, PDFs, office documents), what it is ("HEIC picture"), from its first bytes
/// ([`CLEAN_HEAD`] are enough) and its name.
pub fn cannot(h: &[u8], name: &str) -> Option<&'static str> {
    if h.len() >= 12 && &h[4..8] == b"ftyp" {
        let brand = &h[8..12];
        return Some(match brand {
            b"heic" | b"heix" | b"mif1" | b"msf1" => "HEIC picture",
            b"avif" | b"avis" => "AVIF picture",
            b"qt  " => "QuickTime video",
            _ => "MP4 file",
        });
    }
    if h.len() >= 12 && h.starts_with(b"RIFF") && &h[8..12] == b"WEBP" {
        return Some("WebP picture");
    }
    if h.starts_with(b"II*\0") || h.starts_with(b"MM\0*") {
        return Some("TIFF or raw photo");
    }
    if h.starts_with(b"%PDF-") {
        return Some("PDF");
    }
    let lower = name.to_ascii_lowercase();
    [".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".doc", ".xls", ".ppt"]
        .iter()
        .any(|s| lower.ends_with(s))
        .then_some("office document")
}

/// Whether a file name is the kind cameras, phones and screenshot tools give, which says when
/// it was taken (IMG_20261012_143022, Screenshot 2026-10-12 at 14.30.22) or ties pictures
/// together (DSC_0412).
pub fn name_tells(name: &str) -> bool {
    const PREFIX: [&str; 15] = [
        "IMG",
        "PXL_",
        "DSC",
        "MVIMG",
        "PANO_",
        "GOPR",
        "DJI_",
        "Screenshot",
        "Screen Shot",
        "Screen_Shot",
        "photo_",
        "signal-",
        "WhatsApp Image",
        "Snapchat-",
        "Camera_",
    ];
    let b = name.as_bytes();
    if PREFIX
        .iter()
        .any(|p| b.len() >= p.len() && b[..p.len()].eq_ignore_ascii_case(p.as_bytes()))
    {
        return true;
    }
    let mut run = 0;
    for &c in b {
        run = if c.is_ascii_digit() { run + 1 } else { 0 };
        if run >= 6 {
            return true;
        }
    }
    // A date like 2026-10-12.
    let sep = |c: u8| matches!(c, b'-' | b'_' | b'.' | b' ');
    let dg = |c: u8| c.is_ascii_digit();
    b.windows(10)
        .any(|w| dg(w[0]) && dg(w[1]) && dg(w[2]) && dg(w[3]) && sep(w[4]) && dg(w[5]) && dg(w[6]) && sep(w[7]) && dg(w[8]) && dg(w[9]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(name_tells("IMG_20261012_143022.jpg"));
        assert!(name_tells("Screenshot 2026-10-12 at 14.30.22.png"));
        assert!(name_tells("dsc_0412.JPG"));
        assert!(name_tells("holiday 2026-10-12.png"));
        assert!(!name_tells("cat.png"));
        assert_eq!(cannot(b"\0\0\0\x18ftypheic\0\0\0\0", "x"), Some("HEIC picture"));
        assert_eq!(cannot(b"%PDF-1.7", "a.pdf"), Some("PDF"));
        assert_eq!(cannot(b"PK\x03\x04", "Report.DOCX"), Some("office document"));
        assert_eq!(cannot(b"hello", "a.txt"), None);
    }

    #[test]
    fn png_text_goes() {
        fn chunk(ty: &[u8; 4], d: &[u8]) -> Vec<u8> {
            let mut v = (d.len() as u32).to_be_bytes().to_vec();
            v.extend_from_slice(ty);
            v.extend_from_slice(d);
            v.extend_from_slice(&[0; 4]);
            v
        }
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend(chunk(b"IHDR", &[0; 13]));
        png.extend(chunk(b"tEXt", b"Comment\0secret"));
        png.extend(chunk(b"tIME", &[0; 7]));
        png.extend(chunk(b"IDAT", b"xx"));
        png.extend(chunk(b"IEND", b""));
        let (out, took) = clean(&png, true, &[0; 16]).unwrap();
        assert_eq!(took, CLEAN_COMMENT | CLEAN_TIME);
        assert!(!out.windows(6).any(|w| w == b"secret"));
        assert_eq!(out.len(), png.len() - (12 + 14) - (12 + 7));
        assert!(clean(&png[..png.len() - 5], false, &[0; 16]).is_none());
    }

    #[test]
    fn pictures_decode_upright_and_small() {
        let dir = "tests/data/pictures";
        // Its Exif says to turn it a quarter: 333 by 211 shows as 211 by 333.
        let jpg = std::fs::read(format!("{dir}/exif420.jpg")).unwrap();
        let t = decode(&jpg, 64, 64, [0, 0, 0]).unwrap();
        assert_eq!((t.src_w, t.src_h), (333, 211));
        assert!(t.h == 64 && t.w < 64, "{}x{}", t.w, t.h);
        assert_eq!(t.rgb.len(), (t.w * t.h * 3) as usize);
        let png = std::fs::read(format!("{dir}/text.png")).unwrap();
        assert_eq!(decode(&png, 1024, 1024, [0; 3]).unwrap().w, 333);
        assert!(decode(b"not a picture", 64, 64, [0; 3]).is_err());
        assert!(decode(&jpg[..200], 64, 64, [0; 3]).is_err());
    }

    #[test]
    fn gif_comment_goes() {
        let mut gif = b"GIF89a\x01\x00\x01\x00\x00\x00\x00".to_vec();
        gif.extend_from_slice(b"\x21\xfe\x06secret\x00");
        gif.extend_from_slice(b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b");
        let (out, took) = clean(&gif, false, &[0; 16]).unwrap();
        assert_eq!(took, CLEAN_COMMENT);
        assert!(!out.windows(6).any(|w| w == b"secret"));
        assert!(out.ends_with(b"\x3b"));
    }
}

// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Addresses and the UDP cell format.
//!
//! Every UDP datagram is one 1004-byte cell, the size of a session frame. A room frame (2600
//! bytes) goes as three cells: a magic, a random frame id, the piece's index and count, the
//! frame's length, then the piece, padded with random bytes. Relays and Tor carry whole frames.

use crate::protocol::api::PeerId;
use crate::protocol::crypto::{AEAD_TAG_LEN, SESSION_HEADER_LEN, SESSION_PAD_TARGET, sodium};
use std::fmt;
use std::net::{IpAddr, SocketAddr};

pub const UDP_CELL: usize = SESSION_HEADER_LEN + SESSION_PAD_TARGET + AEAD_TAG_LEN;
const MAGIC: [u8; 2] = [0xC5, 0x7B];
const ID_AT: usize = 2;
const ID_LEN: usize = 4;
const INDEX_AT: usize = 6;
const COUNT_AT: usize = 7;
const LEN_AT: usize = 8;
const HDR: usize = 10;
pub const CHUNK_PAYLOAD: usize = UDP_CELL - HDR;
pub const CHUNK_MAX: usize = 4;
pub const ROOM_FRAME_MAX: usize = CHUNK_MAX * CHUNK_PAYLOAD;
const REASM_SLOTS: usize = 32;
/// A room frame's pieces go one per slot, so they get a while to arrive.
const REASM_TTL: f64 = 30.0;

/// Where a datagram comes from or goes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Addr {
    /// A real address. IPv4 is always V4, never mapped into IPv6.
    Udp(SocketAddr),
    /// A member on the Nostr relays, by its id; [`PeerId::EVERYONE`] is the whole room.
    Relay(PeerId),
    /// A Tor stream (an id the Tor transport picked).
    Tor([u8; 16]),
}

impl Addr {
    /// An address as received from a dual-stack socket, made canonical.
    pub fn udp(sa: SocketAddr) -> Addr {
        Addr::Udp(canonical(sa))
    }

    pub fn is_udp(&self) -> bool {
        matches!(self, Addr::Udp(_))
    }

    /// Better paths are preferred: direct UDP, then Tor (no relay in the middle), then relays.
    pub fn rank(&self) -> u8 {
        match self {
            Addr::Udp(_) => 2,
            Addr::Tor(_) => 1,
            Addr::Relay(_) => 0,
        }
    }

    pub fn kind_index(&self) -> usize {
        match self {
            Addr::Udp(_) => 0,
            Addr::Relay(_) => 1,
            Addr::Tor(_) => 2,
        }
    }
}

/// IPv4-mapped IPv6 as plain IPv4, and no flow label.
pub fn canonical(sa: SocketAddr) -> SocketAddr {
    match sa {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), v6.port()),
            None => SocketAddr::V6(std::net::SocketAddrV6::new(*v6.ip(), v6.port(), 0, v6.scope_id())),
        },
        v4 => v4,
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // "1.2.3.4:5" or "[::1]:5", as written in "px".
            Addr::Udp(sa) => write!(f, "{sa}"),
            Addr::Relay(id) => write!(f, "nostr:{}", id.hex()),
            Addr::Tor(id) => write!(f, "tor:{}", crate::protocol::hex::encode(id)),
        }
    }
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// How many cells a room frame of this length takes.
pub fn pieces(len: usize) -> usize {
    len.div_ceil(CHUNK_PAYLOAD)
}

/// The i-th cell of a room frame, padded with random bytes (a cell's last bytes pick the
/// keystream it's masked with, so they mustn't repeat).
pub fn cell(frame: &[u8], id: &[u8; 4], i: usize, count: usize) -> Vec<u8> {
    let off = i * CHUNK_PAYLOAD;
    let n = (frame.len() - off).min(CHUNK_PAYLOAD);
    let mut c = vec![0u8; UDP_CELL];
    c[..2].copy_from_slice(&MAGIC);
    c[ID_AT..ID_AT + ID_LEN].copy_from_slice(id);
    c[INDEX_AT] = i as u8;
    c[COUNT_AT] = count as u8;
    c[LEN_AT..LEN_AT + 2].copy_from_slice(&(frame.len() as u16).to_be_bytes());
    c[HDR..HDR + n].copy_from_slice(&frame[off..off + n]);
    sodium::random(&mut c[HDR + n..]);
    c
}

struct Partial {
    from: Addr,
    id: [u8; 4],
    count: usize,
    total: usize,
    got: u32,
    born: f64,
    buf: Vec<u8>,
}

/// Room frames being put back together from their cells.
#[derive(Default)]
pub struct Reassembly {
    slots: Vec<Partial>,
}

pub enum CellResult {
    /// Not a cell: a session frame, or junk.
    NotACell,
    /// A piece kept, waiting for the rest.
    Kept,
    /// The last piece: here's the whole frame.
    Frame(Vec<u8>),
}

impl Reassembly {
    /// An unmasked datagram that may be a cell.
    pub fn add(&mut self, d: &[u8], from: Addr, now: f64) -> CellResult {
        if d.len() != UDP_CELL || d[..2] != MAGIC {
            return CellResult::NotACell;
        }
        let (idx, count) = (usize::from(d[INDEX_AT]), usize::from(d[COUNT_AT]));
        let total = usize::from(u16::from_be_bytes([d[LEN_AT], d[LEN_AT + 1]]));
        if !(2..=CHUNK_MAX).contains(&count) || idx >= count {
            return CellResult::NotACell;
        }
        if total <= (count - 1) * CHUNK_PAYLOAD || total > count * CHUNK_PAYLOAD {
            return CellResult::NotACell;
        }
        let id: [u8; 4] = d[ID_AT..ID_AT + ID_LEN].try_into().expect("4 bytes");
        self.slots.retain(|p| now - p.born <= REASM_TTL);
        let pos = self
            .slots
            .iter()
            .position(|p| p.from == from && p.id == id && p.count == count && p.total == total);
        let pos = match pos {
            Some(p) => p,
            None => {
                if self.slots.len() >= REASM_SLOTS {
                    let oldest = (0..self.slots.len())
                        .min_by(|&a, &b| self.slots[a].born.total_cmp(&self.slots[b].born))
                        .expect("full");
                    self.slots.swap_remove(oldest);
                }
                self.slots.push(Partial {
                    from,
                    id,
                    count,
                    total,
                    got: 0,
                    born: now,
                    buf: vec![0u8; count * CHUNK_PAYLOAD],
                });
                self.slots.len() - 1
            }
        };
        let p = &mut self.slots[pos];
        p.buf[idx * CHUNK_PAYLOAD..(idx + 1) * CHUNK_PAYLOAD].copy_from_slice(&d[HDR..]);
        p.got |= 1 << idx;
        if p.got != (1u32 << p.count) - 1 {
            return CellResult::Kept;
        }
        let mut p = self.slots.swap_remove(pos);
        p.buf.truncate(p.total);
        CellResult::Frame(p.buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cells_reassemble_in_any_order() {
        assert_eq!(UDP_CELL, 1004);
        let frame: Vec<u8> = (0..2600u32).map(|i| i as u8).collect();
        let id = [1, 2, 3, 4];
        let n = pieces(frame.len());
        assert_eq!(n, 3);
        let cells: Vec<_> = (0..n).map(|i| cell(&frame, &id, i, n)).collect();
        let from = Addr::udp("127.0.0.1:5".parse().unwrap());
        let mut r = Reassembly::default();
        assert!(matches!(r.add(&cells[2], from, 0.0), CellResult::Kept));
        assert!(matches!(r.add(&cells[0], from, 0.0), CellResult::Kept));
        match r.add(&cells[1], from, 0.0) {
            CellResult::Frame(f) => assert_eq!(f, frame),
            _ => panic!("not reassembled"),
        }
    }

    #[test]
    fn mapped_addresses_are_canonical() {
        let mapped: SocketAddr = "[::ffff:10.0.0.1]:7".parse().unwrap();
        assert_eq!(Addr::udp(mapped).to_string(), "10.0.0.1:7");
        assert_eq!(Addr::udp("[::1]:9".parse().unwrap()).to_string(), "[::1]:9");
    }
}

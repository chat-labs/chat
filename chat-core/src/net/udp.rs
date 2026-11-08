// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! The session's UDP sockets: its own (IPv6 with IPv4 mapped into it where the system allows,
//! else IPv4 alone), and the LAN beacon socket, which every member of the room on this network
//! shares a port on.

use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use tokio::net::UdpSocket;

/// A UDP socket that takes either family's addresses.
pub struct Udp {
    sock: UdpSocket,
    dual: bool,
}

impl Udp {
    /// The session's socket on `port` (0: any free one): dual-stack if it can be.
    pub fn bind(port: u16) -> io::Result<Udp> {
        match bind_v6_dual(port) {
            Ok(s) => Ok(Udp {
                sock: UdpSocket::from_std(s)?,
                dual: true,
            }),
            Err(_) => Ok(Udp {
                sock: UdpSocket::from_std(bind_v4(port, false)?)?,
                dual: false,
            }),
        }
    }

    /// The LAN beacon socket: IPv4, sharing its port with other members on this host.
    pub fn bind_lan(port: u16) -> io::Result<Udp> {
        Ok(Udp {
            sock: UdpSocket::from_std(bind_v4(port, true)?)?,
            dual: false,
        })
    }

    pub fn port(&self) -> u16 {
        self.sock.local_addr().map_or(0, |a| a.port())
    }

    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.sock.recv_from(buf).await
    }

    /// Sends without waiting: a full socket buffer drops the datagram, as the network would.
    pub fn send(&self, data: &[u8], to: SocketAddr) {
        let to = match (to, self.dual) {
            (SocketAddr::V4(v4), true) => SocketAddr::V6(SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0)),
            (SocketAddr::V6(_), false) => return,
            (to, _) => to,
        };
        let _ = self.sock.try_send_to(data, to);
    }
}

fn bind_v6_dual(port: u16) -> io::Result<std::net::UdpSocket> {
    let s = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_only_v6(false)?;
    s.set_broadcast(true)?;
    s.set_nonblocking(true)?;
    s.bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port).into())?;
    Ok(s.into())
}

fn bind_v4(port: u16, shared: bool) -> io::Result<std::net::UdpSocket> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    if shared {
        s.set_reuse_address(true)?;
        #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
        s.set_reuse_port(true)?;
    }
    s.set_broadcast(true)?;
    s.set_nonblocking(true)?;
    s.bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port).into())?;
    Ok(s.into())
}

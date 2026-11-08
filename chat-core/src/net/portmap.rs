// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 finlay@tuta.com
//! Asks the home router to forward a room's UDP port to it, so peers behind NATs that can't be
//! hole-punched can still reach it (direct routing only). Tries PCP, then NAT-PMP, then UPnP-IGD,
//! keeps the mapping renewed, and removes it when the room closes.

use crate::protocol::crypto::sodium;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{oneshot, watch};
use tokio::time::{Instant, sleep, timeout};

const PCP_PORT: u16 = 5351;
const SSDP: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 1900);
const LEASE: u32 = 3600;
const HTTP_CAP: usize = 65536;
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);
const SSDP_WAIT: Duration = Duration::from_secs(3);
const RETRY_AFTER_FAIL: Duration = Duration::from_secs(600);
/// A permanent UPnP mapping (no lease) is checked this often.
const PERMANENT_RECHECK: Duration = Duration::from_secs(3600);
const UPNP_RENEW_RETRY: Duration = Duration::from_secs(60);
/// PCP and NAT-PMP requests go a few times, each wait twice the one before.
const GW_TRIES: u32 = 3;
const GW_RETRY_BASE: f64 = 0.25;
const RENEW_TRIES: u32 = 4;
const RENEW_RETRY_BASE: f64 = 0.5;
/// A mapping is removed on exit with a request that waits this long at most.
const DELETE_WAIT: Duration = Duration::from_secs(1);
/// UPnP's errors: the router only takes permanent mappings, or the port is someone else's.
const UPNP_ONLY_PERMANENT: u32 = 725;
const UPNP_CONFLICT: u32 = 718;
const CONFLICT_TRIES: u32 = 3;

const PCP_VERSION: u8 = 2;
const PCP_OP_MAP: u8 = 1;
const PCP_RESPONSE: u8 = 0x80;
const PCP_MAP_LEN: usize = 60;
const PROTO_UDP: u8 = 17;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Via {
    Pcp,
    NatPmp,
    Upnp,
}

impl Via {
    fn name(self) -> &'static str {
        match self {
            Via::Pcp => "PCP",
            Via::NatPmp => "NAT-PMP",
            Via::Upnp => "UPnP",
        }
    }
}

/// How the mapping is: the port the router forwards (None until one is up), and what the net
/// report says about it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    pub external_port: Option<u16>,
    pub text: String,
}

/// A room's mapping, kept up by a task of its own. [`PortMap::stop`] removes it.
pub(crate) struct PortMap {
    pub status: watch::Receiver<Status>,
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl PortMap {
    pub fn spawn(internal_port: u16, log: tokio::sync::mpsc::UnboundedSender<String>) -> PortMap {
        let (tx, status) = watch::channel(Status {
            external_port: None,
            text: "asking the router...".into(),
        });
        let (stop, stop_rx) = oneshot::channel();
        let task = tokio::spawn(run(internal_port, tx, log, stop_rx));
        PortMap { status, stop, task }
    }

    /// Removes the mapping, waiting about a second for the router at most.
    pub async fn stop(self) {
        let _ = self.stop.send(());
        let _ = timeout(DELETE_WAIT * 2, self.task).await;
    }
}

struct Mapping {
    via: Via,
    external_port: u16,
    external_ip: Option<Ipv4Addr>,
    /// 0: a permanent UPnP mapping.
    lifetime: u32,
}

/// What the gateway and this machine are, for the requests.
struct Net {
    sock: UdpSocket,
    /// The default gateway, for PCP and NAT-PMP; None leaves only UPnP.
    gw: Option<Ipv4Addr>,
    local: Ipv4Addr,
    nonce: [u8; 12],
    internal_port: u16,
    want_external: u16,
    igd: Option<Igd>,
    permanent: bool,
}

struct Igd {
    ip: Ipv4Addr,
    port: u16,
    ctl_path: String,
    service: String,
}

async fn run(
    internal_port: u16,
    tx: watch::Sender<Status>,
    log: tokio::sync::mpsc::UnboundedSender<String>,
    mut stop: oneshot::Receiver<()>,
) {
    loop {
        let mut net = match Net::open(internal_port).await {
            Some(n) => n,
            None => {
                let _ = tx.send(Status {
                    external_port: None,
                    text: "none - can't open a socket to talk to the router".into(),
                });
                tokio::select! { _ = sleep(RETRY_AFTER_FAIL) => continue, _ = &mut stop => return }
            }
        };
        let mapping = tokio::select! { m = net.map() => m, _ = &mut stop => return };
        let mut m = match mapping {
            Ok(m) => m,
            Err(why) => {
                let _ = tx.send(Status {
                    external_port: None,
                    text: format!("none - {why}"),
                });
                tokio::select! { _ = sleep(RETRY_AFTER_FAIL) => continue, _ = &mut stop => return }
            }
        };
        loop {
            let ip = m.external_ip.map_or("?".into(), |ip| ip.to_string());
            let _ = log.send(format!(
                "port mapping: the router forwards {ip}:{} to this room ({})",
                m.external_port,
                m.via.name()
            ));
            let _ = tx.send(Status {
                external_port: Some(m.external_port),
                text: format!("{ip}:{} forwarded here by {}", m.external_port, m.via.name()),
            });
            // Renewed at half the lease; a permanent UPnP mapping is only checked every hour.
            let wait = if m.lifetime > 0 {
                Duration::from_secs(u64::from(m.lifetime) / 2)
            } else {
                PERMANENT_RECHECK
            };
            tokio::select! {
                _ = sleep(wait) => {}
                _ = &mut stop => {
                    net.remove(&m).await;
                    return;
                }
            }
            match net.renew(&m).await {
                Ok(next) => m = next,
                Err(why) => {
                    let _ = log.send(format!("port mapping: {why}"));
                    let _ = tx.send(Status {
                        external_port: None,
                        text: format!("none - {why}"),
                    });
                    break;
                }
            }
        }
        // The network may have changed (another Wi-Fi, a router reboot), so it looks again later.
        tokio::select! { _ = sleep(RETRY_AFTER_FAIL) => {}, _ = &mut stop => return }
    }
}

impl Net {
    async fn open(internal_port: u16) -> Option<Net> {
        let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.ok()?;
        let gw = default_gateway().filter(is_private);
        let local = match gw {
            Some(g) => local_toward(g).await,
            None => local_toward(*SSDP.ip()).await,
        }?;
        // Discovery goes out on the router's side, even when a VPN holds the multicast route.
        if gw.is_some() {
            let _ = socket2::SockRef::from(&sock).set_multicast_if_v4(&local);
        }
        Some(Net {
            sock,
            gw,
            local,
            nonce: sodium::random_array(),
            internal_port,
            want_external: internal_port,
            igd: None,
            permanent: false,
        })
    }

    /// PCP, then NAT-PMP, then UPnP.
    async fn map(&mut self) -> Result<Mapping, String> {
        if self.gw.is_some() {
            match self.ask_gateway(Via::Pcp, LEASE, GW_TRIES, GW_RETRY_BASE).await {
                Some(GwReply::Mapped(m)) => return Ok(m),
                Some(GwReply::Refused | GwReply::OtherProtocol) | None => {}
            }
            if let Some(GwReply::Mapped(m)) = self.ask_gateway(Via::NatPmp, LEASE, GW_TRIES, GW_RETRY_BASE).await {
                return Ok(m);
            }
        }
        self.igd = Some(self.discover().await?);
        self.upnp_add().await
    }

    async fn renew(&mut self, m: &Mapping) -> Result<Mapping, String> {
        if m.via == Via::Upnp {
            return match self.upnp_add().await {
                Ok(m) => Ok(m),
                // Unreachable for now: tried again in a minute, as the mapping may still be there.
                Err(_) => {
                    sleep(UPNP_RENEW_RETRY).await;
                    self.upnp_add().await
                }
            };
        }
        match self.ask_gateway(m.via, LEASE, RENEW_TRIES, RENEW_RETRY_BASE).await {
            Some(GwReply::Mapped(m)) => Ok(m),
            Some(_) => Err("the router refused to renew the mapping".into()),
            None => Err("the router stopped renewing the mapping".into()),
        }
    }

    async fn remove(&mut self, m: &Mapping) {
        match m.via {
            Via::Pcp | Via::NatPmp => {
                for _ in 0..2 {
                    self.send_gateway(m.via, 0).await;
                }
            }
            Via::Upnp => {
                let args = format!(
                    "<NewRemoteHost></NewRemoteHost><NewExternalPort>{}</NewExternalPort><NewProtocol>UDP</NewProtocol>",
                    m.external_port
                );
                if let Some(req) = self.soap("DeletePortMapping", &args) {
                    let igd = self.igd.as_ref().expect("mapped through it");
                    let _ = timeout(DELETE_WAIT, http(igd.ip, igd.port, &req)).await;
                }
            }
        }
    }

    // ---- PCP and NAT-PMP ----

    async fn send_gateway(&self, via: Via, lifetime: u32) {
        let Some(gw) = self.gw else { return };
        let to = SocketAddrV4::new(gw, PCP_PORT);
        match via {
            Via::Pcp => {
                let mut m = [0u8; PCP_MAP_LEN];
                m[0] = PCP_VERSION;
                m[1] = PCP_OP_MAP;
                m[4..8].copy_from_slice(&lifetime.to_be_bytes());
                m[8..24].copy_from_slice(&self.local.to_ipv6_mapped().octets());
                m[24..36].copy_from_slice(&self.nonce);
                m[36] = PROTO_UDP;
                m[40..42].copy_from_slice(&self.internal_port.to_be_bytes());
                m[42..44].copy_from_slice(&self.want_external.to_be_bytes());
                m[44..60].copy_from_slice(&Ipv4Addr::UNSPECIFIED.to_ipv6_mapped().octets());
                let _ = self.sock.send_to(&m, to).await;
            }
            _ => {
                // The external address, then the mapping.
                let _ = self.sock.send_to(&[0, 0], to).await;
                let mut m = [0u8; 12];
                m[1] = 1;
                m[4..6].copy_from_slice(&self.internal_port.to_be_bytes());
                m[6..8].copy_from_slice(&self.want_external.to_be_bytes());
                m[8..12].copy_from_slice(&lifetime.to_be_bytes());
                let _ = self.sock.send_to(&m, to).await;
            }
        }
    }

    /// A request to the gateway, sent `tries` times, each waiting twice as long as the one before.
    async fn ask_gateway(&self, via: Via, lifetime: u32, tries: u32, base: f64) -> Option<GwReply> {
        let gw = self.gw?;
        let mut ext_ip = None;
        let mut buf = [0u8; 1500];
        for t in 0..tries {
            self.send_gateway(via, lifetime).await;
            let until = Instant::now() + Duration::from_secs_f64(base * f64::from(1u32 << t));
            while let Ok(Ok((n, from))) = tokio::time::timeout_at(until, self.sock.recv_from(&mut buf)).await {
                if from != SocketAddr::V4(SocketAddrV4::new(gw, PCP_PORT)) {
                    continue;
                }
                let reply = match via {
                    Via::Pcp => parse_pcp(&buf[..n], &self.nonce),
                    _ => parse_natpmp(&buf[..n], &mut ext_ip),
                };
                if let Some(mut r) = reply {
                    if let GwReply::Mapped(m) = &mut r {
                        m.external_ip = m.external_ip.or(ext_ip);
                    }
                    return Some(r);
                }
            }
        }
        None
    }

    // ---- UPnP ----

    /// The gateway that answers an SSDP search: a private address, port 1900, with a
    /// description at its own address (so a device on the LAN can't point us anywhere else).
    async fn discover(&mut self) -> Result<Igd, String> {
        const TARGETS: [&str; 3] = [
            "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
            "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
            "urn:schemas-upnp-org:service:WANIPConnection:1",
        ];
        let until = Instant::now() + SSDP_WAIT;
        let mut buf = [0u8; 1500];
        let mut found = None;
        'search: for _ in 0..2 {
            for st in TARGETS {
                let msg =
                    format!("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {st}\r\n\r\n");
                let _ = self.sock.send_to(msg.as_bytes(), SSDP).await;
            }
            let resend = Instant::now() + Duration::from_secs(1);
            while let Ok(Ok((n, from))) = tokio::time::timeout_at(resend.min(until), self.sock.recv_from(&mut buf)).await {
                let SocketAddr::V4(from) = from else { continue };
                if from.port() != SSDP.port() || !is_private(from.ip()) {
                    continue;
                }
                let msg = String::from_utf8_lossy(&buf[..n]);
                if !msg.starts_with("HTTP/1.1 200") {
                    continue;
                }
                let Some(loc) = header(&msg, "location") else { continue };
                if let Some((Some(port), path)) = url_path(loc, *from.ip()) {
                    found = Some((*from.ip(), port, path));
                    break 'search;
                }
            }
        }
        let (ip, port, desc) = found.ok_or("no UPnP, NAT-PMP or PCP router answered")?;
        if self.gw.is_none()
            && let Some(local) = local_toward(ip).await
        {
            self.local = local;
        }
        let req = format!("GET {desc} HTTP/1.1\r\nHost: {ip}:{port}\r\nConnection: close\r\n\r\n");
        let (status, body) = http(ip, port, &req).await.ok_or("the UPnP gateway stopped answering")?;
        let usable = "the UPnP gateway offers no usable WAN connection service";
        let (service, url) = (status == 200).then(|| control_url(&body)).flatten().ok_or(usable)?;
        let (at, ctl_path) = url_path(&url, ip).ok_or(usable)?;
        let port = at.unwrap_or(port);
        Ok(Igd {
            ip,
            port,
            ctl_path,
            service,
        })
    }

    fn soap(&self, action: &str, args: &str) -> Option<String> {
        let igd = self.igd.as_ref()?;
        let body = format!(
            "<?xml version=\"1.0\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
             s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:{action} xmlns:u=\"{}\">{args}</u:{action}>\
             </s:Body></s:Envelope>\r\n",
            igd.service
        );
        Some(format!(
            "POST {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nSOAPAction: \"{}#{action}\"\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            igd.ctl_path,
            igd.ip,
            igd.port,
            igd.service,
            body.len()
        ))
    }

    async fn upnp_add(&mut self) -> Result<Mapping, String> {
        let unreachable = || "can't reach the UPnP gateway".to_string();
        let mut conflicts = 0;
        loop {
            let args = format!(
                "<NewRemoteHost></NewRemoteHost><NewExternalPort>{}</NewExternalPort><NewProtocol>UDP</NewProtocol>\
                 <NewInternalPort>{}</NewInternalPort><NewInternalClient>{}</NewInternalClient><NewEnabled>1</NewEnabled>\
                 <NewPortMappingDescription>udp</NewPortMappingDescription><NewLeaseDuration>{}</NewLeaseDuration>",
                self.want_external,
                self.internal_port,
                self.local,
                if self.permanent { 0 } else { LEASE }
            );
            let req = self.soap("AddPortMapping", &args).ok_or_else(unreachable)?;
            let igd = self.igd.as_ref().expect("discovered");
            let (status, body) = http(igd.ip, igd.port, &req).await.ok_or_else(unreachable)?;
            if status == 200 {
                break;
            }
            let code: u32 = xml_text(&body, "errorCode").and_then(|c| c.parse().ok()).unwrap_or(0);
            if code == UPNP_ONLY_PERMANENT && !self.permanent {
                // OnlyPermanentLeasesSupported: mapped without a lease. It's still removed on exit.
                self.permanent = true;
            } else if code == UPNP_CONFLICT && conflicts < CONFLICT_TRIES {
                // ConflictInMappingEntry: something else has this port, so another is tried.
                self.want_external = 20000 + sodium::random_below(40000) as u16;
                conflicts += 1;
            } else {
                let code = if code > 0 { format!(", error {code}") } else { String::new() };
                return Err(format!("the UPnP gateway refused the mapping (HTTP {status}{code})"));
            }
        }
        let external_ip = match self.soap("GetExternalIPAddress", "") {
            Some(req) => {
                let igd = self.igd.as_ref().expect("discovered");
                http(igd.ip, igd.port, &req)
                    .await
                    .filter(|(s, _)| *s == 200)
                    .and_then(|(_, b)| xml_text(&b, "NewExternalIPAddress")?.parse().ok())
            }
            None => None,
        };
        Ok(Mapping {
            via: Via::Upnp,
            external_port: self.want_external,
            external_ip,
            lifetime: if self.permanent { 0 } else { LEASE },
        })
    }
}

enum GwReply {
    Mapped(Mapping),
    Refused,
    /// A NAT-PMP router answering a PCP request with "unsupported version".
    OtherProtocol,
}

/// PCP's answer to our MAP (RFC 6887), matched by its nonce.
fn parse_pcp(d: &[u8], nonce: &[u8; 12]) -> Option<GwReply> {
    if d.len() >= PCP_MAP_LEN && d[0] == PCP_VERSION && d[1] == PCP_RESPONSE | PCP_OP_MAP && d[24..36] == nonce[..] {
        if d[3] != 0 {
            return Some(GwReply::Refused);
        }
        // The external address, unless the router left it all zeros.
        let ext: [u8; 16] = d[44..60].try_into().expect("16 bytes");
        let external_ip = std::net::Ipv6Addr::from(ext).to_ipv4_mapped().filter(|ip| !ip.is_unspecified());
        return Some(GwReply::Mapped(Mapping {
            via: Via::Pcp,
            external_port: u16::from_be_bytes([d[42], d[43]]),
            external_ip,
            lifetime: u32::from_be_bytes([d[4], d[5], d[6], d[7]]),
        }));
    }
    (d.len() >= 2 && d[0] == 0).then_some(GwReply::OtherProtocol)
}

/// NAT-PMP's answers (RFC 6886): the external address, kept, and the mapping.
fn parse_natpmp(d: &[u8], ext_ip: &mut Option<Ipv4Addr>) -> Option<GwReply> {
    if d.len() < 4 || d[0] != 0 {
        return None;
    }
    let ok = u16::from_be_bytes([d[2], d[3]]) == 0;
    match d[1] {
        128 if d.len() >= 12 && ok => {
            *ext_ip = Some(Ipv4Addr::new(d[8], d[9], d[10], d[11]));
            None
        }
        129 if d.len() >= 16 => Some(if ok {
            GwReply::Mapped(Mapping {
                via: Via::NatPmp,
                external_port: u16::from_be_bytes([d[10], d[11]]),
                external_ip: *ext_ip,
                lifetime: u32::from_be_bytes([d[12], d[13], d[14], d[15]]),
            })
        } else {
            GwReply::Refused
        }),
        _ => None,
    }
}

fn is_private(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_private() || ip.is_link_local() || (o[0] == 100 && o[1] & 0xc0 == 64)
}

/// The default IPv4 gateway, from the routing table (Linux); None elsewhere, which leaves UPnP.
fn default_gateway() -> Option<Ipv4Addr> {
    let table = std::fs::read_to_string("/proc/net/route").ok()?;
    // Iface Destination Gateway Flags RefCnt Use Metric Mask: addresses as host-order hex.
    let mut best: Option<(u32, Ipv4Addr)> = None;
    for line in table.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        let hex = |i: usize| f.get(i).and_then(|s| u32::from_str_radix(s, 16).ok());
        let (Some(dest), Some(gw), Some(flags), Some(metric), Some(mask)) =
            (hex(1), hex(2), hex(3), f.get(6).and_then(|s| s.parse().ok()), hex(7))
        else {
            continue;
        };
        // RTF_UP and RTF_GATEWAY.
        if dest != 0 || mask != 0 || flags & 3 != 3 || gw == 0 || best.is_some_and(|(m, _)| metric >= m) {
            continue;
        }
        best = Some((metric, Ipv4Addr::from(gw.to_ne_bytes())));
    }
    best.map(|(_, ip)| ip)
}

/// Our address on the way to `to`.
async fn local_toward(to: Ipv4Addr) -> Option<Ipv4Addr> {
    let s = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.ok()?;
    s.connect((to, PCP_PORT)).await.ok()?;
    match s.local_addr().ok()? {
        SocketAddr::V4(a) if !a.ip().is_unspecified() => Some(*a.ip()),
        _ => None,
    }
}

/// One request, read until the gateway closes the connection.
async fn http(ip: Ipv4Addr, port: u16, req: &str) -> Option<(u16, String)> {
    let fetch = async {
        let mut s = TcpStream::connect((ip, port)).await.ok()?;
        s.write_all(req.as_bytes()).await.ok()?;
        let mut resp = Vec::new();
        s.take(HTTP_CAP as u64 + 1).read_to_end(&mut resp).await.ok()?;
        (resp.len() <= HTTP_CAP).then_some(resp)
    };
    let resp = timeout(HTTP_TIMEOUT, fetch).await.ok()??;
    http_body(&String::from_utf8_lossy(&resp))
}

/// A header's value (its name in any case).
fn header<'a>(msg: &'a str, name: &str) -> Option<&'a str> {
    msg.split("\r\n")
        .skip(1)
        .find_map(|l| {
            l.split_once(':')
                .filter(|(n, _)| n.trim().eq_ignore_ascii_case(name))
                .map(|(_, v)| v.trim())
        })
        .filter(|v| !v.is_empty())
}

/// A response's status and body, a chunked one put back together.
fn http_body(resp: &str) -> Option<(u16, String)> {
    if !resp.starts_with("HTTP/1.") {
        return None;
    }
    let status = resp.get(9..12)?.parse().ok()?;
    let (head, body) = resp.split_once("\r\n\r\n")?;
    let chunked = header(head, "transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    if !chunked {
        return Some((status, body.to_string()));
    }
    let (mut out, mut rest) = (String::new(), body);
    loop {
        let (size, after) = rest.split_once('\n')?;
        let size = usize::from_str_radix(size.trim().split(';').next()?.trim(), 16).ok()?;
        if size == 0 {
            return Some((status, out));
        }
        out.push_str(after.get(..size)?);
        rest = after.get(size..)?.strip_prefix("\r\n")?;
    }
}

/// The text of the first `<name>...</name>`.
fn xml_text(s: &str, name: &str) -> Option<String> {
    let lower = s.to_ascii_lowercase();
    let (open, close) = (
        format!("<{}>", name.to_ascii_lowercase()),
        format!("</{}>", name.to_ascii_lowercase()),
    );
    let a = lower.find(&open)? + open.len();
    let b = a + lower[a..].find(&close)?;
    Some(s[a..b].trim().to_string())
}

/// The WAN connection service a gateway's description offers, and its control URL.
fn control_url(xml: &str) -> Option<(String, String)> {
    const WANTED: [&str; 3] = [
        "urn:schemas-upnp-org:service:WANIPConnection:2",
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "urn:schemas-upnp-org:service:WANPPPConnection:1",
    ];
    let lower = xml.to_ascii_lowercase();
    for want in WANTED {
        let mut pos = 0;
        while let Some(a) = lower[pos..].find("<service>") {
            let start = pos + a;
            let Some(b) = lower[start..].find("</service>") else { break };
            let service = &xml[start..start + b];
            if xml_text(service, "serviceType").as_deref() == Some(want)
                && let Some(url) = xml_text(service, "controlURL")
            {
                return Some((want.to_string(), url));
            }
            pos = start + b + "</service>".len();
        }
    }
    None
}

/// `http://IP[:PORT]/path` at the gateway `ip` (no other host), or a path alone: the port
/// (None for a path alone, which keeps the one in use) and the path, printable ASCII only.
fn url_path(url: &str, ip: Ipv4Addr) -> Option<(Option<u16>, String)> {
    let mut port = None;
    let mut path = url;
    if url.len() >= 7 && url[..7].eq_ignore_ascii_case("http://") {
        let rest = &url[7..];
        let host_end = rest.find([':', '/']).unwrap_or(rest.len());
        if rest[..host_end] != ip.to_string() {
            return None;
        }
        let mut after = &rest[host_end..];
        port = Some(80);
        if let Some(p) = after.strip_prefix(':') {
            let digits = p.find(|c: char| !c.is_ascii_digit()).unwrap_or(p.len());
            port = Some(p[..digits].parse().ok().filter(|&p| p > 0)?);
            after = &p[digits..];
        }
        path = if after.is_empty() { "/" } else { after };
    }
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    path.bytes().all(|c| c > 0x20 && c < 0x7f).then_some((port, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing_what_routers_send() {
        let gw = Ipv4Addr::new(192, 168, 1, 1);
        assert_eq!(
            url_path("http://192.168.1.1:5000/desc.xml", gw),
            Some((Some(5000), "/desc.xml".into()))
        );
        assert_eq!(url_path("http://10.0.0.9/x", gw), None);
        assert_eq!(url_path("ctl/IPConn", gw), Some((None, "/ctl/IPConn".into())));
        let xml = "<root><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>\
                   <controlURL> /ctl/IPConn </controlURL></service></root>";
        assert_eq!(
            control_url(xml),
            Some(("urn:schemas-upnp-org:service:WANIPConnection:1".into(), "/ctl/IPConn".into()))
        );
        let chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        assert_eq!(http_body(chunked), Some((200, "hello world".into())));
        assert_eq!(
            xml_text("<s:Body><errorCode>718</errorCode></s:Body>", "errorCode").as_deref(),
            Some("718")
        );
        let mut ext = None;
        assert!(parse_natpmp(&[0, 128, 0, 0, 0, 0, 0, 0, 203, 0, 113, 7], &mut ext).is_none());
        assert_eq!(ext, Some(Ipv4Addr::new(203, 0, 113, 7)));
        let reply = [0, 129, 0, 0, 0, 0, 0, 0, 0x1f, 0x90, 0x1f, 0x91, 0, 0, 0x0e, 0x10];
        assert!(matches!(parse_natpmp(&reply, &mut ext), Some(GwReply::Mapped(m)) if m.external_port == 8081 && m.lifetime == 3600));
    }
}

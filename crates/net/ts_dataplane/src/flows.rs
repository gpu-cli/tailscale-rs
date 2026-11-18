//! Return traffic for connections this node opened.
//!
//! The packet filter matches an inbound packet's destination port against the tailnet policy,
//! which grants access to services. A reply to a connection this node opened arrives at the
//! node's own ephemeral port, which no rule names, so without this the reply is dropped and only
//! a peer that tracks connections itself (such as `tailscaled`) can be reached. As in
//! `tailscaled`'s filter: a TCP segment other than an opening SYN belongs to a connection the
//! policy already admitted at its SYN, and a UDP datagram is a reply when this node recently sent
//! one on the same flow.

use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

/// How long a UDP flow stays open after this node last sent on it.
const UDP_FLOW_TTL: Duration = Duration::from_secs(120);

/// The most UDP flows remembered; past this the oldest are forgotten first.
const MAX_UDP_FLOWS: usize = 4096;

/// A UDP flow, from this node's side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Flow {
    local: (IpAddr, u16),
    remote: (IpAddr, u16),
}

/// What the inbound filter needs to know about a packet's transport header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// A TCP segment; `opening` is a SYN without an ACK.
    Tcp { opening: bool },
    /// A UDP datagram between these ports.
    Udp { src_port: u16, dst_port: u16 },
    /// Anything else.
    Other,
}

/// UDP flows this node has sent on recently.
#[derive(Debug, Default)]
pub struct Flows {
    udp: HashMap<Flow, Instant>,
}

impl Flows {
    /// Records an outbound packet, `src` being this node.
    pub fn outbound(&mut self, src: IpAddr, dst: IpAddr, transport: Transport, now: Instant) {
        let Transport::Udp { src_port, dst_port } = transport else {
            return;
        };
        let flow = Flow {
            local: (src, src_port),
            remote: (dst, dst_port),
        };
        if self.udp.insert(flow, now).is_none() && self.udp.len() > MAX_UDP_FLOWS {
            self.udp
                .retain(|_, sent| now.saturating_duration_since(*sent) < UDP_FLOW_TTL);
            while self.udp.len() > MAX_UDP_FLOWS {
                let Some(oldest) = self
                    .udp
                    .iter()
                    .min_by_key(|(_, sent)| **sent)
                    .map(|(f, _)| *f)
                else {
                    break;
                };
                self.udp.remove(&oldest);
            }
        }
    }

    /// Whether an inbound packet, `dst` being this node, belongs to a connection already
    /// admitted, so it needs no rule of its own.
    pub fn is_return(&self, src: IpAddr, dst: IpAddr, transport: Transport, now: Instant) -> bool {
        match transport {
            Transport::Tcp { opening } => !opening,
            Transport::Udp { src_port, dst_port } => self
                .udp
                .get(&Flow {
                    local: (dst, dst_port),
                    remote: (src, src_port),
                })
                .is_some_and(|sent| now.saturating_duration_since(*sent) < UDP_FLOW_TTL),
            Transport::Other => false,
        }
    }
}

/// The source, destination and transport of an IP packet, if it is one.
pub fn classify(packet: &[u8]) -> Option<(IpAddr, IpAddr, Transport)> {
    let pkt = etherparse::SlicedPacket::from_ip(packet).ok()?;
    let (src, dst): (IpAddr, IpAddr) = match pkt.net? {
        etherparse::NetSlice::Ipv4(ip) => (
            ip.header().source_addr().into(),
            ip.header().destination_addr().into(),
        ),
        etherparse::NetSlice::Ipv6(ip) => (
            ip.header().source_addr().into(),
            ip.header().destination_addr().into(),
        ),
        _ => return None,
    };
    let transport = match pkt.transport {
        Some(etherparse::TransportSlice::Tcp(tcp)) => Transport::Tcp {
            opening: tcp.syn() && !tcp.ack(),
        },
        Some(etherparse::TransportSlice::Udp(udp)) => Transport::Udp {
            src_port: udp.source_port(),
            dst_port: udp.destination_port(),
        },
        _ => Transport::Other,
    };
    Some((src, dst, transport))
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(100, 64, 0, 1));
    const B: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(100, 64, 0, 2));

    fn udp(src_port: u16, dst_port: u16) -> Transport {
        Transport::Udp { src_port, dst_port }
    }

    #[test]
    fn tcp_other_than_an_opening_syn_is_return_traffic() {
        let flows = Flows::default();
        let now = Instant::now();
        assert!(!flows.is_return(B, A, Transport::Tcp { opening: true }, now));
        assert!(flows.is_return(B, A, Transport::Tcp { opening: false }, now));
    }

    #[test]
    fn a_udp_reply_on_a_flow_this_node_opened_is_return_traffic() {
        let mut flows = Flows::default();
        let now = Instant::now();
        assert!(!flows.is_return(B, A, udp(4747, 50000), now));
        flows.outbound(A, B, udp(50000, 4747), now);
        assert!(flows.is_return(B, A, udp(4747, 50000), now));
        // Another port of the same peer is not that flow.
        assert!(!flows.is_return(B, A, udp(4748, 50000), now));
        assert!(!flows.is_return(B, A, udp(4747, 50001), now));
        // Nor is the same port of another peer.
        let c = IpAddr::V4(std::net::Ipv4Addr::new(100, 64, 0, 3));
        assert!(!flows.is_return(c, A, udp(4747, 50000), now));
    }

    #[test]
    fn a_udp_flow_closes_after_its_ttl_without_outbound_traffic() {
        let mut flows = Flows::default();
        let now = Instant::now();
        flows.outbound(A, B, udp(50000, 4747), now);
        let later = now + UDP_FLOW_TTL + Duration::from_secs(1);
        assert!(!flows.is_return(B, A, udp(4747, 50000), later));
        flows.outbound(A, B, udp(50000, 4747), later);
        assert!(flows.is_return(B, A, udp(4747, 50000), later));
    }

    #[test]
    fn the_table_is_bounded_and_forgets_the_oldest_flow() {
        let mut flows = Flows::default();
        let now = Instant::now();
        for i in 0..=MAX_UDP_FLOWS {
            flows.outbound(
                A,
                B,
                udp(i as u16, 4747),
                now + Duration::from_millis(i as u64),
            );
        }
        assert_eq!(flows.udp.len(), MAX_UDP_FLOWS);
        let end = now + Duration::from_millis(MAX_UDP_FLOWS as u64);
        assert!(!flows.is_return(B, A, udp(4747, 0), end));
        assert!(flows.is_return(B, A, udp(4747, MAX_UDP_FLOWS as u16), end));
    }

    #[test]
    fn classify_reads_tcp_flags_and_udp_ports() {
        let mut syn = Vec::new();
        etherparse::PacketBuilder::ipv4([100, 64, 0, 2], [100, 64, 0, 1], 64)
            .tcp(4747, 50000, 1, 1024)
            .syn()
            .write(&mut syn, &[])
            .unwrap();
        assert_eq!(
            classify(&syn),
            Some((B, A, Transport::Tcp { opening: true }))
        );

        let mut syn_ack = Vec::new();
        etherparse::PacketBuilder::ipv4([100, 64, 0, 2], [100, 64, 0, 1], 64)
            .tcp(4747, 50000, 1, 1024)
            .syn()
            .ack(1)
            .write(&mut syn_ack, &[])
            .unwrap();
        assert_eq!(
            classify(&syn_ack),
            Some((B, A, Transport::Tcp { opening: false }))
        );

        let mut dgram = Vec::new();
        etherparse::PacketBuilder::ipv4([100, 64, 0, 2], [100, 64, 0, 1], 64)
            .udp(4747, 50000)
            .write(&mut dgram, b"hi")
            .unwrap();
        assert_eq!(classify(&dgram), Some((B, A, udp(4747, 50000))));
    }
}

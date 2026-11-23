//! The STUN codec held against stun-rs, the library it replaced: what it sends is a
//! Binding request stun-rs reads as one, what stun-rs encodes it reads the same, and a
//! mangled response it accepts is one stun-rs also accepts with the same answer.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use proptest::prelude::*;
use stun_rs::{
    MessageClass, MessageDecoderBuilder, MessageEncoderBuilder, StunMessageBuilder,
    attributes::stun::{Fingerprint, Software, XorMappedAddress},
    methods::BINDING,
};
use ts_netcheck::stun::{TransactionId, new_txn, try_decode};

fn encode_response(txn: [u8; 12], addr: SocketAddr, software: Option<&str>, fingerprint: bool) -> Vec<u8> {
    let mut builder = StunMessageBuilder::new(BINDING, MessageClass::SuccessResponse)
        .with_transaction_id(stun_rs::TransactionId::from(txn))
        .with_attribute(XorMappedAddress::from(addr));
    if let Some(software) = software {
        builder = builder.with_attribute(Software::new(software).unwrap());
    }
    if fingerprint {
        builder = builder.with_attribute(Fingerprint::default());
    }
    let msg = builder.build();
    let mut buf = vec![0u8; 1024];
    let n = MessageEncoderBuilder::default().build().encode(&mut buf, &msg).unwrap();
    buf.truncate(n);
    buf
}

/// What stun-rs makes of `packet`, held to what this codec decodes: a Binding success
/// response's transaction and XOR-mapped address.
fn reference(packet: &[u8]) -> Option<(TransactionId, SocketAddr)> {
    let (msg, n) = MessageDecoderBuilder::default().build().decode(packet).ok()?;
    if n != packet.len() || msg.class() != MessageClass::SuccessResponse || msg.method() != BINDING {
        return None;
    }
    let addr = *msg.get::<XorMappedAddress>()?.as_xor_mapped_address().ok()?.socket_address();
    Some((TransactionId(*msg.transaction_id().as_bytes()), addr))
}

/// `packet` with the value of every attribute the codec does not read made ASCII text,
/// and a FINGERPRINT that held over the original taken again over the result. stun-rs
/// refuses a SOFTWARE (or other text attribute) that is not UTF-8, which the codec never
/// looks at; this is the same message to the codec, and one stun-rs can judge on what the
/// codec does read.
fn unread_as_text(packet: &[u8]) -> Vec<u8> {
    const XOR_MAPPED_ADDRESS: u16 = 0x0020;
    const FINGERPRINT: u16 = 0x8028;
    let mut out = packet.to_vec();
    let mut at = 20;
    while at + 4 <= out.len() {
        let kind = u16::from_be_bytes([out[at], out[at + 1]]);
        let len = usize::from(u16::from_be_bytes([out[at + 2], out[at + 3]]));
        let end = at + 4 + len;
        if end > out.len() {
            break;
        }
        if kind == FINGERPRINT && len == 4 {
            let held = crc32fast::hash(&packet[..at]) ^ 0x5354_554E;
            if out[at + 4..end] == held.to_be_bytes() {
                let crc = crc32fast::hash(&out[..at]) ^ 0x5354_554E;
                out[at + 4..end].copy_from_slice(&crc.to_be_bytes());
            }
        } else if kind != XOR_MAPPED_ADDRESS {
            out[at + 4..end].fill(b'a');
        }
        at += 4 + len.next_multiple_of(4);
    }
    out
}

fn addr() -> impl Strategy<Value = SocketAddr> {
    prop_oneof![
        (any::<[u8; 4]>(), any::<u16>()).prop_map(|(ip, port)| SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)),
        (any::<[u8; 16]>(), any::<u16>()).prop_map(|(ip, port)| SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port)),
    ]
}

#[test]
fn a_request_is_one_stun_rs_reads() {
    for _ in 0..1000 {
        let (txn, buf) = new_txn();
        let (msg, n) = MessageDecoderBuilder::default().build().decode(&buf).unwrap();
        assert_eq!(n, buf.len());
        assert_eq!(msg.class(), MessageClass::Request);
        assert_eq!(msg.method(), BINDING);
        assert_eq!(msg.transaction_id().as_bytes(), &txn.0);
        assert!(msg.get::<Fingerprint>().is_some());
        assert!(msg.get::<Software>().is_some());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20_000))]

    #[test]
    fn a_response_stun_rs_encodes_reads_the_same(
        txn in any::<[u8; 12]>(),
        addr in addr(),
        software in proptest::option::of("[a-z ]{0,40}"),
        fingerprint in any::<bool>(),
    ) {
        let packet = encode_response(txn, addr, software.as_deref(), fingerprint);
        prop_assert_eq!(try_decode(&packet), Some((TransactionId(txn), addr)));
        prop_assert_eq!(try_decode(&packet), reference(&packet));
    }

    #[test]
    fn a_mangled_response_is_read_only_as_stun_rs_reads_it(
        txn in any::<[u8; 12]>(),
        addr in addr(),
        software in proptest::option::of("[a-z ]{0,40}"),
        fingerprint in any::<bool>(),
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 0..4),
        cut in any::<Option<usize>>(),
    ) {
        let mut packet = encode_response(txn, addr, software.as_deref(), fingerprint);
        for (at, bits) in flips {
            let at = at % packet.len();
            packet[at] ^= bits;
        }
        if let Some(cut) = cut {
            packet.truncate(cut % (packet.len() + 1));
        }
        if let Some(ours) = try_decode(&packet) {
            prop_assert_eq!(Some(ours), reference(&unread_as_text(&packet)), "{:?}", packet);
        }
    }

    #[test]
    fn random_bytes_never_panic(packet in proptest::collection::vec(any::<u8>(), 0..200)) {
        if let Some(ours) = try_decode(&packet) {
            prop_assert_eq!(Some(ours), reference(&unread_as_text(&packet)));
        }
    }
}

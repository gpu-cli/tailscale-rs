//! STUN functionality: the one exchange netcheck needs, a Binding request and the
//! XOR-MAPPED-ADDRESS of its success response (RFC 8489).

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::BytesMut;

const SOFTWARE: &[u8] = b"tailnode";

const HEADER_LEN: usize = 20;
const MAGIC_COOKIE: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;

const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_SOFTWARE: u16 = 0x8022;
const ATTR_FINGERPRINT: u16 = 0x8028;
/// XORed into the CRC-32 that makes a FINGERPRINT.
const FINGERPRINT_XOR: u32 = 0x5354_554E;

/// A STUN transaction ID: the 96 bits a response repeats from its request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TransactionId(pub [u8; 12]);

/// Create a new STUN binding transaction with a random id.
pub fn new_txn() -> (TransactionId, BytesMut) {
    let txn = TransactionId(rand::random());
    (txn, encode_request(txn))
}

/// The Binding request for `txn`, with SOFTWARE and FINGERPRINT attributes.
fn encode_request(txn: TransactionId) -> BytesMut {
    let software_len = SOFTWARE.len().next_multiple_of(4);
    let body_len = 4 + software_len + 8;
    let mut buf = BytesMut::with_capacity(HEADER_LEN + body_len);
    buf.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    buf.extend_from_slice(&(body_len as u16).to_be_bytes());
    buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    buf.extend_from_slice(&txn.0);
    buf.extend_from_slice(&ATTR_SOFTWARE.to_be_bytes());
    buf.extend_from_slice(&(SOFTWARE.len() as u16).to_be_bytes());
    buf.extend_from_slice(SOFTWARE);
    buf.resize(buf.len() + software_len - SOFTWARE.len(), 0);
    // The header's length already counts the fingerprint the CRC is taken before.
    let crc = crc32fast::hash(&buf) ^ FINGERPRINT_XOR;
    buf.extend_from_slice(&ATTR_FINGERPRINT.to_be_bytes());
    buf.extend_from_slice(&4u16.to_be_bytes());
    buf.extend_from_slice(&crc.to_be_bytes());
    buf
}

/// Try to decode `packet` as a STUN binding success response, returning its transaction
/// ID and the XOR-mapped address it contains. A packet that is not one, or whose
/// FINGERPRINT does not match, gives `None`.
pub fn try_decode(packet: &[u8]) -> Option<(TransactionId, SocketAddr)> {
    let decoded = decode(packet);
    if decoded.is_none() {
        tracing::debug!(len = packet.len(), "not a STUN binding response");
    }
    decoded
}

fn decode(packet: &[u8]) -> Option<(TransactionId, SocketAddr)> {
    let header = packet.get(..HEADER_LEN)?;
    let kind = u16::from_be_bytes([header[0], header[1]]);
    let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
    let cookie = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    if kind != BINDING_SUCCESS
        || cookie != MAGIC_COOKIE
        || len % 4 != 0
        || packet.len() != HEADER_LEN + len
    {
        return None;
    }
    let txn = TransactionId(header[8..20].try_into().ok()?);

    let mut mapped = None;
    let mut at = HEADER_LEN;
    while at < packet.len() {
        let attr = packet.get(at..at + 4)?;
        let kind = u16::from_be_bytes([attr[0], attr[1]]);
        let len = usize::from(u16::from_be_bytes([attr[2], attr[3]]));
        let value = packet.get(at + 4..at + 4 + len)?;
        let next = at + 4 + len.next_multiple_of(4);
        if next > packet.len() {
            return None;
        }
        match kind {
            // The first one counts; a later one is ignored, as RFC 8489 §14 says.
            ATTR_XOR_MAPPED_ADDRESS if mapped.is_none() => {
                mapped = Some(xor_mapped_address(value, &txn)?);
            }
            ATTR_FINGERPRINT => {
                // The last attribute, over everything before it.
                if next != packet.len() || len != 4 {
                    return None;
                }
                let want = crc32fast::hash(&packet[..at]) ^ FINGERPRINT_XOR;
                if value != want.to_be_bytes() {
                    return None;
                }
            }
            _ => {}
        }
        at = next;
    }
    Some((txn, mapped?))
}

fn xor_mapped_address(value: &[u8], txn: &TransactionId) -> Option<SocketAddr> {
    let cookie = MAGIC_COOKIE.to_be_bytes();
    let family = *value.get(1)?;
    let port = u16::from_be_bytes([*value.get(2)?, *value.get(3)?]) ^ (MAGIC_COOKIE >> 16) as u16;
    let ip = match (family, value.len()) {
        (0x01, 8) => {
            let mut octets = [0u8; 4];
            for (i, octet) in octets.iter_mut().enumerate() {
                *octet = value[4 + i] ^ cookie[i];
            }
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        (0x02, 20) => {
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&cookie);
            key[4..].copy_from_slice(&txn.0);
            let mut octets = [0u8; 16];
            for (i, octet) in octets.iter_mut().enumerate() {
                *octet = value[4 + i] ^ key[i];
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The response a server sends for `txn` mapping to `addr`, with `extra` attributes
    /// (type, value) after the address.
    fn response(txn: TransactionId, addr: SocketAddr, extra: &[(u16, &[u8])]) -> Vec<u8> {
        let mut attrs = Vec::new();
        let port = addr.port() ^ (MAGIC_COOKIE >> 16) as u16;
        let mut value = vec![0, 0];
        value.extend_from_slice(&port.to_be_bytes());
        let cookie = MAGIC_COOKIE.to_be_bytes();
        match addr.ip() {
            IpAddr::V4(ip) => {
                value[1] = 1;
                value.extend(ip.octets().iter().zip(cookie).map(|(a, b)| a ^ b));
            }
            IpAddr::V6(ip) => {
                value[1] = 2;
                let key: Vec<u8> = cookie.iter().chain(&txn.0).copied().collect();
                value.extend(ip.octets().iter().zip(key).map(|(a, b)| a ^ b));
            }
        }
        for (kind, value) in [(ATTR_XOR_MAPPED_ADDRESS, value.as_slice())]
            .into_iter()
            .chain(extra.iter().copied())
        {
            attrs.extend_from_slice(&kind.to_be_bytes());
            attrs.extend_from_slice(&(value.len() as u16).to_be_bytes());
            attrs.extend_from_slice(value);
            attrs.resize(attrs.len().next_multiple_of(4), 0);
        }
        let mut packet = Vec::new();
        packet.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        packet.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        packet.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        packet.extend_from_slice(&txn.0);
        packet.extend_from_slice(&attrs);
        packet
    }

    #[test]
    fn a_request_is_a_binding_request_with_its_fingerprint() {
        let (txn, buf) = new_txn();
        assert_eq!(buf.len(), 20 + 12 + 8);
        assert_eq!(&buf[..2], &[0, 1]);
        assert_eq!(&buf[8..20], &txn.0);
        let crc = crc32fast::hash(&buf[..buf.len() - 8]) ^ FINGERPRINT_XOR;
        assert_eq!(&buf[buf.len() - 4..], &crc.to_be_bytes());
    }

    #[test]
    fn a_response_gives_its_transaction_and_address() {
        let txn = TransactionId([7; 12]);
        for addr in ["203.0.113.9:41641", "[2001:db8::1]:3478"] {
            let addr: SocketAddr = addr.parse().unwrap();
            assert_eq!(try_decode(&response(txn, addr, &[])), Some((txn, addr)));
        }
    }

    #[test]
    fn a_fingerprint_is_checked_when_present() {
        let txn = TransactionId([3; 12]);
        let addr: SocketAddr = "198.51.100.4:1234".parse().unwrap();
        let mut packet = response(txn, addr, &[]);
        // A fingerprint over the message, with the length already counting it.
        let len = u16::from_be_bytes([packet[2], packet[3]]) + 8;
        packet[2..4].copy_from_slice(&len.to_be_bytes());
        let crc = crc32fast::hash(&packet) ^ FINGERPRINT_XOR;
        packet.extend_from_slice(&ATTR_FINGERPRINT.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes());
        packet.extend_from_slice(&crc.to_be_bytes());
        assert_eq!(try_decode(&packet), Some((txn, addr)));
        let last = packet.len() - 1;
        packet[last] ^= 1;
        assert_eq!(try_decode(&packet), None);
    }

    #[test]
    fn what_is_not_a_success_response_gives_nothing() {
        let txn = TransactionId([1; 12]);
        let addr: SocketAddr = "192.0.2.1:80".parse().unwrap();
        let good = response(txn, addr, &[(ATTR_SOFTWARE, b"x")]);
        assert!(try_decode(&good).is_some());
        let mut request = good.clone();
        request[..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
        let mut cookie = good.clone();
        cookie[4] ^= 1;
        let mut long = good.clone();
        long[3] += 4;
        let mut attr_past_end = good.clone();
        attr_past_end[23] = 200;
        let mut no_address = response(txn, addr, &[]);
        no_address[20..22].copy_from_slice(&0x0001u16.to_be_bytes());
        for bad in [
            &good[..19],
            &good[..good.len() - 1],
            &request[..],
            &cookie[..],
            &long[..],
            &attr_past_end[..],
            &no_address[..],
            &[][..],
        ] {
            assert_eq!(try_decode(bad), None, "{bad:?}");
        }
    }
}

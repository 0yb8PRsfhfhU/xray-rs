//! Ported from `Xray-core/common/protocol/address_test.go` and `uuid_test.go`.

use bytes::Bytes;
use kernel::types::net::{AddrCodec, Address};
use kernel::types::uuid::Uuid;

fn rd(codec: AddrCodec, input: &[u8]) -> kernel::Result<(Address, u16)> {
    let mut b = Bytes::copy_from_slice(input);
    codec.read(&mut b)
}

#[test]
fn address_reading() {
    // Standard family (0x01=v4, 0x03=domain, 0x04=v6), port-last.
    let std = AddrCodec::TROJAN;
    // VLESS family (0x01=v4, 0x02=domain, 0x03=v6), port-first.
    let vless = AddrCodec::VLESS;

    // empty / truncated
    assert!(rd(std, &[]).is_err());
    assert!(rd(std, &[0, 0, 0, 0, 0]).is_err());

    // IPv4, port-last
    let (a, p) = rd(std, &[1, 0, 0, 0, 0, 0, 53]).unwrap();
    assert_eq!(a, Address::parse("0.0.0.0"));
    assert_eq!(p, 53);

    // IPv4, port-first
    let (a, p) = rd(vless, &[0, 53, 1, 0, 0, 0, 0]).unwrap();
    assert_eq!(a, Address::parse("0.0.0.0"));
    assert_eq!(p, 53);

    // truncated IPv4
    assert!(rd(std, &[1, 0, 0, 0, 0]).is_err());

    // IPv6, port-last
    let (a, p) = rd(
        std,
        &[4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 0, 80],
    )
    .unwrap();
    assert_eq!(
        a,
        Address::from_ip_bytes(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6]).unwrap()
    );
    assert_eq!(p, 80);

    // Domain example.com:80
    let mut input = vec![3, 11];
    input.extend_from_slice(b"example.com");
    input.extend_from_slice(&[0, 80]);
    let (a, p) = rd(std, &input).unwrap();
    assert_eq!(a, Address::Domain("example.com".into()));
    assert_eq!(p, 80);

    // Domain present but port truncated
    let mut input = vec![3, 9];
    input.extend_from_slice(b"v2ray.com");
    input.push(0);
    assert!(rd(std, &input).is_err());

    // Domain "8.8.8.8" parses back to an IP
    let mut input = vec![3, 7];
    input.extend_from_slice(b"8.8.8.8");
    input.extend_from_slice(&[0, 80]);
    let (a, _) = rd(std, &input).unwrap();
    assert_eq!(a, Address::parse("8.8.8.8"));

    // Domain with invalid leading byte (\n) errors
    let mut input = vec![3, 7];
    input.extend_from_slice(&[10, b'8', b'.', b'8', b'.', b'8']);
    input.extend_from_slice(&[0, 80]);
    assert!(rd(std, &input).is_err());

    // IPv6 encoded as a domain string parses to an IP
    let mut input = vec![3, 24];
    input.extend_from_slice(b"2a00:1450:4007:816::200e");
    input.extend_from_slice(&[0, 80]);
    let (a, p) = rd(std, &input).unwrap();
    assert_eq!(a, Address::parse("2a00:1450:4007:816::200e"));
    assert_eq!(p, 80);
}

#[test]
fn address_writing() {
    use bytes::BytesMut;
    let mut buf = BytesMut::new();
    AddrCodec::TROJAN
        .write(&mut buf, &Address::parse("127.0.0.1"), 80)
        .unwrap();
    assert_eq!(&buf[..], &[1, 127, 0, 0, 1, 0, 80]);
}

#[test]
fn uuid_parse_bytes_and_string() {
    let s = "2418d087-648d-4990-86e8-19dca1d006d3";
    let want = [
        0x24, 0x18, 0xd0, 0x87, 0x64, 0x8d, 0x49, 0x90, 0x86, 0xe8, 0x19, 0xdc, 0xa1, 0xd0, 0x06,
        0xd3,
    ];
    let u = Uuid::parse_str(s).unwrap();
    assert_eq!(u.as_bytes(), &want);
    assert_eq!(u.to_string(), s);

    // short-string derivation is deterministic v5-over-zero-namespace
    let derived = Uuid::parse_str("example").unwrap();
    let known = Uuid::parse_str("feb54431-301b-52bb-a6dd-e1e93e81bb9e").unwrap();
    assert_eq!(derived, known);

    // bad hex / wrong length
    assert!(Uuid::parse_str("2418d087-648k-4990-86e8-19dca1d006d3").is_err());
    assert!(Uuid::parse_str("2418d087-648d-4990-86e8-19dca1d0").is_err());
}

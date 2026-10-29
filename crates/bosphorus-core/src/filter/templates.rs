//! WinDivert filter fragments derived from `ValdikSS/GoodbyeDPI`
//! `src/goodbyedpi.c` (`master`):
//!   * lines 33-61   — `DIVERT_NO_LOCALNETSv4/v6_{SRC,DST}` (verbatim)
//!   * lines 242-245 — `maxpayloadsize_str` (verbatim)
//!   * lines 82-84   — `FILTER_PASSIVE_BLOCK_QUIC` (deliberate, documented
//!     changes; see [`QUIC_CAPTURE_FMT`])
//!
//! Do not paraphrase or "tidy" the verbatim constants — they must match
//! GoodbyeDPI byte for byte (C adjacent-string-literal concatenation already
//! applied). The QUIC fragment is ours: it captures instead of dropping, because
//! a filter cannot tell QUIC from an ordinary large UDP datagram.

pub const NO_LOCALNETS_V4_DST: &str = "((ip.DstAddr < 127.0.0.1 or ip.DstAddr > 127.255.255.255) and (ip.DstAddr < 10.0.0.0 or ip.DstAddr > 10.255.255.255) and (ip.DstAddr < 192.168.0.0 or ip.DstAddr > 192.168.255.255) and (ip.DstAddr < 172.16.0.0 or ip.DstAddr > 172.31.255.255) and (ip.DstAddr < 169.254.0.0 or ip.DstAddr > 169.254.255.255))";

pub const NO_LOCALNETS_V4_SRC: &str = "((ip.SrcAddr < 127.0.0.1 or ip.SrcAddr > 127.255.255.255) and (ip.SrcAddr < 10.0.0.0 or ip.SrcAddr > 10.255.255.255) and (ip.SrcAddr < 192.168.0.0 or ip.SrcAddr > 192.168.255.255) and (ip.SrcAddr < 172.16.0.0 or ip.SrcAddr > 172.31.255.255) and (ip.SrcAddr < 169.254.0.0 or ip.SrcAddr > 169.254.255.255))";

pub const NO_LOCALNETS_V6_DST: &str = "((ipv6.DstAddr > ::1) and (ipv6.DstAddr < 2001::0 or ipv6.DstAddr > 2001:1::0) and (ipv6.DstAddr < fc00::0 or ipv6.DstAddr > fe00::0) and (ipv6.DstAddr < fe80::0 or ipv6.DstAddr > fec0::0) and (ipv6.DstAddr < ff00::0 or ipv6.DstAddr > ffff::0))";

pub const NO_LOCALNETS_V6_SRC: &str = "((ipv6.SrcAddr > ::1) and (ipv6.SrcAddr < 2001::0 or ipv6.SrcAddr > 2001:1::0) and (ipv6.SrcAddr < fc00::0 or ipv6.SrcAddr > fe00::0) and (ipv6.SrcAddr < fe80::0 or ipv6.SrcAddr > fec0::0) and (ipv6.SrcAddr < ff00::0 or ipv6.SrcAddr > ffff::0))";

/// Capture clause for both QUIC blocking policies
/// ([`QuicPolicy::Blocked`](crate::config::QuicPolicy::Blocked) and
/// [`QuicPolicy::All`](crate::config::QuicPolicy::All)).
///
/// This is *not* a drop rule. WinDivert's filter language can only inspect the
/// first payload bytes and the datagram length, so it cannot prove that a
/// datagram is QUIC: an ordinary UDP/443 datagram of 1200 bytes whose first byte
/// is `0x80..=0xFF` satisfies the same test. GoodbyeDPI's
/// `FILTER_PASSIVE_BLOCK_QUIC` (goodbyedpi.c:82-84) accepts that ambiguity and
/// drops the packet; this project instead hands candidates to
/// [`crate::packet::quic`], which parses the long header and drops only real
/// connection attempts. Everything else is forwarded untouched.
///
/// Deliberate differences from GoodbyeDPI:
///
/// * no `udp.Payload32[1b] == 0x01` version pin — that only matches QUIC v1 and
///   would let v2 (RFC 9369) and draft versions open connections untouched;
/// * `{min_first_byte}` is `0x80` (the long-header form bit), not `0xC0`, because
///   RFC 9287 lets endpoints grease the fixed bit to zero — see
///   [`LONG_HEADER_FIRST_BYTE_MIN`](crate::packet::quic::LONG_HEADER_FIRST_BYTE_MIN);
/// * `{dst_ports}` is the configured TLS/QUIC port set, so a custom
///   `tls_ports`/QUIC port is not silently ignored;
/// * `udp.PayloadLength >= 1200` — a datagram carrying an Initial must be padded
///   to 1200 bytes, so the short packets of an established connection never
///   reach the engine.
pub const QUIC_CAPTURE_FMT: &str = "(outbound and !impostor and !loopback and udp and {dst_ports} and udp.PayloadLength >= 1200 and udp.Payload[0] >= {min_first_byte} and ({v4dst} or {v6dst}))";

/// `maxpayloadsize_str` (goodbyedpi.c:242-245) — verbatim, with GoodbyeDPI's
/// `%hu` replaced by the `{n}` placeholder. "GET " = 0x47455420,
/// "POST" = 0x504F5354 (big endian).
pub const MAXPAYLOAD_FMT: &str = "and (tcp.PayloadLength ? tcp.PayloadLength < {n} or tcp.Payload32[0] == 0x47455420 or tcp.Payload32[0] == 0x504F5354 or (tcp.Payload[0] == 0x16 and tcp.Payload[1] == 0x03 and tcp.Payload[2] <= 0x03): true)";

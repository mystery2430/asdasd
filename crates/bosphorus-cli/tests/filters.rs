//! Integration: every filter string `bosphorus-core` builds must be accepted by
//! WinDivert's own compiler (`WinDivertHelperCompileFilter`, user-mode).

use std::net::{IpAddr, Ipv4Addr};

use bosphorus_core::config::QuicPolicy;
use bosphorus_core::{filter, EvasionConfig};
use bosphorus_divert::{compile_filter, Layer};

#[test]
fn default_filters_compile() {
    let f = filter::build(&EvasionConfig::default()).expect("build");
    compile_filter(&f.main, Layer::Network).expect("main filter accepted");
}

/// Every policy's filter, including the selective QUIC clause the engine needs
/// captured and the blanket drop clause only `all` opens.
#[test]
fn every_quic_policy_produces_filters_windivert_accepts() {
    for policy in [QuicPolicy::Off, QuicPolicy::Blocked, QuicPolicy::All] {
        let cfg = EvasionConfig {
            quic: policy,
            ..Default::default()
        };
        let f = filter::build(&cfg).expect("build");
        compile_filter(&f.main, Layer::Network)
            .unwrap_or_else(|e| panic!("main filter for {policy:?} rejected: {e:?}"));
    }
}

/// The selective clause has to reach the engine, so a missing piece here is a
/// silently disabled feature rather than a loud failure.
#[test]
fn the_selective_quic_clause_is_present_and_version_agnostic() {
    let f = filter::build(&EvasionConfig::default()).expect("build");
    let s = f.main.to_str().unwrap();
    assert!(s.contains("udp.DstPort == 443"), "no QUIC capture: {s}");
    assert!(s.contains("udp.PayloadLength >= 1200"));
    assert!(
        !s.contains("udp.Payload32[1b]"),
        "pinning the version would miss QUIC v2 and the drafts"
    );
    // Long-header form bit only. `>= 0xC0` also required the fixed bit, which
    // RFC 9287 allows endpoints to grease to zero, so greased Initials were
    // never captured: the engine could not classify (and refuse) them.
    assert!(
        s.contains("udp.Payload[0] >= 0x80"),
        "QUIC gate must accept every long header: {s}"
    );
    assert!(
        !s.contains("udp.Payload[0] >= 0xC0"),
        "the greasable fixed bit must not gate capture: {s}"
    );
    assert!(
        !s.contains("udp.SrcPort") || !s.contains("0xC0"),
        "sanity: the QUIC clause is a capture, not a drop rule"
    );
}

#[test]
fn dns_redirection_is_rejected_instead_of_silently_capturing_port_53() {
    let cfg = EvasionConfig {
        dns_upstream: Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))),
        ..Default::default()
    };
    let err = filter::build(&cfg).expect_err("unimplemented DNS redirection must fail");
    let text = err.to_string();
    assert!(text.contains("dns_upstream"), "{text}");
    assert!(text.contains("not implemented"), "{text}");
}

#[test]
fn custom_max_payload_compiles() {
    let cfg = EvasionConfig {
        max_payload_filter: 800,
        ..Default::default()
    };
    let f = filter::build(&cfg).expect("build");
    compile_filter(&f.main, Layer::Network).expect("main filter accepted");
}

#[test]
fn default_filter_carries_the_cloudflare_https_alt_ports_and_compiles() {
    let f = filter::build(&EvasionConfig::default()).expect("build");
    let s = f.main.to_str().unwrap();
    for p in ["443", "2053", "2083", "2087", "2096", "8443"] {
        assert!(
            s.contains(&format!("tcp.DstPort == {p}")),
            "outbound missing {p}"
        );
        assert!(
            s.contains(&format!("tcp.SrcPort == {p}")),
            "inbound missing {p}"
        );
    }
    compile_filter(&f.main, Layer::Network).expect("alt-port main filter accepted by WinDivert");
}

#[test]
fn a_wide_custom_tls_port_set_still_compiles() {
    let cfg = EvasionConfig {
        tls_ports: vec![443, 2053, 2083, 2087, 2096, 8443],
        ..Default::default()
    };
    let f = filter::build(&cfg).expect("build");
    compile_filter(&f.main, Layer::Network).expect("6-port main filter accepted by WinDivert");
}

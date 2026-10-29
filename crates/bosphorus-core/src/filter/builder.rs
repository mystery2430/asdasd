use std::ffi::CString;

use crate::config::EvasionConfig;
use crate::error::CoreError;
use crate::filter::templates as t;

/// The WinDivert filter strings for a run.
///
/// There is deliberately only one filter. An earlier revision opened a second
/// `WINDIVERT_FLAG_DROP` handle whose filter claimed to match QUIC; a filter can
/// only look at the first payload bytes and the length, so it also matched
/// ordinary UDP/443 traffic and dropped it without any way to tell. QUIC
/// candidates now come in on the main handle and are classified by
/// [`crate::packet::quic`] before anything is dropped.
#[derive(Debug)]
pub struct Filters {
    /// Main capture handle (divert mode): outbound TLS requests + inbound
    /// SYN-ACK / RST / first-data(`16`) for verdict feedback, plus QUIC
    /// candidates when [`crate::config::QuicPolicy::wants_capture`].
    pub main: CString,
}

/// `(tcp.DstPort == 443 or tcp.DstPort == 2083 or ...)` for `field`
/// (`tcp.DstPort` / `tcp.SrcPort`) over every configured TLS port.
fn port_clause(ports: &[u16], field: &str) -> String {
    let inner = ports
        .iter()
        .map(|p| format!("{field} == {p}"))
        .collect::<Vec<_>>()
        .join(" or ");
    format!("({inner})")
}

/// Build the filter strings from config. String assembly only — call
/// `bosphorus_divert::compile_filter` to check them against WinDivert.
pub fn build(cfg: &EvasionConfig) -> Result<Filters, CoreError> {
    let maxpayload = t::MAXPAYLOAD_FMT.replace("{n}", &cfg.max_payload_filter.to_string());
    let ports = cfg.effective_tls_ports();
    // One source of truth with the packet parser: the coarse gate is the QUIC
    // long-header form bit. Requiring the fixed bit too (`0xC0`) missed long
    // headers whose fixed bit is greased to zero (RFC 9287).
    let min_first_byte = format!("{:#04X}", crate::packet::quic::LONG_HEADER_FIRST_BYTE_MIN);

    // Inbound verdict clause: SYN-ACK (passive TTL, M7), RST (DpiReset), and the
    // first data segment of a TLS response — `Payload[0] == 0x16` confirmed in
    // M0/V1 as a reliable ServerHello marker (WinDivert does no reassembly).
    let inbound = format!(
        "(inbound and {src_ports} and \
           ((tcp.Syn and tcp.Ack) or tcp.Rst or (tcp.PayloadLength > 0 and tcp.Payload[0] == 0x16)) \
           and ({v4src} or {v6src}))",
        src_ports = port_clause(ports, "tcp.SrcPort"),
        v4src = t::NO_LOCALNETS_V4_SRC,
        v6src = t::NO_LOCALNETS_V6_SRC,
    );

    // Outbound clause: mirrors GoodbyeDPI's outbound half. 443 plus the
    // Cloudflare HTTPS-alt ports (see `EvasionConfig::tls_ports`).
    let outbound = format!(
        "(outbound and {dst_ports} and tcp.Ack and ({v4dst} or {v6dst}))",
        dst_ports = port_clause(ports, "tcp.DstPort"),
        v4dst = t::NO_LOCALNETS_V4_DST,
        v6dst = t::NO_LOCALNETS_V6_DST,
    );

    let mut main =
        format!("(tcp and !impostor and !loopback {maxpayload} and ({inbound} or {outbound}))");
    if cfg.quic.wants_capture() {
        // Both blocking policies need the datagram: the engine decides per
        // destination for `blocked`, and `all` still needs the parser to tell a
        // QUIC Initial from an ordinary UDP datagram that merely looks like one.
        main.push_str(" or ");
        main.push_str(
            &t::QUIC_CAPTURE_FMT
                .replace("{dst_ports}", &port_clause(ports, "udp.DstPort"))
                .replace("{v4dst}", t::NO_LOCALNETS_V4_DST)
                .replace("{v6dst}", t::NO_LOCALNETS_V6_DST)
                .replace("{min_first_byte}", &min_first_byte),
        );
    }
    if cfg.dns_upstream.is_some() {
        // Capturing UDP/53 is not DNS redirection. Until the engine can rewrite
        // both directions, checksums included, reject the configuration instead
        // of silently leaving traffic on its original resolver.
        return Err(CoreError::Config(
            "dns_upstream is not implemented; remove it from the configuration".into(),
        ));
    }

    let main =
        CString::new(main).map_err(|_| CoreError::Filter("main filter has interior NUL".into()))?;

    Ok(Filters { main })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::QuicPolicy;
    use std::net::{IpAddr, Ipv4Addr};

    fn count(s: &str, ch: char) -> usize {
        s.chars().filter(|c| *c == ch).count()
    }

    #[test]
    fn parens_balanced_default() {
        let f = build(&EvasionConfig::default()).unwrap();
        let s = f.main.to_str().unwrap();
        assert_eq!(count(s, '('), count(s, ')'), "main: {s}");
        // One handle only: QUIC is classified by the engine, never dropped by a
        // driver filter that cannot tell it from ordinary UDP.
        assert!(s.contains("udp.DstPort == 443"), "{s}");
    }

    #[test]
    fn verbatim_fragments_present() {
        let s = build(&EvasionConfig::default())
            .unwrap()
            .main
            .into_string()
            .unwrap();
        assert!(s.contains(t::NO_LOCALNETS_V4_SRC));
        assert!(s.contains(t::NO_LOCALNETS_V6_DST));
        assert!(s.contains("tcp.Payload[0] == 0x16"));
        assert!(s.contains("tcp.PayloadLength < 1200")); // {n} substituted
        assert!(!s.contains("udp.SrcPort == 53")); // no DNS clause by default
    }

    #[test]
    fn selective_quic_is_captured_by_the_main_filter() {
        let s = build(&EvasionConfig::default())
            .unwrap()
            .main
            .into_string()
            .unwrap();
        assert!(s.contains("udp.DstPort == 443"));
        assert!(s.contains("udp.PayloadLength >= 1200"));
        let gate = format!(
            "udp.Payload[0] >= {:#04X}",
            crate::packet::quic::LONG_HEADER_FIRST_BYTE_MIN
        );
        assert!(s.contains(&gate), "selective gate missing {gate}: {s}");
        assert!(
            !s.contains("udp.Payload[0] >= 0xC0"),
            "the gate must not require the greasable fixed bit: {s}"
        );
        assert!(
            !s.contains("udp.Payload32[1b]"),
            "the version pin would miss QUIC v2 and the drafts"
        );
        assert_eq!(count(&s, '('), count(&s, ')'));
    }

    #[test]
    fn quic_off_captures_no_udp_at_all() {
        let cfg = EvasionConfig {
            quic: QuicPolicy::Off,
            ..Default::default()
        };
        let s = build(&cfg).unwrap().main.into_string().unwrap();
        assert!(!s.contains("udp"), "no UDP capture at all: {s}");
    }

    #[test]
    fn quic_all_captures_candidates_for_the_engine_instead_of_dropping_them() {
        // Regression: `all` used to open a WINDIVERT_FLAG_DROP handle whose only
        // test was "large UDP on 443 starting with a high byte". That silently
        // discarded non-QUIC UDP and could not be corrected later, because the
        // driver never delivered the packet. `all` must now behave like
        // `blocked` at capture time and let the parser decide.
        let cfg = EvasionConfig {
            quic: QuicPolicy::All,
            ..Default::default()
        };
        let s = build(&cfg).unwrap().main.into_string().unwrap();
        assert!(s.contains("udp.DstPort == 443"), "no QUIC capture: {s}");
        assert!(s.contains("udp.PayloadLength >= 1200"), "{s}");
        let gate = format!(
            "udp.Payload[0] >= {:#04X}",
            crate::packet::quic::LONG_HEADER_FIRST_BYTE_MIN
        );
        assert!(s.contains(&gate), "missing gate {gate}: {s}");
        assert!(!s.contains("0xC0"), "fixed bit must not gate capture: {s}");
        assert_eq!(count(&s, '('), count(&s, ')'), "{s}");
    }

    #[test]
    fn both_blocking_policies_use_the_configured_ports() {
        // Regression: the old blanket-drop filter hard-coded 443 while the
        // selective path used `tls_ports`, so `--quic all` silently ignored a
        // configured QUIC port.
        for policy in [QuicPolicy::Blocked, QuicPolicy::All] {
            let cfg = EvasionConfig {
                quic: policy,
                tls_ports: vec![443, 8443],
                ..Default::default()
            };
            let s = build(&cfg).unwrap().main.into_string().unwrap();
            for port in [443, 8443] {
                assert!(
                    s.contains(&format!("udp.DstPort == {port}")),
                    "{policy:?} misses UDP {port}: {s}"
                );
            }
        }
    }

    #[test]
    fn unsupported_dns_redirection_is_rejected() {
        let cfg = EvasionConfig {
            dns_upstream: Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))),
            ..Default::default()
        };
        match build(&cfg) {
            Err(CoreError::Config(msg)) => {
                assert!(msg.contains("dns_upstream"), "{msg}");
                assert!(msg.contains("not implemented"), "{msg}");
            }
            other => panic!("unimplemented DNS redirection must fail loudly: {other:?}"),
        }
    }

    #[test]
    fn default_filter_covers_the_cloudflare_https_alt_ports() {
        let s = build(&EvasionConfig::default())
            .unwrap()
            .main
            .into_string()
            .unwrap();
        for p in [443u16, 2053, 2083, 2087, 2096, 8443] {
            assert!(
                s.contains(&format!("tcp.DstPort == {p}")),
                "outbound missing {p}: {s}"
            );
            assert!(
                s.contains(&format!("tcp.SrcPort == {p}")),
                "inbound missing {p}: {s}"
            );
        }
        assert_eq!(count(&s, '('), count(&s, ')'), "unbalanced: {s}");
    }

    #[test]
    fn tls_ports_are_configurable_and_empty_falls_back_to_443() {
        let custom = EvasionConfig {
            tls_ports: vec![443, 9443],
            ..Default::default()
        };
        let s = build(&custom).unwrap().main.into_string().unwrap();
        assert!(s.contains("tcp.DstPort == 9443"));
        assert!(!s.contains("2096"), "default set not used when overridden");

        let cleared = EvasionConfig {
            tls_ports: vec![],
            ..Default::default()
        };
        let s = build(&cleared).unwrap().main.into_string().unwrap();
        assert!(s.contains("(tcp.DstPort == 443)"));
        assert!(!s.contains("2083"));
        assert_eq!(count(&s, '('), count(&s, ')'));
    }

    #[test]
    fn port_clause_shape() {
        assert_eq!(
            port_clause(&[443, 2096], "tcp.DstPort"),
            "(tcp.DstPort == 443 or tcp.DstPort == 2096)"
        );
        assert_eq!(port_clause(&[443], "tcp.SrcPort"), "(tcp.SrcPort == 443)");
    }
}

use std::ffi::CString;

use crate::config::EvasionConfig;
use crate::error::CoreError;
use crate::filter::templates as t;

/// The WinDivert filter strings for a run.
#[derive(Debug)]
pub struct Filters {
    /// Main capture handle (divert mode): outbound 443 requests + inbound 443
    /// SYN-ACK / RST / first-data(`16`) for verdict feedback.
    pub main: CString,
    /// QUIC-drop handle (`WINDIVERT_FLAG_DROP`), when enabled.
    pub quic_drop: Option<CString>,
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
    let min_first_byte = format!(
        "{:#04X}",
        crate::packet::quic::LONG_HEADER_FIRST_BYTE_MIN
    );

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
    if cfg.quic.wants_selective_capture() {
        // The engine decides per destination, so these have to be captured
        // rather than dropped in the driver.
        main.push_str(" or ");
        main.push_str(
            &t::QUIC_SELECTIVE_FMT
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
    let quic_drop = if cfg.quic.wants_blanket_drop() {
        let filter = t::QUIC_DROP.replace("{min_first_byte}", &min_first_byte);
        Some(CString::new(filter).map_err(|_| CoreError::Filter("quic filter has interior NUL".into()))?)
    } else {
        None
    };

    Ok(Filters { main, quic_drop })
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
        assert!(
            f.quic_drop.is_none(),
            "selective QUIC needs capture, not a drop handle"
        );
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
    fn quic_off_touches_neither_the_filter_nor_the_drop_handle() {
        let cfg = EvasionConfig {
            quic: QuicPolicy::Off,
            ..Default::default()
        };
        let f = build(&cfg).unwrap();
        let s = f.main.to_str().unwrap();
        assert!(!s.contains("udp"), "no UDP capture at all: {s}");
        assert!(f.quic_drop.is_none());
    }

    #[test]
    fn quic_all_drops_in_the_driver_instead_of_capturing() {
        let cfg = EvasionConfig {
            quic: QuicPolicy::All,
            ..Default::default()
        };
        let f = build(&cfg).unwrap();
        assert!(!f.main.to_str().unwrap().contains("udp"));
        let drop_filter = f.quic_drop.unwrap().into_string().unwrap();
        // The v1-only version field must not reappear: it misses v2 and drafts.
        assert!(!drop_filter.contains("Payload32[1b]"), "{drop_filter}");
        assert!(drop_filter.contains("udp.PayloadLength >= 1200"));
        // The gate is the long-header form bit alone (0x80), shared with the
        // packet parser. `0xC0` also required the fixed bit, which RFC 9287 lets
        // endpoints grease to zero, so those Initials escaped the blanket drop.
        let gate = format!(
            "udp.Payload[0] >= {:#04X}",
            crate::packet::quic::LONG_HEADER_FIRST_BYTE_MIN
        );
        assert!(drop_filter.contains(&gate), "drop gate missing {gate}: {drop_filter}");
        assert!(!drop_filter.contains("0xC0"), "fixed bit must not be required: {drop_filter}");
        assert_eq!(
            drop_filter,
            t::QUIC_DROP.replace(
                "{min_first_byte}",
                &format!("{:#04X}", crate::packet::quic::LONG_HEADER_FIRST_BYTE_MIN)
            )
        );
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

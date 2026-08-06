use std::net::{
    IpAddr,
    Ipv4Addr,
    Ipv6Addr,
};

/// Whether the address falls outside public unicast space, and so must not be
/// reachable by resolving an untrusted DID.
///
/// `IpAddr::is_global` is unstable, so the ranges are spelled out.
pub const fn is_restricted(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_restricted_v4(ip),
        IpAddr::V6(ip) => is_restricted_v6(ip),
    }
}

const fn is_restricted_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();

    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || a == 0
        || a >= 240
        || (a == 100 && (b & 0xC0) == 64)
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (b & 0xFE) == 18)
}

const fn is_restricted_v6(ip: Ipv6Addr) -> bool {
    // ::ffff:127.0.0.1 reaches the same host as 127.0.0.1.
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_restricted_v4(mapped);
    }

    let first = ip.segments()[0];

    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (first & 0xFE00) == 0xFC00
        || (first & 0xFFC0) == 0xFE80
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    fn restricted(s: &str) -> bool {
        is_restricted(IpAddr::from_str(s).expect("valid address"))
    }

    #[test]
    fn blocks_loopback_and_metadata() {
        assert!(restricted("127.0.0.1"));
        assert!(restricted("127.1.2.3"));
        assert!(restricted("0.0.0.0"));
        assert!(restricted("169.254.169.254"));
        assert!(restricted("::1"));
        assert!(restricted("::"));
    }

    #[test]
    fn blocks_private_ranges() {
        assert!(restricted("10.0.0.1"));
        assert!(restricted("172.16.0.1"));
        assert!(restricted("192.168.1.1"));
        assert!(restricted("100.64.0.1"));
        assert!(restricted("198.18.0.1"));
        assert!(restricted("192.0.0.1"));
        assert!(restricted("255.255.255.255"));
        assert!(restricted("240.0.0.1"));
    }

    #[test]
    fn blocks_ipv6_local() {
        assert!(restricted("fc00::1"));
        assert!(restricted("fd00::1"));
        assert!(restricted("fe80::1"));
        assert!(restricted("ff02::1"));
    }

    #[test]
    fn blocks_ipv4_mapped_loopback() {
        assert!(restricted("::ffff:127.0.0.1"));
        assert!(restricted("::ffff:169.254.169.254"));
        assert!(restricted("::ffff:10.0.0.1"));
    }

    #[test]
    fn allows_public() {
        assert!(!restricted("1.1.1.1"));
        assert!(!restricted("8.8.8.8"));
        assert!(!restricted("192.0.3.1"));
        assert!(!restricted("198.20.0.1"));
        assert!(!restricted("2606:4700:4700::1111"));
    }
}

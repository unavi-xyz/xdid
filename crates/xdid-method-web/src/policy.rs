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
    if let Some(embedded) = embedded_v4(ip) {
        return is_restricted_v4(embedded);
    }

    let s = ip.segments();

    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (s[0] & 0xFE00) == 0xFC00
        || (s[0] & 0xFFC0) == 0xFE80
        // 100::/64, discard-only.
        || (s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0)
        // 2001::/23, IETF protocol assignments, which includes Teredo and the
        // benchmarking range.
        || (s[0] == 0x2001 && (s[1] & 0xFE00) == 0)
        // 2001:db8::/32, documentation.
        || (s[0] == 0x2001 && s[1] == 0x0db8)
}

/// The IPv4 destination an address carries, for the encodings that embed one.
/// Each reaches the same host as the bare IPv4 address, so handling only the
/// mapped form leaves the rest as a way around [`is_restricted_v4`].
const fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return Some(mapped);
    }

    let s = ip.segments();

    // 6to4, 2002:<v4>::/48.
    if s[0] == 0x2002 {
        return Some(v4_of(s[1], s[2]));
    }

    // NAT64 well-known prefix, 64:ff9b::/96.
    if s[0] == 0x0064 && s[1] == 0xFF9B && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 {
        return Some(v4_of(s[6], s[7]));
    }

    // IPv4-compatible, ::<v4>, deprecated by RFC 4291. `::` and `::1` also
    // match, and both land in 0.0.0.0/8, which is restricted.
    if s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 {
        return Some(v4_of(s[6], s[7]));
    }

    None
}

const fn v4_of(high: u16, low: u16) -> Ipv4Addr {
    let [a, b] = high.to_be_bytes();
    let [c, d] = low.to_be_bytes();

    Ipv4Addr::new(a, b, c, d)
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

    /// Four encodings carry an IPv4 destination. Handling only the mapped form
    /// leaves the other three reaching the same hosts.
    #[test]
    fn blocks_every_ipv4_embedding() {
        assert!(restricted("::127.0.0.1"), "IPv4-compatible");
        assert!(restricted("::169.254.169.254"), "IPv4-compatible");
        assert!(restricted("2002:7f00:1::"), "6to4 to 127.0.0.1");
        assert!(restricted("2002:a9fe:a9fe::"), "6to4 to 169.254.169.254");
        assert!(restricted("64:ff9b::127.0.0.1"), "NAT64");
        assert!(restricted("64:ff9b::10.0.0.1"), "NAT64");
    }

    #[test]
    fn blocks_reserved_ipv6_ranges() {
        assert!(restricted("2001:db8::1"), "documentation");
        assert!(restricted("2001::1"), "Teredo");
        assert!(restricted("2001:2::1"), "benchmarking");
        assert!(restricted("100::1"), "discard-only");
    }

    #[test]
    fn allows_public() {
        assert!(!restricted("1.1.1.1"));
        assert!(!restricted("8.8.8.8"));
        assert!(!restricted("192.0.3.1"));
        assert!(!restricted("198.20.0.1"));
        assert!(!restricted("2606:4700:4700::1111"));
        assert!(!restricted("2001:4860:4860::8888"));
    }

    /// An embedding whose destination is public reaches a public host, so the
    /// widened rules must not swallow the whole prefix.
    #[test]
    fn allows_a_public_ipv4_embedding() {
        assert!(!restricted("2002:808:808::"));
        assert!(!restricted("64:ff9b::8.8.8.8"));
    }
}

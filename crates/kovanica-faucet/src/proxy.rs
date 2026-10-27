//! Trusted-proxy aware client IP resolution.
//!
//! The faucet rate limiter keys on the client IP. Behind a reverse proxy every
//! request arrives from the proxy's socket address, so without `X-Forwarded-For`
//! (XFF) all clients collapse onto one bucket and one caller can exhaust
//! everyone's quota.
//!
//! XFF is fully client-controllable, so it is **only** honoured when the socket
//! peer itself is a configured trusted proxy:
//!
//! * socket peer **not** trusted → always use the socket peer IP, XFF ignored;
//! * socket peer trusted → walk the XFF chain right-to-left, skipping trusted
//!   hops; the first untrusted address is the real client. If every hop is
//!   trusted, the leftmost entry is used. A malformed header fails closed to the
//!   socket peer IP.

use std::net::IpAddr;

use anyhow::{bail, Result};

/// A single allowlist entry: a bare IP (`10.0.0.7`) or a CIDR (`10.0.0.0/8`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let (addr_part, prefix_part) = match s.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (s, None),
        };
        let net: IpAddr = addr_part
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid IP address `{addr_part}` in `{s}`"))?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_part {
            Some(p) => p
                .parse::<u8>()
                .map_err(|_| anyhow::anyhow!("invalid prefix length `{p}` in `{s}`"))?,
            None => max,
        };
        if prefix > max {
            bail!("prefix length {prefix} exceeds {max} in `{s}`");
        }
        Ok(Self { net, prefix })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.net, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let bits = u32::from(net);
                let mask = match self.prefix {
                    0 => 0,
                    p if p >= 32 => u32::MAX,
                    p => u32::MAX << (32 - p),
                };
                (bits & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let bits = u128::from(net);
                let mask = match self.prefix {
                    0 => 0,
                    p if p >= 128 => u128::MAX,
                    p => u128::MAX << (128 - p),
                };
                (bits & mask) == (u128::from(ip) & mask)
            }
            // IPv4 and IPv6 never match across families.
            _ => false,
        }
    }
}

/// A parsed list of trusted reverse-proxy IPs/CIDRs.
#[derive(Clone, Debug, Default)]
pub struct TrustedProxies {
    entries: Vec<Cidr>,
}

impl TrustedProxies {
    /// Parse a comma-separated list of IPs and CIDRs.
    ///
    /// An empty/whitespace-only list yields "trust nobody". A malformed entry is
    /// an error so an operator typo fails fast instead of silently disabling
    /// trust (or, worse, silently widening it).
    pub fn parse_list(list: &str) -> Result<Self> {
        let mut entries = Vec::new();
        for raw in list.split(',') {
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            entries.push(Cidr::parse(raw)?);
        }
        Ok(Self { entries })
    }

    /// No trusted proxies configured.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether `ip` is one of the configured trusted proxies.
    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        self.entries.iter().any(|cidr| cidr.contains(ip))
    }
}

/// The IP the rate limiter should key on.
///
/// `socket_ip` is the TCP peer; `forwarded_for` is the raw `X-Forwarded-For`
/// header value (if any).
pub fn client_ip(
    socket_ip: IpAddr,
    forwarded_for: Option<&str>,
    trusted: &TrustedProxies,
) -> IpAddr {
    // Never honour client-supplied XFF unless the peer is a trusted proxy.
    if trusted.is_empty() || !trusted.is_trusted(socket_ip) {
        return socket_ip;
    }
    let Some(header) = forwarded_for else {
        return socket_ip;
    };

    // Walk right-to-left: the rightmost entry was appended by the proxy closest
    // to us. The first address that is not itself a trusted proxy is the client.
    for raw in header.split(',').rev() {
        match parse_forwarded_ip(raw) {
            Some(ip) if !trusted.is_trusted(ip) => return ip,
            // Trusted hop: keep walking towards the origin.
            Some(_) => continue,
            // Malformed header: fail closed to the socket peer.
            None => return socket_ip,
        }
    }

    // Every hop was trusted (or the header had no parseable entry): fall back to
    // the leftmost address if it parses, otherwise the socket peer.
    header
        .split(',')
        .next()
        .and_then(parse_forwarded_ip)
        .unwrap_or(socket_ip)
}

/// Parse one `X-Forwarded-For` element, tolerating `ip:port` and `[v6]:port`.
fn parse_forwarded_ip(raw: &str) -> Option<IpAddr> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Some(ip);
    }
    // `[2001:db8::1]:443`
    if let Some(rest) = raw.strip_prefix('[') {
        if let Some((addr, _)) = rest.split_once(']') {
            return addr.parse::<IpAddr>().ok();
        }
    }
    // `203.0.113.9:443`
    if let Some((addr, port)) = raw.rsplit_once(':') {
        if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            return addr.parse::<IpAddr>().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    // ---- CIDR parsing/matching -------------------------------------------

    #[test]
    fn cidr_matches_exact_ip_and_subnet() {
        let exact = Cidr::parse("10.0.0.7").unwrap();
        assert!(exact.contains(ip("10.0.0.7")));
        assert!(!exact.contains(ip("10.0.0.8")));

        let subnet = Cidr::parse("10.0.0.0/24").unwrap();
        assert!(subnet.contains(ip("10.0.0.1")));
        assert!(subnet.contains(ip("10.0.0.255")));
        assert!(!subnet.contains(ip("10.0.1.0")));

        let v6 = Cidr::parse("2001:db8::/32").unwrap();
        assert!(v6.contains(ip("2001:db8:1::1")));
        assert!(!v6.contains(ip("2001:db9::1")));

        // Family mismatch never matches.
        assert!(!subnet.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        // /0 matches the whole family.
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(ip("8.8.8.8")));
    }

    #[test]
    fn cidr_rejects_malformed_entries() {
        assert!(Cidr::parse("not-an-ip").is_err());
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("10.0.0.0/abc").is_err());
        assert!(Cidr::parse("2001:db8::/129").is_err());
    }

    #[test]
    fn parse_list_skips_blanks_but_rejects_typos() {
        let t = TrustedProxies::parse_list(" 10.0.0.1 , ,10.0.0.0/8 ,").unwrap();
        assert!(!t.is_empty());
        assert!(t.is_trusted(v4(10, 1, 2, 3)));
        assert!(t.is_trusted(v4(10, 0, 0, 1)));
        assert!(!t.is_trusted(v4(11, 0, 0, 1)));

        assert!(TrustedProxies::parse_list("").unwrap().is_empty());
        assert!(TrustedProxies::parse_list("garbage").is_err());
    }

    // ---- XFF handling -----------------------------------------------------

    #[test]
    fn untrusted_socket_ignores_client_supplied_xff() {
        let trusted = TrustedProxies::parse_list("10.0.0.0/8").unwrap();
        // Socket peer is NOT in the trusted list, so a spoofed XFF is ignored.
        let peer = v4(203, 0, 113, 9);
        assert_eq!(
            client_ip(peer, Some("1.2.3.4"), &trusted),
            v4(203, 0, 113, 9)
        );
    }

    #[test]
    fn empty_trusted_list_ignores_xff() {
        let trusted = TrustedProxies::default();
        let peer = v4(10, 0, 0, 1);
        assert_eq!(client_ip(peer, Some("1.2.3.4"), &trusted), v4(10, 0, 0, 1));
    }

    #[test]
    fn trusted_socket_honours_xff() {
        let trusted = TrustedProxies::parse_list("10.0.0.0/8").unwrap();
        let peer = v4(10, 0, 0, 1);
        assert_eq!(
            client_ip(peer, Some("198.51.100.7"), &trusted),
            v4(198, 51, 100, 7)
        );
    }

    #[test]
    fn trusted_socket_without_xff_uses_socket_ip() {
        let trusted = TrustedProxies::parse_list("10.0.0.0/8").unwrap();
        let peer = v4(10, 0, 0, 1);
        assert_eq!(client_ip(peer, None, &trusted), v4(10, 0, 0, 1));
    }

    #[test]
    fn proxy_chain_returns_first_untrusted_hop_from_the_right() {
        let trusted = TrustedProxies::parse_list("10.0.0.0/8").unwrap();
        let peer = v4(10, 0, 0, 1);
        // client -> 10.9.9.9 (trusted proxy) -> us (10.0.0.1)
        assert_eq!(
            client_ip(peer, Some("198.51.100.7, 10.9.9.9"), &trusted),
            v4(198, 51, 100, 7)
        );
        // A spoofed extra hop on the left is ignored once a real client is found.
        assert_eq!(
            client_ip(peer, Some("9.9.9.9, 198.51.100.7, 10.9.9.9"), &trusted),
            v4(198, 51, 100, 7)
        );
    }

    #[test]
    fn all_hops_trusted_falls_back_to_leftmost() {
        let trusted = TrustedProxies::parse_list("10.0.0.0/8").unwrap();
        let peer = v4(10, 0, 0, 1);
        assert_eq!(
            client_ip(peer, Some("10.1.1.1, 10.2.2.2"), &trusted),
            v4(10, 1, 1, 1)
        );
    }

    #[test]
    fn malformed_xff_fails_closed_to_socket_ip() {
        let trusted = TrustedProxies::parse_list("10.0.0.0/8").unwrap();
        let peer = v4(10, 0, 0, 1);
        assert_eq!(client_ip(peer, Some("unknown"), &trusted), peer);
        assert_eq!(client_ip(peer, Some(""), &trusted), peer);
    }

    #[test]
    fn forwarded_ip_parsing_tolerates_ports_and_brackets() {
        assert_eq!(
            parse_forwarded_ip(" 203.0.113.9 "),
            Some(v4(203, 0, 113, 9))
        );
        assert_eq!(
            parse_forwarded_ip("203.0.113.9:443"),
            Some(v4(203, 0, 113, 9))
        );
        assert_eq!(
            parse_forwarded_ip("[2001:db8::1]:443"),
            Some(ip("2001:db8::1"))
        );
        assert_eq!(parse_forwarded_ip("2001:db8::1"), Some(ip("2001:db8::1")));
        assert_eq!(parse_forwarded_ip("nope"), None);
    }
}

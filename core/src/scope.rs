//! Zorunlu kapsam kilidi (Strict Scope Lock).
//!
//! İzin verilen aralıklar: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8
//! (+ IPv6 loopback `::1`).
//!
//! Tasarım ilkesi: soket açan her fonksiyon ham `IpAddr` yerine [`ScopedIp`] alır.
//! `ScopedIp` yalnızca doğrulayan kurucularla (`TryFrom`, `FromStr`, `Deserialize`)
//! üretilebildiği için kapsam kontrolünü atlayan bir derleme yolu yoktur.
//!
//! Kasıtlı olarak desteklenmeyenler (kapsam dışına kaçış yolları):
//! - Hostname / DNS çözümlemesi
//! - IPv6 CIDR ve loopback dışındaki IPv6 adresleri (link-local dahil)

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use schemars::gen::SchemaGenerator;
use schemars::schema::Schema;
use schemars::JsonSchema;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// (ağ adresi, önek uzunluğu)
const ALLOWED_V4: [(u32, u8); 4] = [
    (0x0A00_0000, 8),  // 10.0.0.0/8
    (0xAC10_0000, 12), // 172.16.0.0/12
    (0xC0A8_0000, 16), // 192.168.0.0/16
    (0x7F00_0000, 8),  // 127.0.0.0/8
];

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ScopeError {
    #[error("hedef kapsam dışında (yalnızca RFC 1918 + loopback): {0}")]
    OutOfScope(String),
    #[error("geçersiz hedef biçimi '{0}': yalnızca IP adresi veya IPv4 CIDR kabul edilir")]
    InvalidFormat(String),
    #[error("geçersiz önek uzunluğu: {0}")]
    InvalidPrefix(String),
}

const fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    }
}

fn v4_in_scope(ip: u32) -> bool {
    ALLOWED_V4.iter().any(|&(net, p)| ip & mask(p) == net)
}

/// Tüm CIDR bloğu izin verilen bir aralığın içinde mi?
fn block_in_scope(base: u32, prefix: u8) -> bool {
    ALLOWED_V4
        .iter()
        .any(|&(net, p)| prefix >= p && base & mask(p) == net)
}

// ---------------------------------------------------------------------------
// ScopedIp
// ---------------------------------------------------------------------------

/// Kapsam doğrulaması geçmiş tek bir IP adresi.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ScopedIp(IpAddr);

impl ScopedIp {
    pub fn addr(&self) -> IpAddr {
        self.0
    }

    /// Soket fonksiyonlarına verilecek adres yalnızca bu yolla üretilmelidir.
    pub fn socket_addr(&self, port: u16) -> SocketAddr {
        SocketAddr::new(self.0, port)
    }

    /// Yalnızca `ScopedNet` içinden, blok zaten doğrulandıktan sonra çağrılır.
    fn from_v4_prevalidated(v: u32) -> Self {
        Self(IpAddr::V4(Ipv4Addr::from(v)))
    }
}

impl TryFrom<IpAddr> for ScopedIp {
    type Error = ScopeError;

    fn try_from(ip: IpAddr) -> Result<Self, Self::Error> {
        // ::ffff:a.b.c.d biçimini IPv4'e indirgeyip öyle denetle.
        let canon = ip.to_canonical();
        let ok = match canon {
            IpAddr::V4(v4) => v4_in_scope(u32::from(v4)),
            IpAddr::V6(v6) => v6 == Ipv6Addr::LOCALHOST,
        };
        if ok {
            Ok(Self(canon))
        } else {
            Err(ScopeError::OutOfScope(ip.to_string()))
        }
    }
}

impl FromStr for ScopedIp {
    type Err = ScopeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ip: IpAddr = s
            .trim()
            .parse()
            .map_err(|_| ScopeError::InvalidFormat(s.to_string()))?;
        Self::try_from(ip)
    }
}

impl fmt::Display for ScopedIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Serialize for ScopedIp {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

/// Deserialize de kapsamı zorlar: dışarıdan gelen JSON ile kilit aşılamaz.
impl<'de> Deserialize<'de> for ScopedIp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let ip = IpAddr::deserialize(d)?;
        ScopedIp::try_from(ip).map_err(de::Error::custom)
    }
}

impl JsonSchema for ScopedIp {
    fn schema_name() -> String {
        "ScopedIp".to_string()
    }

    fn json_schema(gen: &mut SchemaGenerator) -> Schema {
        IpAddr::json_schema(gen)
    }
}

// ---------------------------------------------------------------------------
// ScopedNet
// ---------------------------------------------------------------------------

/// Tamamı kapsam içinde olan bir IPv4 CIDR bloğu. Ana bilgisayar bitleri normalize edilir
/// (`192.168.1.5/24` -> `192.168.1.0/24`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScopedNet {
    base: u32,
    prefix: u8,
}

impl ScopedNet {
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    pub fn network(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.base)
    }

    /// Taranabilir host sayısı. /31 ve /32 için tüm adresler, diğerlerinde
    /// ağ ve yayın (broadcast) adresi hariç.
    pub fn host_count(&self) -> u64 {
        let total = 1u64 << (32 - u32::from(self.prefix));
        if self.prefix >= 31 {
            total
        } else {
            total - 2
        }
    }

    pub fn hosts(&self) -> impl Iterator<Item = ScopedIp> {
        let last = u64::from(self.base | !mask(self.prefix));
        let first = u64::from(self.base);
        let (start, end) = if self.prefix >= 31 {
            (first, last)
        } else {
            (first + 1, last - 1)
        };
        // Blok `FromStr` içinde doğrulandığı için içindeki her adres kapsamdadır.
        (start..=end).map(|n| ScopedIp::from_v4_prevalidated(n as u32))
    }
}

impl FromStr for ScopedNet {
    type Err = ScopeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let (ip_part, prefix_part) = s
            .split_once('/')
            .ok_or_else(|| ScopeError::InvalidFormat(s.to_string()))?;
        let ip: Ipv4Addr = ip_part
            .parse()
            .map_err(|_| ScopeError::InvalidFormat(s.to_string()))?;
        let prefix: u8 = prefix_part
            .parse()
            .map_err(|_| ScopeError::InvalidPrefix(s.to_string()))?;
        if prefix > 32 {
            return Err(ScopeError::InvalidPrefix(s.to_string()));
        }
        let base = u32::from(ip) & mask(prefix);
        if !block_in_scope(base, prefix) {
            return Err(ScopeError::OutOfScope(s.to_string()));
        }
        Ok(Self { base, prefix })
    }
}

impl fmt::Display for ScopedNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", Ipv4Addr::from(self.base), self.prefix)
    }
}

impl Serialize for ScopedNet {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ScopedNet {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        raw.parse().map_err(de::Error::custom)
    }
}

impl JsonSchema for ScopedNet {
    fn schema_name() -> String {
        "ScopedNet".to_string()
    }

    fn json_schema(gen: &mut SchemaGenerator) -> Schema {
        String::json_schema(gen)
    }
}

// ---------------------------------------------------------------------------
// ScopedTarget
// ---------------------------------------------------------------------------

/// CLI/API'den gelen tek hedef: IP veya CIDR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScopedTarget {
    Ip(ScopedIp),
    Net(ScopedNet),
}

impl ScopedTarget {
    pub fn host_count(&self) -> u64 {
        match self {
            Self::Ip(_) => 1,
            Self::Net(n) => n.host_count(),
        }
    }

    pub fn hosts(&self) -> Box<dyn Iterator<Item = ScopedIp> + Send> {
        match *self {
            Self::Ip(ip) => Box::new(std::iter::once(ip)),
            Self::Net(net) => Box::new(net.hosts()),
        }
    }
}

impl FromStr for ScopedTarget {
    type Err = ScopeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains('/') {
            s.parse().map(Self::Net)
        } else {
            s.parse().map(Self::Ip)
        }
    }
}

impl fmt::Display for ScopedTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => ip.fmt(f),
            Self::Net(net) => net.fmt(f),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn accepts_private_and_loopback_ips() {
        for s in [
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.1",
            "127.0.0.1",
            "127.255.255.254",
            "::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(s.parse::<ScopedIp>().is_ok(), "{s} kabul edilmeliydi");
        }
    }

    #[test]
    fn rejects_public_and_boundary_ips() {
        for s in [
            "8.8.8.8",
            "1.1.1.1",
            "11.0.0.1",
            "172.15.255.255",
            "172.32.0.1",
            "192.167.255.255",
            "192.169.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "169.254.1.1",
            "2001:db8::1",
            "fe80::1",
            "::ffff:8.8.8.8",
        ] {
            assert!(
                matches!(s.parse::<ScopedIp>(), Err(ScopeError::OutOfScope(_))),
                "{s} reddedilmeliydi"
            );
        }
    }

    #[test]
    fn rejects_hostnames_and_garbage() {
        for s in ["example.com", "localhost", "", "010.0.0.1", "0x7f.0.0.1", "1.2.3"] {
            assert!(
                matches!(s.parse::<ScopedIp>(), Err(ScopeError::InvalidFormat(_))),
                "{s:?} geçersiz biçim olmalıydı"
            );
        }
    }

    #[test]
    fn accepts_in_scope_cidrs() {
        for s in [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
            "192.168.1.0/24",
            "10.1.2.3/32",
            "172.20.0.0/16",
        ] {
            assert!(s.parse::<ScopedNet>().is_ok(), "{s} kabul edilmeliydi");
        }
    }

    #[test]
    fn rejects_cidrs_that_escape_scope() {
        for s in [
            "0.0.0.0/0",
            "10.0.0.0/7",
            "172.0.0.0/8",
            "172.16.0.0/11",
            "192.168.0.0/15",
            "8.8.8.0/24",
            "192.0.0.0/8",
        ] {
            assert!(
                matches!(s.parse::<ScopedNet>(), Err(ScopeError::OutOfScope(_))),
                "{s} reddedilmeliydi"
            );
        }
    }

    #[test]
    fn rejects_malformed_cidrs() {
        assert!(matches!(
            "192.168.1.1/33".parse::<ScopedNet>(),
            Err(ScopeError::InvalidPrefix(_))
        ));
        assert!(matches!(
            "192.168.1.1/".parse::<ScopedNet>(),
            Err(ScopeError::InvalidPrefix(_))
        ));
        assert!(matches!(
            "10.0.0.1/abc".parse::<ScopedNet>(),
            Err(ScopeError::InvalidPrefix(_))
        ));
        assert!(matches!(
            "example.com/24".parse::<ScopedNet>(),
            Err(ScopeError::InvalidFormat(_))
        ));
        assert!(matches!(
            "::1/128".parse::<ScopedNet>(),
            Err(ScopeError::InvalidFormat(_))
        ));
    }

    #[test]
    fn normalizes_host_bits() {
        let net: ScopedNet = "192.168.1.77/24".parse().unwrap();
        assert_eq!(net.to_string(), "192.168.1.0/24");
    }

    #[test]
    fn host_counts_and_iteration() {
        let cases = [
            ("192.168.1.0/24", 254u64),
            ("192.168.1.0/30", 2),
            ("192.168.1.0/31", 2),
            ("192.168.1.5/32", 1),
        ];
        for (s, expected) in cases {
            let net: ScopedNet = s.parse().unwrap();
            assert_eq!(net.host_count(), expected, "{s}");
            assert_eq!(net.hosts().count() as u64, expected, "{s}");
        }
        let net: ScopedNet = "192.168.1.0/30".parse().unwrap();
        let hosts: Vec<String> = net.hosts().map(|h| h.to_string()).collect();
        assert_eq!(hosts, ["192.168.1.1", "192.168.1.2"]);
    }

    #[test]
    fn every_iterated_host_is_in_scope() {
        let net: ScopedNet = "172.31.255.0/24".parse().unwrap();
        assert!(net.hosts().all(|h| ScopedIp::try_from(h.addr()).is_ok()));
    }

    #[test]
    fn deserialize_enforces_scope() {
        assert!(serde_json::from_str::<ScopedIp>("\"8.8.8.8\"").is_err());
        assert!(serde_json::from_str::<ScopedIp>("\"192.168.1.10\"").is_ok());
        assert!(serde_json::from_str::<ScopedNet>("\"8.8.8.0/24\"").is_err());
        assert!(serde_json::from_str::<ScopedNet>("\"10.0.0.0/24\"").is_ok());
    }

    #[test]
    fn target_dispatch() {
        assert!(matches!(
            "10.0.0.5".parse::<ScopedTarget>(),
            Ok(ScopedTarget::Ip(_))
        ));
        assert!(matches!(
            "10.0.0.0/24".parse::<ScopedTarget>(),
            Ok(ScopedTarget::Net(_))
        ));
        assert!("1.1.1.1".parse::<ScopedTarget>().is_err());
        assert!("1.1.1.0/24".parse::<ScopedTarget>().is_err());
    }

    #[test]
    fn socket_addr_keeps_ip() {
        let ip: ScopedIp = "192.168.1.1".parse().unwrap();
        assert_eq!(ip.socket_addr(443).to_string(), "192.168.1.1:443");
    }
}

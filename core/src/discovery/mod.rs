//! M1: canlı host keşfi. Üç yöntem (ARP, ICMP echo, TCP-connect) IP bazında birleştirilir.
//!
//! Hata toleransı: bir yöntem yetki/ağ hatası verirse tarama durmaz. `warning` olayı
//! yayılır ve diğer yöntemler çalışmaya devam eder. Yalnızca hedef sayısı sınırı
//! ve olay çıktısı hataları taramayı durdurur.

pub mod arp;
pub mod icmp;
pub mod oui;
pub mod tcp_ping;

use std::collections::BTreeMap;

use pnet::util::MacAddr;
use thiserror::Error;

use crate::error::CoreError;
use crate::events::{DiscoveryMethod, Event, EventSink, Module};
use crate::ratelimit::Throttle;
use crate::scope::{ScopedIp, ScopedTarget};

/// Tek taramada en fazla adres (bellek ve süre koruması). /16 sınırına denk.
pub const MAX_HOSTS: u64 = 65_536;

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("hedef sayısı çok büyük: {total} (en fazla {max})")]
    TooLarge { total: u64, max: u64 },
    #[error("ham ARP çerçevesi hazırlanamadı")]
    Packet,
    #[error("ARP kanalı bu arayüz tipini desteklemiyor")]
    UnsupportedChannel,
    #[error("ARP isteği gönderilemedi")]
    Send,
    #[error("ICMP soketi açılamadı: {0}")]
    Icmp(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    pub arp: bool,
    pub icmp: bool,
    pub tcp: bool,
}

/// Birleştirilmiş tek host kaydı.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Host {
    pub mac: Option<MacAddr>,
    pub methods: Vec<DiscoveryMethod>,
}

fn warn(sink: &EventSink, code: &str, message: String) {
    let _ = sink.emit(Event::Warning {
        module: Module::Discovery,
        code: code.to_string(),
        message,
    });
}

fn progress(sink: &EventSink, done: u64, total: u64) {
    let _ = sink.emit(Event::Progress {
        module: Module::Discovery,
        done,
        total,
    });
}

/// Hedefleri tarar, sonuçları birleştirir ve her canlı host için `host_found` yayar.
/// Dönüş değeri bulunan host sayısıdır.
pub async fn discover(
    targets: &[ScopedTarget],
    opts: Options,
    throttle: &Throttle,
    sink: &EventSink,
) -> Result<usize, CoreError> {
    let total_addrs: u64 = targets.iter().map(ScopedTarget::host_count).sum();
    if total_addrs > MAX_HOSTS {
        return Err(DiscoveryError::TooLarge {
            total: total_addrs,
            max: MAX_HOSTS,
        }
        .into());
    }
    let hosts: Vec<ScopedIp> = targets.iter().flat_map(|t| t.hosts()).collect();

    let steps = [opts.arp, opts.icmp, opts.tcp]
        .iter()
        .filter(|on| **on)
        .count() as u64;
    let mut done = 0u64;
    let mut found: BTreeMap<ScopedIp, Host> = BTreeMap::new();

    if opts.arp {
        match arp::scan(&hosts, throttle, sink).await {
            Ok(list) => {
                for (ip, mac) in list {
                    let host = found.entry(ip).or_default();
                    host.mac = Some(mac);
                    host.methods.push(DiscoveryMethod::Arp);
                }
            }
            Err(e) => warn(sink, "arp_unavailable", e.to_string()),
        }
        done += 1;
        progress(sink, done, steps);
    }

    if opts.icmp {
        match icmp::scan(&hosts, throttle).await {
            Ok(list) => {
                for ip in list {
                    found.entry(ip).or_default().methods.push(DiscoveryMethod::Icmp);
                }
            }
            Err(e) => warn(sink, "icmp_unavailable", e.to_string()),
        }
        done += 1;
        progress(sink, done, steps);
    }

    if opts.tcp {
        match tcp_ping::scan(&hosts, throttle).await {
            Ok(list) => {
                for ip in list {
                    found
                        .entry(ip)
                        .or_default()
                        .methods
                        .push(DiscoveryMethod::TcpConnect);
                }
            }
            Err(e) => warn(sink, "tcp_connect_failed", e.to_string()),
        }
        done += 1;
        progress(sink, done, steps);
    }

    for (ip, host) in &found {
        sink.emit(Event::HostFound {
            ip: *ip,
            mac: host.mac.map(|m| m.to_string()),
            vendor: host.mac.and_then(oui::vendor_of).map(str::to_string),
            methods: host.methods.clone(),
        })?;
    }

    Ok(found.len())
}

//! ARP taraması (M1). Yalnızca aynı L2 segmentindeki hedefler (yerel arayüzün alt ağı).
//! Ham çerçeve için CAP_NET_RAW (veya root) gerekir. Yetki yoksa çağıran `warning` yayar.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use tokio::runtime::Handle;

use super::DiscoveryError;
use crate::error::CoreError;
use crate::events::{Event, EventSink, Module};
use crate::ratelimit::Throttle;
use crate::scope::ScopedIp;

const ETH_LEN: usize = 14;
const ARP_LEN: usize = 28;
const FRAME_LEN: usize = ETH_LEN + ARP_LEN;
/// Okuma döngüsünün dilimi; süre kontrolü için kısa tutulur.
const READ_SLICE: Duration = Duration::from_millis(50);

struct Plan {
    iface: NetworkInterface,
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    targets: Vec<Ipv4Addr>,
}

/// Hedefe L2 olarak ulaşabilen (alt ağı içinde olan) ilk uygun arayüzü bulur.
fn route_for(target: Ipv4Addr) -> Option<(NetworkInterface, MacAddr, Ipv4Addr)> {
    datalink::interfaces().into_iter().find_map(|iface| {
        if iface.is_loopback() || !iface.is_up() {
            return None;
        }
        let mac = iface.mac?;
        let src = iface.ips.iter().find_map(|net| match net.ip() {
            IpAddr::V4(v4) if net.contains(IpAddr::V4(target)) => Some(v4),
            _ => None,
        })?;
        Some((iface, mac, src))
    })
}

/// Hedefleri arayüze göre gruplar. Dönen ikinci değer L2'de ulaşılamayan hedef sayısıdır.
fn build_plans(hosts: &[ScopedIp]) -> (Vec<Plan>, usize) {
    let mut plans: BTreeMap<String, Plan> = BTreeMap::new();
    let mut skipped = 0usize;
    for ip in hosts {
        let IpAddr::V4(dst) = ip.addr() else {
            skipped += 1;
            continue;
        };
        let Some((iface, src_mac, src_ip)) = route_for(dst) else {
            skipped += 1;
            continue;
        };
        plans
            .entry(iface.name.clone())
            .or_insert_with(|| Plan {
                iface,
                src_mac,
                src_ip,
                targets: Vec::new(),
            })
            .targets
            .push(dst);
    }
    (plans.into_values().collect(), skipped)
}

/// Yayın (broadcast) ARP isteği çerçevesini `frame` içine yazar.
fn build_request(frame: &mut [u8], src_mac: MacAddr, src_ip: Ipv4Addr, dst: Ipv4Addr) -> Option<()> {
    {
        let mut arp = MutableArpPacket::new(frame.get_mut(ETH_LEN..)?)?;
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Request);
        arp.set_sender_hw_addr(src_mac);
        arp.set_sender_proto_addr(src_ip);
        arp.set_target_hw_addr(MacAddr::zero());
        arp.set_target_proto_addr(dst);
    }
    let mut eth = MutableEthernetPacket::new(frame)?;
    eth.set_destination(MacAddr::broadcast());
    eth.set_source(src_mac);
    eth.set_ethertype(EtherTypes::Arp);
    Some(())
}

/// Gelen çerçeve bir ARP yanıtıysa (IP, MAC) döner.
fn parse_reply(frame: &[u8]) -> Option<(Ipv4Addr, MacAddr)> {
    let eth = EthernetPacket::new(frame)?;
    if eth.get_ethertype() != EtherTypes::Arp {
        return None;
    }
    let arp = ArpPacket::new(eth.payload())?;
    if arp.get_operation() != ArpOperations::Reply {
        return None;
    }
    Some((arp.get_sender_proto_addr(), arp.get_sender_hw_addr()))
}

/// Tek arayüz üzerinde: istekleri gönderir, pencere boyunca yanıtları toplar.
fn scan_iface(
    plan: &Plan,
    handle: &Handle,
    throttle: &Throttle,
    window: Duration,
) -> Result<HashMap<Ipv4Addr, MacAddr>, CoreError> {
    let cfg = datalink::Config {
        read_timeout: Some(READ_SLICE),
        ..Default::default()
    };
    let (mut tx, mut rx) = match datalink::channel(&plan.iface, cfg)? {
        Channel::Ethernet(tx, rx) => (tx, rx),
        #[allow(unreachable_patterns)]
        _ => return Err(DiscoveryError::UnsupportedChannel.into()),
    };

    let wanted: HashSet<Ipv4Addr> = plan.targets.iter().copied().collect();

    for &dst in &plan.targets {
        // Paket hızı sınırı: asenkron semaforu bloklayan iş parçacığından bekler.
        let _permit = handle.block_on(throttle.acquire())?;
        let mut frame = [0u8; FRAME_LEN];
        build_request(&mut frame, plan.src_mac, plan.src_ip, dst).ok_or(DiscoveryError::Packet)?;
        tx.send_to(&frame, None).ok_or(DiscoveryError::Send)??;
    }

    let deadline = Instant::now() + window;
    let mut found = HashMap::new();
    while Instant::now() < deadline {
        match rx.next() {
            Ok(frame) => {
                if let Some((ip, mac)) = parse_reply(frame) {
                    if wanted.contains(&ip) {
                        found.entry(ip).or_insert(mac);
                    }
                }
            }
            Err(e) if matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(found)
}

/// ARP taraması. Dönen liste (IP, MAC) çiftleridir.
pub async fn scan(
    hosts: &[ScopedIp],
    throttle: &Throttle,
    sink: &EventSink,
) -> Result<Vec<(ScopedIp, MacAddr)>, CoreError> {
    let (plans, skipped) = build_plans(hosts);
    if skipped > 0 {
        let _ = sink.emit(Event::Warning {
            module: Module::Discovery,
            code: "arp_not_local".into(),
            message: format!("{skipped} hedef yerel L2 segmentinde değil, ARP atlandı"),
        });
    }

    let handle = Handle::current();
    let throttle = throttle.clone();
    let window = throttle.timeout();
    let blocking_sink = sink.clone();

    let replies = tokio::task::spawn_blocking(move || {
        let mut out: Vec<(Ipv4Addr, MacAddr)> = Vec::new();
        for plan in &plans {
            match scan_iface(plan, &handle, &throttle, window) {
                Ok(map) => out.extend(map),
                Err(e) => {
                    let _ = blocking_sink.emit(Event::Warning {
                        module: Module::Discovery,
                        code: "arp_unavailable".into(),
                        message: format!("{}: {e}", plan.iface.name),
                    });
                }
            }
        }
        out
    })
    .await
    .map_err(|e| CoreError::Task(e.to_string()))?;

    Ok(replies
        .into_iter()
        .filter_map(|(ip, mac)| {
            ScopedIp::try_from(IpAddr::V4(ip))
                .ok()
                .map(|scoped| (scoped, mac))
        })
        .collect())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn request_frame_is_broadcast_arp_request() {
        let src_mac = MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x01);
        let src_ip: Ipv4Addr = "192.168.1.2".parse().unwrap();
        let dst: Ipv4Addr = "192.168.1.10".parse().unwrap();
        let mut frame = [0u8; FRAME_LEN];
        build_request(&mut frame, src_mac, src_ip, dst).unwrap();

        let eth = EthernetPacket::new(&frame).unwrap();
        assert_eq!(eth.get_destination(), MacAddr::broadcast());
        assert_eq!(eth.get_ethertype(), EtherTypes::Arp);

        let arp = ArpPacket::new(eth.payload()).unwrap();
        assert_eq!(arp.get_operation(), ArpOperations::Request);
        assert_eq!(arp.get_sender_proto_addr(), src_ip);
        assert_eq!(arp.get_target_proto_addr(), dst);
        // İstek çerçevesi yanıt olarak ayrıştırılmamalı.
        assert!(parse_reply(&frame).is_none());
    }

    #[test]
    fn parses_reply_frame() {
        let mut frame = [0u8; FRAME_LEN];
        {
            let mut arp = MutableArpPacket::new(&mut frame[ETH_LEN..]).unwrap();
            arp.set_hardware_type(ArpHardwareTypes::Ethernet);
            arp.set_protocol_type(EtherTypes::Ipv4);
            arp.set_hw_addr_len(6);
            arp.set_proto_addr_len(4);
            arp.set_operation(ArpOperations::Reply);
            arp.set_sender_hw_addr(MacAddr::new(0x28, 0x6f, 0xb9, 1, 2, 3));
            arp.set_sender_proto_addr("10.0.0.7".parse().unwrap());
        }
        {
            let mut eth = MutableEthernetPacket::new(&mut frame).unwrap();
            eth.set_ethertype(EtherTypes::Arp);
        }
        let (ip, mac) = parse_reply(&frame).unwrap();
        assert_eq!(ip, "10.0.0.7".parse::<Ipv4Addr>().unwrap());
        assert_eq!(mac, MacAddr::new(0x28, 0x6f, 0xb9, 1, 2, 3));
    }

    #[test]
    fn ignores_non_arp_frames() {
        let frame = [0u8; FRAME_LEN];
        assert!(parse_reply(&frame).is_none());
    }
}

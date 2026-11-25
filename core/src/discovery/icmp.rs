//! ICMP echo taraması (M1). `surge-ping` ile. Linux'ta raw soket (CAP_NET_RAW, root)
//! veya `net.ipv4.ping_group_range` içinde olmak gerekir.

use std::collections::BTreeSet;

use surge_ping::{Client, Config, PingIdentifier, PingSequence, ICMP};
use tokio::task::JoinSet;

use super::DiscoveryError;
use crate::error::CoreError;
use crate::ratelimit::Throttle;
use crate::scope::ScopedIp;

const PAYLOAD: [u8; 16] = [0; 16];

pub async fn scan(hosts: &[ScopedIp], throttle: &Throttle) -> Result<Vec<ScopedIp>, CoreError> {
    let config = Config::builder().kind(ICMP::V4).build();
    let client = Client::new(&config).map_err(|e| DiscoveryError::Icmp(e.to_string()))?;

    let timeout = throttle.timeout();
    let ident_raw = (std::process::id() & 0xFFFF) as u16;
    let mut set = JoinSet::new();

    for &ip in hosts {
        let permit = throttle.acquire().await?;
        let client = client.clone();
        set.spawn(async move {
            let _permit = permit;
            let mut pinger = client.pinger(ip.addr(), PingIdentifier(ident_raw)).await;
            pinger.timeout(timeout);
            let alive = pinger.ping(PingSequence(0), &PAYLOAD).await.is_ok();
            (ip, alive)
        });
    }

    let mut alive = BTreeSet::new();
    while let Some(joined) = set.join_next().await {
        if let Ok((ip, true)) = joined {
            alive.insert(ip);
        }
    }
    Ok(alive.into_iter().collect())
}

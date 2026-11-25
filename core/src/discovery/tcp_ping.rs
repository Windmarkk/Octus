//! TCP-connect ping (M1 yedek yöntemi). Bağlantı kabul edilirse veya RST gelirse
//! (`ConnectionRefused`) host canlıdır. Zaman aşımı canlı değil sayılır.
//! Ham soket gerektirmez; yetkisiz çalışır.

use std::collections::BTreeSet;
use std::io;

use tokio::net::TcpStream;
use tokio::task::JoinSet;

use crate::error::CoreError;
use crate::ratelimit::Throttle;
use crate::scope::ScopedIp;

/// Varsayılan yoklama portları: SSH, HTTP, HTTPS, SMB.
pub const PORTS: [u16; 4] = [22, 80, 443, 445];

pub async fn scan(hosts: &[ScopedIp], throttle: &Throttle) -> Result<Vec<ScopedIp>, CoreError> {
    scan_ports(hosts, &PORTS, throttle).await
}

pub async fn scan_ports(
    hosts: &[ScopedIp],
    ports: &[u16],
    throttle: &Throttle,
) -> Result<Vec<ScopedIp>, CoreError> {
    let timeout = throttle.timeout();
    let mut set = JoinSet::new();

    for &ip in hosts {
        for &port in ports {
            // Semafor dolu ise burada bekler; böylece eşzamanlılık sınırı korunur.
            let permit = throttle.acquire().await?;
            set.spawn(async move {
                let _permit = permit;
                let attempt =
                    tokio::time::timeout(timeout, TcpStream::connect(ip.socket_addr(port))).await;
                let alive = match attempt {
                    Ok(Ok(_stream)) => true,
                    Ok(Err(e)) => e.kind() == io::ErrorKind::ConnectionRefused,
                    Err(_elapsed) => false,
                };
                (ip, alive)
            });
        }
    }

    let mut alive = BTreeSet::new();
    while let Some(joined) = set.join_next().await {
        if let Ok((ip, true)) = joined {
            alive.insert(ip);
        }
    }
    Ok(alive.into_iter().collect())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::ratelimit::Limits;
    use std::net::TcpListener;
    use std::time::Duration;

    fn throttle() -> Throttle {
        Throttle::new(&Limits {
            max_concurrency: 16,
            packets_per_sec: 10_000,
            timeout: Duration::from_millis(500),
        })
        .unwrap()
    }

    #[tokio::test]
    async fn open_port_marks_host_alive() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let host: ScopedIp = "127.0.0.1".parse().unwrap();
        let alive = scan_ports(&[host], &[port], &throttle()).await.unwrap();
        assert_eq!(alive, vec![host]);
    }

    #[tokio::test]
    async fn refused_port_still_means_alive() {
        // Bağlanıp hemen kapatılan portta RST gelir; host yine canlıdır.
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let host: ScopedIp = "127.0.0.1".parse().unwrap();
        let alive = scan_ports(&[host], &[port], &throttle()).await.unwrap();
        assert_eq!(alive, vec![host]);
    }
}

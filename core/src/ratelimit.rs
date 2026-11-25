//! Eşzamanlılık sınırı (semafor) + paket/saniye sınırı (governor) + katı timeout.
//!
//! Tüm ağ modülleri iş başlatmadan önce [`Throttle::acquire`] çağırır; dönen izin
//! (permit) bırakılana kadar eşzamanlılık yuvası dolu sayılır.

use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

type DirectLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Sert üst/alt sınırlar: yanlış bir CLI argümanı ağı boğamasın.
pub const CONCURRENCY_RANGE: (u64, u64) = (1, 2048);
pub const PPS_RANGE: (u64, u64) = (1, 100_000);
pub const TIMEOUT_MS_RANGE: (u64, u64) = (50, 30_000);

#[derive(Debug, Error)]
pub enum LimitError {
    #[error("{name} aralık dışı: {value} (izin verilen {min}..={max})")]
    OutOfRange {
        name: &'static str,
        value: u64,
        min: u64,
        max: u64,
    },
    #[error("eşzamanlılık semaforu kapatıldı")]
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_concurrency: usize,
    pub packets_per_sec: u32,
    pub timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_concurrency: 128,
            packets_per_sec: 500,
            timeout: Duration::from_millis(1500),
        }
    }
}

fn check(name: &'static str, value: u64, (min, max): (u64, u64)) -> Result<(), LimitError> {
    if (min..=max).contains(&value) {
        Ok(())
    } else {
        Err(LimitError::OutOfRange {
            name,
            value,
            min,
            max,
        })
    }
}

impl Limits {
    pub fn validate(&self) -> Result<(), LimitError> {
        check(
            "concurrency",
            self.max_concurrency as u64,
            CONCURRENCY_RANGE,
        )?;
        check("pps", u64::from(self.packets_per_sec), PPS_RANGE)?;
        check(
            "timeout_ms",
            self.timeout.as_millis() as u64,
            TIMEOUT_MS_RANGE,
        )
    }
}

#[derive(Clone)]
pub struct Throttle {
    semaphore: Arc<Semaphore>,
    limiter: Arc<DirectLimiter>,
    timeout: Duration,
}

impl Throttle {
    pub fn new(limits: &Limits) -> Result<Self, LimitError> {
        limits.validate()?;
        let pps = NonZeroU32::new(limits.packets_per_sec).ok_or(LimitError::OutOfRange {
            name: "pps",
            value: 0,
            min: PPS_RANGE.0,
            max: PPS_RANGE.1,
        })?;
        // Başlangıçta ani patlamayı önlemek için burst, saniyelik hızın onda biri.
        let burst = NonZeroU32::new((limits.packets_per_sec / 10).max(1)).unwrap_or(NonZeroU32::MIN);
        let quota = Quota::per_second(pps).allow_burst(burst);
        Ok(Self {
            semaphore: Arc::new(Semaphore::new(limits.max_concurrency)),
            limiter: Arc::new(RateLimiter::direct(quota)),
            timeout: limits.timeout,
        })
    }

    /// Bir eşzamanlılık yuvası ve bir paket hakkı alana kadar bekler.
    pub async fn acquire(&self) -> Result<OwnedSemaphorePermit, LimitError> {
        let permit = Arc::clone(&self.semaphore)
            .acquire_owned()
            .await
            .map_err(|_| LimitError::Closed)?;
        self.limiter.until_ready().await;
        Ok(permit)
    }

    /// Her ağ işlemi için kullanılacak katı zaman aşımı.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

    #[test]
    fn defaults_are_valid() {
        assert!(Limits::default().validate().is_ok());
    }

    #[test]
    fn rejects_out_of_range_values() {
        let base = Limits::default();
        assert!(Limits { max_concurrency: 0, ..base }.validate().is_err());
        assert!(Limits { max_concurrency: 5000, ..base }.validate().is_err());
        assert!(Limits { packets_per_sec: 0, ..base }.validate().is_err());
        assert!(Limits { packets_per_sec: 1_000_000, ..base }.validate().is_err());
        assert!(Limits { timeout: Duration::from_millis(1), ..base }.validate().is_err());
        assert!(Limits { timeout: Duration::from_secs(120), ..base }.validate().is_err());
    }

    #[tokio::test]
    async fn concurrency_is_capped() {
        let limits = Limits {
            max_concurrency: 3,
            packets_per_sec: 100_000,
            timeout: Duration::from_millis(500),
        };
        let throttle = Throttle::new(&limits).unwrap();
        let current = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..20 {
            let t = throttle.clone();
            let cur = Arc::clone(&current);
            let pk = Arc::clone(&peak);
            handles.push(tokio::spawn(async move {
                let _permit = t.acquire().await.unwrap();
                let n = cur.fetch_add(1, SeqCst) + 1;
                pk.fetch_max(n, SeqCst);
                tokio::time::sleep(Duration::from_millis(5)).await;
                cur.fetch_sub(1, SeqCst);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert!(peak.load(SeqCst) <= 3, "tepe eşzamanlılık: {}", peak.load(SeqCst));
        assert!(peak.load(SeqCst) >= 1);
    }
}

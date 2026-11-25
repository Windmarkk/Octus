//! Octus çekirdek ağ motoru.
//!
//! Katmanlar:
//! - [`scope`]: tip düzeyinde RFC 1918 kapsam kilidi (`ScopedIp`, `ScopedNet`)
//! - [`events`]: Python ile paylaşılan NDJSON olay sözleşmesi
//! - [`ratelimit`]: eşzamanlılık + paket/saniye sınırı
//! - [`error`]: ortak hata tipi ve sabit çıkış kodları
//! - [`discovery`]: M1 canlı host keşfi (ARP, ICMP, TCP-connect)

pub mod discovery;
pub mod error;
pub mod events;
pub mod ratelimit;
pub mod scope;

pub use discovery::{DiscoveryError, Host};
pub use error::{exit, CoreError};
pub use events::{DiscoveryMethod, Event, EventSink, FinishStatus, Module};
pub use ratelimit::{Limits, Throttle};
pub use scope::{ScopeError, ScopedIp, ScopedNet, ScopedTarget};

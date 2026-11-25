//! Ortak hata tipi ve sabit süreç çıkış kodları (Python orkestratörü ile sözleşme).

use thiserror::Error;

use crate::discovery::DiscoveryError;
use crate::events::EventError;
use crate::ratelimit::LimitError;
use crate::scope::ScopeError;

/// Süreç çıkış kodları. `2` clap'in kullanım hatası kodudur ve ayrılmıştır.
pub mod exit {
    pub const OK: u8 = 0;
    pub const INTERNAL: u8 = 1;
    pub const USAGE: u8 = 2;
    pub const SCOPE_VIOLATION: u8 = 3;
    pub const PERMISSION_DENIED: u8 = 4;
    pub const INTERRUPTED: u8 = 5;
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error(transparent)]
    Scope(#[from] ScopeError),
    #[error(transparent)]
    Limits(#[from] LimitError),
    #[error(transparent)]
    Events(#[from] EventError),
    #[error(transparent)]
    Discovery(#[from] DiscoveryError),
    #[error("G/Ç hatası: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON hatası: {0}")]
    Json(#[from] serde_json::Error),
    #[error("görev hatası: {0}")]
    Task(String),
}

impl CoreError {
    /// Olay akışındaki `error` olayında kullanılan makine-okunur kod.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Scope(_) => "scope_violation",
            Self::Limits(_) => "invalid_limits",
            Self::Events(_) => "event_output_failed",
            Self::Discovery(_) => "discovery_error",
            Self::Io(_) => "io_error",
            Self::Json(_) => "json_error",
            Self::Task(_) => "task_failed",
        }
    }

    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Scope(_) => exit::SCOPE_VIOLATION,
            Self::Limits(_) | Self::Discovery(_) => exit::USAGE,
            Self::Events(_) | Self::Io(_) | Self::Json(_) | Self::Task(_) => exit::INTERNAL,
        }
    }
}

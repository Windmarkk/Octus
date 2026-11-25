//! Rust -> Python olay sözleşmesi.
//!
//! Kanal: stdout üzerinde NDJSON (satır başına tek JSON nesnesi). Loglar stderr'e gider.
//! Her satır bir [`Envelope`]'dur: `schema_version`, `scan_id`, `ts_ms` ve `type`
//! alanları her olayda bulunur.
//!
//! Sözleşmenin tek kaynağı bu dosyadır; `octus-core schema` komutu JSON Schema üretir.

use std::future::Future;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use schemars::JsonSchema;
use serde::Serialize;
use thiserror::Error;

use crate::error::CoreError;
use crate::scope::ScopedIp;

/// Şemada geriye dönük uyumsuz değişiklik olduğunda artırılır.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Module {
    Core,
    Discovery,
    PortScan,
    Banner,
    Tls,
    Passive,
    Pipeline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FinishStatus {
    Ok,
    Failed,
    Cancelled,
}

/// Bir hostun hangi yöntemle canlı görüldüğü.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryMethod {
    Arp,
    Icmp,
    TcpConnect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct VerifiedTarget {
    /// Normalize edilmiş hedef (IP veya CIDR).
    pub target: String,
    pub host_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    ScanStarted {
        module: Module,
    },
    ScopeVerified {
        targets: Vec<VerifiedTarget>,
    },
    Progress {
        module: Module,
        done: u64,
        total: u64,
    },
    Warning {
        module: Module,
        code: String,
        message: String,
    },
    Error {
        module: Module,
        code: String,
        message: String,
    },
    /// M1: canlı host. `mac` ve `vendor` yalnızca ARP ile gelir.
    HostFound {
        ip: ScopedIp,
        mac: Option<String>,
        vendor: Option<String>,
        methods: Vec<DiscoveryMethod>,
    },
    ScanFinished {
        module: Module,
        status: FinishStatus,
        duration_ms: u64,
    },
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct Envelope {
    pub schema_version: u32,
    pub scan_id: String,
    /// Unix epoch, milisaniye.
    pub ts_ms: u64,
    #[serde(flatten)]
    pub event: Event,
}

#[derive(Debug, Error)]
pub enum EventError {
    #[error("olay serileştirilemedi: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("olay çıktısı yazılamadı (alıcı kapanmış olabilir): {0}")]
    Io(#[from] io::Error),
    #[error("olay çıktısı kilidi bozuldu")]
    Poisoned,
    #[error("geçersiz scan_id: yalnızca [A-Za-z0-9_-], 1..=64 karakter")]
    InvalidScanId,
}

/// Python tarafının dosya adı/log anahtarı olarak güvenle kullanabilmesi için sıkı biçim.
pub fn validate_scan_id(id: &str) -> Result<(), EventError> {
    let ok = !id.is_empty()
    && id.len() <= 64
    && id
    .chars()
    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if ok {
        Ok(())
    } else {
        Err(EventError::InvalidScanId)
    }
}

pub fn generate_scan_id() -> String {
    format!("{:x}-{:x}", now_ms(), std::process::id())
}

fn now_ms() -> u64 {
    SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map(|d| d.as_millis() as u64)
    .unwrap_or(0)
}

/// Klonlanabilir, iş parçacığı güvenli NDJSON yazıcısı. Her olay tek `write_all` +
/// `flush` ile yazılır; satırlar birbirine karışmaz.
#[derive(Clone)]
pub struct EventSink {
    scan_id: Arc<str>,
    out: Arc<Mutex<Box<dyn Write + Send>>>,
}

impl EventSink {
    pub fn stdout(scan_id: impl Into<String>) -> Self {
        Self::with_writer(scan_id, io::stdout())
    }

    pub fn with_writer<W: Write + Send + 'static>(scan_id: impl Into<String>, w: W) -> Self {
        let id: String = scan_id.into();
        Self {
            scan_id: Arc::from(id.as_str()),
            out: Arc::new(Mutex::new(Box::new(w))),
        }
    }

    pub fn scan_id(&self) -> &str {
        &self.scan_id
    }

    pub fn emit(&self, event: Event) -> Result<(), EventError> {
        let envelope = Envelope {
            schema_version: SCHEMA_VERSION,
            scan_id: self.scan_id.to_string(),
            ts_ms: now_ms(),
            event,
        };
        let mut line = serde_json::to_vec(&envelope)?;
        line.push(b'\n');
        let mut guard = self.out.lock().map_err(|_| EventError::Poisoned)?;
        guard.write_all(&line)?;
        guard.flush()?;
        Ok(())
    }
}

/// Bir modül çalışmasını `scan_started` ... `scan_finished` olaylarıyla sarar.
/// Hata durumunda `error` olayı otomatik yayılır; böylece Python tarafı her çalışmanın
/// nasıl bittiğini akıştan okuyabilir.
pub async fn run_with_lifecycle<F, Fut>(
    sink: &EventSink,
    module: Module,
    f: F,
) -> Result<(), CoreError>
where
F: FnOnce() -> Fut,
Fut: Future<Output = Result<(), CoreError>>,
{
    let started = Instant::now();
    sink.emit(Event::ScanStarted { module })?;
    let result = f().await;
    if let Err(e) = &result {
        // Alıcı kapanmışsa asıl hatayı gizlememek için yayın hatası yok sayılır.
        let _ = sink.emit(Event::Error {
            module,
            code: e.code().to_string(),
                          message: e.to_string(),
        });
    }
    let status = if result.is_ok() {
        FinishStatus::Ok
    } else {
        FinishStatus::Failed
    };
    let _ = sink.emit(Event::ScanFinished {
        module,
        status,
        duration_ms: started.elapsed().as_millis() as u64,
    });
    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::scope::ScopeError;

    #[derive(Clone, Default)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedBuf {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl SharedBuf {
        fn lines(&self) -> Vec<serde_json::Value> {
            let data = self.0.lock().unwrap().clone();
            String::from_utf8(data)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
        }
    }

    #[test]
    fn envelope_is_flat_ndjson() {
        let buf = SharedBuf::default();
        let sink = EventSink::with_writer("scan-1", buf.clone());
        sink.emit(Event::Progress {
            module: Module::PortScan,
            done: 5,
            total: 10,
        })
        .unwrap();
        let lines = buf.lines();
        assert_eq!(lines.len(), 1);
        let v = &lines[0];
        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["scan_id"], "scan-1");
        assert_eq!(v["type"], "progress");
        assert_eq!(v["module"], "port_scan");
        assert_eq!(v["done"], 5);
        assert!(v["ts_ms"].as_u64().unwrap() > 0);
    }

    #[test]
    fn host_found_serializes_methods() {
        let buf = SharedBuf::default();
        let sink = EventSink::with_writer("s", buf.clone());
        sink.emit(Event::HostFound {
            ip: "192.168.1.10".parse().unwrap(),
                  mac: Some("28:6f:b9:00:00:01".into()),
                  vendor: None,
                  methods: vec![DiscoveryMethod::Arp, DiscoveryMethod::TcpConnect],
        })
        .unwrap();
        let v = &buf.lines()[0];
        assert_eq!(v["type"], "host_found");
        assert_eq!(v["ip"], "192.168.1.10");
        assert_eq!(v["methods"][1], "tcp_connect");
        assert!(v["vendor"].is_null());
    }

    #[tokio::test]
    async fn lifecycle_emits_error_and_failed_finish() {
        let buf = SharedBuf::default();
        let sink = EventSink::with_writer("s", buf.clone());
        let res = run_with_lifecycle(&sink, Module::Core, || async {
            Err(CoreError::Scope(ScopeError::OutOfScope("8.8.8.8".into())))
        })
        .await;
        assert!(res.is_err());
        let lines = buf.lines();
        let types: Vec<&str> = lines.iter().map(|l| l["type"].as_str().unwrap()).collect();
        assert_eq!(types, ["scan_started", "error", "scan_finished"]);
        assert_eq!(lines[1]["code"], "scope_violation");
        assert_eq!(lines[2]["status"], "failed");
    }

    #[tokio::test]
    async fn lifecycle_success_path() {
        let buf = SharedBuf::default();
        let sink = EventSink::with_writer("s", buf.clone());
        run_with_lifecycle(&sink, Module::Core, || async { Ok(()) })
        .await
        .unwrap();
        let lines = buf.lines();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1]["status"], "ok");
    }

    #[test]
    fn scan_id_validation() {
        assert!(validate_scan_id("abc-123_X").is_ok());
        assert!(validate_scan_id("").is_err());
        assert!(validate_scan_id("a b").is_err());
        assert!(validate_scan_id("../etc").is_err());
        assert!(validate_scan_id(&"a".repeat(65)).is_err());
        assert!(validate_scan_id(&generate_scan_id()).is_ok());
    }
}

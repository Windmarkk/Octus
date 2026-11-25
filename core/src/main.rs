//! Octus çekirdek motoru CLI'si.
//!
//! Sözleşme: stdout = NDJSON olay akışı, stderr = insan-okunur loglar.
//! Çıkış kodları için bkz. `octus_core::exit`.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use octus_core::discovery;
use octus_core::events::{
    generate_scan_id, run_with_lifecycle, validate_scan_id, Envelope, VerifiedTarget,
};
use octus_core::{exit, CoreError, Event, EventSink, Limits, Module, ScopedTarget, Throttle};

#[derive(Parser)]
#[command(name = "octus-core", version, about = "Octus çekirdek ağ motoru (yalnızca RFC 1918)")]
struct Cli {
    /// Tarama kimliği; verilmezse otomatik üretilir.
    #[arg(long, global = true)]
    scan_id: Option<String>,

    /// Eşzamanlı işlem üst sınırı.
    #[arg(long, global = true, default_value_t = 128)]
    concurrency: usize,

    /// Saniyedeki en fazla paket/bağlantı denemesi.
    #[arg(long, global = true, default_value_t = 500)]
    pps: u32,

    /// Her ağ işlemi için zaman aşımı (ms).
    #[arg(long, global = true, default_value_t = 1500)]
    timeout_ms: u64,

    /// Log seviyesi (stderr): error, warn, info, debug, trace.
    #[arg(long, global = true, default_value = "warn")]
    log_level: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Hedeflerin kapsam kilidini geçip geçmediğini doğrular; ağa paket göndermez.
    CheckScope {
        /// IP adresi veya IPv4 CIDR (hostname kabul edilmez).
        #[arg(required = true)]
        targets: Vec<String>,
    },
    /// M1: canlı host keşfi (ARP + ICMP + TCP-connect).
    Discover {
        /// IP adresi veya IPv4 CIDR (hostname kabul edilmez).
        #[arg(required = true)]
        targets: Vec<String>,
        /// ARP taramasını atla.
        #[arg(long)]
        no_arp: bool,
        /// ICMP echo taramasını atla.
        #[arg(long)]
        no_icmp: bool,
        /// TCP-connect taramasını atla.
        #[arg(long)]
        no_tcp: bool,
    },
    /// Olay sözleşmesinin JSON Schema'sını üretir (varsayılan: stdout).
    Schema {
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging(&cli.log_level);
    match run(cli).await {
        Ok(()) => ExitCode::from(exit::OK),
        Err(e) => {
            tracing::error!(code = e.code(), "{e}");
            ExitCode::from(e.exit_code())
        }
    }
}

fn init_logging(level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_new(level)
    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    tracing_subscriber::fmt()
    .with_env_filter(filter)
    .with_writer(std::io::stderr)
    .init();
}

async fn run(cli: Cli) -> Result<(), CoreError> {
    let limits = Limits {
        max_concurrency: cli.concurrency,
        packets_per_sec: cli.pps,
        timeout: Duration::from_millis(cli.timeout_ms),
    };
    // Sınırlar geçersizse hiçbir şey başlamadan reddedilir.
    let throttle = Throttle::new(&limits)?;

    match cli.command {
        Command::Schema { out } => write_schema(out),
        Command::CheckScope { targets } => {
            let sink = EventSink::stdout(resolve_scan_id(cli.scan_id)?);
            run_with_lifecycle(&sink, Module::Core, || async { check_scope(&sink, &targets) })
            .await
        }
        Command::Discover {
            targets,
            no_arp,
            no_icmp,
            no_tcp,
        } => {
            let parsed = parse_targets(&targets)?;
            let opts = discovery::Options {
                arp: !no_arp,
                icmp: !no_icmp,
                tcp: !no_tcp,
            };
            let sink = EventSink::stdout(resolve_scan_id(cli.scan_id)?);
            run_with_lifecycle(&sink, Module::Discovery, || async {
                sink.emit(Event::ScopeVerified {
                    targets: verified(&parsed),
                })?;
                discovery::discover(&parsed, opts, &throttle, &sink)
                .await
                .map(|_| ())
            })
            .await
        }
    }
}

fn resolve_scan_id(given: Option<String>) -> Result<String, CoreError> {
    match given {
        Some(id) => {
            validate_scan_id(&id)?;
            Ok(id)
        }
        None => Ok(generate_scan_id()),
    }
}

/// Hepsi-ya-da-hiçbiri: tek bir hedef bile kapsam dışıysa hata döner.
fn parse_targets(raw: &[String]) -> Result<Vec<ScopedTarget>, CoreError> {
    raw.iter()
    .map(|t| t.parse::<ScopedTarget>().map_err(CoreError::from))
    .collect()
}

fn verified(parsed: &[ScopedTarget]) -> Vec<VerifiedTarget> {
    parsed
    .iter()
    .map(|t| VerifiedTarget {
        target: t.to_string(),
         host_count: t.host_count(),
    })
    .collect()
}

fn check_scope(sink: &EventSink, raw: &[String]) -> Result<(), CoreError> {
    let parsed = parse_targets(raw)?;
    sink.emit(Event::ScopeVerified {
        targets: verified(&parsed),
    })?;
    Ok(())
}

fn write_schema(out: Option<PathBuf>) -> Result<(), CoreError> {
    let schema = schemars::schema_for!(Envelope);
    let mut json = serde_json::to_string_pretty(&schema)?;
    json.push('\n');
    match out {
        Some(path) => {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, json)?;
        }
        None => print!("{json}"),
    }
    Ok(())
}

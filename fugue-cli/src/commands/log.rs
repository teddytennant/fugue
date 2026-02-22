use anyhow::Result;
use fugue_core::audit::{AuditLog, AuditSeverity};
use fugue_core::FugueConfig;

pub async fn audit(count: usize, severity: Option<&str>) -> Result<()> {
    let audit_path = FugueConfig::data_dir().join("audit.db");

    if !audit_path.exists() {
        println!("No audit log found. Start fugue to begin logging.");
        return Ok(());
    }

    let log = AuditLog::open(&audit_path)?;

    let events = if let Some(sev) = severity {
        let severity = match sev {
            "info" => AuditSeverity::Info,
            "warning" => AuditSeverity::Warning,
            "critical" => AuditSeverity::Critical,
            other => {
                eprintln!("Unknown severity '{}'. Use: info, warning, critical", other);
                std::process::exit(1);
            }
        };
        log.query_by_severity(severity, count)?
    } else {
        log.query_recent(count)?
    };

    if events.is_empty() {
        println!("No audit events found");
        return Ok(());
    }

    for event in &events {
        let sev = match event.severity {
            AuditSeverity::Info => "INFO",
            AuditSeverity::Warning => "WARN",
            AuditSeverity::Critical => "CRIT",
        };
        println!(
            "[{}] [{}] {:?} {} — {}",
            event.timestamp.format("%Y-%m-%d %H:%M:%S"),
            sev,
            event.event_type,
            event.subject,
            event.detail,
        );
    }

    Ok(())
}

pub async fn app(_count: usize) -> Result<()> {
    // Application logs go to stderr/stdout via tracing
    // This command would tail a log file if we wrote to one
    println!("Application logs are written to stderr.");
    println!("Use RUST_LOG=fugue=debug to increase verbosity.");
    println!("For structured JSON logs, set FUGUE_LOG_FORMAT=json.");
    Ok(())
}

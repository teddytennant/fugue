#![deny(unsafe_code)]

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::error::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: Option<i64>,
    pub timestamp: DateTime<Utc>,
    pub event_type: AuditEventType,
    pub subject: String,
    pub detail: String,
    pub severity: AuditSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    PluginInstalled,
    PluginRemoved,
    PluginApproved,
    PluginRevoked,
    PluginExecuted,
    PluginBinaryChanged,
    CapabilityGranted,
    CapabilityDenied,
    CredentialAccessed,
    CredentialSet,
    CredentialRemoved,
    AdapterConnected,
    AdapterDisconnected,
    ConfigLoaded,
    ConfigChanged,
    NetworkBindAttempt,
    AuthenticationFailure,
    ServiceStarted,
    ServiceStopped,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuditSeverity {
    Info,
    Warning,
    Critical,
}

pub struct AuditLog {
    conn: Connection,
}

impl AuditLog {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path)?;
        let log = Self { conn };
        log.init_tables()?;
        Ok(log)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let log = Self { conn };
        log.init_tables()?;
        Ok(log)
    }

    fn init_tables(&self) -> Result<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                subject TEXT NOT NULL,
                detail TEXT NOT NULL,
                severity TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_audit_timestamp
                ON audit_log(timestamp);

            CREATE INDEX IF NOT EXISTS idx_audit_event_type
                ON audit_log(event_type);

            CREATE INDEX IF NOT EXISTS idx_audit_severity
                ON audit_log(severity);
            ",
        )?;
        Ok(())
    }

    pub fn append(&self, event: &AuditEvent) -> Result<i64> {
        let event_type = serde_json::to_string(&event.event_type)
            .unwrap_or_default()
            .trim_matches('"')
            .to_string();
        let severity = serde_json::to_string(&event.severity)
            .unwrap_or_default()
            .trim_matches('"')
            .to_string();

        self.conn.execute(
            "INSERT INTO audit_log (timestamp, event_type, subject, detail, severity)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                event.timestamp.to_rfc3339(),
                event_type,
                event.subject,
                event.detail,
                severity,
            ],
        )?;

        Ok(self.conn.last_insert_rowid())
    }

    pub fn query_recent(&self, limit: usize) -> Result<Vec<AuditEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp, event_type, subject, detail, severity
             FROM audit_log
             ORDER BY timestamp DESC
             LIMIT ?1",
        )?;

        let events = stmt
            .query_map(params![limit as i64], |row| {
                Ok(AuditEventRaw {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    event_type: row.get(2)?,
                    subject: row.get(3)?,
                    detail: row.get(4)?,
                    severity: row.get(5)?,
                })
            })?
            .filter_map(|r| r.ok())
            .filter_map(|raw| raw.into_event().ok())
            .collect::<Vec<_>>();

        let mut events = events;
        events.reverse();
        Ok(events)
    }

    pub fn query_by_type(
        &self,
        event_type: &AuditEventType,
        limit: usize,
    ) -> Result<Vec<AuditEvent>> {
        let type_str = serde_json::to_string(event_type)
            .unwrap_or_default()
            .trim_matches('"')
            .to_string();

        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp, event_type, subject, detail, severity
             FROM audit_log
             WHERE event_type = ?1
             ORDER BY timestamp DESC
             LIMIT ?2",
        )?;

        let events = stmt
            .query_map(params![type_str, limit as i64], |row| {
                Ok(AuditEventRaw {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    event_type: row.get(2)?,
                    subject: row.get(3)?,
                    detail: row.get(4)?,
                    severity: row.get(5)?,
                })
            })?
            .filter_map(|r| r.ok())
            .filter_map(|raw| raw.into_event().ok())
            .collect::<Vec<_>>();

        let mut events = events;
        events.reverse();
        Ok(events)
    }

    pub fn query_by_severity(
        &self,
        severity: AuditSeverity,
        limit: usize,
    ) -> Result<Vec<AuditEvent>> {
        let sev_str = serde_json::to_string(&severity)
            .unwrap_or_default()
            .trim_matches('"')
            .to_string();

        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp, event_type, subject, detail, severity
             FROM audit_log
             WHERE severity = ?1
             ORDER BY timestamp DESC
             LIMIT ?2",
        )?;

        let events = stmt
            .query_map(params![sev_str, limit as i64], |row| {
                Ok(AuditEventRaw {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    event_type: row.get(2)?,
                    subject: row.get(3)?,
                    detail: row.get(4)?,
                    severity: row.get(5)?,
                })
            })?
            .filter_map(|r| r.ok())
            .filter_map(|raw| raw.into_event().ok())
            .collect::<Vec<_>>();

        let mut events = events;
        events.reverse();
        Ok(events)
    }

    pub fn count(&self) -> Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))?;
        Ok(count as usize)
    }
}

struct AuditEventRaw {
    id: i64,
    timestamp: String,
    event_type: String,
    subject: String,
    detail: String,
    severity: String,
}

impl AuditEventRaw {
    fn into_event(self) -> std::result::Result<AuditEvent, String> {
        let timestamp = DateTime::parse_from_rfc3339(&self.timestamp)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(|e| format!("invalid timestamp: {}", e))?;

        let event_type: AuditEventType =
            serde_json::from_str(&format!("\"{}\"", self.event_type))
                .map_err(|e| format!("invalid event type: {}", e))?;

        let severity: AuditSeverity =
            serde_json::from_str(&format!("\"{}\"", self.severity))
                .map_err(|e| format!("invalid severity: {}", e))?;

        Ok(AuditEvent {
            id: Some(self.id),
            timestamp,
            event_type,
            subject: self.subject,
            detail: self.detail,
            severity,
        })
    }
}

/// Helper to create an audit event
pub fn event(
    event_type: AuditEventType,
    subject: impl Into<String>,
    detail: impl Into<String>,
    severity: AuditSeverity,
) -> AuditEvent {
    AuditEvent {
        id: None,
        timestamp: Utc::now(),
        event_type,
        subject: subject.into(),
        detail: detail.into(),
        severity,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_append_and_query() {
        let log = AuditLog::open_in_memory().unwrap();

        let evt = event(
            AuditEventType::ServiceStarted,
            "fugue-core",
            "core service started",
            AuditSeverity::Info,
        );
        log.append(&evt).unwrap();

        let events = log.query_recent(10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, AuditEventType::ServiceStarted);
        assert_eq!(events[0].subject, "fugue-core");
    }

    #[test]
    fn test_query_by_type() {
        let log = AuditLog::open_in_memory().unwrap();

        log.append(&event(
            AuditEventType::PluginInstalled,
            "echo-tool",
            "installed",
            AuditSeverity::Info,
        ))
        .unwrap();
        log.append(&event(
            AuditEventType::ServiceStarted,
            "core",
            "started",
            AuditSeverity::Info,
        ))
        .unwrap();
        log.append(&event(
            AuditEventType::PluginInstalled,
            "search-tool",
            "installed",
            AuditSeverity::Info,
        ))
        .unwrap();

        let events = log
            .query_by_type(&AuditEventType::PluginInstalled, 10)
            .unwrap();
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn test_query_by_severity() {
        let log = AuditLog::open_in_memory().unwrap();

        log.append(&event(
            AuditEventType::PluginExecuted,
            "tool",
            "executed",
            AuditSeverity::Info,
        ))
        .unwrap();
        log.append(&event(
            AuditEventType::CapabilityDenied,
            "bad-plugin",
            "denied net access",
            AuditSeverity::Warning,
        ))
        .unwrap();
        log.append(&event(
            AuditEventType::PluginBinaryChanged,
            "suspicious",
            "binary hash changed",
            AuditSeverity::Critical,
        ))
        .unwrap();

        let warnings = log.query_by_severity(AuditSeverity::Warning, 10).unwrap();
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].subject, "bad-plugin");

        let critical = log.query_by_severity(AuditSeverity::Critical, 10).unwrap();
        assert_eq!(critical.len(), 1);
    }

    #[test]
    fn test_count() {
        let log = AuditLog::open_in_memory().unwrap();
        assert_eq!(log.count().unwrap(), 0);

        for i in 0..5 {
            log.append(&event(
                AuditEventType::PluginExecuted,
                format!("plugin-{}", i),
                "executed",
                AuditSeverity::Info,
            ))
            .unwrap();
        }

        assert_eq!(log.count().unwrap(), 5);
    }

    #[test]
    fn test_append_only_integrity() {
        let log = AuditLog::open_in_memory().unwrap();

        log.append(&event(
            AuditEventType::ServiceStarted,
            "core",
            "started",
            AuditSeverity::Info,
        ))
        .unwrap();

        // Verify no UPDATE or DELETE operations are exposed
        // The API only provides append and query
        let events = log.query_recent(10).unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0].id.is_some());
    }

    #[test]
    fn test_file_backed_audit_log() {
        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("audit.db");

        {
            let log = AuditLog::open(&db_path).unwrap();
            log.append(&event(
                AuditEventType::ServiceStarted,
                "core",
                "started",
                AuditSeverity::Info,
            ))
            .unwrap();
        }

        {
            let log = AuditLog::open(&db_path).unwrap();
            let events = log.query_recent(10).unwrap();
            assert_eq!(events.len(), 1);
        }
    }

    #[test]
    fn test_all_event_types() {
        let log = AuditLog::open_in_memory().unwrap();

        let event_types = vec![
            AuditEventType::PluginInstalled,
            AuditEventType::PluginRemoved,
            AuditEventType::PluginApproved,
            AuditEventType::PluginRevoked,
            AuditEventType::PluginExecuted,
            AuditEventType::PluginBinaryChanged,
            AuditEventType::CapabilityGranted,
            AuditEventType::CapabilityDenied,
            AuditEventType::CredentialAccessed,
            AuditEventType::CredentialSet,
            AuditEventType::CredentialRemoved,
            AuditEventType::AdapterConnected,
            AuditEventType::AdapterDisconnected,
            AuditEventType::ConfigLoaded,
            AuditEventType::ConfigChanged,
            AuditEventType::NetworkBindAttempt,
            AuditEventType::AuthenticationFailure,
            AuditEventType::ServiceStarted,
            AuditEventType::ServiceStopped,
        ];

        for et in &event_types {
            log.append(&event(
                et.clone(),
                "test",
                "testing all event types",
                AuditSeverity::Info,
            ))
            .unwrap();
        }

        assert_eq!(log.count().unwrap(), event_types.len());

        // Each event type should be queryable individually
        for et in &event_types {
            let events = log.query_by_type(et, 10).unwrap();
            assert_eq!(events.len(), 1, "event type {:?} should have 1 entry", et);
        }
    }

    #[test]
    fn test_query_recent_limit() {
        let log = AuditLog::open_in_memory().unwrap();

        for i in 0..10 {
            log.append(&event(
                AuditEventType::PluginExecuted,
                format!("plugin-{}", i),
                "executed",
                AuditSeverity::Info,
            ))
            .unwrap();
        }

        let events = log.query_recent(3).unwrap();
        assert_eq!(events.len(), 3);
        // Should return the 3 most recent in chronological order
        assert_eq!(events[0].subject, "plugin-7");
        assert_eq!(events[1].subject, "plugin-8");
        assert_eq!(events[2].subject, "plugin-9");
    }

    #[test]
    fn test_query_recent_empty_log() {
        let log = AuditLog::open_in_memory().unwrap();
        let events = log.query_recent(10).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn test_query_by_type_empty_result() {
        let log = AuditLog::open_in_memory().unwrap();

        log.append(&event(
            AuditEventType::ServiceStarted,
            "core",
            "started",
            AuditSeverity::Info,
        ))
        .unwrap();

        let events = log
            .query_by_type(&AuditEventType::PluginInstalled, 10)
            .unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn test_all_severity_levels() {
        let log = AuditLog::open_in_memory().unwrap();

        log.append(&event(
            AuditEventType::ServiceStarted,
            "core",
            "info event",
            AuditSeverity::Info,
        ))
        .unwrap();
        log.append(&event(
            AuditEventType::CapabilityDenied,
            "plugin",
            "warning event",
            AuditSeverity::Warning,
        ))
        .unwrap();
        log.append(&event(
            AuditEventType::PluginBinaryChanged,
            "plugin",
            "critical event",
            AuditSeverity::Critical,
        ))
        .unwrap();

        let info = log.query_by_severity(AuditSeverity::Info, 10).unwrap();
        assert_eq!(info.len(), 1);

        let warn = log.query_by_severity(AuditSeverity::Warning, 10).unwrap();
        assert_eq!(warn.len(), 1);

        let crit = log.query_by_severity(AuditSeverity::Critical, 10).unwrap();
        assert_eq!(crit.len(), 1);
    }

    #[test]
    fn test_event_has_timestamp() {
        let log = AuditLog::open_in_memory().unwrap();

        let before = chrono::Utc::now();
        log.append(&event(
            AuditEventType::ServiceStarted,
            "core",
            "started",
            AuditSeverity::Info,
        ))
        .unwrap();
        let after = chrono::Utc::now();

        let events = log.query_recent(1).unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0].timestamp >= before);
        assert!(events[0].timestamp <= after);
    }

    #[test]
    fn test_event_id_assigned() {
        let log = AuditLog::open_in_memory().unwrap();

        let id = log
            .append(&event(
                AuditEventType::ServiceStarted,
                "core",
                "started",
                AuditSeverity::Info,
            ))
            .unwrap();
        assert!(id > 0);

        let events = log.query_recent(1).unwrap();
        assert_eq!(events[0].id, Some(id));
    }

    #[test]
    fn test_event_helper_function() {
        let evt = event(
            AuditEventType::PluginInstalled,
            "test-plugin",
            "installed via CLI",
            AuditSeverity::Info,
        );

        assert_eq!(evt.event_type, AuditEventType::PluginInstalled);
        assert_eq!(evt.subject, "test-plugin");
        assert_eq!(evt.detail, "installed via CLI");
        assert_eq!(evt.severity, AuditSeverity::Info);
        assert!(evt.id.is_none()); // Not yet persisted
    }

    #[test]
    fn test_event_detail_preserved() {
        let log = AuditLog::open_in_memory().unwrap();

        let long_detail = "x".repeat(10_000);
        log.append(&event(
            AuditEventType::PluginExecuted,
            "plugin",
            long_detail.clone(),
            AuditSeverity::Info,
        ))
        .unwrap();

        let events = log.query_recent(1).unwrap();
        assert_eq!(events[0].detail, long_detail);
    }

    #[test]
    fn test_open_creates_parent_dirs() {
        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("sub").join("dir").join("audit.db");

        let log = AuditLog::open(&db_path).unwrap();
        log.append(&event(
            AuditEventType::ServiceStarted,
            "core",
            "started",
            AuditSeverity::Info,
        ))
        .unwrap();

        assert!(db_path.exists());
    }
}

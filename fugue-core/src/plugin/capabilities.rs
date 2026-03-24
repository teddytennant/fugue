#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fmt;

/// A capability that a plugin can request
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Read files (optionally scoped to a path)
    FsRead(Option<String>),
    /// Write files (optionally scoped to a path)
    FsWrite(Option<String>),
    /// Outbound HTTP (optionally scoped to a URL pattern)
    NetOutbound(Option<String>),
    /// Send/receive messages through the router
    IpcMessages,
    /// Invoke LLM provider through core
    LlmCall,
    /// Read from the state store
    StateRead,
    /// Write to the state store
    StateWrite,
    /// Execute host subprocesses (CRITICAL)
    ExecSubprocess,
    /// Access a specific vault credential (CRITICAL)
    CredentialRead(String),
}

/// Check that `granted` is a prefix of `requested` at a path/URL boundary.
/// Prevents "/tmp" from matching "/tmp_evil" while still matching "/tmp/file".
fn path_prefix_matches(granted: &str, requested: &str) -> bool {
    if requested == granted {
        return true;
    }
    let prefix = if granted.ends_with('/') {
        granted.to_string()
    } else {
        format!("{}/", granted)
    };
    requested.starts_with(&prefix)
}

impl Capability {
    /// Parse a capability string like "fs:read", "net:outbound:https://api.example.com"
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.splitn(3, ':').collect();
        match parts.as_slice() {
            ["fs", "read"] => Some(Capability::FsRead(None)),
            ["fs", "read", path] => Some(Capability::FsRead(Some(path.to_string()))),
            ["fs", "write"] => Some(Capability::FsWrite(None)),
            ["fs", "write", path] => Some(Capability::FsWrite(Some(path.to_string()))),
            ["net", "outbound"] => Some(Capability::NetOutbound(None)),
            ["net", "outbound", url] => Some(Capability::NetOutbound(Some(url.to_string()))),
            ["ipc", "messages"] => Some(Capability::IpcMessages),
            ["llm", "call"] => Some(Capability::LlmCall),
            ["state", "read"] => Some(Capability::StateRead),
            ["state", "write"] => Some(Capability::StateWrite),
            ["exec", "subprocess"] => Some(Capability::ExecSubprocess),
            ["credential", "read", name] => Some(Capability::CredentialRead(name.to_string())),
            _ => None,
        }
    }

    /// Get the risk level of this capability
    pub fn risk_level(&self) -> RiskLevel {
        match self {
            Capability::IpcMessages | Capability::StateRead | Capability::LlmCall => RiskLevel::Low,
            Capability::StateWrite | Capability::FsRead(_) | Capability::NetOutbound(Some(_)) => {
                RiskLevel::Medium
            }
            Capability::FsWrite(_) | Capability::NetOutbound(None) => RiskLevel::High,
            Capability::ExecSubprocess | Capability::CredentialRead(_) => RiskLevel::Critical,
        }
    }

    /// Check if a granted capability satisfies a requested one
    pub fn satisfies(&self, requested: &Capability) -> bool {
        match (self, requested) {
            // Global fs:read satisfies any scoped fs:read
            (Capability::FsRead(None), Capability::FsRead(_)) => true,
            // Scoped fs:read satisfies if path matches at a boundary
            (Capability::FsRead(Some(granted)), Capability::FsRead(Some(requested))) => {
                path_prefix_matches(granted, requested)
            }
            // Global fs:write satisfies any scoped fs:write
            (Capability::FsWrite(None), Capability::FsWrite(_)) => true,
            (Capability::FsWrite(Some(granted)), Capability::FsWrite(Some(requested))) => {
                path_prefix_matches(granted, requested)
            }
            // Global net:outbound satisfies any scoped net:outbound
            (Capability::NetOutbound(None), Capability::NetOutbound(_)) => true,
            (Capability::NetOutbound(Some(granted)), Capability::NetOutbound(Some(requested))) => {
                path_prefix_matches(granted, requested)
            }
            // Exact match for everything else
            _ => self == requested,
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Capability::FsRead(None) => write!(f, "fs:read"),
            Capability::FsRead(Some(path)) => write!(f, "fs:read:{}", path),
            Capability::FsWrite(None) => write!(f, "fs:write"),
            Capability::FsWrite(Some(path)) => write!(f, "fs:write:{}", path),
            Capability::NetOutbound(None) => write!(f, "net:outbound"),
            Capability::NetOutbound(Some(url)) => write!(f, "net:outbound:{}", url),
            Capability::IpcMessages => write!(f, "ipc:messages"),
            Capability::LlmCall => write!(f, "llm:call"),
            Capability::StateRead => write!(f, "state:read"),
            Capability::StateWrite => write!(f, "state:write"),
            Capability::ExecSubprocess => write!(f, "exec:subprocess"),
            Capability::CredentialRead(name) => write!(f, "credential:read:{}", name),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "LOW"),
            RiskLevel::Medium => write!(f, "MEDIUM"),
            RiskLevel::High => write!(f, "HIGH"),
            RiskLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Check if a set of granted capabilities satisfies all requested capabilities
pub fn check_capabilities(granted: &[Capability], requested: &[Capability]) -> Vec<Capability> {
    let mut denied = Vec::new();
    for req in requested {
        let satisfied = granted.iter().any(|g| g.satisfies(req));
        if !satisfied {
            denied.push(req.clone());
        }
    }
    denied
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_capabilities() {
        assert_eq!(Capability::parse("fs:read"), Some(Capability::FsRead(None)));
        assert_eq!(
            Capability::parse("fs:read:/tmp"),
            Some(Capability::FsRead(Some("/tmp".to_string())))
        );
        assert_eq!(
            Capability::parse("net:outbound"),
            Some(Capability::NetOutbound(None))
        );
        assert_eq!(
            Capability::parse("net:outbound:https://api.example.com"),
            Some(Capability::NetOutbound(Some(
                "https://api.example.com".to_string()
            )))
        );
        assert_eq!(
            Capability::parse("ipc:messages"),
            Some(Capability::IpcMessages)
        );
        assert_eq!(Capability::parse("llm:call"), Some(Capability::LlmCall));
        assert_eq!(Capability::parse("state:read"), Some(Capability::StateRead));
        assert_eq!(
            Capability::parse("state:write"),
            Some(Capability::StateWrite)
        );
        assert_eq!(
            Capability::parse("exec:subprocess"),
            Some(Capability::ExecSubprocess)
        );
        assert_eq!(
            Capability::parse("credential:read:api-key"),
            Some(Capability::CredentialRead("api-key".to_string()))
        );
        assert_eq!(Capability::parse("invalid"), None);
    }

    #[test]
    fn test_display_roundtrip() {
        let caps = vec![
            Capability::FsRead(None),
            Capability::FsRead(Some("/tmp".to_string())),
            Capability::FsWrite(None),
            Capability::NetOutbound(None),
            Capability::NetOutbound(Some("https://api.example.com".to_string())),
            Capability::IpcMessages,
            Capability::LlmCall,
            Capability::StateRead,
            Capability::StateWrite,
            Capability::ExecSubprocess,
            Capability::CredentialRead("my-key".to_string()),
        ];

        for cap in caps {
            let displayed = cap.to_string();
            let parsed = Capability::parse(&displayed).unwrap();
            assert_eq!(parsed, cap);
        }
    }

    #[test]
    fn test_risk_levels() {
        assert_eq!(Capability::IpcMessages.risk_level(), RiskLevel::Low);
        assert_eq!(Capability::StateRead.risk_level(), RiskLevel::Low);
        assert_eq!(Capability::LlmCall.risk_level(), RiskLevel::Low);
        assert_eq!(Capability::StateWrite.risk_level(), RiskLevel::Medium);
        assert_eq!(Capability::FsRead(None).risk_level(), RiskLevel::Medium);
        assert_eq!(Capability::FsWrite(None).risk_level(), RiskLevel::High);
        assert_eq!(Capability::NetOutbound(None).risk_level(), RiskLevel::High);
        assert_eq!(Capability::ExecSubprocess.risk_level(), RiskLevel::Critical);
        assert_eq!(
            Capability::CredentialRead("x".to_string()).risk_level(),
            RiskLevel::Critical
        );
    }

    #[test]
    fn test_global_satisfies_scoped() {
        let global_read = Capability::FsRead(None);
        let scoped_read = Capability::FsRead(Some("/tmp/data".to_string()));
        assert!(global_read.satisfies(&scoped_read));
    }

    #[test]
    fn test_scoped_satisfies_subpath() {
        let granted = Capability::FsRead(Some("/tmp".to_string()));
        let requested = Capability::FsRead(Some("/tmp/data/file.txt".to_string()));
        assert!(granted.satisfies(&requested));
    }

    #[test]
    fn test_scoped_does_not_satisfy_different_path() {
        let granted = Capability::FsRead(Some("/home".to_string()));
        let requested = Capability::FsRead(Some("/tmp/data".to_string()));
        assert!(!granted.satisfies(&requested));
    }

    #[test]
    fn test_check_capabilities_all_granted() {
        let granted = vec![
            Capability::IpcMessages,
            Capability::LlmCall,
            Capability::StateRead,
        ];
        let requested = vec![Capability::IpcMessages, Capability::LlmCall];
        let denied = check_capabilities(&granted, &requested);
        assert!(denied.is_empty());
    }

    #[test]
    fn test_check_capabilities_some_denied() {
        let granted = vec![Capability::IpcMessages];
        let requested = vec![
            Capability::IpcMessages,
            Capability::LlmCall,
            Capability::ExecSubprocess,
        ];
        let denied = check_capabilities(&granted, &requested);
        assert_eq!(denied.len(), 2);
        assert!(denied.contains(&Capability::LlmCall));
        assert!(denied.contains(&Capability::ExecSubprocess));
    }

    #[test]
    fn test_net_outbound_scoped_satisfies() {
        let granted = Capability::NetOutbound(Some("https://api.example.com".to_string()));
        let requested =
            Capability::NetOutbound(Some("https://api.example.com/v1/data".to_string()));
        assert!(granted.satisfies(&requested));
    }

    #[test]
    fn test_net_outbound_global_satisfies_scoped() {
        let granted = Capability::NetOutbound(None);
        let requested = Capability::NetOutbound(Some("https://anywhere.com".to_string()));
        assert!(granted.satisfies(&requested));
    }

    // --- Path traversal prevention tests ---

    #[test]
    fn test_fs_read_scoped_does_not_satisfy_similar_prefix() {
        let granted = Capability::FsRead(Some("/tmp".to_string()));
        let requested = Capability::FsRead(Some("/tmp_evil".to_string()));
        assert!(!granted.satisfies(&requested));
    }

    #[test]
    fn test_fs_write_scoped_does_not_satisfy_similar_prefix() {
        let granted = Capability::FsWrite(Some("/home/user".to_string()));
        let requested = Capability::FsWrite(Some("/home/user2".to_string()));
        assert!(!granted.satisfies(&requested));
    }

    #[test]
    fn test_net_outbound_scoped_does_not_satisfy_similar_prefix() {
        let granted = Capability::NetOutbound(Some("https://api.example.com".to_string()));
        let requested =
            Capability::NetOutbound(Some("https://api.example.com.evil.net".to_string()));
        assert!(!granted.satisfies(&requested));
    }

    #[test]
    fn test_fs_read_scoped_exact_match() {
        let granted = Capability::FsRead(Some("/tmp/data".to_string()));
        let requested = Capability::FsRead(Some("/tmp/data".to_string()));
        assert!(granted.satisfies(&requested));
    }

    #[test]
    fn test_fs_read_scoped_with_trailing_slash() {
        let granted = Capability::FsRead(Some("/tmp/".to_string()));
        let requested = Capability::FsRead(Some("/tmp/data/file.txt".to_string()));
        assert!(granted.satisfies(&requested));
    }

    // --- FsWrite scoped tests ---

    #[test]
    fn test_fs_write_scoped_satisfies_subpath() {
        let granted = Capability::FsWrite(Some("/var/data".to_string()));
        let requested = Capability::FsWrite(Some("/var/data/output.log".to_string()));
        assert!(granted.satisfies(&requested));
    }

    #[test]
    fn test_fs_write_scoped_does_not_satisfy_different_path() {
        let granted = Capability::FsWrite(Some("/var/data".to_string()));
        let requested = Capability::FsWrite(Some("/etc/config".to_string()));
        assert!(!granted.satisfies(&requested));
    }

    #[test]
    fn test_fs_write_global_satisfies_scoped() {
        let granted = Capability::FsWrite(None);
        let requested = Capability::FsWrite(Some("/anywhere".to_string()));
        assert!(granted.satisfies(&requested));
    }

    // --- Scoped does not satisfy global ---

    #[test]
    fn test_fs_read_scoped_does_not_satisfy_global() {
        let granted = Capability::FsRead(Some("/tmp".to_string()));
        let requested = Capability::FsRead(None);
        assert!(!granted.satisfies(&requested));
    }

    #[test]
    fn test_fs_write_scoped_does_not_satisfy_global() {
        let granted = Capability::FsWrite(Some("/tmp".to_string()));
        let requested = Capability::FsWrite(None);
        assert!(!granted.satisfies(&requested));
    }

    #[test]
    fn test_net_outbound_scoped_does_not_satisfy_global() {
        let granted = Capability::NetOutbound(Some("https://example.com".to_string()));
        let requested = Capability::NetOutbound(None);
        assert!(!granted.satisfies(&requested));
    }

    // --- Cross-type does not satisfy ---

    #[test]
    fn test_fs_read_does_not_satisfy_fs_write() {
        let granted = Capability::FsRead(None);
        let requested = Capability::FsWrite(None);
        assert!(!granted.satisfies(&requested));
    }

    // --- check_capabilities edge cases ---

    #[test]
    fn test_check_capabilities_empty_granted() {
        let granted: Vec<Capability> = vec![];
        let requested = vec![Capability::IpcMessages];
        let denied = check_capabilities(&granted, &requested);
        assert_eq!(denied, vec![Capability::IpcMessages]);
    }

    #[test]
    fn test_check_capabilities_empty_requested() {
        let granted = vec![Capability::IpcMessages];
        let requested: Vec<Capability> = vec![];
        let denied = check_capabilities(&granted, &requested);
        assert!(denied.is_empty());
    }

    // --- path_prefix_matches unit tests ---

    #[test]
    fn test_path_prefix_matches_direct() {
        assert!(path_prefix_matches("/tmp", "/tmp"));
        assert!(path_prefix_matches("/tmp", "/tmp/file"));
        assert!(path_prefix_matches("/tmp/", "/tmp/file"));
        assert!(!path_prefix_matches("/tmp", "/tmp_evil"));
        assert!(!path_prefix_matches("/tmp", "/tm"));
        assert!(!path_prefix_matches("/tmp/data", "/tmp"));
    }
}

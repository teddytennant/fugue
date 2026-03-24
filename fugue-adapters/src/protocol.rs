#![deny(unsafe_code)]

//! Adapter protocol — shared types and helpers for channel adapter communication
//! with the fugue core over Unix domain sockets using MessagePack.

use fugue_core::ipc::{self, IpcMessage};
use tokio::net::UnixStream;

/// State machine for the adapter handshake with core
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeState {
    Disconnected,
    Connecting,
    WaitingForAck,
    Connected { session_id: String },
    Failed { reason: String },
}

/// Adapter connection to the fugue core
pub struct AdapterConnection {
    stream: UnixStream,
    state: HandshakeState,
    adapter_name: String,
    adapter_type: String,
}

impl AdapterConnection {
    pub async fn connect(
        socket_path: &std::path::Path,
        adapter_name: String,
        adapter_type: String,
    ) -> Result<Self, fugue_core::error::FugueError> {
        let stream = UnixStream::connect(socket_path).await?;
        Ok(Self {
            stream,
            state: HandshakeState::Connecting,
            adapter_name,
            adapter_type,
        })
    }

    pub fn state(&self) -> &HandshakeState {
        &self.state
    }

    /// Perform the handshake with the core
    pub async fn handshake(&mut self) -> Result<String, fugue_core::error::FugueError> {
        let register = IpcMessage::Register {
            adapter_name: self.adapter_name.clone(),
            adapter_type: self.adapter_type.clone(),
        };

        ipc::write_message(&mut self.stream, &register).await?;
        self.state = HandshakeState::WaitingForAck;

        let response = ipc::read_message(&mut self.stream).await?;

        match response {
            IpcMessage::RegisterAck { session_id } => {
                self.state = HandshakeState::Connected {
                    session_id: session_id.clone(),
                };
                Ok(session_id)
            }
            IpcMessage::Error { message, .. } => {
                self.state = HandshakeState::Failed {
                    reason: message.clone(),
                };
                Err(fugue_core::error::FugueError::Ipc(format!(
                    "handshake failed: {}",
                    message
                )))
            }
            other => {
                let reason = format!("unexpected response: {:?}", other);
                self.state = HandshakeState::Failed {
                    reason: reason.clone(),
                };
                Err(fugue_core::error::FugueError::Ipc(reason))
            }
        }
    }

    /// Consume the connection and return the underlying stream.
    /// Use this when you need to split the stream for bidirectional communication.
    pub fn into_stream(self) -> UnixStream {
        self.stream
    }

    /// Send a message to the core
    pub async fn send(&mut self, msg: &IpcMessage) -> Result<(), fugue_core::error::FugueError> {
        ipc::write_message(&mut self.stream, msg).await
    }

    /// Receive a message from the core
    pub async fn recv(&mut self) -> Result<IpcMessage, fugue_core::error::FugueError> {
        ipc::read_message(&mut self.stream).await
    }

    /// Send an incoming message from a channel user
    pub async fn send_incoming(
        &mut self,
        sender_id: String,
        sender_name: Option<String>,
        content: String,
        message_id: String,
    ) -> Result<(), fugue_core::error::FugueError> {
        let request_id = uuid::Uuid::new_v4().to_string();
        let msg = IpcMessage::IncomingMessage {
            channel: self.adapter_name.clone(),
            sender_id,
            sender_name,
            content,
            message_id,
            request_id,
        };
        self.send(&msg).await
    }
}

/// Filter for checking if a sender is in an allowlist
pub fn is_allowed(sender_id: &str, allowlist: &[String]) -> bool {
    allowlist.is_empty() || allowlist.iter().any(|id| id == sender_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_state_initial() {
        let state = HandshakeState::Disconnected;
        assert_eq!(state, HandshakeState::Disconnected);
    }

    #[test]
    fn test_is_allowed_empty_allowlist() {
        assert!(is_allowed("anyone", &[]));
    }

    #[test]
    fn test_is_allowed_in_list() {
        let allowlist = vec!["123".to_string(), "456".to_string()];
        assert!(is_allowed("123", &allowlist));
        assert!(is_allowed("456", &allowlist));
    }

    #[test]
    fn test_is_allowed_not_in_list() {
        let allowlist = vec!["123".to_string()];
        assert!(!is_allowed("789", &allowlist));
    }

    #[tokio::test]
    async fn test_adapter_handshake() {
        let dir = tempfile::TempDir::new().unwrap();
        let sock_path = dir.path().join("test.sock");

        let listener = fugue_core::ipc::create_listener(&sock_path).await.unwrap();

        let sock_path_clone = sock_path.clone();
        let client = tokio::spawn(async move {
            let mut conn = AdapterConnection::connect(
                &sock_path_clone,
                "test-adapter".to_string(),
                "cli".to_string(),
            )
            .await
            .unwrap();

            let session_id = conn.handshake().await.unwrap();
            assert!(!session_id.is_empty());
            assert!(matches!(conn.state(), HandshakeState::Connected { .. }));
        });

        let (mut stream, _) = listener.accept().await.unwrap();
        let msg = ipc::read_message(&mut stream).await.unwrap();

        match msg {
            IpcMessage::Register {
                adapter_name,
                adapter_type,
            } => {
                assert_eq!(adapter_name, "test-adapter");
                assert_eq!(adapter_type, "cli");
            }
            _ => panic!("expected Register message"),
        }

        let ack = IpcMessage::RegisterAck {
            session_id: "sess-123".to_string(),
        };
        ipc::write_message(&mut stream, &ack).await.unwrap();

        client.await.unwrap();
    }

    #[tokio::test]
    async fn test_adapter_handshake_error_response() {
        let dir = tempfile::TempDir::new().unwrap();
        let sock_path = dir.path().join("test.sock");

        let listener = fugue_core::ipc::create_listener(&sock_path).await.unwrap();

        let sock_path_clone = sock_path.clone();
        let client = tokio::spawn(async move {
            let mut conn = AdapterConnection::connect(
                &sock_path_clone,
                "bad-adapter".to_string(),
                "cli".to_string(),
            )
            .await
            .unwrap();

            let result = conn.handshake().await;
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("handshake failed"));
            assert!(matches!(conn.state(), HandshakeState::Failed { .. }));
        });

        let (mut stream, _) = listener.accept().await.unwrap();
        let _msg = ipc::read_message(&mut stream).await.unwrap();

        // Respond with an error
        let err = IpcMessage::Error {
            request_id: None,
            message: "adapter not allowed".to_string(),
        };
        ipc::write_message(&mut stream, &err).await.unwrap();

        client.await.unwrap();
    }

    #[tokio::test]
    async fn test_adapter_handshake_unexpected_response() {
        let dir = tempfile::TempDir::new().unwrap();
        let sock_path = dir.path().join("test.sock");

        let listener = fugue_core::ipc::create_listener(&sock_path).await.unwrap();

        let sock_path_clone = sock_path.clone();
        let client = tokio::spawn(async move {
            let mut conn = AdapterConnection::connect(
                &sock_path_clone,
                "adapter".to_string(),
                "cli".to_string(),
            )
            .await
            .unwrap();

            let result = conn.handshake().await;
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("unexpected response"));
        });

        let (mut stream, _) = listener.accept().await.unwrap();
        let _msg = ipc::read_message(&mut stream).await.unwrap();

        // Respond with an unexpected message type
        let pong = IpcMessage::Pong;
        ipc::write_message(&mut stream, &pong).await.unwrap();

        client.await.unwrap();
    }

    #[tokio::test]
    async fn test_adapter_send_incoming() {
        let dir = tempfile::TempDir::new().unwrap();
        let sock_path = dir.path().join("test.sock");

        let listener = fugue_core::ipc::create_listener(&sock_path).await.unwrap();

        let sock_path_clone = sock_path.clone();
        let client = tokio::spawn(async move {
            let mut conn = AdapterConnection::connect(
                &sock_path_clone,
                "test-adapter".to_string(),
                "telegram".to_string(),
            )
            .await
            .unwrap();

            conn.send_incoming(
                "user-123".to_string(),
                Some("Alice".to_string()),
                "Hello from user".to_string(),
                "msg-001".to_string(),
            )
            .await
            .unwrap();
        });

        let (mut stream, _) = listener.accept().await.unwrap();
        let msg = ipc::read_message(&mut stream).await.unwrap();

        match msg {
            IpcMessage::IncomingMessage {
                channel,
                sender_id,
                sender_name,
                content,
                message_id,
                request_id,
            } => {
                assert_eq!(channel, "test-adapter");
                assert_eq!(sender_id, "user-123");
                assert_eq!(sender_name, Some("Alice".to_string()));
                assert_eq!(content, "Hello from user");
                assert_eq!(message_id, "msg-001");
                // request_id should be a valid UUID
                assert!(uuid::Uuid::parse_str(&request_id).is_ok());
            }
            _ => panic!("expected IncomingMessage"),
        }

        client.await.unwrap();
    }

    #[tokio::test]
    async fn test_adapter_send_and_recv() {
        let dir = tempfile::TempDir::new().unwrap();
        let sock_path = dir.path().join("test.sock");

        let listener = fugue_core::ipc::create_listener(&sock_path).await.unwrap();

        let sock_path_clone = sock_path.clone();
        let client = tokio::spawn(async move {
            let mut conn = AdapterConnection::connect(
                &sock_path_clone,
                "adapter".to_string(),
                "cli".to_string(),
            )
            .await
            .unwrap();

            // Send a ping
            conn.send(&IpcMessage::Ping).await.unwrap();

            // Receive pong
            let msg = conn.recv().await.unwrap();
            assert!(matches!(msg, IpcMessage::Pong));
        });

        let (mut stream, _) = listener.accept().await.unwrap();
        let msg = ipc::read_message(&mut stream).await.unwrap();
        assert!(matches!(msg, IpcMessage::Ping));

        ipc::write_message(&mut stream, &IpcMessage::Pong)
            .await
            .unwrap();

        client.await.unwrap();
    }

    #[tokio::test]
    async fn test_adapter_connect_nonexistent_socket() {
        let result = AdapterConnection::connect(
            std::path::Path::new("/nonexistent/socket.sock"),
            "adapter".to_string(),
            "cli".to_string(),
        )
        .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_handshake_state_variants() {
        let disconnected = HandshakeState::Disconnected;
        let connecting = HandshakeState::Connecting;
        let waiting = HandshakeState::WaitingForAck;
        let connected = HandshakeState::Connected {
            session_id: "sess-1".to_string(),
        };
        let failed = HandshakeState::Failed {
            reason: "test".to_string(),
        };

        assert_eq!(disconnected, HandshakeState::Disconnected);
        assert_eq!(connecting, HandshakeState::Connecting);
        assert_eq!(waiting, HandshakeState::WaitingForAck);
        assert_ne!(disconnected, connecting);
        assert_ne!(connected, failed);
    }

    #[test]
    fn test_is_allowed_with_single_entry() {
        let allowlist = vec!["only-me".to_string()];
        assert!(is_allowed("only-me", &allowlist));
        assert!(!is_allowed("not-me", &allowlist));
    }

    #[test]
    fn test_is_allowed_empty_sender_id() {
        assert!(is_allowed("", &[]));
        assert!(!is_allowed("", &["user1".to_string()]));
        assert!(is_allowed("", &["".to_string()]));
    }
}

#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::error::{FugueError, Result};

/// Maximum frame size: 16 MiB
const MAX_FRAME_SIZE: u32 = 16 * 1024 * 1024;

/// IPC message types between core and adapters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcMessage {
    /// Adapter registers itself with the core
    Register {
        adapter_name: String,
        adapter_type: String,
    },

    /// Acknowledgment of registration
    RegisterAck { session_id: String },

    /// Incoming message from a channel
    IncomingMessage {
        channel: String,
        sender_id: String,
        sender_name: Option<String>,
        content: String,
        message_id: String,
        /// Unique request ID for end-to-end tracing and correlation
        request_id: String,
    },

    /// Outgoing message to a channel
    OutgoingMessage {
        channel: String,
        recipient_id: String,
        content: String,
        reply_to: Option<String>,
        /// Unique request ID for end-to-end tracing and correlation
        request_id: String,
    },

    /// Request to invoke an LLM provider
    LlmRequest {
        provider: String,
        messages: Vec<ChatMessage>,
        request_id: String,
    },

    /// LLM response
    LlmResponse {
        request_id: String,
        content: String,
    },

    /// Error response
    Error {
        request_id: Option<String>,
        message: String,
    },

    /// Heartbeat
    Ping,

    /// Heartbeat response
    Pong,

    /// Shutdown signal
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

/// Encode a message as a length-prefixed MessagePack frame
pub fn encode_frame(msg: &IpcMessage) -> Result<Vec<u8>> {
    let payload = rmp_serde::to_vec(msg)
        .map_err(|e| FugueError::Ipc(format!("failed to encode message: {}", e)))?;

    let len = payload.len() as u32;
    if len > MAX_FRAME_SIZE {
        return Err(FugueError::Ipc(format!(
            "frame too large: {} bytes (max {})",
            len, MAX_FRAME_SIZE
        )));
    }

    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Decode a length-prefixed MessagePack frame
pub fn decode_frame(data: &[u8]) -> Result<(IpcMessage, usize)> {
    if data.len() < 4 {
        return Err(FugueError::Ipc("incomplete frame header".to_string()));
    }

    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if len > MAX_FRAME_SIZE {
        return Err(FugueError::Ipc(format!(
            "frame too large: {} bytes (max {})",
            len, MAX_FRAME_SIZE
        )));
    }

    let total_len = 4 + len as usize;
    if data.len() < total_len {
        return Err(FugueError::Ipc("incomplete frame payload".to_string()));
    }

    let msg: IpcMessage = rmp_serde::from_slice(&data[4..total_len])
        .map_err(|e| FugueError::Ipc(format!("failed to decode message: {}", e)))?;

    Ok((msg, total_len))
}

/// Write a message to an async stream
pub async fn write_message(stream: &mut UnixStream, msg: &IpcMessage) -> Result<()> {
    let frame = encode_frame(msg)?;
    stream.write_all(&frame).await?;
    stream.flush().await?;
    Ok(())
}

/// Read a message from an async stream
pub async fn read_message(stream: &mut UnixStream) -> Result<IpcMessage> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;

    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_SIZE {
        return Err(FugueError::Ipc(format!(
            "frame too large: {} bytes (max {})",
            len, MAX_FRAME_SIZE
        )));
    }

    let mut payload = vec![0u8; len as usize];
    stream.read_exact(&mut payload).await?;

    let msg: IpcMessage = rmp_serde::from_slice(&payload)
        .map_err(|e| FugueError::Ipc(format!("failed to decode message: {}", e)))?;

    Ok(msg)
}

/// Create a Unix socket listener, removing stale socket file if needed
pub async fn create_listener(path: &std::path::Path) -> Result<UnixListener> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Remove stale socket file
    if path.exists() {
        std::fs::remove_file(path)?;
    }

    let listener = UnixListener::bind(path)?;
    tracing::info!("IPC listener bound to {}", path.display());
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let msg = IpcMessage::Register {
            adapter_name: "telegram".to_string(),
            adapter_type: "telegram".to_string(),
        };

        let frame = encode_frame(&msg).unwrap();
        let (decoded, consumed) = decode_frame(&frame).unwrap();
        assert_eq!(consumed, frame.len());

        match decoded {
            IpcMessage::Register {
                adapter_name,
                adapter_type,
            } => {
                assert_eq!(adapter_name, "telegram");
                assert_eq!(adapter_type, "telegram");
            }
            _ => panic!("unexpected message type"),
        }
    }

    #[test]
    fn test_encode_decode_incoming_message() {
        let msg = IpcMessage::IncomingMessage {
            channel: "telegram".to_string(),
            sender_id: "12345".to_string(),
            sender_name: Some("Alice".to_string()),
            content: "Hello, world!".to_string(),
            message_id: "msg-001".to_string(),
            request_id: "req-incoming-001".to_string(),
        };

        let frame = encode_frame(&msg).unwrap();
        let (decoded, _) = decode_frame(&frame).unwrap();

        match decoded {
            IpcMessage::IncomingMessage {
                channel,
                sender_id,
                sender_name,
                content,
                message_id,
                request_id,
            } => {
                assert_eq!(channel, "telegram");
                assert_eq!(sender_id, "12345");
                assert_eq!(sender_name, Some("Alice".to_string()));
                assert_eq!(content, "Hello, world!");
                assert_eq!(message_id, "msg-001");
                assert_eq!(request_id, "req-incoming-001");
            }
            _ => panic!("unexpected message type"),
        }
    }

    #[test]
    fn test_encode_decode_ping_pong() {
        let ping = encode_frame(&IpcMessage::Ping).unwrap();
        let (decoded, _) = decode_frame(&ping).unwrap();
        assert!(matches!(decoded, IpcMessage::Ping));

        let pong = encode_frame(&IpcMessage::Pong).unwrap();
        let (decoded, _) = decode_frame(&pong).unwrap();
        assert!(matches!(decoded, IpcMessage::Pong));
    }

    #[test]
    fn test_incomplete_header() {
        let result = decode_frame(&[0, 0]);
        assert!(result.is_err());
    }

    #[test]
    fn test_incomplete_payload() {
        let msg = IpcMessage::Ping;
        let frame = encode_frame(&msg).unwrap();
        // Truncate the frame
        let result = decode_frame(&frame[..frame.len() - 1]);
        assert!(result.is_err());
    }

    #[test]
    fn test_frame_too_large() {
        // Craft a header claiming a huge payload
        let len = (MAX_FRAME_SIZE + 1).to_be_bytes();
        let result = decode_frame(&len);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("too large"));
    }

    #[test]
    fn test_llm_request_roundtrip() {
        let msg = IpcMessage::LlmRequest {
            provider: "ollama".to_string(),
            messages: vec![
                ChatMessage {
                    role: "system".to_string(),
                    content: "You are a helpful assistant.".to_string(),
                },
                ChatMessage {
                    role: "user".to_string(),
                    content: "Hello!".to_string(),
                },
            ],
            request_id: "req-001".to_string(),
        };

        let frame = encode_frame(&msg).unwrap();
        let (decoded, _) = decode_frame(&frame).unwrap();

        match decoded {
            IpcMessage::LlmRequest {
                provider,
                messages,
                request_id,
            } => {
                assert_eq!(provider, "ollama");
                assert_eq!(messages.len(), 2);
                assert_eq!(request_id, "req-001");
            }
            _ => panic!("unexpected message type"),
        }
    }

    #[tokio::test]
    async fn test_async_read_write() {
        let dir = tempfile::TempDir::new().unwrap();
        let sock_path = dir.path().join("test.sock");

        let listener = create_listener(&sock_path).await.unwrap();

        let sock_path_clone = sock_path.clone();
        let writer = tokio::spawn(async move {
            let mut stream = UnixStream::connect(&sock_path_clone).await.unwrap();
            let msg = IpcMessage::Register {
                adapter_name: "test".to_string(),
                adapter_type: "cli".to_string(),
            };
            write_message(&mut stream, &msg).await.unwrap();
        });

        let (mut stream, _addr) = listener.accept().await.unwrap();
        let msg = read_message(&mut stream).await.unwrap();
        writer.await.unwrap();

        match msg {
            IpcMessage::Register {
                adapter_name,
                adapter_type,
            } => {
                assert_eq!(adapter_name, "test");
                assert_eq!(adapter_type, "cli");
            }
            _ => panic!("unexpected message type"),
        }
    }
}

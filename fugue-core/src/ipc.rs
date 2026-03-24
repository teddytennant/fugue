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
    LlmResponse { request_id: String, content: String },

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

    let len = u32::try_from(payload.len()).map_err(|_| {
        FugueError::Ipc(format!(
            "frame too large: {} bytes (max {})",
            payload.len(),
            MAX_FRAME_SIZE
        ))
    })?;
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

/// Write a message to any async writer (works with split stream halves).
pub async fn write_to<W: AsyncWriteExt + Unpin>(writer: &mut W, msg: &IpcMessage) -> Result<()> {
    let frame = encode_frame(msg)?;
    writer.write_all(&frame).await?;
    writer.flush().await?;
    Ok(())
}

/// Read a message from any async reader (works with split stream halves).
pub async fn read_from<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<IpcMessage> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;

    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_SIZE {
        return Err(FugueError::Ipc(format!(
            "frame too large: {} bytes (max {})",
            len, MAX_FRAME_SIZE
        )));
    }

    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await?;

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

    #[test]
    fn test_encode_decode_outgoing_message() {
        let msg = IpcMessage::OutgoingMessage {
            channel: "telegram".to_string(),
            recipient_id: "user-456".to_string(),
            content: "Hello back!".to_string(),
            reply_to: Some("msg-001".to_string()),
            request_id: "req-out-001".to_string(),
        };

        let frame = encode_frame(&msg).unwrap();
        let (decoded, consumed) = decode_frame(&frame).unwrap();
        assert_eq!(consumed, frame.len());

        match decoded {
            IpcMessage::OutgoingMessage {
                channel,
                recipient_id,
                content,
                reply_to,
                request_id,
            } => {
                assert_eq!(channel, "telegram");
                assert_eq!(recipient_id, "user-456");
                assert_eq!(content, "Hello back!");
                assert_eq!(reply_to, Some("msg-001".to_string()));
                assert_eq!(request_id, "req-out-001");
            }
            _ => panic!("unexpected message type"),
        }
    }

    #[test]
    fn test_encode_decode_outgoing_message_no_reply() {
        let msg = IpcMessage::OutgoingMessage {
            channel: "cli".to_string(),
            recipient_id: "user".to_string(),
            content: "Hi".to_string(),
            reply_to: None,
            request_id: "req-002".to_string(),
        };

        let frame = encode_frame(&msg).unwrap();
        let (decoded, _) = decode_frame(&frame).unwrap();

        match decoded {
            IpcMessage::OutgoingMessage { reply_to, .. } => {
                assert_eq!(reply_to, None);
            }
            _ => panic!("unexpected message type"),
        }
    }

    #[test]
    fn test_encode_decode_llm_response() {
        let msg = IpcMessage::LlmResponse {
            request_id: "req-llm-001".to_string(),
            content: "The answer is 42.".to_string(),
        };

        let frame = encode_frame(&msg).unwrap();
        let (decoded, _) = decode_frame(&frame).unwrap();

        match decoded {
            IpcMessage::LlmResponse {
                request_id,
                content,
            } => {
                assert_eq!(request_id, "req-llm-001");
                assert_eq!(content, "The answer is 42.");
            }
            _ => panic!("unexpected message type"),
        }
    }

    #[test]
    fn test_encode_decode_error_with_request_id() {
        let msg = IpcMessage::Error {
            request_id: Some("req-err-001".to_string()),
            message: "something went wrong".to_string(),
        };

        let frame = encode_frame(&msg).unwrap();
        let (decoded, _) = decode_frame(&frame).unwrap();

        match decoded {
            IpcMessage::Error {
                request_id,
                message,
            } => {
                assert_eq!(request_id, Some("req-err-001".to_string()));
                assert_eq!(message, "something went wrong");
            }
            _ => panic!("unexpected message type"),
        }
    }

    #[test]
    fn test_encode_decode_error_without_request_id() {
        let msg = IpcMessage::Error {
            request_id: None,
            message: "general error".to_string(),
        };

        let frame = encode_frame(&msg).unwrap();
        let (decoded, _) = decode_frame(&frame).unwrap();

        match decoded {
            IpcMessage::Error {
                request_id,
                message,
            } => {
                assert_eq!(request_id, None);
                assert_eq!(message, "general error");
            }
            _ => panic!("unexpected message type"),
        }
    }

    #[test]
    fn test_encode_decode_register_ack() {
        let msg = IpcMessage::RegisterAck {
            session_id: "sess-abc-123".to_string(),
        };

        let frame = encode_frame(&msg).unwrap();
        let (decoded, _) = decode_frame(&frame).unwrap();

        match decoded {
            IpcMessage::RegisterAck { session_id } => {
                assert_eq!(session_id, "sess-abc-123");
            }
            _ => panic!("unexpected message type"),
        }
    }

    #[test]
    fn test_encode_decode_shutdown() {
        let msg = IpcMessage::Shutdown;
        let frame = encode_frame(&msg).unwrap();
        let (decoded, _) = decode_frame(&frame).unwrap();
        assert!(matches!(decoded, IpcMessage::Shutdown));
    }

    #[test]
    fn test_encode_decode_incoming_no_sender_name() {
        let msg = IpcMessage::IncomingMessage {
            channel: "cli".to_string(),
            sender_id: "anon".to_string(),
            sender_name: None,
            content: "anonymous message".to_string(),
            message_id: "msg-anon".to_string(),
            request_id: "req-anon".to_string(),
        };

        let frame = encode_frame(&msg).unwrap();
        let (decoded, _) = decode_frame(&frame).unwrap();

        match decoded {
            IpcMessage::IncomingMessage { sender_name, .. } => {
                assert_eq!(sender_name, None);
            }
            _ => panic!("unexpected message type"),
        }
    }

    #[test]
    fn test_decode_frame_empty_input() {
        let result = decode_frame(&[]);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("incomplete frame header"));
    }

    #[test]
    fn test_decode_frame_exactly_four_bytes_zero_length() {
        // A frame with length 0 should try to decode an empty msgpack payload
        let data = [0u8, 0, 0, 0];
        let result = decode_frame(&data);
        // Zero-length payload is not valid msgpack
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_frames_in_buffer() {
        let msg1 = IpcMessage::Ping;
        let msg2 = IpcMessage::Pong;

        let frame1 = encode_frame(&msg1).unwrap();
        let frame2 = encode_frame(&msg2).unwrap();

        let mut buffer = Vec::new();
        buffer.extend_from_slice(&frame1);
        buffer.extend_from_slice(&frame2);

        let (decoded1, consumed1) = decode_frame(&buffer).unwrap();
        assert!(matches!(decoded1, IpcMessage::Ping));

        let (decoded2, consumed2) = decode_frame(&buffer[consumed1..]).unwrap();
        assert!(matches!(decoded2, IpcMessage::Pong));
        assert_eq!(consumed1 + consumed2, buffer.len());
    }

    #[test]
    fn test_encode_decode_unicode_content() {
        let msg = IpcMessage::IncomingMessage {
            channel: "cli".to_string(),
            sender_id: "user".to_string(),
            sender_name: Some("\u{1F600}".to_string()),
            content: "\u{4F60}\u{597D}\u{4E16}\u{754C}".to_string(),
            message_id: "msg-unicode".to_string(),
            request_id: "req-unicode".to_string(),
        };

        let frame = encode_frame(&msg).unwrap();
        let (decoded, _) = decode_frame(&frame).unwrap();

        match decoded {
            IpcMessage::IncomingMessage {
                sender_name,
                content,
                ..
            } => {
                assert_eq!(sender_name, Some("\u{1F600}".to_string()));
                assert_eq!(content, "\u{4F60}\u{597D}\u{4E16}\u{754C}");
            }
            _ => panic!("unexpected message type"),
        }
    }

    #[tokio::test]
    async fn test_async_multiple_messages() {
        let dir = tempfile::TempDir::new().unwrap();
        let sock_path = dir.path().join("test.sock");

        let listener = create_listener(&sock_path).await.unwrap();

        let sock_path_clone = sock_path.clone();
        let writer = tokio::spawn(async move {
            let mut stream = UnixStream::connect(&sock_path_clone).await.unwrap();
            write_message(&mut stream, &IpcMessage::Ping).await.unwrap();
            write_message(&mut stream, &IpcMessage::Pong).await.unwrap();
            write_message(&mut stream, &IpcMessage::Shutdown)
                .await
                .unwrap();
        });

        let (mut stream, _) = listener.accept().await.unwrap();

        let msg1 = read_message(&mut stream).await.unwrap();
        assert!(matches!(msg1, IpcMessage::Ping));

        let msg2 = read_message(&mut stream).await.unwrap();
        assert!(matches!(msg2, IpcMessage::Pong));

        let msg3 = read_message(&mut stream).await.unwrap();
        assert!(matches!(msg3, IpcMessage::Shutdown));

        writer.await.unwrap();
    }

    #[tokio::test]
    async fn test_create_listener_removes_stale_socket() {
        let dir = tempfile::TempDir::new().unwrap();
        let sock_path = dir.path().join("test.sock");

        // Create a stale socket file
        std::fs::write(&sock_path, "stale").unwrap();

        // Should succeed by removing the stale file
        let _listener = create_listener(&sock_path).await.unwrap();
    }

    #[tokio::test]
    async fn test_create_listener_creates_parent_dirs() {
        let dir = tempfile::TempDir::new().unwrap();
        let sock_path = dir.path().join("subdir").join("nested").join("test.sock");

        let _listener = create_listener(&sock_path).await.unwrap();
        assert!(sock_path.exists());
    }
}

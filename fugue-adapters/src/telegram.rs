#![deny(unsafe_code)]

//! Telegram Bot API adapter for fugue.
//!
//! Connects to the fugue daemon via Unix socket IPC and bridges messages
//! between Telegram chats and the LLM pipeline.

use crate::protocol::{is_allowed, AdapterConnection};
use fugue_core::ipc::{self, IpcMessage};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing;

/// Telegram Bot API base URL
const TELEGRAM_API_BASE: &str = "https://api.telegram.org";

/// Long-poll timeout in seconds (Telegram recommends 30)
const POLL_TIMEOUT_SECS: u64 = 30;

/// Maximum message length Telegram accepts (4096 chars)
const MAX_MESSAGE_LENGTH: usize = 4096;

/// Telegram adapter that bridges between the Bot API and fugue daemon
pub struct TelegramAdapter {
    bot_token: String,
    client: reqwest::Client,
    allowed_ids: Vec<String>,
}

// --- Telegram Bot API types ---

#[derive(Debug, Deserialize)]
struct TelegramResponse<T> {
    ok: bool,
    result: Option<T>,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Update {
    pub update_id: i64,
    pub message: Option<Message>,
}

#[derive(Debug, Deserialize)]
pub struct Message {
    pub message_id: i64,
    pub from: Option<User>,
    pub chat: Chat,
    pub text: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct User {
    pub id: i64,
    pub first_name: String,
    pub last_name: Option<String>,
    pub username: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Chat {
    pub id: i64,
    #[serde(rename = "type")]
    pub chat_type: String,
}

#[derive(Debug, Serialize)]
struct SendMessageRequest<'a> {
    chat_id: i64,
    text: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reply_to_message_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parse_mode: Option<&'a str>,
}

impl TelegramAdapter {
    pub fn new(bot_token: String, allowed_ids: Vec<String>) -> Self {
        Self {
            bot_token,
            client: reqwest::Client::new(),
            allowed_ids,
        }
    }

    fn api_url(&self, method: &str) -> String {
        format!("{}/bot{}/{}", TELEGRAM_API_BASE, self.bot_token, method)
    }

    /// Poll for new updates from the Telegram Bot API using long-polling
    pub async fn poll_updates(&self, offset: i64) -> Result<Vec<Update>, AdapterError> {
        let url = self.api_url("getUpdates");
        let resp = self
            .client
            .get(&url)
            .query(&[
                ("offset", offset.to_string()),
                ("timeout", POLL_TIMEOUT_SECS.to_string()),
                ("allowed_updates", "[\"message\"]".to_string()),
            ])
            .send()
            .await
            .map_err(|e| AdapterError::Api(format!("getUpdates failed: {}", e)))?;

        let body: TelegramResponse<Vec<Update>> = resp
            .json()
            .await
            .map_err(|e| AdapterError::Api(format!("failed to parse updates: {}", e)))?;

        if !body.ok {
            return Err(AdapterError::Api(
                body.description
                    .unwrap_or_else(|| "unknown Telegram error".to_string()),
            ));
        }

        Ok(body.result.unwrap_or_default())
    }

    /// Send a text message via the Telegram Bot API
    pub async fn send_message(
        &self,
        chat_id: i64,
        text: &str,
        reply_to: Option<i64>,
    ) -> Result<(), AdapterError> {
        // Split long messages into chunks
        let chunks = split_message(text, MAX_MESSAGE_LENGTH);
        for chunk in &chunks {
            let body = SendMessageRequest {
                chat_id,
                text: chunk,
                reply_to_message_id: if chunk == chunks.first().unwrap_or(&"".to_string()) {
                    reply_to
                } else {
                    None
                },
                parse_mode: None,
            };

            let url = self.api_url("sendMessage");
            let resp = self
                .client
                .post(&url)
                .json(&body)
                .send()
                .await
                .map_err(|e| AdapterError::Api(format!("sendMessage failed: {}", e)))?;

            let result: TelegramResponse<serde_json::Value> = resp
                .json()
                .await
                .map_err(|e| AdapterError::Api(format!("failed to parse sendMessage: {}", e)))?;

            if !result.ok {
                return Err(AdapterError::Api(
                    result
                        .description
                        .unwrap_or_else(|| "sendMessage failed".to_string()),
                ));
            }
        }

        Ok(())
    }

    /// Run the Telegram adapter, connecting to the fugue daemon
    pub async fn run(&self, socket_path: &Path) -> Result<(), AdapterError> {
        // Connect to daemon
        let mut conn =
            AdapterConnection::connect(socket_path, "telegram".to_string(), "telegram".to_string())
                .await
                .map_err(|e| AdapterError::Connection(format!("failed to connect: {}", e)))?;

        let session_id = conn
            .handshake()
            .await
            .map_err(|e| AdapterError::Connection(format!("handshake failed: {}", e)))?;

        tracing::info!("telegram adapter connected (session: {})", session_id);

        // Split the underlying stream for bidirectional communication
        // We need to take ownership of the stream from the connection
        let stream = conn.into_stream();
        let (mut read_half, mut write_half) = stream.into_split();

        // Response handler — reads IPC responses and sends to Telegram
        let client = self.client.clone();
        let bot_token = self.bot_token.clone();
        let response_task = async move {
            loop {
                match ipc::read_from(&mut read_half).await {
                    Ok(IpcMessage::OutgoingMessage {
                        content,
                        recipient_id,
                        reply_to,
                        ..
                    }) => {
                        let chat_id: i64 = match recipient_id.parse() {
                            Ok(id) => id,
                            Err(_) => {
                                tracing::warn!("invalid chat_id: {}", recipient_id);
                                continue;
                            }
                        };

                        let reply_msg_id: Option<i64> =
                            reply_to.as_ref().and_then(|r| r.parse().ok());

                        let url = format!("{}/bot{}/sendMessage", TELEGRAM_API_BASE, bot_token);

                        let chunks = split_message(&content, MAX_MESSAGE_LENGTH);
                        for (i, chunk) in chunks.iter().enumerate() {
                            let body = serde_json::json!({
                                "chat_id": chat_id,
                                "text": chunk,
                                "reply_to_message_id": if i == 0 { reply_msg_id } else { None },
                            });

                            if let Err(e) = client.post(&url).json(&body).send().await {
                                tracing::error!("failed to send Telegram message: {}", e);
                            }
                        }
                    }
                    Ok(IpcMessage::Shutdown) => {
                        tracing::info!("shutdown signal received");
                        break;
                    }
                    Ok(_) => {} // Ignore other message types
                    Err(e) => {
                        tracing::debug!("IPC read error: {}", e);
                        break;
                    }
                }
            }
        };

        // Poll loop — fetch updates from Telegram and forward to daemon
        let poll_task = async {
            let mut offset: i64 = 0;
            loop {
                match self.poll_updates(offset).await {
                    Ok(updates) => {
                        for update in updates {
                            offset = update.update_id + 1;

                            let message = match update.message {
                                Some(m) => m,
                                None => continue,
                            };

                            let text = match message.text {
                                Some(t) => t,
                                None => continue, // Skip non-text messages
                            };

                            let sender_id = message.chat.id.to_string();

                            // Check allowlist
                            if !is_allowed(&sender_id, &self.allowed_ids) {
                                tracing::debug!("message from {} blocked by allowlist", sender_id);
                                continue;
                            }

                            let sender_name = message.from.as_ref().map(|u| match &u.last_name {
                                Some(last) => format!("{} {}", u.first_name, last),
                                None => u.first_name.clone(),
                            });

                            let request_id = uuid::Uuid::new_v4().to_string();
                            let ipc_msg = IpcMessage::IncomingMessage {
                                channel: "telegram".to_string(),
                                sender_id: sender_id.clone(),
                                sender_name,
                                content: text,
                                message_id: message.message_id.to_string(),
                                request_id,
                            };

                            if let Err(e) = ipc::write_to(&mut write_half, &ipc_msg).await {
                                tracing::error!("failed to send message to daemon: {}", e);
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("poll error: {}", e);
                        // Back off on errors
                        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    }
                }
            }
        };

        // Run both tasks concurrently — if either exits, the adapter stops
        tokio::select! {
            _ = response_task => {
                tracing::info!("response handler exited");
            }
            _ = poll_task => {
                tracing::info!("poll loop exited");
            }
        }

        Ok(())
    }
}

/// Split a message into chunks that fit within Telegram's message length limit.
/// Splits on newline boundaries when possible, falls back to hard split.
pub fn split_message(text: &str, max_len: usize) -> Vec<String> {
    if text.len() <= max_len {
        return vec![text.to_string()];
    }

    let mut chunks = Vec::new();
    let mut remaining = text;

    while !remaining.is_empty() {
        if remaining.len() <= max_len {
            chunks.push(remaining.to_string());
            break;
        }

        // Try to split on a newline within the limit
        let split_at = remaining[..max_len]
            .rfind('\n')
            .map(|pos| pos + 1) // Include the newline
            .unwrap_or(max_len); // Hard split if no newline found

        chunks.push(remaining[..split_at].to_string());
        remaining = &remaining[split_at..];
    }

    chunks
}

/// Errors specific to the Telegram adapter
#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("API error: {0}")]
    Api(String),
    #[error("connection error: {0}")]
    Connection(String),
    #[error("IPC error: {0}")]
    Ipc(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_message_short() {
        let chunks = split_message("hello", 4096);
        assert_eq!(chunks, vec!["hello"]);
    }

    #[test]
    fn test_split_message_exact_limit() {
        let msg = "a".repeat(4096);
        let chunks = split_message(&msg, 4096);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].len(), 4096);
    }

    #[test]
    fn test_split_message_over_limit() {
        let msg = "a".repeat(5000);
        let chunks = split_message(&msg, 4096);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].len(), 4096);
        assert_eq!(chunks[1].len(), 904);
    }

    #[test]
    fn test_split_message_on_newline() {
        let msg = format!("{}\n{}", "a".repeat(2000), "b".repeat(3000));
        let chunks = split_message(&msg, 4096);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0], format!("{}\n", "a".repeat(2000)));
        assert_eq!(chunks[1], "b".repeat(3000));
    }

    #[test]
    fn test_split_message_empty() {
        let chunks = split_message("", 4096);
        assert_eq!(chunks, vec![""]);
    }

    #[test]
    fn test_split_message_multiple_chunks() {
        let msg = "a".repeat(10000);
        let chunks = split_message(&msg, 4096);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].len(), 4096);
        assert_eq!(chunks[1].len(), 4096);
        assert_eq!(chunks[2].len(), 1808);
    }

    #[test]
    fn test_api_url() {
        let adapter = TelegramAdapter::new("123:ABC".to_string(), vec![]);
        assert_eq!(
            adapter.api_url("getUpdates"),
            "https://api.telegram.org/bot123:ABC/getUpdates"
        );
        assert_eq!(
            adapter.api_url("sendMessage"),
            "https://api.telegram.org/bot123:ABC/sendMessage"
        );
    }

    #[test]
    fn test_adapter_error_display() {
        let e = AdapterError::Api("bad request".to_string());
        assert_eq!(e.to_string(), "API error: bad request");

        let e = AdapterError::Connection("refused".to_string());
        assert_eq!(e.to_string(), "connection error: refused");

        let e = AdapterError::Ipc("broken pipe".to_string());
        assert_eq!(e.to_string(), "IPC error: broken pipe");
    }

    #[test]
    fn test_update_deserialization() {
        let json = r#"{
            "update_id": 123456,
            "message": {
                "message_id": 789,
                "from": {
                    "id": 42,
                    "first_name": "Test",
                    "last_name": "User",
                    "username": "testuser"
                },
                "chat": {
                    "id": 42,
                    "type": "private"
                },
                "text": "Hello bot!"
            }
        }"#;

        let update: Update = serde_json::from_str(json).unwrap();
        assert_eq!(update.update_id, 123456);

        let msg = update.message.unwrap();
        assert_eq!(msg.message_id, 789);
        assert_eq!(msg.text.unwrap(), "Hello bot!");
        assert_eq!(msg.chat.id, 42);
        assert_eq!(msg.chat.chat_type, "private");

        let from = msg.from.unwrap();
        assert_eq!(from.id, 42);
        assert_eq!(from.first_name, "Test");
        assert_eq!(from.last_name, Some("User".to_string()));
        assert_eq!(from.username, Some("testuser".to_string()));
    }

    #[test]
    fn test_update_without_message() {
        let json = r#"{"update_id": 100}"#;
        let update: Update = serde_json::from_str(json).unwrap();
        assert_eq!(update.update_id, 100);
        assert!(update.message.is_none());
    }

    #[test]
    fn test_message_without_text() {
        let json = r#"{
            "update_id": 100,
            "message": {
                "message_id": 1,
                "chat": {"id": 1, "type": "private"}
            }
        }"#;
        let update: Update = serde_json::from_str(json).unwrap();
        let msg = update.message.unwrap();
        assert!(msg.text.is_none());
        assert!(msg.from.is_none());
    }

    #[test]
    fn test_message_without_from() {
        let json = r#"{
            "update_id": 100,
            "message": {
                "message_id": 1,
                "chat": {"id": 1, "type": "group"},
                "text": "channel post"
            }
        }"#;
        let update: Update = serde_json::from_str(json).unwrap();
        let msg = update.message.unwrap();
        assert!(msg.from.is_none());
        assert_eq!(msg.text.unwrap(), "channel post");
    }

    #[test]
    fn test_telegram_response_ok() {
        let json = r#"{"ok": true, "result": [{"update_id": 1}]}"#;
        let resp: TelegramResponse<Vec<Update>> = serde_json::from_str(json).unwrap();
        assert!(resp.ok);
        assert_eq!(resp.result.unwrap().len(), 1);
    }

    #[test]
    fn test_telegram_response_error() {
        let json = r#"{"ok": false, "description": "Unauthorized"}"#;
        let resp: TelegramResponse<Vec<Update>> = serde_json::from_str(json).unwrap();
        assert!(!resp.ok);
        assert_eq!(resp.description.unwrap(), "Unauthorized");
        assert!(resp.result.is_none());
    }

    #[test]
    fn test_send_message_serialization() {
        let req = SendMessageRequest {
            chat_id: 123,
            text: "hello",
            reply_to_message_id: Some(456),
            parse_mode: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["chat_id"], 123);
        assert_eq!(json["text"], "hello");
        assert_eq!(json["reply_to_message_id"], 456);
        assert!(json.get("parse_mode").is_none()); // skip_serializing_if
    }

    #[test]
    fn test_send_message_no_reply() {
        let req = SendMessageRequest {
            chat_id: 123,
            text: "hello",
            reply_to_message_id: None,
            parse_mode: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert!(json.get("reply_to_message_id").is_none());
    }

    #[test]
    fn test_user_display_name_full() {
        let user = User {
            id: 1,
            first_name: "John".to_string(),
            last_name: Some("Doe".to_string()),
            username: Some("johndoe".to_string()),
        };
        let name = match &user.last_name {
            Some(last) => format!("{} {}", user.first_name, last),
            None => user.first_name.clone(),
        };
        assert_eq!(name, "John Doe");
    }

    #[test]
    fn test_user_display_name_first_only() {
        let user = User {
            id: 1,
            first_name: "Alice".to_string(),
            last_name: None,
            username: None,
        };
        let name = match &user.last_name {
            Some(last) => format!("{} {}", user.first_name, last),
            None => user.first_name.clone(),
        };
        assert_eq!(name, "Alice");
    }

    #[test]
    fn test_split_message_preserves_newlines_in_short() {
        let msg = "line1\nline2\nline3";
        let chunks = split_message(msg, 4096);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], msg);
    }

    #[test]
    fn test_adapter_new() {
        let adapter = TelegramAdapter::new(
            "123:TOKEN".to_string(),
            vec!["111".to_string(), "222".to_string()],
        );
        assert_eq!(adapter.bot_token, "123:TOKEN");
        assert_eq!(adapter.allowed_ids.len(), 2);
    }

    #[test]
    fn test_adapter_new_empty_allowlist() {
        let adapter = TelegramAdapter::new("token".to_string(), vec![]);
        assert!(adapter.allowed_ids.is_empty());
    }

    #[test]
    fn test_update_batch_deserialization() {
        let json = r#"[
            {"update_id": 1, "message": {"message_id": 1, "chat": {"id": 1, "type": "private"}, "text": "hello"}},
            {"update_id": 2, "message": {"message_id": 2, "chat": {"id": 1, "type": "private"}, "text": "world"}},
            {"update_id": 3}
        ]"#;
        let updates: Vec<Update> = serde_json::from_str(json).unwrap();
        assert_eq!(updates.len(), 3);
        assert_eq!(
            updates[0].message.as_ref().unwrap().text.as_ref().unwrap(),
            "hello"
        );
        assert_eq!(
            updates[1].message.as_ref().unwrap().text.as_ref().unwrap(),
            "world"
        );
        assert!(updates[2].message.is_none());
    }

    #[test]
    fn test_telegram_response_empty_result() {
        let json = r#"{"ok": true, "result": []}"#;
        let resp: TelegramResponse<Vec<Update>> = serde_json::from_str(json).unwrap();
        assert!(resp.ok);
        assert!(resp.result.unwrap().is_empty());
    }

    #[test]
    fn test_chat_types() {
        for chat_type in &["private", "group", "supergroup", "channel"] {
            let json = format!(r#"{{"id": 1, "type": "{}"}}"#, chat_type);
            let chat: Chat = serde_json::from_str(&json).unwrap();
            assert_eq!(chat.chat_type, *chat_type);
        }
    }

    #[test]
    fn test_split_message_unicode() {
        // Unicode characters should not be split mid-character
        let msg = "\u{1F600}".repeat(2000); // 2000 emoji = 8000 bytes
        let chunks = split_message(&msg, 4096);
        assert!(chunks.len() >= 1);
        // Every chunk should be valid UTF-8 (would panic on construction if not)
        for chunk in &chunks {
            assert!(!chunk.is_empty());
        }
    }

    #[tokio::test]
    async fn test_adapter_connect_to_daemon() {
        // Test that the adapter can connect to a daemon and exchange messages
        let dir = tempfile::TempDir::new().unwrap();
        let sock_path = dir.path().join("test.sock");

        let listener = fugue_core::ipc::create_listener(&sock_path).await.unwrap();

        let sock_clone = sock_path.clone();
        let client = tokio::spawn(async move {
            let mut conn = crate::protocol::AdapterConnection::connect(
                &sock_clone,
                "telegram".to_string(),
                "telegram".to_string(),
            )
            .await
            .unwrap();

            let session = conn.handshake().await.unwrap();
            assert!(!session.is_empty());

            // Send a message that would come from Telegram
            conn.send_incoming(
                "12345".to_string(),
                Some("Test User".to_string()),
                "Hello from Telegram".to_string(),
                "msg-1".to_string(),
            )
            .await
            .unwrap();
        });

        // Server side
        let (mut stream, _) = listener.accept().await.unwrap();
        let msg = fugue_core::ipc::read_message(&mut stream).await.unwrap();
        match msg {
            IpcMessage::Register {
                adapter_name,
                adapter_type,
            } => {
                assert_eq!(adapter_name, "telegram");
                assert_eq!(adapter_type, "telegram");
            }
            _ => panic!("expected Register"),
        }

        fugue_core::ipc::write_message(
            &mut stream,
            &IpcMessage::RegisterAck {
                session_id: "sess-tg".to_string(),
            },
        )
        .await
        .unwrap();

        // Read the incoming message
        let msg = fugue_core::ipc::read_message(&mut stream).await.unwrap();
        match msg {
            IpcMessage::IncomingMessage {
                channel,
                sender_id,
                sender_name,
                content,
                ..
            } => {
                assert_eq!(channel, "telegram");
                assert_eq!(sender_id, "12345");
                assert_eq!(sender_name, Some("Test User".to_string()));
                assert_eq!(content, "Hello from Telegram");
            }
            _ => panic!("expected IncomingMessage"),
        }

        client.await.unwrap();
    }
}

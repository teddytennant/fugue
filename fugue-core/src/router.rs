#![deny(unsafe_code)]

use std::collections::HashMap;
use tokio::sync::mpsc;

use crate::error::{FugueError, Result};
use crate::ipc::{ChatMessage, IpcMessage};

/// A routable message within the system
#[derive(Debug, Clone)]
pub struct RoutableMessage {
    pub channel: String,
    pub sender_id: String,
    pub sender_name: Option<String>,
    pub content: String,
    pub message_id: String,
    /// Unique request ID for end-to-end tracing and correlation
    pub request_id: String,
}

/// Response to be sent back through a channel
#[derive(Debug, Clone)]
pub struct RouteResponse {
    pub channel: String,
    pub recipient_id: String,
    pub content: String,
    pub reply_to: Option<String>,
    /// Unique request ID for end-to-end tracing and correlation
    pub request_id: String,
}

/// Channel handle for sending responses back to adapters
pub struct ChannelHandle {
    pub name: String,
    pub sender: mpsc::Sender<RouteResponse>,
}

/// Core message router
pub struct Router {
    channels: HashMap<String, mpsc::Sender<RouteResponse>>,
    message_tx: mpsc::Sender<RoutableMessage>,
    message_rx: Option<mpsc::Receiver<RoutableMessage>>,
    system_prompt: Option<String>,
}

impl Router {
    pub fn new(buffer_size: usize) -> Self {
        let (message_tx, message_rx) = mpsc::channel(buffer_size);
        Self {
            channels: HashMap::new(),
            message_tx,
            message_rx: Some(message_rx),
            system_prompt: None,
        }
    }

    pub fn set_system_prompt(&mut self, prompt: String) {
        self.system_prompt = Some(prompt);
    }

    pub fn system_prompt(&self) -> Option<&str> {
        self.system_prompt.as_deref()
    }

    /// Register a channel adapter
    pub fn register_channel(
        &mut self,
        name: String,
        response_sender: mpsc::Sender<RouteResponse>,
    ) {
        tracing::info!("registered channel: {}", name);
        self.channels.insert(name, response_sender);
    }

    /// Unregister a channel adapter
    pub fn unregister_channel(&mut self, name: &str) -> bool {
        let removed = self.channels.remove(name).is_some();
        if removed {
            tracing::info!("unregistered channel: {}", name);
        }
        removed
    }

    /// Get the sender for routing incoming messages to the core
    pub fn incoming_sender(&self) -> mpsc::Sender<RoutableMessage> {
        self.message_tx.clone()
    }

    /// Take the receiver for processing incoming messages
    pub fn take_receiver(&mut self) -> Option<mpsc::Receiver<RoutableMessage>> {
        self.message_rx.take()
    }

    /// Route a response to the appropriate channel
    pub async fn send_response(&self, response: RouteResponse) -> Result<()> {
        let sender = self.channels.get(&response.channel).ok_or_else(|| {
            FugueError::Router(format!("channel '{}' not registered", response.channel))
        })?;

        sender.send(response).await.map_err(|e| {
            FugueError::Router(format!("failed to send response: {}", e))
        })?;

        Ok(())
    }

    /// List registered channel names
    pub fn list_channels(&self) -> Vec<&str> {
        self.channels.keys().map(|s| s.as_str()).collect()
    }

    /// Check if a channel is registered
    pub fn has_channel(&self, name: &str) -> bool {
        self.channels.contains_key(name)
    }

    /// Build the message list for an LLM call, prepending system prompt if set
    pub fn build_llm_messages(&self, history: &[ChatMessage]) -> Vec<ChatMessage> {
        let mut messages = Vec::new();

        if let Some(ref system) = self.system_prompt {
            messages.push(ChatMessage {
                role: "system".to_string(),
                content: system.clone(),
            });
        }

        messages.extend_from_slice(history);
        messages
    }

    /// Convert an IPC incoming message to a routable message
    pub fn ipc_to_routable(msg: &IpcMessage) -> Option<RoutableMessage> {
        match msg {
            IpcMessage::IncomingMessage {
                channel,
                sender_id,
                sender_name,
                content,
                message_id,
                request_id,
            } => Some(RoutableMessage {
                channel: channel.clone(),
                sender_id: sender_id.clone(),
                sender_name: sender_name.clone(),
                content: content.clone(),
                message_id: message_id.clone(),
                request_id: request_id.clone(),
            }),
            _ => None,
        }
    }

    /// Convert a route response to an IPC outgoing message
    pub fn response_to_ipc(response: &RouteResponse) -> IpcMessage {
        IpcMessage::OutgoingMessage {
            channel: response.channel.clone(),
            recipient_id: response.recipient_id.clone(),
            content: response.content.clone(),
            reply_to: response.reply_to.clone(),
            request_id: response.request_id.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_register_and_list_channels() {
        let mut router = Router::new(16);
        let (tx, _rx) = mpsc::channel(16);

        router.register_channel("cli".to_string(), tx.clone());
        router.register_channel("telegram".to_string(), tx);

        let channels = router.list_channels();
        assert!(channels.contains(&"cli"));
        assert!(channels.contains(&"telegram"));
        assert_eq!(channels.len(), 2);
    }

    #[tokio::test]
    async fn test_unregister_channel() {
        let mut router = Router::new(16);
        let (tx, _rx) = mpsc::channel(16);

        router.register_channel("cli".to_string(), tx);
        assert!(router.has_channel("cli"));

        let removed = router.unregister_channel("cli");
        assert!(removed);
        assert!(!router.has_channel("cli"));

        let removed_again = router.unregister_channel("cli");
        assert!(!removed_again);
    }

    #[tokio::test]
    async fn test_send_response() {
        let mut router = Router::new(16);
        let (tx, mut rx) = mpsc::channel(16);

        router.register_channel("cli".to_string(), tx);

        let response = RouteResponse {
            channel: "cli".to_string(),
            recipient_id: "user1".to_string(),
            content: "Hello!".to_string(),
            reply_to: None,
            request_id: "req-001".to_string(),
        };

        router.send_response(response).await.unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received.content, "Hello!");
        assert_eq!(received.recipient_id, "user1");
        assert_eq!(received.request_id, "req-001");
    }

    #[tokio::test]
    async fn test_send_response_unknown_channel() {
        let router = Router::new(16);

        let response = RouteResponse {
            channel: "nonexistent".to_string(),
            recipient_id: "user1".to_string(),
            content: "Hello!".to_string(),
            reply_to: None,
            request_id: "req-001".to_string(),
        };

        let result = router.send_response(response).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_incoming_message_routing() {
        let mut router = Router::new(16);
        let sender = router.incoming_sender();
        let mut receiver = router.take_receiver().unwrap();

        let msg = RoutableMessage {
            channel: "cli".to_string(),
            sender_id: "user1".to_string(),
            sender_name: Some("Alice".to_string()),
            content: "Hello!".to_string(),
            message_id: "msg-1".to_string(),
            request_id: "req-001".to_string(),
        };

        sender.send(msg).await.unwrap();

        let received = receiver.recv().await.unwrap();
        assert_eq!(received.content, "Hello!");
        assert_eq!(received.channel, "cli");
        assert_eq!(received.request_id, "req-001");
    }

    #[test]
    fn test_build_llm_messages_with_system_prompt() {
        let mut router = Router::new(16);
        router.set_system_prompt("You are a helpful assistant.".to_string());

        let history = vec![ChatMessage {
            role: "user".to_string(),
            content: "Hi".to_string(),
        }];

        let messages = router.build_llm_messages(&history);
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].role, "system");
        assert_eq!(messages[0].content, "You are a helpful assistant.");
        assert_eq!(messages[1].role, "user");
    }

    #[test]
    fn test_build_llm_messages_without_system_prompt() {
        let router = Router::new(16);

        let history = vec![ChatMessage {
            role: "user".to_string(),
            content: "Hi".to_string(),
        }];

        let messages = router.build_llm_messages(&history);
        assert_eq!(messages.len(), 1);
    }

    #[test]
    fn test_ipc_to_routable() {
        let ipc_msg = IpcMessage::IncomingMessage {
            channel: "telegram".to_string(),
            sender_id: "123".to_string(),
            sender_name: Some("Bob".to_string()),
            content: "Hello".to_string(),
            message_id: "msg-1".to_string(),
            request_id: "req-001".to_string(),
        };

        let routable = Router::ipc_to_routable(&ipc_msg).unwrap();
        assert_eq!(routable.channel, "telegram");
        assert_eq!(routable.sender_id, "123");
        assert_eq!(routable.content, "Hello");
        assert_eq!(routable.request_id, "req-001");
    }

    #[test]
    fn test_ipc_to_routable_non_message() {
        let ipc_msg = IpcMessage::Ping;
        assert!(Router::ipc_to_routable(&ipc_msg).is_none());
    }

    #[test]
    fn test_response_to_ipc() {
        let response = RouteResponse {
            channel: "cli".to_string(),
            recipient_id: "user1".to_string(),
            content: "Response".to_string(),
            reply_to: Some("msg-1".to_string()),
            request_id: "req-001".to_string(),
        };

        let ipc = Router::response_to_ipc(&response);
        match ipc {
            IpcMessage::OutgoingMessage {
                channel,
                recipient_id,
                content,
                reply_to,
                request_id,
            } => {
                assert_eq!(channel, "cli");
                assert_eq!(recipient_id, "user1");
                assert_eq!(content, "Response");
                assert_eq!(reply_to, Some("msg-1".to_string()));
                assert_eq!(request_id, "req-001");
            }
            _ => panic!("unexpected message type"),
        }
    }
}

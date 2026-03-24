#![deny(unsafe_code)]

//! CLI channel adapter — provides an interactive terminal chat interface.
//! Unlike other adapters, this runs in-process (no separate Unix socket needed).

use fugue_core::router::{RoutableMessage, RouteResponse};
use tokio::sync::mpsc;

/// Run the CLI channel adapter in-process
pub async fn run_cli_adapter(
    incoming_tx: mpsc::Sender<RoutableMessage>,
    mut response_rx: mpsc::Receiver<RouteResponse>,
) {
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let mut reader = BufReader::new(stdin);

    let mut msg_counter: u64 = 0;

    loop {
        // Print prompt
        let _ = stdout.write_all(b"> ").await;
        let _ = stdout.flush().await;

        let mut line = String::new();
        match reader.read_line(&mut line).await {
            Ok(0) => break, // EOF
            Ok(_) => {}
            Err(e) => {
                eprintln!("read error: {}", e);
                break;
            }
        }

        let input = line.trim();
        if input.is_empty() {
            continue;
        }

        if input == "/quit" || input == "/exit" {
            break;
        }

        msg_counter += 1;
        let request_id = uuid::Uuid::new_v4().to_string();
        let msg = RoutableMessage {
            channel: "cli".to_string(),
            sender_id: "cli-user".to_string(),
            sender_name: Some("User".to_string()),
            content: input.to_string(),
            message_id: format!("cli-{}", msg_counter),
            request_id,
        };

        if incoming_tx.send(msg).await.is_err() {
            eprintln!("core disconnected");
            break;
        }

        // Wait for response
        match response_rx.recv().await {
            Some(response) => {
                let _ = stdout
                    .write_all(format!("\n{}\n\n", response.content).as_bytes())
                    .await;
                let _ = stdout.flush().await;
            }
            None => {
                eprintln!("response channel closed");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cli_adapter_message_routing() {
        let (incoming_tx, mut incoming_rx) = mpsc::channel::<RoutableMessage>(16);
        let (response_tx, _response_rx) = mpsc::channel::<RouteResponse>(16);

        // Simulate sending a message as if from the CLI
        let msg = RoutableMessage {
            channel: "cli".to_string(),
            sender_id: "cli-user".to_string(),
            sender_name: Some("User".to_string()),
            content: "hello".to_string(),
            message_id: "cli-1".to_string(),
            request_id: "req-001".to_string(),
        };

        incoming_tx.send(msg).await.unwrap();

        // Receive the message on the core side
        let received = incoming_rx.recv().await.unwrap();
        assert_eq!(received.content, "hello");
        assert_eq!(received.channel, "cli");

        // Send a response back
        let response = RouteResponse {
            channel: "cli".to_string(),
            recipient_id: "cli-user".to_string(),
            content: "Hi there!".to_string(),
            reply_to: Some("cli-1".to_string()),
            request_id: "req-001".to_string(),
        };
        response_tx.send(response).await.unwrap();
    }
}

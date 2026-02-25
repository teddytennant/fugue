#![deny(unsafe_code)]

use serde::{Deserialize, Serialize};

use crate::config::{ProviderConfig, ProviderType};
use crate::error::{FugueError, Result};
use crate::ipc::ChatMessage;
use crate::vault::Vault;

/// Classify an HTTP error status code into a descriptive category
fn classify_http_error(status: reqwest::StatusCode, provider: &str, body: &str) -> FugueError {
    let code = status.as_u16();
    let category = match code {
        401 => "authentication error (invalid or missing API key)",
        403 => "forbidden (insufficient permissions)",
        404 => "not found (check base_url and model name)",
        429 => "rate limited (too many requests, retry after backoff)",
        500 => "internal server error (provider-side issue)",
        502 => "bad gateway (provider may be temporarily unavailable)",
        503 => "service unavailable (provider may be overloaded or down)",
        _ => "request failed",
    };

    FugueError::Provider(format!(
        "{} API error: {} {} - {}. Response: {}",
        provider, code, category, status.canonical_reason().unwrap_or("Unknown"), body
    ))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmResponse {
    pub content: String,
    pub model: String,
    pub usage: Option<Usage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Usage {
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
}

pub struct ProviderManager {
    client: reqwest::Client,
    providers: Vec<(String, ProviderConfig, Option<String>)>,
}

impl Default for ProviderManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ProviderManager {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            providers: Vec::new(),
        }
    }

    /// Register a provider with its resolved credential
    pub fn register(
        &mut self,
        name: String,
        config: ProviderConfig,
        vault: Option<&Vault>,
    ) -> Result<()> {
        let api_key = if let Some(ref cred_ref) = config.credential {
            let vault = vault.ok_or_else(|| {
                FugueError::Provider(format!(
                    "provider '{}' references credential but no vault is configured",
                    name
                ))
            })?;
            Some(vault.resolve_credential(cred_ref)?)
        } else {
            None
        };

        self.providers.push((name, config, api_key));
        Ok(())
    }

    /// Send a chat completion request to the named provider
    pub async fn chat(
        &self,
        provider_name: &str,
        messages: &[ChatMessage],
    ) -> Result<LlmResponse> {
        let (_, config, api_key) = self
            .providers
            .iter()
            .find(|(name, _, _)| name == provider_name)
            .ok_or_else(|| {
                FugueError::Provider(format!("provider '{}' not found", provider_name))
            })?;

        match config.provider_type {
            ProviderType::Ollama => self.chat_ollama(config, messages).await,
            ProviderType::Anthropic => {
                self.chat_anthropic(config, api_key.as_deref(), messages)
                    .await
            }
            ProviderType::OpenAI => {
                self.chat_openai(config, api_key.as_deref(), messages)
                    .await
            }
        }
    }

    pub fn list_providers(&self) -> Vec<&str> {
        self.providers.iter().map(|(name, _, _)| name.as_str()).collect()
    }

    async fn chat_ollama(
        &self,
        config: &ProviderConfig,
        messages: &[ChatMessage],
    ) -> Result<LlmResponse> {
        let base_url = config
            .base_url
            .as_deref()
            .unwrap_or("http://localhost:11434");
        let model = config.model.as_deref().unwrap_or("llama3.2");

        let body = serde_json::json!({
            "model": model,
            "messages": messages.iter().map(|m| {
                serde_json::json!({
                    "role": m.role,
                    "content": m.content,
                })
            }).collect::<Vec<_>>(),
            "stream": false,
        });

        let resp = self
            .client
            .post(format!("{}/api/chat", base_url))
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(classify_http_error(status, "Ollama", &body));
        }

        let data: serde_json::Value = resp.json().await?;

        let content = data["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();

        Ok(LlmResponse {
            content,
            model: model.to_string(),
            usage: None,
        })
    }

    async fn chat_anthropic(
        &self,
        config: &ProviderConfig,
        api_key: Option<&str>,
        messages: &[ChatMessage],
    ) -> Result<LlmResponse> {
        let api_key = api_key.ok_or_else(|| {
            FugueError::Provider("Anthropic provider requires an API key".to_string())
        })?;

        let base_url = config
            .base_url
            .as_deref()
            .unwrap_or("https://api.anthropic.com");
        let model = config
            .model
            .as_deref()
            .unwrap_or("claude-sonnet-4-20250514");

        // Separate system message from conversation messages
        let system_msg = messages
            .iter()
            .find(|m| m.role == "system")
            .map(|m| m.content.clone());

        let conv_messages: Vec<serde_json::Value> = messages
            .iter()
            .filter(|m| m.role != "system")
            .map(|m| {
                serde_json::json!({
                    "role": m.role,
                    "content": m.content,
                })
            })
            .collect();

        let mut body = serde_json::json!({
            "model": model,
            "max_tokens": 4096,
            "messages": conv_messages,
        });

        if let Some(system) = system_msg {
            body["system"] = serde_json::Value::String(system);
        }

        let resp = self
            .client
            .post(format!("{}/v1/messages", base_url))
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(classify_http_error(status, "Anthropic", &body));
        }

        let data: serde_json::Value = resp.json().await?;

        let content = data["content"]
            .as_array()
            .and_then(|arr| arr.first())
            .and_then(|block| block["text"].as_str())
            .unwrap_or("")
            .to_string();

        let usage = Usage {
            prompt_tokens: data["usage"]["input_tokens"].as_u64(),
            completion_tokens: data["usage"]["output_tokens"].as_u64(),
            total_tokens: None,
        };

        Ok(LlmResponse {
            content,
            model: model.to_string(),
            usage: Some(usage),
        })
    }

    async fn chat_openai(
        &self,
        config: &ProviderConfig,
        api_key: Option<&str>,
        messages: &[ChatMessage],
    ) -> Result<LlmResponse> {
        let api_key = api_key.ok_or_else(|| {
            FugueError::Provider("OpenAI provider requires an API key".to_string())
        })?;

        let base_url = config
            .base_url
            .as_deref()
            .unwrap_or("https://api.openai.com");
        let model = config.model.as_deref().unwrap_or("gpt-4o");

        let body = serde_json::json!({
            "model": model,
            "messages": messages.iter().map(|m| {
                serde_json::json!({
                    "role": m.role,
                    "content": m.content,
                })
            }).collect::<Vec<_>>(),
        });

        let resp = self
            .client
            .post(format!("{}/v1/chat/completions", base_url))
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(classify_http_error(status, "OpenAI", &body));
        }

        let data: serde_json::Value = resp.json().await?;

        let content = data["choices"]
            .as_array()
            .and_then(|arr| arr.first())
            .and_then(|choice| choice["message"]["content"].as_str())
            .unwrap_or("")
            .to_string();

        let usage = Usage {
            prompt_tokens: data["usage"]["prompt_tokens"].as_u64(),
            completion_tokens: data["usage"]["completion_tokens"].as_u64(),
            total_tokens: data["usage"]["total_tokens"].as_u64(),
        };

        Ok(LlmResponse {
            content,
            model: model.to_string(),
            usage: Some(usage),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_manager_list_empty() {
        let pm = ProviderManager::new();
        assert!(pm.list_providers().is_empty());
    }

    #[test]
    fn test_register_ollama_no_credential() {
        let mut pm = ProviderManager::new();
        let config = ProviderConfig {
            provider_type: ProviderType::Ollama,
            base_url: Some("http://localhost:11434".to_string()),
            model: Some("llama3.2".to_string()),
            credential: None,
            extra: Default::default(),
        };

        pm.register("ollama".to_string(), config, None).unwrap();
        assert_eq!(pm.list_providers(), vec!["ollama"]);
    }

    #[tokio::test]
    async fn test_chat_unknown_provider() {
        let pm = ProviderManager::new();
        let messages = vec![ChatMessage {
            role: "user".to_string(),
            content: "hello".to_string(),
        }];

        let result = pm.chat("nonexistent", &messages).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not found"));
    }

    #[test]
    fn test_classify_http_error_auth() {
        let err = classify_http_error(
            reqwest::StatusCode::UNAUTHORIZED,
            "OpenAI",
            "invalid api key",
        );
        let msg = err.to_string();
        assert!(msg.contains("401"));
        assert!(msg.contains("authentication error"));
        assert!(msg.contains("OpenAI"));
    }

    #[test]
    fn test_classify_http_error_rate_limit() {
        let err = classify_http_error(
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            "Anthropic",
            "rate limit exceeded",
        );
        let msg = err.to_string();
        assert!(msg.contains("429"));
        assert!(msg.contains("rate limited"));
    }

    #[test]
    fn test_classify_http_error_server() {
        let err = classify_http_error(
            reqwest::StatusCode::INTERNAL_SERVER_ERROR,
            "Ollama",
            "internal error",
        );
        let msg = err.to_string();
        assert!(msg.contains("500"));
        assert!(msg.contains("internal server error"));
    }

    #[test]
    fn test_classify_http_error_generic() {
        let err = classify_http_error(
            reqwest::StatusCode::BAD_REQUEST,
            "OpenAI",
            "bad request body",
        );
        let msg = err.to_string();
        assert!(msg.contains("400"));
        assert!(msg.contains("request failed"));
    }
}

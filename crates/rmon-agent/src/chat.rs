//! The OpenAI-compatible chat-completions wire format, and the transport
//! that speaks it.
//!
//! rMon talks to [Passiv], which fronts models through LiteLLM and exposes
//! the OpenAI `/v1/chat/completions` surface. Only that surface is
//! modelled here — not any provider's extensions — so pointing rMon at a
//! different OpenAI-compatible endpoint is a configuration change rather
//! than a code change.
//!
//! [`ChatTransport`] exists so the agent loop can be tested without a
//! network or an API key: the loop's interesting behaviour is how it
//! handles tool calls, refusals, and runaway iteration, none of which
//! should require a live model to exercise.
//!
//! [Passiv]: https://gateway.mezzanin.eu

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// Who produced a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

/// One function call the model asked for.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    #[serde(rename = "type", default = "default_tool_type")]
    pub kind: String,
    pub function: FunctionCall,
}

fn default_tool_type() -> String {
    "function".to_string()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FunctionCall {
    pub name: String,
    /// JSON object, as a string. The API deliberately transports this as
    /// text rather than as structured JSON, and models do sometimes emit
    /// text that isn't valid JSON, so parsing is the caller's problem to
    /// handle rather than something to assume away here.
    pub arguments: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
    /// Set on `Role::Tool` messages to say which call this answers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

impl Message {
    pub fn system(content: impl Into<String>) -> Self {
        Self::text(Role::System, content)
    }

    pub fn user(content: impl Into<String>) -> Self {
        Self::text(Role::User, content)
    }

    pub fn assistant(content: impl Into<String>) -> Self {
        Self::text(Role::Assistant, content)
    }

    fn text(role: Role, content: impl Into<String>) -> Self {
        Self {
            role,
            content: Some(content.into()),
            tool_calls: None,
            tool_call_id: None,
        }
    }

    /// A tool's result, addressed to the call that requested it.
    pub fn tool_result(tool_call_id: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            role: Role::Tool,
            content: Some(content.into()),
            tool_calls: None,
            tool_call_id: Some(tool_call_id.into()),
        }
    }
}

/// A tool offered to the model.
#[derive(Debug, Clone, Serialize)]
pub struct ToolSpec {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub function: FunctionSpec,
}

#[derive(Debug, Clone, Serialize)]
pub struct FunctionSpec {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<Message>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<ToolSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChatResponse {
    pub choices: Vec<Choice>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Choice {
    pub message: Message,
    #[serde(default)]
    pub finish_reason: Option<String>,
}

/// Anything that can answer a chat request.
pub trait ChatTransport: Send + Sync {
    fn complete(&self, request: &ChatRequest) -> Result<ChatResponse>;
}

/// Talks to a real OpenAI-compatible endpoint.
pub struct HttpTransport {
    client: reqwest::blocking::Client,
    base_url: String,
    api_key: String,
}

impl HttpTransport {
    pub fn new(
        base_url: impl Into<String>,
        api_key: impl Into<String>,
        timeout_secs: u64,
    ) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .build()
            .context("building the HTTP client")?;
        Ok(Self {
            client,
            base_url: base_url.into().trim_end_matches('/').to_string(),
            api_key: api_key.into(),
        })
    }
}

impl ChatTransport for HttpTransport {
    fn complete(&self, request: &ChatRequest) -> Result<ChatResponse> {
        let url = format!("{}/chat/completions", self.base_url);
        let response = self
            .client
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(request)
            .send()
            .with_context(|| format!("POST {url}"))?;

        let status = response.status();
        let body = response.text().unwrap_or_default();
        if !status.is_success() {
            // The body carries the gateway's own explanation — an unknown
            // model name, an expired key, a rate limit — and quoting it is
            // far more useful than the status code alone. It is the
            // provider's error text, not the user's data.
            bail!("{url} returned {status}: {}", body.trim());
        }
        serde_json::from_str(&body)
            .with_context(|| format!("decoding the response from {url}: {}", truncate(&body, 400)))
    }
}

/// Model ids the gateway will serve, from `GET /v1/models`.
///
/// The settings tab offers these as a picker rather than a free-text field,
/// because a mistyped model is indistinguishable from a broken key until the
/// first question fails, and the gateway's route aliases (`claude-opus`,
/// `gpt-5.4`) are not guessable.
///
/// Sorted, and deduplicated by the gateway's own listing order being
/// unspecified.
pub fn list_models(base_url: &str, api_key: &str, timeout_secs: u64) -> Result<Vec<String>> {
    #[derive(Deserialize)]
    struct Listing {
        data: Vec<Entry>,
    }
    #[derive(Deserialize)]
    struct Entry {
        id: String,
    }

    let url = format!("{}/models", base_url.trim_end_matches('/'));
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .build()
        .context("building the HTTP client")?;
    let response = client
        .get(&url)
        .bearer_auth(api_key)
        .send()
        .with_context(|| format!("GET {url}"))?;

    let status = response.status();
    let body = response.text().unwrap_or_default();
    if !status.is_success() {
        bail!("{url} returned {status}: {}", body.trim());
    }

    let listing: Listing = serde_json::from_str(&body).with_context(|| {
        format!(
            "decoding the model list from {url}: {}",
            truncate(&body, 400)
        )
    })?;
    let mut ids: Vec<String> = listing.data.into_iter().map(|e| e.id).collect();
    ids.sort();
    ids.dedup();
    Ok(ids)
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    // Char-boundary safe: a naive byte slice would panic on a response
    // that happens to be cut mid-codepoint.
    let end = s
        .char_indices()
        .map(|(i, _)| i)
        .take_while(|&i| i <= max)
        .last()
        .unwrap_or(0);
    format!("{}…", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_messages_serialise_with_their_call_id() {
        let m = Message::tool_result("call_1", "{\"ok\":true}");
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v["role"], "tool");
        assert_eq!(v["tool_call_id"], "call_1");
    }

    /// Absent fields must stay absent: sending `"tool_calls": null` on
    /// every user message is rejected by some OpenAI-compatible gateways.
    #[test]
    fn empty_fields_are_omitted_not_nulled() {
        let v = serde_json::to_value(Message::user("hi")).unwrap();
        assert!(v.get("tool_calls").is_none());
        assert!(v.get("tool_call_id").is_none());
    }

    #[test]
    fn response_with_tool_calls_round_trips() {
        let json = r#"{
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_abc",
                        "type": "function",
                        "function": {"name": "system_metrics", "arguments": "{}"}
                    }]
                },
                "finish_reason": "tool_calls"
            }]
        }"#;
        let parsed: ChatResponse = serde_json::from_str(json).unwrap();
        let calls = parsed.choices[0].message.tool_calls.as_ref().unwrap();
        assert_eq!(calls[0].function.name, "system_metrics");
    }

    #[test]
    fn truncate_never_splits_a_codepoint() {
        let s = "é".repeat(500);
        let t = truncate(&s, 401);
        assert!(t.ends_with('…'));
    }
}

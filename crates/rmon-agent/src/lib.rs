//! An LLM agent that explains what is making this machine slow, using
//! rMon's own telemetry as its evidence.
//!
//! # Shape
//!
//! The model is given read-only tools over the live snapshot (see
//! [`tools`]) and asked a question. It calls tools, reads results, and
//! answers. The loop is ordinary and deliberately small; the parts worth
//! attention are the constraints around it:
//!
//! - **It cannot change anything.** The only action tool is
//!   `propose_kill_process`, which returns a proposal for a human to
//!   approve. Nothing in this crate calls `kill_process`.
//! - **It cannot run away.** Tool iterations are capped
//!   ([`MAX_ITERATIONS`]); hitting the cap ends the turn with what was
//!   gathered rather than looping until the context window or the bill
//!   runs out.
//! - **It is told when a number is missing.** rMon distinguishes "measured
//!   zero" from "could not measure" throughout, and the tool layer carries
//!   that distinction into JSON as `null`. The system prompt makes the
//!   consequence explicit, because the characteristic LLM failure here is
//!   building a confident causal story on an absent reading.
//!
//! # Transport
//!
//! Requests go to any OpenAI-compatible `/v1` endpoint — by default the
//! [Passiv] gateway, which fronts models through LiteLLM. Nothing in the
//! wire format is provider-specific, so switching endpoints is
//! configuration. See [`AgentConfig`].
//!
//! [Passiv]: https://gateway.mezzanin.eu

pub mod chat;
pub mod tools;

use std::sync::Arc;

use anyhow::{Context, Result, bail};

use chat::{ChatRequest, ChatTransport, HttpTransport, Message, Role};
pub use rmon_core::config::LlmSettings;
pub use tools::{PendingAction, ThrottleSummary, ToolContext, ToolOutcome};

/// The Passiv production gateway. Staging is `gateway-dev.mezzanin.eu/v1`.
pub const DEFAULT_BASE_URL: &str = "https://gateway.mezzanin.eu/v1";
/// The Passiv staging gateway.
pub const STAGING_BASE_URL: &str = "https://gateway-dev.mezzanin.eu/v1";

/// The endpoints Passiv provisions, offered as one-click presets so the
/// endpoint field does not have to be typed from memory. A key minted on one
/// is not valid on the other, which is the mistake the labels exist to
/// prevent.
pub const ENDPOINTS: [(&str, &str); 2] = [
    ("production", DEFAULT_BASE_URL),
    ("staging", STAGING_BASE_URL),
];
/// Environment variables consulted for the API key, in order.
pub const API_KEY_VARS: [&str; 2] = ["RMON_LLM_API_KEY", "OPENAI_API_KEY"];

/// Ceiling on tool round-trips within a single turn.
///
/// Six is generous for the question this agent answers — system metrics,
/// a process listing, a couple of detail lookups, and an answer — while
/// still bounding a model that has decided to enumerate every process on
/// the machine one call at a time.
pub const MAX_ITERATIONS: usize = 6;

const DEFAULT_TIMEOUT_SECS: u64 = 120;

/// Where a resolved value came from, so the UI can name it when a saved
/// setting and an environment variable both exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The settings tab, via `%APPDATA%\rMon\config.json`.
    Saved,
    /// The settings tab, unsealed this session with a Windows Hello gesture.
    Hello,
    /// An environment variable, named.
    Env(&'static str),
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Saved => f.write_str("saved settings"),
            Self::Hello => f.write_str("saved settings, unlocked with Windows Hello"),
            Self::Env(var) => f.write_str(var),
        }
    }
}

/// Where to send requests, as what model, with which key.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub base_url: String,
    pub model: String,
    pub api_key: String,
    pub timeout_secs: u64,
    /// Which of the two places the key was found in.
    pub key_source: Source,
}

impl AgentConfig {
    /// Reads configuration from the saved settings, falling back to the
    /// environment for anything not set there.
    ///
    /// Saved settings win over environment variables, which inverts the
    /// usual server-side precedence on purpose. Here the settings tab is
    /// the thing the user just typed into, and a stale `RMON_LLM_API_KEY`
    /// silently shadowing it is the harder failure to diagnose: the UI
    /// would be showing a key it was not using. [`Self::key_source`]
    /// records which one won so the UI can say.
    ///
    /// The key is still never written to the SQLite store, and on disk it
    /// exists only as a DPAPI blob — see [`rmon_core::config`].
    pub fn resolve(unlocked: Option<&str>) -> Result<Self> {
        let saved = rmon_core::config::load().map(|s| s.llm).unwrap_or_default();
        Self::from_saved_or_env(&saved, unlocked, &|var| std::env::var(var).ok())
    }

    /// [`Self::resolve`] with both global inputs injected.
    ///
    /// The saved file and the process environment are both global mutable
    /// state, so the precedence rules are tested through here rather than
    /// by mutating either.
    /// `unlocked` is the plaintext already obtained this session by a
    /// Windows Hello gesture, if any. It is passed in rather than fetched
    /// here because obtaining it blocks on the user, which has to happen on
    /// a worker thread and at most once per session — not on every question.
    pub fn from_saved_or_env(
        saved: &LlmSettings,
        unlocked: Option<&str>,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Self> {
        let non_empty = |s: String| Some(s).filter(|v| !v.trim().is_empty());

        // A saved blob that will not decrypt is reported rather than
        // skipped: falling through to the environment would answer "no API
        // key found" for a user who can see their key in the settings tab.
        let saved_key = saved.api_key().context("reading the saved API key")?;

        let (api_key, key_source) = match unlocked
            .filter(|k| !k.trim().is_empty())
            .map(|k| (k.to_string(), Source::Hello))
            .or_else(|| saved_key.map(|k| (k, Source::Saved)))
        {
            Some(pair) => pair,
            // A key sealed behind Hello is present but unreadable until the
            // user consents. That is a different state from having no key,
            // and must not fall through to the environment.
            None if saved.requires_hello() => {
                bail!("the saved key is protected by Windows Hello — unlock it to continue")
            }
            None => {
                let found = API_KEY_VARS
                    .iter()
                    .find_map(|var| env(var).and_then(non_empty).map(|k| (k, Source::Env(var))));
                match found {
                    Some(pair) => pair,
                    None => bail!(
                        "no API key yet — add one in Settings, or set {} (or {})",
                        API_KEY_VARS[0],
                        API_KEY_VARS[1]
                    ),
                }
            }
        };

        let model = saved
            .model
            .clone()
            .and_then(non_empty)
            .or_else(|| env("RMON_LLM_MODEL").and_then(non_empty))
            .ok_or_else(|| {
                anyhow::anyhow!("no model chosen — pick one in Settings, or set RMON_LLM_MODEL")
            })?;

        let base_url = saved
            .base_url
            .clone()
            .and_then(non_empty)
            .or_else(|| env("RMON_LLM_BASE_URL").and_then(non_empty))
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());

        Ok(Self {
            base_url,
            model,
            api_key,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            key_source,
        })
    }

    /// Whether an agent could be constructed, without constructing one.
    /// Used by the UI to explain itself before the user tries.
    pub fn describe_availability(unlocked: Option<&str>) -> std::result::Result<String, String> {
        match Self::resolve(unlocked) {
            Ok(c) => Ok(format!(
                "{} via {} (key from {})",
                c.model, c.base_url, c.key_source
            )),
            Err(e) => Err(format!("{e:#}")),
        }
    }
}

/// What happened during a turn, for the UI to render as it goes.
#[derive(Debug, Clone)]
pub enum AgentEvent {
    /// The model asked for a tool, with a human-readable argument summary.
    ToolCall { name: String, arguments: String },
    /// A tool answered. Carries the byte size only — the payload itself is
    /// for the model, not the screen.
    ToolResult { name: String, bytes: usize },
    /// The model proposed an action needing approval.
    ActionProposed(PendingAction),
    /// The turn finished with this answer.
    Answer(String),
    /// The turn ended without an answer.
    Failed(String),
}

/// The system prompt.
///
/// Most of it is about epistemics rather than capability, because the
/// failure mode that matters is not an agent that cannot find the data —
/// the tools hand it over readily — but one that narrates a confident
/// cause from a partial reading.
pub const SYSTEM_PROMPT: &str = "\
You are the analysis assistant built into rMon, a Windows process monitor. You \
help the user work out why their machine is slow, using only the telemetry \
rMon gives you through tools.

Method for performance questions:
- Call system_metrics first. If the CPU or GPU is being throttled, every \
per-process CPU% and GPU% figure is measuring the limit rather than the \
workload, and you must say so before blaming any process.
- Then look at the processes, and at trend_suspects for leaks and idle burners.

Method for software identity, purpose, or suspicion questions:
- Use process_detail and program_detail. Identity comes from executable path, \
installer publisher/location, command line, and the parent/child chain — never \
from a familiar filename alone.
- Explain the software's ordinary purpose when you know it, then separate that \
general knowledge from what rMon measured on this machine.
- Registry presence is not a trust verdict. Missing publisher metadata, an \
unattributed process, or an unsigned/unknown binary is a reason to verify, not \
proof of malware. Give concrete read-only verification commands when useful.
- Windows uninstall entries do not provide a complete package dependency graph \
or reliable last-used time. Never call an app safe to uninstall merely because \
it is idle now; name known dependents/current children and say what remains unknown.
- Prefer few, targeted tool calls over enumerating everything.

Reporting:
- A null in tool output means the reading was unavailable, NOT zero. Never \
treat a null as evidence of absence, and say plainly when something could not \
be measured.
- Distinguish what you measured from what you inferred. The CPU throttle \
verdict carries throttle_measured_not_inferred: when it is false, the verdict \
is a heuristic from clock speed that a healthy idle machine also produces.
- Give the user a short, concrete answer: what is slow, what the evidence is, \
and what they could do. No preamble, no restating the question.
- If the evidence does not support a conclusion, say that instead of picking \
the largest number and building a story around it.

You cannot change anything on this machine. propose_kill_process only asks the \
user for permission; use it sparingly and only with a specific reason.";

/// A single-turn agent over a captured machine state.
pub struct Agent {
    transport: Arc<dyn ChatTransport>,
    model: String,
    messages: Vec<Message>,
}

impl Agent {
    pub fn new(config: &AgentConfig) -> Result<Self> {
        let transport = HttpTransport::new(&config.base_url, &config.api_key, config.timeout_secs)?;
        Ok(Self::with_transport(Arc::new(transport), &config.model))
    }

    /// Constructs an agent over any transport. The seam that makes the
    /// loop testable without a network or a key.
    pub fn with_transport(transport: Arc<dyn ChatTransport>, model: &str) -> Self {
        Self {
            transport,
            model: model.to_string(),
            messages: vec![Message::system(SYSTEM_PROMPT)],
        }
    }

    /// Conversation so far, for a UI that wants to show it.
    pub fn messages(&self) -> &[Message] {
        &self.messages
    }

    /// Runs one turn: the user's question, through however many tool calls
    /// the model needs, to an answer.
    ///
    /// `on_event` is called as things happen so the UI can show progress
    /// rather than a spinner. Returns the final answer, and any action
    /// awaiting approval.
    pub fn ask(
        &mut self,
        question: &str,
        ctx: &ToolContext,
        mut on_event: impl FnMut(AgentEvent),
    ) -> Result<(String, Vec<PendingAction>)> {
        self.messages.push(Message::user(question));
        let mut pending = Vec::new();

        for iteration in 0..MAX_ITERATIONS {
            let request = ChatRequest {
                model: self.model.clone(),
                messages: self.messages.clone(),
                tools: tools::specs(),
                temperature: Some(0.2),
            };
            let response = self.transport.complete(&request)?;
            let Some(choice) = response.choices.into_iter().next() else {
                bail!("the gateway returned no choices");
            };
            let message = choice.message;
            self.messages.push(message.clone());

            let calls = message.tool_calls.unwrap_or_default();
            if calls.is_empty() {
                let answer = message.content.unwrap_or_default();
                on_event(AgentEvent::Answer(answer.clone()));
                return Ok((answer, pending));
            }

            for call in calls {
                let name = call.function.name.clone();
                on_event(AgentEvent::ToolCall {
                    name: name.clone(),
                    arguments: call.function.arguments.clone(),
                });

                // A tool that fails reports the failure back to the model
                // rather than ending the turn: a malformed argument is
                // something the model can correct on the next iteration,
                // and aborting would throw away the work already done.
                let result = match tools::dispatch(ctx, &call.id, &name, &call.function.arguments) {
                    Ok(ToolOutcome::Value(v)) => v.to_string(),
                    Ok(ToolOutcome::NeedsApproval(action)) => {
                        on_event(AgentEvent::ActionProposed(action.clone()));
                        let ack = serde_json::json!({
                            "status": "awaiting_user_approval",
                            "note": "The proposal was shown to the user. Nothing has been \
                                     terminated. Do not assume it was approved.",
                        });
                        pending.push(action);
                        ack.to_string()
                    }
                    Err(e) => serde_json::json!({"error": format!("{e:#}")}).to_string(),
                };

                on_event(AgentEvent::ToolResult {
                    name,
                    bytes: result.len(),
                });
                self.messages.push(Message::tool_result(&call.id, result));
            }

            if iteration + 1 == MAX_ITERATIONS {
                // Ask for a conclusion from what it already has, rather
                // than returning nothing after spending the whole budget.
                self.messages.push(Message::user(
                    "You have reached the tool-call limit. Answer now from what you already \
                     gathered, and say explicitly what you could not check.",
                ));
                let request = ChatRequest {
                    model: self.model.clone(),
                    messages: self.messages.clone(),
                    tools: Vec::new(),
                    temperature: Some(0.2),
                };
                let response = self.transport.complete(&request)?;
                let answer = response
                    .choices
                    .into_iter()
                    .next()
                    .and_then(|c| c.message.content)
                    .unwrap_or_else(|| "the model returned no answer".to_string());
                self.messages.push(Message::assistant(answer.clone()));
                on_event(AgentEvent::Answer(answer.clone()));
                return Ok((answer, pending));
            }
        }
        unreachable!("the loop returns on its final iteration")
    }
}

/// Counts how many messages of a role are in a transcript. Small helper
/// used by the UI and by tests.
pub fn count_role(messages: &[Message], role: Role) -> usize {
    messages.iter().filter(|m| m.role == role).count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chat::{ChatResponse, Choice, FunctionCall, ToolCall};
    use std::sync::Mutex;

    /// Replays a fixed script of responses, recording what it was asked.
    struct ScriptedTransport {
        responses: Mutex<Vec<ChatResponse>>,
        seen: Mutex<Vec<ChatRequest>>,
    }

    impl ScriptedTransport {
        fn new(responses: Vec<ChatResponse>) -> Arc<Self> {
            Arc::new(Self {
                responses: Mutex::new(responses),
                seen: Mutex::new(Vec::new()),
            })
        }
    }

    impl ChatTransport for ScriptedTransport {
        fn complete(&self, request: &ChatRequest) -> Result<ChatResponse> {
            self.seen.lock().unwrap().push(request.clone());
            let mut r = self.responses.lock().unwrap();
            if r.is_empty() {
                bail!("script exhausted");
            }
            Ok(r.remove(0))
        }
    }

    fn answer(text: &str) -> ChatResponse {
        ChatResponse {
            choices: vec![Choice {
                message: Message::assistant(text),
                finish_reason: Some("stop".into()),
            }],
        }
    }

    fn calls(specs: &[(&str, &str, &str)]) -> ChatResponse {
        ChatResponse {
            choices: vec![Choice {
                message: Message {
                    role: Role::Assistant,
                    content: None,
                    tool_calls: Some(
                        specs
                            .iter()
                            .map(|(id, name, args)| ToolCall {
                                id: id.to_string(),
                                kind: "function".into(),
                                function: FunctionCall {
                                    name: name.to_string(),
                                    arguments: args.to_string(),
                                },
                            })
                            .collect(),
                    ),
                    tool_call_id: None,
                },
                finish_reason: Some("tool_calls".into()),
            }],
        }
    }

    fn ctx() -> ToolContext {
        ToolContext {
            snapshot: rmon_core::Snapshot {
                timestamp: chrono::Utc::now(),
                processes: vec![rmon_core::ProcessSample {
                    pid: 10,
                    ppid: None,
                    name: "busy.exe".into(),
                    cpu_percent: 90.0,
                    gpu_percent: 0.0,
                    gpu_source: rmon_core::GpuSource::Unavailable,
                    user: None,
                    command_line: None,
                    executable_path: Some(r"C:\Apps\busy.exe".into()),
                    handle_count: None,
                    mem_bytes: None,
                }],
                system: Default::default(),
            },
            trends: Vec::new(),
            throttle: ThrottleSummary::default(),
            installed_programs: Vec::new(),
        }
    }

    #[test]
    fn a_plain_answer_ends_the_turn() {
        let t = ScriptedTransport::new(vec![answer("Nothing is throttling.")]);
        let mut agent = Agent::with_transport(t.clone(), "test-model");
        let (a, pending) = agent.ask("why slow?", &ctx(), |_| {}).unwrap();
        assert_eq!(a, "Nothing is throttling.");
        assert!(pending.is_empty());
        assert_eq!(t.seen.lock().unwrap().len(), 1);
    }

    #[test]
    fn tool_calls_are_executed_and_fed_back() {
        let t = ScriptedTransport::new(vec![
            calls(&[("c1", "system_metrics", "{}")]),
            answer("CPU is fine."),
        ]);
        let mut agent = Agent::with_transport(t.clone(), "test-model");
        let mut events = Vec::new();
        agent.ask("why slow?", &ctx(), |e| events.push(e)).unwrap();

        // The tool result must reach the model on the second request.
        let seen = t.seen.lock().unwrap();
        assert!(seen[1].messages.iter().any(|m| m.role == Role::Tool));
        assert!(matches!(events[0], AgentEvent::ToolCall { .. }));
    }

    /// A tool error is reported to the model, not raised: the model can
    /// fix a bad argument on the next iteration.
    #[test]
    fn tool_errors_do_not_abort_the_turn() {
        let t = ScriptedTransport::new(vec![
            calls(&[("c1", "process_detail", "not json")]),
            answer("Recovered."),
        ]);
        let mut agent = Agent::with_transport(t.clone(), "test-model");
        let (a, _) = agent.ask("q", &ctx(), |_| {}).unwrap();
        assert_eq!(a, "Recovered.");
        let seen = t.seen.lock().unwrap();
        let tool_msg = seen[1]
            .messages
            .iter()
            .find(|m| m.role == Role::Tool)
            .unwrap();
        assert!(tool_msg.content.as_ref().unwrap().contains("error"));
    }

    /// The safety property, end to end: a proposed kill surfaces for
    /// approval and the model is told nothing was terminated.
    #[test]
    fn proposed_kills_surface_for_approval_and_are_not_executed() {
        let t = ScriptedTransport::new(vec![
            calls(&[(
                "c1",
                "propose_kill_process",
                r#"{"pid":10,"reason":"pegged"}"#,
            )]),
            answer("Proposed."),
        ]);
        let mut agent = Agent::with_transport(t.clone(), "test-model");
        let mut proposed = Vec::new();
        let (_, pending) = agent
            .ask("fix it", &ctx(), |e| {
                if let AgentEvent::ActionProposed(a) = e {
                    proposed.push(a);
                }
            })
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(proposed.len(), 1);
        assert_eq!(pending[0].pid, 10);

        let seen = t.seen.lock().unwrap();
        let tool_msg = seen[1]
            .messages
            .iter()
            .find(|m| m.role == Role::Tool)
            .unwrap();
        let content = tool_msg.content.as_ref().unwrap();
        assert!(content.contains("awaiting_user_approval"));
        assert!(content.contains("Nothing has been terminated"));
    }

    /// A model that only ever calls tools must still produce an answer,
    /// rather than looping until the budget is gone.
    #[test]
    fn the_iteration_cap_forces_a_conclusion() {
        let mut script: Vec<ChatResponse> = (0..MAX_ITERATIONS)
            .map(|_| calls(&[("c", "system_metrics", "{}")]))
            .collect();
        script.push(answer("Ran out of steps; here is what I have."));
        let t = ScriptedTransport::new(script);
        let mut agent = Agent::with_transport(t.clone(), "test-model");

        let (a, _) = agent.ask("q", &ctx(), |_| {}).unwrap();
        assert_eq!(a, "Ran out of steps; here is what I have.");

        // The final request must offer no tools, or the model could keep
        // calling them and the cap would not bind.
        let seen = t.seen.lock().unwrap();
        assert!(seen.last().unwrap().tools.is_empty());
    }

    #[test]
    fn every_request_carries_the_system_prompt_first() {
        let t = ScriptedTransport::new(vec![answer("ok")]);
        let mut agent = Agent::with_transport(t.clone(), "test-model");
        agent.ask("q", &ctx(), |_| {}).unwrap();
        let seen = t.seen.lock().unwrap();
        assert_eq!(seen[0].messages[0].role, Role::System);
    }

    /// Builds an env lookup from pairs, so a test states exactly what the
    /// process environment would hold.
    fn env_of(pairs: &[(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |want: &str| {
            owned
                .iter()
                .find(|(k, _)| k == want)
                .map(|(_, v)| v.clone())
        }
    }

    fn saved_with_key(key: &str) -> LlmSettings {
        let mut s = LlmSettings::default();
        s.set_api_key(key).unwrap();
        s
    }

    #[test]
    fn saved_key_wins_over_the_environment() {
        let saved = saved_with_key("sk-saved");
        let env = env_of(&[("RMON_LLM_API_KEY", "sk-env"), ("RMON_LLM_MODEL", "m")]);

        let config = AgentConfig::from_saved_or_env(&saved, None, &env).unwrap();

        assert_eq!(config.api_key, "sk-saved");
        assert_eq!(config.key_source, Source::Saved);
    }

    #[test]
    fn environment_is_the_fallback_when_nothing_is_saved() {
        let env = env_of(&[("OPENAI_API_KEY", "sk-env"), ("RMON_LLM_MODEL", "m")]);

        let config = AgentConfig::from_saved_or_env(&LlmSettings::default(), None, &env).unwrap();

        assert_eq!(config.api_key, "sk-env");
        assert_eq!(config.key_source, Source::Env("OPENAI_API_KEY"));
        assert_eq!(config.model, "m");
    }

    #[test]
    fn the_first_named_key_variable_wins() {
        let env = env_of(&[
            ("RMON_LLM_API_KEY", "sk-first"),
            ("OPENAI_API_KEY", "sk-second"),
            ("RMON_LLM_MODEL", "m"),
        ]);

        let config = AgentConfig::from_saved_or_env(&LlmSettings::default(), None, &env).unwrap();

        assert_eq!(config.api_key, "sk-first");
        assert_eq!(config.key_source, Source::Env("RMON_LLM_API_KEY"));
    }

    #[test]
    fn saved_model_and_base_url_win_over_the_environment() {
        let mut saved = saved_with_key("sk-saved");
        saved.model = Some("claude-opus".into());
        saved.base_url = Some("https://gateway-dev.mezzanin.eu/v1".into());
        let env = env_of(&[
            ("RMON_LLM_MODEL", "gpt-5.4"),
            ("RMON_LLM_BASE_URL", "https://elsewhere/v1"),
        ]);

        let config = AgentConfig::from_saved_or_env(&saved, None, &env).unwrap();

        assert_eq!(config.model, "claude-opus");
        assert_eq!(config.base_url, "https://gateway-dev.mezzanin.eu/v1");
    }

    #[test]
    fn base_url_falls_back_to_the_passiv_gateway() {
        let saved = saved_with_key("sk-saved");
        let env = env_of(&[("RMON_LLM_MODEL", "m")]);

        let config = AgentConfig::from_saved_or_env(&saved, None, &env).unwrap();

        assert_eq!(config.base_url, DEFAULT_BASE_URL);
    }

    /// A saved-but-blank field is the state left by clearing a text box,
    /// and must not beat a real value from the environment.
    #[test]
    fn blank_saved_values_fall_through_rather_than_winning() {
        let mut saved = saved_with_key("sk-saved");
        saved.model = Some("   ".into());
        saved.base_url = Some(String::new());
        let env = env_of(&[
            ("RMON_LLM_MODEL", "gpt-5.4"),
            ("RMON_LLM_BASE_URL", "https://elsewhere/v1"),
        ]);

        let config = AgentConfig::from_saved_or_env(&saved, None, &env).unwrap();

        assert_eq!(config.model, "gpt-5.4");
        assert_eq!(config.base_url, "https://elsewhere/v1");
    }

    #[test]
    fn a_missing_key_points_at_settings_first() {
        let env = env_of(&[("RMON_LLM_MODEL", "m")]);

        let err = AgentConfig::from_saved_or_env(&LlmSettings::default(), None, &env).unwrap_err();

        let text = format!("{err:#}");
        assert!(text.contains("Settings"), "{text}");
        assert!(text.contains("RMON_LLM_API_KEY"), "{text}");
    }

    #[test]
    fn a_missing_model_is_reported_separately_from_a_missing_key() {
        let saved = saved_with_key("sk-saved");

        let err = AgentConfig::from_saved_or_env(&saved, None, &env_of(&[])).unwrap_err();

        let text = format!("{err:#}");
        assert!(text.contains("model"), "{text}");
    }

    /// A key sealed for another user decrypts to nothing. Reporting that as
    /// "no API key" would send someone to re-enter a key the settings tab is
    /// already showing as present.
    #[test]
    fn an_unreadable_saved_key_is_an_error_not_a_fallback() {
        let saved = LlmSettings {
            api_key_sealed: Some("00ff00ff".into()),
            ..Default::default()
        };
        let env = env_of(&[("RMON_LLM_API_KEY", "sk-env"), ("RMON_LLM_MODEL", "m")]);

        let err = AgentConfig::from_saved_or_env(&saved, None, &env).unwrap_err();

        assert!(format!("{err:#}").contains("saved API key"), "{err:#}");
    }

    /// A settings object whose key is sealed behind Hello, built without
    /// touching the real Hello store — only `requires_hello` is consulted.
    fn saved_behind_hello() -> LlmSettings {
        LlmSettings {
            api_key_hello: Some(rmon_core::config::HelloSealed {
                challenge: "00".into(),
                blob: "00".into(),
            }),
            model: Some("m".into()),
            ..Default::default()
        }
    }

    /// The important negative case: a Hello-protected key must not silently
    /// fall through to an environment variable. Doing so would hand the agent
    /// a different key than the one the user believes is in use, and would
    /// quietly defeat the protection they turned on.
    #[test]
    fn a_hello_locked_key_does_not_fall_through_to_the_environment() {
        let env = env_of(&[("RMON_LLM_API_KEY", "sk-env"), ("RMON_LLM_MODEL", "m")]);

        let err = AgentConfig::from_saved_or_env(&saved_behind_hello(), None, &env).unwrap_err();

        let text = format!("{err:#}");
        assert!(text.contains("Windows Hello"), "{text}");
        assert!(text.contains("unlock"), "{text}");
    }

    #[test]
    fn a_session_unlock_satisfies_a_hello_locked_key() {
        let env = env_of(&[("RMON_LLM_API_KEY", "sk-env")]);

        let config =
            AgentConfig::from_saved_or_env(&saved_behind_hello(), Some("sk-unlocked"), &env)
                .unwrap();

        assert_eq!(config.api_key, "sk-unlocked");
        assert_eq!(config.key_source, Source::Hello);
        assert_eq!(config.model, "m");
    }

    /// The unlocked value outranks a plain saved blob too, so that turning
    /// Hello on mid-session takes effect rather than silently using the old
    /// unprotected copy.
    #[test]
    fn a_session_unlock_outranks_the_plain_saved_key() {
        let mut saved = saved_with_key("sk-plain");
        saved.model = Some("m".into());

        let config =
            AgentConfig::from_saved_or_env(&saved, Some("sk-unlocked"), &env_of(&[])).unwrap();

        assert_eq!(config.api_key, "sk-unlocked");
        assert_eq!(config.key_source, Source::Hello);
    }

    /// A blank unlock is the state of "not unlocked yet" and must not be
    /// mistaken for a key.
    #[test]
    fn a_blank_unlock_is_not_a_key() {
        let env = env_of(&[("RMON_LLM_MODEL", "m")]);

        let err =
            AgentConfig::from_saved_or_env(&saved_behind_hello(), Some("   "), &env).unwrap_err();

        assert!(format!("{err:#}").contains("Windows Hello"), "{err:#}");
    }
}

//! ojiichan: scaffolded observability (backend=rustrak)
//!
//! Mirrors ojiichan's Python helpers for services that can't import the Python
//! library: Sentry/rustrak error reporting plus ELK structured
//! events. Every value is read from the environment, preferring an
//! `OJIICHAN_`-prefixed override, then the conventional name.
//! See `OBSERVABILITY.md` for the environment variables this reads.

use std::env;

/// Resolve a config value: `OJIICHAN_<NAME>` first, then the bare `<NAME>`.
pub fn env_var(name: &str) -> Option<String> {
    env::var(format!("OJIICHAN_{name}"))
        .ok()
        .or_else(|| env::var(name).ok())
}

fn env_bool(name: &str, default: bool) -> bool {
    match env_var(name) {
        Some(value) => matches!(value.to_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        None => default,
    }
}

/// Initialize Sentry/rustrak when `SENTRY_DSN` is set.
///
/// Hold the returned guard for the lifetime of the process so buffered events
/// are flushed on drop. Returns `None` (the no-op path) when no DSN is set.
#[must_use]
pub fn init_sentry() -> Option<sentry::ClientInitGuard> {
    let dsn = env_var("SENTRY_DSN")?;
    let environment = env_var("ENVIRONMENT")
        .or_else(|| env_var("APP_ENV"))
        .or_else(|| env_var("ENV"));
    let release = env_var("RELEASE").or_else(|| env_var("GIT_COMMIT"));
    let traces_sample_rate = env_var("SENTRY_TRACES_SAMPLE_RATE")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0.0);

    Some(sentry::init((
        dsn,
        sentry::ClientOptions {
            release: release.map(Into::into),
            environment: environment.map(Into::into),
            traces_sample_rate,
            ..Default::default()
        },
    )))
}

/// Report an error to Sentry/rustrak (no-op until `init_sentry`).
pub fn capture_error(err: &(dyn std::error::Error + 'static)) {
    sentry::capture_error(err);
}

/// Report an `anyhow::Error` (which doesn't implement `std::error::Error`)
/// to Sentry/rustrak, preserving its full source chain.
pub fn capture_anyhow(err: &anyhow::Error) {
    sentry::integrations::anyhow::capture_anyhow(err);
}

fn service() -> String {
    env_var("SERVICE_NAME")
        .or_else(|| env_var("APP_NAME"))
        .unwrap_or_else(|| "app".to_string())
}

fn elk_base_url() -> Option<String> {
    let host = env_var("ELASTICSEARCH_HOST")?;
    if host.starts_with("http://") || host.starts_with("https://") {
        return Some(host);
    }
    let scheme = if env_bool("ELASTICSEARCH_USE_SSL", true) {
        "https"
    } else {
        "http"
    };
    let port = env_var("ELASTICSEARCH_PORT").unwrap_or_else(|| "443".to_string());
    Some(format!("{scheme}://{host}:{port}"))
}

/// Write transport for structured events: `es` (default), `logstash`, or `otlp`.
/// Unknown values fall back to `es`. The document shape is identical across
/// transports, so events stay queryable together.
fn elk_transport() -> String {
    let value = env_var("ELK_TRANSPORT")
        .unwrap_or_else(|| "es".to_string())
        .to_lowercase();
    match value.as_str() {
        "logstash" | "otlp" => value,
        _ => "es".to_string(),
    }
}

fn http_timeout() -> std::time::Duration {
    let secs = env_var("ELASTICSEARCH_TIMEOUT")
        .and_then(|value| value.parse().ok())
        .unwrap_or(10.0);
    std::time::Duration::from_secs_f64(secs)
}

/// Ship one structured event to ELK, matching the index naming and document
/// shape of ojiichan's Python `ElkClient.log_event`
/// (`<index_prefix>-<topic>` / `_doc`). The sink is chosen by `ELK_TRANSPORT`.
///
/// Returns `false` (and logs to stderr) when the transport is unconfigured or
/// the request fails — the diagnostics path never panics.
pub fn log_event(
    event_type: &str,
    data: serde_json::Value,
    level: &str,
    topic: Option<&str>,
    failure: Option<bool>,
) -> bool {
    let mut document = serde_json::Map::new();
    if let serde_json::Value::Object(map) = data {
        document.extend(map);
    }
    let operation = document
        .get("operation")
        .and_then(|value| value.as_str())
        .unwrap_or(event_type)
        .to_string();

    document.insert("@timestamp".into(), chrono::Utc::now().to_rfc3339().into());
    document.insert("event_type".into(), event_type.into());
    document.insert("operation".into(), operation.into());
    document.insert("level".into(), level.into());
    document.insert("service".into(), service().into());
    if let Some(flag) = failure {
        document.insert("failure".into(), flag.into());
    }

    let prefix = env_var("ELASTICSEARCH_INDEX_PREFIX").unwrap_or_else(|| "app".to_string());
    let index = format!("{prefix}-{}", topic.unwrap_or(event_type));
    let document = serde_json::Value::Object(document);

    match elk_transport().as_str() {
        "logstash" => send_logstash(&index, &document),
        "otlp" => send_otlp(&document, level),
        _ => send_elasticsearch(&index, &document),
    }
}

fn send_elasticsearch(index: &str, document: &serde_json::Value) -> bool {
    let Some(base) = elk_base_url() else {
        eprintln!("[ELK:{index}] {document}");
        return false;
    };
    let client = reqwest::blocking::Client::new();
    let mut request = client
        .post(format!("{base}/{index}/_doc"))
        .timeout(http_timeout())
        .json(document);
    if let (Some(user), Some(password)) = (
        env_var("ELASTICSEARCH_USERNAME"),
        env_var("ELASTICSEARCH_PASSWORD"),
    ) {
        request = request.basic_auth(user, Some(password));
    }
    match request.send() {
        Ok(response) => response.status().is_success(),
        Err(err) => {
            eprintln!("[ELK:{index}] send failed: {err}");
            false
        }
    }
}

/// POST the document to a Logstash HTTP input. The index travels as an `index`
/// field so a Logstash pipeline can route to the same `<prefix>-<topic>` index
/// the `es` transport writes to directly.
fn send_logstash(index: &str, document: &serde_json::Value) -> bool {
    let Some(url) = env_var("LOGSTASH_URL").map(|u| u.trim_end_matches('/').to_string()) else {
        eprintln!("[ELK:{index}] {document}");
        return false;
    };
    let mut payload = document.clone();
    if let serde_json::Value::Object(map) = &mut payload {
        map.insert("index".into(), index.into());
    }
    let client = reqwest::blocking::Client::new();
    let mut request = client.post(&url).timeout(http_timeout()).json(&payload);
    if let (Some(user), Some(password)) = (
        env_var("ELASTICSEARCH_USERNAME"),
        env_var("ELASTICSEARCH_PASSWORD"),
    ) {
        request = request.basic_auth(user, Some(password));
    }
    match request.send() {
        Ok(response) => response.status().is_success(),
        Err(err) => {
            eprintln!("[ELK:{index}] send failed: {err}");
            false
        }
    }
}

/// Map a textual level to an OTLP SeverityNumber.
/// <https://opentelemetry.io/docs/specs/otel/logs/data-model/#severity-fields>
fn otlp_severity_number(level: &str) -> i32 {
    match level.to_lowercase().as_str() {
        "trace" => 1,
        "debug" => 5,
        "warn" | "warning" => 13,
        "error" => 17,
        "fatal" | "critical" => 21,
        _ => 9,
    }
}

fn otlp_any_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Bool(b) => serde_json::json!({ "boolValue": b }),
        serde_json::Value::Number(n) if n.is_i64() || n.is_u64() => {
            serde_json::json!({ "intValue": n.to_string() })
        }
        serde_json::Value::Number(n) => serde_json::json!({ "doubleValue": n.as_f64() }),
        serde_json::Value::String(s) => serde_json::json!({ "stringValue": s }),
        other => serde_json::json!({ "stringValue": other.to_string() }),
    }
}

/// Parse the standard `OTEL_EXPORTER_OTLP_HEADERS` format: comma-separated
/// `key=value` pairs, e.g. `authorization=Bearer xyz,x-tenant=acme`.
fn parse_otlp_headers(raw: &str) -> Vec<(String, String)> {
    raw.split(',')
        .filter_map(|pair| {
            let pair = pair.trim();
            pair.split_once('=')
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}

/// Ship the event as an OTLP/HTTP JSON LogRecord to `<endpoint>/v1/logs`.
fn send_otlp(document: &serde_json::Value, level: &str) -> bool {
    let Some(endpoint) = env_var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .map(|e| e.trim_end_matches('/').to_string())
    else {
        eprintln!("[OTLP] {document}");
        return false;
    };
    let url = if endpoint.ends_with("/v1/logs") {
        endpoint
    } else {
        format!("{endpoint}/v1/logs")
    };

    let obj = document.as_object().cloned().unwrap_or_default();
    let time_unix_nano = obj
        .get("@timestamp")
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.timestamp_nanos_opt().unwrap_or(0).to_string())
        .unwrap_or_else(|| "0".to_string());
    let service_name = obj
        .get("service")
        .and_then(|v| v.as_str())
        .unwrap_or("app")
        .to_string();
    let body_text = obj
        .get("message")
        .or_else(|| obj.get("event_type"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let attributes: Vec<serde_json::Value> = obj
        .iter()
        .filter(|(key, _)| key.as_str() != "@timestamp")
        .map(|(key, value)| serde_json::json!({ "key": key, "value": otlp_any_value(value) }))
        .collect();

    let payload = serde_json::json!({
        "resourceLogs": [{
            "resource": {
                "attributes": [{
                    "key": "service.name",
                    "value": { "stringValue": service_name }
                }]
            },
            "scopeLogs": [{
                "scope": { "name": "ojiichan" },
                "logRecords": [{
                    "timeUnixNano": time_unix_nano,
                    "severityNumber": otlp_severity_number(level),
                    "severityText": level.to_uppercase(),
                    "body": { "stringValue": body_text },
                    "attributes": attributes
                }]
            }]
        }]
    });

    let client = reqwest::blocking::Client::new();
    let mut request = client.post(&url).timeout(http_timeout()).json(&payload);
    for (key, value) in env_var("OTEL_EXPORTER_OTLP_HEADERS")
        .map(|raw| parse_otlp_headers(&raw))
        .unwrap_or_default()
    {
        request = request.header(key, value);
    }
    match request.send() {
        Ok(response) => response.status().is_success(),
        Err(err) => {
            eprintln!("[OTLP] send failed: {err}");
            false
        }
    }
}

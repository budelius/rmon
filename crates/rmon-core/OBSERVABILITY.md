# Observability (Rust)

Scaffolded by [ojiichan](https://gitlab.com/martin-wieser/ojiichan) to wire this
service into the same stack as the Python services: **ELK** structured events and
**rustrak** (Sentry-compatible) error reporting.

## Cargo dependencies

```toml
[dependencies]
sentry = "0.34"
reqwest = { version = "0.12", default-features = false, features = ["blocking", "json", "rustls-tls"] }
serde_json = "1"
chrono = "0.4"
```

## Wiring

`src/observability.rs` exposes `init_sentry`, `capture_error`, and `log_event`.
Add `mod observability;` to your crate root and keep the Sentry guard alive for
the whole process:

```rust
mod observability;

fn main() {
    // Hold the guard until `main` returns so events flush on shutdown.
    let _sentry = observability::init_sentry();

    if let Err(err) = run() {
        observability::capture_error(err.as_ref());
        observability::log_event(
            "startup_failed",
            serde_json::json!({ "operation": "startup", "error": err.to_string() }),
            "error",
            Some("lifecycle"),
            Some(true),
        );
    }
}
```

`log_event` uses `reqwest::blocking`, so it works without an async runtime. Call
it from a blocking context (or `tokio::task::spawn_blocking` inside async code).

## Environment

| Variable | Purpose |
| --- | --- |
| `SENTRY_DSN` | rustrak/Sentry ingest DSN. Unset ⇒ reporting no-ops. |
| `ENVIRONMENT` / `APP_ENV` | Deployment environment tag. |
| `RELEASE` / `GIT_COMMIT` | Release identifier. |
| `SERVICE_NAME` / `APP_NAME` | Logical service name. |
| `ELASTICSEARCH_HOST` | ELK host (with or without scheme). Unset ⇒ ELK no-ops. |
| `ELASTICSEARCH_PORT` | Defaults to `443`. |
| `ELASTICSEARCH_USERNAME` / `ELASTICSEARCH_PASSWORD` | Basic auth (also used for Logstash). |
| `ELASTICSEARCH_INDEX_PREFIX` | Index prefix; defaults to `app`. |
| `ELK_TRANSPORT` | Write transport: `es` (default), `logstash`, or `otlp`. |
| `LOGSTASH_URL` | Logstash HTTP input URL (`logstash` transport). |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP/HTTP base URL, e.g. a Collector (`otlp` transport). |
| `OTEL_EXPORTER_OTLP_HEADERS` | OTLP headers, `key=value` comma-separated (e.g. auth). |

All values also accept an `OJIICHAN_`-prefixed override (e.g.
`OJIICHAN_SENTRY_DSN`), matching the Python toolkit's resolution order.

## Write transports

`log_event` builds one canonical document and ships it through the transport
selected by `ELK_TRANSPORT`. The document shape is identical across transports,
so events stay queryable together regardless of how they were written.

| Transport | Sink | Notes |
| --- | --- | --- |
| `es` (default) | `POST <host>/<prefix>-<topic>/_doc` | Direct to Elasticsearch. |
| `logstash` | `POST $LOGSTASH_URL` | Document sent with an extra `index` field; route it in your pipeline with `elasticsearch { index => "%{index}" }`. |
| `otlp` | `POST $OTEL_EXPORTER_OTLP_ENDPOINT/v1/logs` | OpenTelemetry LogRecord (JSON); point at a Collector that exports to ELK. |

> **Obachan:** use project-scoped writer credentials only with direct `es`.
> Obachan's Data Prepper `logstash`/`otlp` listeners require the shared
> `ojiichan` ingest identity and `app-*` indices. Production shared ingest uses
> `https://ingest.pseekoo.io`; probe it before rollout.

> **Reads stay on Elasticsearch.** Transports only affect the *write* path.
> Querying logs / health checks read from Elasticsearch no matter which transport
> wrote the events.

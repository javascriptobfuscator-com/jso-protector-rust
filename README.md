# jso-protector — Rust crate

Rust crate for the [JavaScript Obfuscator](https://javascriptobfuscator.com/) HTTP API. Mirrors the `protect()` surface of every other JSO language client (Node, Python, Go, .NET, Ruby, PHP) so behavior stays in lockstep across runtimes.

Sync HTTP client built on [`ureq`](https://crates.io/crates/ureq) + `serde_json`. No async runtime required.

## Install

```toml
[dependencies]
jso-protector = "0.1"
```

## Quick start

```rust
use std::collections::HashMap;
use jso_protector::{Client, ProtectRequest};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut files = HashMap::new();
    files.insert("app.js".into(), std::fs::read_to_string("dist/app.js")?);

    let client = Client::new();
    let result = client.protect(ProtectRequest {
        files,
        preset: Some("balanced".into()),
        label: std::env::var("GIT_COMMIT").ok(),
        // api_key / api_password default to JSO_API_KEY / JSO_API_PASSWORD env vars.
        ..Default::default()
    })?;

    for (name, code) in &result.files {
        std::fs::write(format!("dist-protected/{name}"), code)?;
    }
    println!("BuildId: {:?}", result.build_id);
    println!("Fingerprint: {:?}", result.polymorphism_fingerprint);
    Ok(())
}
```

## Credentials

Reads `JSO_API_KEY` / `JSO_API_PASSWORD` (or the long-form `JAVASCRIPT_OBFUSCATOR_API_KEY` / `JAVASCRIPT_OBFUSCATOR_API_PASSWORD`) from the environment before falling back to `ProtectRequest::api_key` / `api_password`.

## Presets

Same three-preset table as every other JSO client. See [`presets()`](src/lib.rs) for the exact option lists. For fine-grained control, pass `ProtectRequest::options`:

```rust
use serde_json::json;
let mut req = ProtectRequest::default();
req.options.insert("LockDomain".into(), json!(true));
req.options.insert("LockDomainList".into(), json!("example.com"));
```

Explicit options win over preset defaults.

## Result

[`ProtectResult`](src/lib.rs):

| Field | Type | Notes |
|---|---|---|
| `files` | `HashMap<String, String>` | Protected source by input filename. |
| `build_id` | `Option<String>` | Stable identifier for this run. |
| `polymorphism_fingerprint` | `Option<String>` | Short fingerprint over the protected output. |
| `report` | `serde_json::Value` | Full Report — identifier maps, enabled options, compatibility findings, release metadata. |
| `raw` | `serde_json::Value` | Complete raw response body. |

## Error handling

```rust
match client.protect(req) {
    Ok(result) => { /* ship */ }
    Err(jso_protector::Error::Api { message, kind, code }) => {
        eprintln!("JSO failed: kind={:?} code={:?} {}", kind, code, message);
    }
    Err(e) => eprintln!("JSO failed: {}", e),
}
```

All error variants implement `std::error::Error` and `Display`. Messages never include the API key or password.

## Custom agent

```rust
let agent = ureq::AgentBuilder::new()
    .timeout(std::time::Duration::from_secs(60))
    .build();
let client = Client::with_agent(agent);
```

Useful for tests (point at a mockito server), for installing a custom proxy, or for tweaking TLS config.

## Tests

```bash
cargo test
```

Unit tests in `src/lib.rs`; integration tests in `tests/integration.rs` via [`mockito`](https://crates.io/crates/mockito) — no real network.

## License

MIT OR Apache-2.0.

//! Rust client for the JavaScript Obfuscator HTTP API.
//!
//! Mirrors the `protect()` surface of the `jso-protector` npm CLI, the
//! Python / Go / .NET / Ruby / PHP clients so behavior stays in lockstep
//! across runtimes.
//!
//! # Quick start
//!
//! ```no_run
//! use std::collections::HashMap;
//! use jso_protector::{Client, ProtectRequest};
//!
//! let mut files = HashMap::new();
//! files.insert("app.js".to_string(), std::fs::read_to_string("dist/app.js").unwrap());
//!
//! let client = Client::new();
//! let result = client.protect(ProtectRequest {
//!     files,
//!     preset: Some("balanced".into()),
//!     label: std::env::var("GIT_COMMIT").ok(),
//!     ..Default::default()
//! }).unwrap();
//!
//! for (name, code) in &result.files {
//!     std::fs::write(format!("dist-protected/{name}"), code).unwrap();
//! }
//! println!("BuildId: {:?}", result.build_id);
//! println!("Fingerprint: {:?}", result.polymorphism_fingerprint);
//! ```

use std::collections::HashMap;
use std::env;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;

/// Crate version. Sent as the User-Agent suffix.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Production HTTP API endpoint. Override [`ProtectRequest::endpoint`] only for
/// staging or self-hosted setups.
pub const DEFAULT_ENDPOINT: &str = "https://javascriptobfuscator.com/HttpApi.ashx";

/// Errors raised by [`Client::protect`]. Messages never include the API key
/// or password.
#[derive(Debug, Error)]
pub enum Error {
    #[error("JSO API credentials not configured. Set api_key/api_password or export JSO_API_KEY / JSO_API_PASSWORD.")]
    MissingCredentials,
    #[error("at least one file is required")]
    EmptyFiles,
    #[error("unknown preset {0:?}")]
    UnknownPreset(String),
    #[error("HTTP {status}: {snippet}")]
    Http { status: u16, snippet: String },
    #[error("connection failed: {0}")]
    Transport(String),
    #[error("malformed JSON in response: {0}")]
    MalformedResponse(String),
    /// Server replied with a non-Succeed `Type`. Carries the API's message
    /// plus optional Type / ErrorCode for routing.
    #[error("{message}")]
    Api {
        message: String,
        kind: Option<String>,
        code: Option<String>,
    },
}

/// Outcome of a successful [`Client::protect`] call.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProtectResult {
    /// Protected source keyed by input filename.
    pub files: HashMap<String, String>,
    /// Stable identifier for this protection run.
    pub build_id: Option<String>,
    /// Short fingerprint over the protected output.
    pub polymorphism_fingerprint: Option<String>,
    /// Full Report — identifier maps, enabled options, compatibility findings, release metadata.
    pub report: Value,
    /// Complete raw decoded response body.
    pub raw: Value,
}

/// Options for a single [`Client::protect`] call. Use [`Default::default`] for
/// "balanced preset, no overrides, env-var credentials, default endpoint".
#[derive(Debug, Default, Clone)]
pub struct ProtectRequest {
    /// Map of filename to source. Required.
    pub files: HashMap<String, String>,
    /// One of "standard", "balanced", "maximum". Defaults to "balanced".
    pub preset: Option<String>,
    /// Pascal-case option overrides that win over preset defaults.
    pub options: HashMap<String, Value>,
    /// Release label forwarded as `ReleaseLabel` on the API request.
    pub label: Option<String>,
    /// Audit-log project name. Default "rust-session".
    pub project_name: Option<String>,
    /// Base64 API key. Defaults to JSO_API_KEY / JAVASCRIPT_OBFUSCATOR_API_KEY env vars when None.
    pub api_key: Option<String>,
    /// Base64 API password. Defaults to JSO_API_PASSWORD / JAVASCRIPT_OBFUSCATOR_API_PASSWORD env vars.
    pub api_password: Option<String>,
    /// API endpoint override. Defaults to [`DEFAULT_ENDPOINT`].
    pub endpoint: Option<String>,
    /// Request timeout. Default 180 seconds.
    pub timeout: Option<Duration>,
}

/// The three named presets. Matches every other JSO language client.
pub fn presets() -> HashMap<&'static str, HashMap<&'static str, bool>> {
    let mut out = HashMap::new();
    out.insert("standard", HashMap::from([
        ("Compress", true),
        ("EncodeStrings", true),
        ("MoveStringsIntoArray", true),
        ("NameMangling", true),
    ]));
    out.insert("balanced", HashMap::from([
        ("Compress", true),
        ("EncodeStrings", true),
        ("EncryptStrings", true),
        ("MoveStringsIntoArray", true),
        ("NameMangling", true),
        ("DeepObfuscate", true),
        ("FlatTransform", true),
        ("CodeTransposition", true),
    ]));
    out.insert("maximum", HashMap::from([
        ("Compress", true),
        ("EncodeStrings", true),
        ("EncryptStrings", true),
        ("MoveStringsIntoArray", true),
        ("NameMangling", true),
        ("DeepObfuscate", true),
        ("FlatTransform", true),
        ("CodeTransposition", true),
        ("ProtectMembers", true),
        ("RenameGlobals", true),
        ("MoveMembers", true),
        ("DeadCodeInsertion", true),
    ]));
    out
}

/// Stateless client wrapping a [`ureq::Agent`].
pub struct Client {
    agent: ureq::Agent,
}

impl Default for Client {
    fn default() -> Self { Self::new() }
}

impl Client {
    /// Create a new client with a 180-second request timeout.
    pub fn new() -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(180))
            .user_agent(&format!("jso-protector-rust/{VERSION}"))
            .build();
        Self { agent }
    }

    /// Use a pre-configured `ureq::Agent`. Useful for tests and for setups that
    /// want a custom timeout / proxy / TLS config.
    pub fn with_agent(agent: ureq::Agent) -> Self { Self { agent } }

    /// Send `req.files` to the JSO API and return the protected output.
    pub fn protect(&self, req: ProtectRequest) -> Result<ProtectResult, Error> {
        let api_key = resolve_cred(req.api_key.as_deref(),
            &["JSO_API_KEY", "JAVASCRIPT_OBFUSCATOR_API_KEY"]);
        let api_pwd = resolve_cred(req.api_password.as_deref(),
            &["JSO_API_PASSWORD", "JAVASCRIPT_OBFUSCATOR_API_PASSWORD"]);
        if api_key.is_empty() || api_pwd.is_empty() {
            return Err(Error::MissingCredentials);
        }
        if req.files.is_empty() {
            return Err(Error::EmptyFiles);
        }

        let preset_name = req.preset.as_deref().unwrap_or("balanced").to_lowercase();
        let presets_table = presets();
        let preset_opts = presets_table.get(preset_name.as_str())
            .ok_or_else(|| Error::UnknownPreset(req.preset.clone().unwrap_or_default()))?;

        let endpoint = req.endpoint.clone().unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());
        let project_name = req.project_name.clone().unwrap_or_else(|| "rust-session".to_string());

        // Build the payload by hand so we control key order and which Items shape ships.
        let items: Vec<Value> = req.files.iter()
            .map(|(name, code)| json!({ "FileName": name, "FileCode": code }))
            .collect();
        let mut payload = serde_json::Map::new();
        payload.insert("APIKey".to_string(), Value::String(api_key));
        payload.insert("APIPwd".to_string(), Value::String(api_pwd));
        payload.insert("Name".to_string(), Value::String(project_name));
        if let Some(label) = &req.label {
            if !label.is_empty() {
                payload.insert("ReleaseLabel".to_string(), Value::String(label.clone()));
            }
        }
        payload.insert("Items".to_string(), Value::Array(items));
        // Preset first, explicit options override.
        for (k, v) in preset_opts {
            payload.insert(k.to_string(), Value::Bool(*v));
        }
        for (k, v) in &req.options {
            payload.insert(k.clone(), v.clone());
        }

        let body = Value::Object(payload);
        let resp = self.agent.post(&endpoint)
            .set("Content-Type", "text/json")
            .send_json(body);

        let response = match resp {
            Ok(r) => r,
            Err(ureq::Error::Status(code, response)) => {
                let snippet = response.into_string().unwrap_or_default();
                let trunc: String = snippet.chars().take(200).collect();
                return Err(Error::Http { status: code, snippet: trunc });
            }
            Err(e) => return Err(Error::Transport(e.to_string())),
        };

        let parsed: Value = response.into_json()
            .map_err(|e| Error::MalformedResponse(e.to_string()))?;

        let type_ = parsed.get("Type").and_then(|v| v.as_str()).unwrap_or("");
        if type_ != "Succeed" {
            let message = parsed.get("Message").and_then(|v| v.as_str())
                .or_else(|| parsed.get("ErrorCode").and_then(|v| v.as_str()))
                .unwrap_or("API request failed")
                .to_string();
            let code = parsed.get("ErrorCode").and_then(|v| v.as_str()).map(String::from);
            return Err(Error::Api { message, kind: Some(type_.to_string()), code });
        }

        let mut result = ProtectResult::default();
        if let Some(items_arr) = parsed.get("Items").and_then(|v| v.as_array()) {
            for item in items_arr {
                let name = item.get("FileName").and_then(|v| v.as_str()).unwrap_or("");
                let code = item.get("FileCode").and_then(|v| v.as_str()).unwrap_or("");
                if !name.is_empty() {
                    result.files.insert(name.to_string(), code.to_string());
                }
            }
        }
        if result.files.is_empty() {
            return Err(Error::Api {
                message: "API response did not include any protected files".into(),
                kind: None, code: None,
            });
        }
        if let Some(report) = parsed.get("Report") {
            result.build_id = report.get("BuildId").and_then(|v| v.as_str()).map(String::from);
            result.polymorphism_fingerprint = report.get("PolymorphismFingerprint").and_then(|v| v.as_str()).map(String::from);
            result.report = report.clone();
        }
        result.raw = parsed;
        Ok(result)
    }
}

fn resolve_cred(arg: Option<&str>, env_var_names: &[&str]) -> String {
    if let Some(v) = arg {
        let t = v.trim();
        if !t.is_empty() { return t.to_string(); }
    }
    for name in env_var_names {
        if let Ok(v) = env::var(name) {
            let t = v.trim();
            if !t.is_empty() { return t.to_string(); }
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn preset_table_has_expected_entries() {
        let ps = presets();
        assert!(ps.contains_key("standard"));
        assert!(ps.contains_key("balanced"));
        assert!(ps.contains_key("maximum"));
        assert!(ps["maximum"].len() > ps["standard"].len());
    }

    #[test]
    fn unknown_preset_errors() {
        let mut files = HashMap::new();
        files.insert("a.js".to_string(), "x".to_string());
        let result = Client::new().protect(ProtectRequest {
            files,
            preset: Some("elephant".to_string()),
            api_key: Some("k".to_string()),
            api_password: Some("p".to_string()),
            ..Default::default()
        });
        assert!(matches!(result, Err(Error::UnknownPreset(_))));
    }

    #[test]
    fn empty_files_errors() {
        let result = Client::new().protect(ProtectRequest {
            api_key: Some("k".to_string()),
            api_password: Some("p".to_string()),
            ..Default::default()
        });
        assert!(matches!(result, Err(Error::EmptyFiles)));
    }

    #[test]
    fn missing_credentials_errors() {
        // Save and clear env to avoid pollution across test runs.
        let saved = [
            ("JSO_API_KEY", env::var("JSO_API_KEY").ok()),
            ("JSO_API_PASSWORD", env::var("JSO_API_PASSWORD").ok()),
            ("JAVASCRIPT_OBFUSCATOR_API_KEY", env::var("JAVASCRIPT_OBFUSCATOR_API_KEY").ok()),
            ("JAVASCRIPT_OBFUSCATOR_API_PASSWORD", env::var("JAVASCRIPT_OBFUSCATOR_API_PASSWORD").ok()),
        ];
        for (name, _) in &saved { env::remove_var(name); }
        let mut files = HashMap::new();
        files.insert("a.js".to_string(), "x".to_string());
        let result = Client::new().protect(ProtectRequest { files, ..Default::default() });
        for (name, val) in &saved { if let Some(v) = val { env::set_var(name, v); } }
        assert!(matches!(result, Err(Error::MissingCredentials)));
    }

    // Network-roundtrip tests live in tests/integration.rs using mockito.
}

//! Integration tests against a mockito-backed mock JSO server. No real
//! network calls.

use std::collections::HashMap;

use jso_protector::{Client, ProtectRequest, Error};
use mockito::{Matcher, ServerGuard};
use serde_json::{json, Value};

fn make_files() -> HashMap<String, String> {
    let mut files = HashMap::new();
    files.insert("app.js".to_string(), "let x = 1;".to_string());
    files
}

fn agent_for(server: &ServerGuard) -> ureq::Agent {
    let _ = server.url();
    ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(5))
        .build()
}

#[test]
fn label_propagates_as_release_label() {
    let mut server = mockito::Server::new();
    let url = server.url();

    let mock = server.mock("POST", "/HttpApi.ashx")
        .match_body(Matcher::PartialJsonString(json!({
            "ReleaseLabel": "ci-build-7f3a",
            "APIKey": "k",
            "APIPwd": "p",
            "FlatTransform": true
        }).to_string()))
        .with_status(200)
        .with_header("content-type", "text/json")
        .with_body(json!({
            "Type": "Succeed",
            "Items": [{ "FileName": "app.js", "FileCode": "PROTECTED;" }],
            "Report": {
                "BuildId": "rel-1",
                "PolymorphismFingerprint": "abc123"
            }
        }).to_string())
        .create();

    let client = Client::with_agent(agent_for(&server));
    let result = client.protect(ProtectRequest {
        files: make_files(),
        preset: Some("balanced".to_string()),
        label: Some("ci-build-7f3a".to_string()),
        api_key: Some("k".to_string()),
        api_password: Some("p".to_string()),
        endpoint: Some(format!("{url}/HttpApi.ashx")),
        ..Default::default()
    }).expect("protect failed");

    mock.assert();
    assert_eq!(result.build_id.as_deref(), Some("rel-1"));
    assert_eq!(result.polymorphism_fingerprint.as_deref(), Some("abc123"));
    assert_eq!(result.files.get("app.js").map(String::as_str), Some("PROTECTED;"));
}

#[test]
fn options_override_preset() {
    let mut server = mockito::Server::new();
    let url = server.url();

    let mock = server.mock("POST", "/HttpApi.ashx")
        .match_body(Matcher::PartialJsonString(json!({
            "FlatTransform": false,
            "LockDomain": true,
            "LockDomainList": "example.com"
        }).to_string()))
        .with_status(200)
        .with_body(json!({
            "Type": "Succeed",
            "Items": [{ "FileName": "x.js", "FileCode": "OK;" }]
        }).to_string())
        .create();

    let mut options = HashMap::new();
    options.insert("FlatTransform".to_string(), Value::Bool(false));
    options.insert("LockDomain".to_string(), Value::Bool(true));
    options.insert("LockDomainList".to_string(), Value::String("example.com".to_string()));

    let mut files = HashMap::new();
    files.insert("x.js".to_string(), "y".to_string());

    let client = Client::with_agent(agent_for(&server));
    client.protect(ProtectRequest {
        files,
        preset: Some("balanced".to_string()),
        options,
        api_key: Some("k".to_string()),
        api_password: Some("p".to_string()),
        endpoint: Some(format!("{url}/HttpApi.ashx")),
        ..Default::default()
    }).expect("protect failed");
    mock.assert();
}

#[test]
fn non_succeed_type_returns_api_error_with_metadata() {
    let mut server = mockito::Server::new();
    let url = server.url();

    server.mock("POST", "/HttpApi.ashx")
        .with_status(200)
        .with_body(json!({
            "Type": "Error",
            "Message": "Invalid API key",
            "ErrorCode": "AUTH_FAIL"
        }).to_string())
        .create();

    let client = Client::with_agent(agent_for(&server));
    let err = client.protect(ProtectRequest {
        files: make_files(),
        api_key: Some("k".to_string()),
        api_password: Some("p".to_string()),
        endpoint: Some(format!("{url}/HttpApi.ashx")),
        ..Default::default()
    }).expect_err("expected error");

    match err {
        Error::Api { message, kind, code } => {
            assert_eq!(message, "Invalid API key");
            assert_eq!(kind.as_deref(), Some("Error"));
            assert_eq!(code.as_deref(), Some("AUTH_FAIL"));
        }
        other => panic!("expected Error::Api, got {other:?}"),
    }
}

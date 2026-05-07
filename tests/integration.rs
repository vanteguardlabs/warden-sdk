//! Integration tests against a tokio-spawned axum stub.
//!
//! We spin up a real HTTP server inside each test rather than mocking
//! at a trait layer, so the full reqwest -> response decoder path is
//! exercised. Each test gets its own server bound to port 0 (kernel
//! picks a free port) and tears it down via a oneshot channel on exit.
//!
//! Coverage:
//! * happy path `call_tool` — 200 + JSON body
//! * structured-JSON veto from `warden-lite`
//! * plain-text veto from full-edition `warden-proxy`
//! * 401 → `WardenError::Unauthorized`
//! * 400 → `WardenError::BadRequest`
//! * `LedgerClient::audit_correlation` — typed `LedgerEntry` decode
//! * `LedgerClient::verify` — typed `VerifyResult` decode
//! * bearer header is forwarded

use std::net::SocketAddr;

use axum::{
    Json, Router,
    extract::Path,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use serde_json::{Value, json};
use tokio::sync::oneshot;

use warden_sdk::{Auth, LedgerClient, WardenClient, WardenError};

use axum::extract::Query;
use std::collections::HashMap;

/// One-shot fixture: spawn `router` on a fresh port; return the URL
/// (e.g. `http://127.0.0.1:54321`) plus a sender that drops the
/// server when the test ends.
async fn spawn(router: Router) -> (String, oneshot::Sender<()>) {
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let (tx, rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        // `with_graceful_shutdown` runs until `rx` resolves. Drop on
        // the test side ends the server cleanly.
        axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                let _ = rx.await;
            })
            .await
            .expect("serve");
    });
    (format!("http://{addr}"), tx)
}

#[tokio::test]
async fn call_tool_happy_path_returns_upstream_json() {
    let app = Router::new().route(
        "/mcp",
        post(|Json(body): Json<Value>| async move {
            // Echo the JSON-RPC id back so we can assert the SDK
            // populated it.
            let id = body.get("id").cloned().unwrap_or(Value::Null);
            (
                StatusCode::OK,
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {"content": [{"type": "text", "text": "ok"}]},
                })),
            )
                .into_response()
        }),
    );
    let (url, shutdown) = spawn(app).await;

    let client = WardenClient::builder(&url).unwrap().build().unwrap();
    let reply = client
        .call_tool("search", json!({"q": "rust async"}))
        .await
        .expect("happy path");
    assert_eq!(reply["jsonrpc"], "2.0");
    assert_eq!(reply["result"]["content"][0]["text"], "ok");
    drop(shutdown);
}

#[tokio::test]
async fn call_tool_structured_veto_parses_fields() {
    // Mirrors warden-lite's `DenyResponse` shape.
    let app = Router::new().route(
        "/mcp",
        post(|| async {
            (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "security_violation",
                    "reasons": ["Direct execution of SQL queries is prohibited."],
                    "review_reasons": [],
                    "intent_category": "DangerousTool",
                })),
            )
                .into_response()
        }),
    );
    let (url, shutdown) = spawn(app).await;

    let client = WardenClient::builder(&url).unwrap().build().unwrap();
    let err = client
        .call_tool("sql_execute", json!({"query": "DROP TABLE x"}))
        .await
        .expect_err("expected veto");
    match err {
        WardenError::Veto { intent_category, reasons, review_reasons, raw } => {
            assert_eq!(intent_category, "DangerousTool");
            assert_eq!(reasons.len(), 1);
            assert!(reasons[0].contains("SQL"));
            assert!(review_reasons.is_empty());
            assert!(raw.contains("security_violation"));
        }
        other => panic!("expected Veto, got {other:?}"),
    }
    drop(shutdown);
}

#[tokio::test]
async fn call_tool_plain_text_veto_keeps_body_in_raw() {
    // Mirrors what full-edition warden-proxy returns today.
    let app = Router::new().route(
        "/mcp",
        post(|| async {
            (
                StatusCode::FORBIDDEN,
                "Security Violation: shell_exec is denied for this agent",
            )
                .into_response()
        }),
    );
    let (url, shutdown) = spawn(app).await;

    let client = WardenClient::builder(&url).unwrap().build().unwrap();
    let err = client
        .call_tool("shell_exec", json!({"cmd": "rm -rf /"}))
        .await
        .expect_err("expected veto");
    match err {
        WardenError::Veto { intent_category, reasons, review_reasons, raw } => {
            // No structured fields, but the raw body is preserved.
            assert!(intent_category.is_empty());
            assert!(reasons.is_empty());
            assert!(review_reasons.is_empty());
            assert!(raw.starts_with("Security Violation"));
        }
        other => panic!("expected Veto, got {other:?}"),
    }
    drop(shutdown);
}

#[tokio::test]
async fn unauthorized_response_maps_to_unauthorized_error() {
    let app = Router::new().route(
        "/mcp",
        post(|| async {
            (StatusCode::UNAUTHORIZED, "missing or invalid bearer token").into_response()
        }),
    );
    let (url, shutdown) = spawn(app).await;

    let client = WardenClient::builder(&url).unwrap().build().unwrap();
    let err = client
        .call_tool("search", json!({}))
        .await
        .expect_err("expected unauthorized");
    match err {
        WardenError::Unauthorized(body) => assert!(body.contains("bearer")),
        other => panic!("expected Unauthorized, got {other:?}"),
    }
    drop(shutdown);
}

#[tokio::test]
async fn bad_request_maps_to_bad_request_error() {
    let app = Router::new().route(
        "/mcp",
        post(|| async {
            (StatusCode::BAD_REQUEST, "invalid JSON-RPC body: missing field `method`")
                .into_response()
        }),
    );
    let (url, shutdown) = spawn(app).await;

    let client = WardenClient::builder(&url).unwrap().build().unwrap();
    let err = client
        .call_tool("search", json!({}))
        .await
        .expect_err("expected bad request");
    match err {
        WardenError::BadRequest(body) => assert!(body.contains("method")),
        other => panic!("expected BadRequest, got {other:?}"),
    }
    drop(shutdown);
}

#[tokio::test]
async fn bearer_token_is_forwarded_in_authorization_header() {
    // The handler asserts the header is present; if not, returns 401
    // and the SDK surfaces it as `Unauthorized`. So a successful
    // `call_tool` here proves the SDK forwarded the token.
    let app = Router::new().route(
        "/mcp",
        post(|headers: HeaderMap| async move {
            let got = headers
                .get("authorization")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");
            if got == "Bearer secret-token" {
                (StatusCode::OK, Json(json!({"jsonrpc":"2.0","id":1,"result":"ok"})))
                    .into_response()
            } else {
                (StatusCode::UNAUTHORIZED, format!("got: {got}")).into_response()
            }
        }),
    );
    let (url, shutdown) = spawn(app).await;

    let client = WardenClient::builder(&url)
        .unwrap()
        .auth(Auth::Bearer("secret-token".into()))
        .build()
        .unwrap();
    let reply = client
        .call_tool("search", json!({}))
        .await
        .expect("token should be accepted");
    assert_eq!(reply["result"], "ok");
    drop(shutdown);
}

#[tokio::test]
async fn audit_correlation_decodes_ledger_entries() {
    let app = Router::new().route(
        "/audit/correlation/{cid}",
        get(|Path(cid): Path<String>| async move {
            // Two rows per request — what the chain actually carries.
            let row = |seq: i64, layer: &str| {
                json!({
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "timestamp": "2026-05-02T12:34:56Z",
                    "agent_id": "demo-bot",
                    "method": format!("tools/call:{layer}"),
                    "intent_category": "BenignTool",
                    "authorized": true,
                    "reasoning": format!("layer={layer}"),
                    "policy_decision": null,
                    "seq": seq,
                    "prev_hash": "0".repeat(64),
                    "entry_hash": "a".repeat(64),
                    "correlation_id": cid,
                })
            };
            Json(json!([row(1, "proxy"), row(2, "policy")])).into_response()
        }),
    );
    let (url, shutdown) = spawn(app).await;

    let ledger = LedgerClient::new(&url).unwrap();
    let rows = ledger
        .audit_correlation("3f4b8c2a-9e1d-47fa-8a6c-c0a8d8888c8c")
        .await
        .expect("audit");
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| r.correlation_id.is_some()));
    assert_eq!(rows[0].seq, 1);
    assert_eq!(rows[1].seq, 2);
    drop(shutdown);
}

#[tokio::test]
async fn verify_decodes_chain_status() {
    let app = Router::new().route(
        "/verify",
        get(|| async {
            Json(json!({
                "valid": true,
                "entries_checked": 47,
                "first_invalid_seq": null
            }))
        }),
    );
    let (url, shutdown) = spawn(app).await;

    let ledger = LedgerClient::new(&url).unwrap();
    let v = ledger.verify().await.expect("verify");
    assert!(v.valid);
    assert_eq!(v.entries_checked, 47);
    assert!(v.first_invalid_seq.is_none());
    drop(shutdown);
}

#[tokio::test]
async fn audit_correlation_percent_encodes_path() {
    // Hit a server that only matches the encoded path, to confirm
    // we're escaping characters that would otherwise reroute the
    // request. A correlation_id with a `/` in it would otherwise
    // hit a different route.
    let app = Router::new().route(
        // Axum captures the literal "a%2Fb" segment because we
        // declare the path that way; with a naive (non-encoded)
        // SDK, the request would hit /audit/correlation/a/b instead
        // and 404. Confirms the encoder is on the request path.
        "/audit/correlation/{cid}",
        get(|Path(cid): Path<String>| async move {
            // axum decodes percent escapes before handing us `cid`,
            // so we see "a/b" here, and we rely on the route not
            // having matched something else first.
            assert_eq!(cid, "a/b");
            Json(json!([])).into_response()
        }),
    );
    let (url, shutdown) = spawn(app).await;

    let ledger = LedgerClient::new(&url).unwrap();
    let rows = ledger.audit_correlation("a/b").await.expect("audit");
    assert!(rows.is_empty());
    drop(shutdown);
}

#[tokio::test]
async fn audit_agent_paged_forwards_limit_and_offset() {
    // Server captures the query string into a HashMap so we can assert
    // the SDK puts the right values on the wire. Returning a constant
    // body keeps the test focused on URL construction.
    let app = Router::new().route(
        "/audit/{agent_id}",
        get(|Path(_aid): Path<String>, Query(q): Query<HashMap<String, String>>| async move {
            assert_eq!(q.get("limit").map(String::as_str), Some("25"));
            assert_eq!(q.get("offset").map(String::as_str), Some("50"));
            Json(json!([])).into_response()
        }),
    );
    let (url, shutdown) = spawn(app).await;

    let ledger = LedgerClient::new(&url).unwrap();
    let rows = ledger
        .audit_agent_paged("demo-bot", 25, 50)
        .await
        .expect("paged");
    assert!(rows.is_empty());
    drop(shutdown);
}

#[tokio::test]
async fn audit_agent_count_decodes_count_field() {
    let app = Router::new().route(
        "/audit/{agent_id}/count",
        get(|Path(aid): Path<String>| async move {
            assert_eq!(aid, "demo-bot");
            Json(json!({ "count": 1234 }))
        }),
    );
    let (url, shutdown) = spawn(app).await;

    let ledger = LedgerClient::new(&url).unwrap();
    let n = ledger.audit_agent_count("demo-bot").await.expect("count");
    assert_eq!(n, 1234);
    drop(shutdown);
}

#[tokio::test]
async fn list_exports_decodes_export_records() {
    // Mirror the ledger's GET /exports payload — newest-first array
    // of ExportRecord objects. Confirms the wire-mirror struct on the
    // SDK side decodes cleanly against a real HTTP response.
    let app = Router::new().route(
        "/exports",
        get(|| async {
            Json(json!([
                {
                    "snapshot_id": "550e8400-e29b-41d4-a716-446655440000",
                    "written_at": "2026-05-04T08:00:00Z",
                    "data_uri": "file:///snap/v2.parquet",
                    "manifest_uri": "file:///snap/v2.manifest.json",
                    "data_sha256": "f".repeat(64),
                    "byte_size": 2048,
                    "row_count": 100,
                    "seq_lo": 51,
                    "seq_hi": 150
                },
                {
                    "snapshot_id": "660f9511-f3ac-52e5-b827-557766551111",
                    "written_at": "2026-05-03T08:00:00Z",
                    "data_uri": "file:///snap/v1.parquet",
                    "manifest_uri": "file:///snap/v1.manifest.json",
                    "data_sha256": "e".repeat(64),
                    "byte_size": 1024,
                    "row_count": 50,
                    "seq_lo": 1,
                    "seq_hi": 50
                }
            ]))
        }),
    );
    let (url, shutdown) = spawn(app).await;

    let ledger = LedgerClient::new(&url).unwrap();
    let rows = ledger.list_exports().await.expect("exports");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].row_count, 100);
    assert_eq!(rows[0].seq_lo, 51);
    assert_eq!(rows[1].row_count, 50);
    drop(shutdown);
}

// ── PoliciesClient (warden-specs/TECH_SPEC.md
//    #console-policy-management) ───────────────────────────────────────

#[tokio::test]
async fn policies_list_decodes_into_typed_rows() {
    use warden_sdk::PoliciesClient;
    let app = Router::new().route(
        "/policies",
        get(|| async {
            (
                StatusCode::OK,
                Json(json!({
                    "policies": [
                        {
                            "name": "governance.rego",
                            "content_type": "rego",
                            "active": true,
                            "current_version": 3,
                            "deleted_at": null,
                            "created_at": "2026-05-08T00:00:00Z",
                            "updated_at": "2026-05-08T01:00:00Z"
                        },
                        {
                            "name": "attestation_allowlist.json",
                            "content_type": "json",
                            "active": true,
                            "current_version": 1,
                            "deleted_at": null,
                            "created_at": "2026-05-08T00:00:00Z",
                            "updated_at": "2026-05-08T00:00:00Z"
                        }
                    ]
                })),
            )
                .into_response()
        }),
    );
    let (url, shutdown) = spawn(app).await;
    let client = PoliciesClient::new(&url).unwrap();
    let rows = client.list(false).await.expect("list");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].name, "governance.rego");
    assert_eq!(rows[0].current_version, 3);
    assert_eq!(rows[1].content_type, "json");
    drop(shutdown);
}

#[tokio::test]
async fn policies_create_round_trips_typed_request_and_response() {
    use warden_sdk::{CreatePolicyRequest, PoliciesClient};
    let app = Router::new().route(
        "/policies",
        post(|Json(body): Json<Value>| async move {
            // Assert the SDK serialised every field correctly so a
            // future server-side rename surfaces here.
            assert_eq!(body["name"], "extra.rego");
            assert_eq!(body["content_type"], "rego");
            assert_eq!(body["reason"], "test");
            assert_eq!(body["actor_sub"], "alice");
            assert_eq!(body["actor_idp"], "oidc:test");
            (
                StatusCode::CREATED,
                Json(json!({
                    "name": "extra.rego",
                    "version": 1,
                    "body_sha256": "deadbeef",
                    "current_version": 1,
                    "active": true,
                    "event_kind": "policy.created"
                })),
            )
                .into_response()
        }),
    );
    let (url, shutdown) = spawn(app).await;
    let client = PoliciesClient::new(&url).unwrap();
    let resp = client
        .create(&CreatePolicyRequest {
            name: "extra.rego",
            content_type: "rego",
            body: "package warden.authz\nimport rego.v1\ndefault allow := false",
            reason: "test",
            actor_sub: "alice",
            actor_idp: "oidc:test",
        })
        .await
        .expect("create");
    assert_eq!(resp.event_kind, "policy.created");
    assert_eq!(resp.version, 1);
    drop(shutdown);
}

#[tokio::test]
async fn policies_update_409_carries_conflict_response() {
    use warden_sdk::{PoliciesClient, UpdatePolicyRequest};
    let app = Router::new().route(
        "/policies/{name}",
        axum::routing::put(|Path(_n): Path<String>| async {
            (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "version_conflict",
                    "policy": {
                        "name": "governance.rego",
                        "content_type": "rego",
                        "active": true,
                        "current_version": 7,
                        "deleted_at": null,
                        "created_at": "2026-05-08T00:00:00Z",
                        "updated_at": "2026-05-08T05:00:00Z"
                    }
                })),
            )
                .into_response()
        }),
    );
    let (url, shutdown) = spawn(app).await;
    let client = PoliciesClient::new(&url).unwrap();
    // `WardenClient` doesn't impl `Debug`, so `expect_err` would
    // need a `Debug` bound on the success arm. The `match` form is
    // both `Debug`-free and clippy-happy.
    let result = client
        .update(
            "governance.rego",
            &UpdatePolicyRequest {
                body: "package warden.authz\ndefault allow := false",
                reason: "test",
                actor_sub: "alice",
                actor_idp: "oidc:test",
                expected_current_version: 1,
            },
        )
        .await;
    let err = match result {
        Ok(_) => panic!("expected 409"),
        Err(e) => e,
    };
    let WardenError::Server { status, body } = err else {
        panic!("expected Server, got {err}");
    };
    assert_eq!(status, StatusCode::CONFLICT);
    let conflict = PoliciesClient::parse_conflict(&body).expect("parse_conflict");
    assert_eq!(conflict.error, "version_conflict");
    assert_eq!(conflict.policy.current_version, 7);
    drop(shutdown);
}

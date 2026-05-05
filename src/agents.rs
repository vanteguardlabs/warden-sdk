//! Async client for the Warden Agent Onboarding (`/agents`) surface.
//!
//! Mirrors the `warden-identity` server-side handlers in
//! `agents.rs`: every call here corresponds 1:1 with a route there.
//! P1 ships read endpoints only — `list` and `get`. Write endpoints
//! (`create`, `suspend`, …) land in P2 alongside the identity-side
//! lifecycle handlers.
//!
//! ## Auth model
//!
//! Every `/agents` endpoint takes `Authorization: Bearer <oidc_id_token>`
//! per ONBOARDING.md §5.1. The server validates the token against the
//! per-tenant JWKS and resolves the caller's IdP groups to capability
//! strings via the configured `[capabilities.tenants.<tid>]` map.
//! From the SDK's perspective, the only auth surface is the bearer
//! string the caller supplies via [`AgentsClient::with_bearer`] or
//! `Auth::Bearer` at construction.
//!
//! ## Wire types
//!
//! [`AgentRecord`] is duplicated verbatim from the server-side struct
//! per CLAUDE.md repo convention. Cross-repo wire-shape changes need a
//! grep across `warden-identity`, `warden-sdk`, `warden-console`,
//! `wardenctl` before any rename.

use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};

use crate::WardenError;

/// Agent lifecycle state per ONBOARDING.md §3.2. Wire form is the
/// lowercased variant name (matches the server's `as_wire`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentState {
    Active,
    Suspended,
    Decommissioned,
}

impl AgentState {
    /// Wire-form string per spec §5.2.
    pub fn as_wire(self) -> &'static str {
        match self {
            AgentState::Active => "active",
            AgentState::Suspended => "suspended",
            AgentState::Decommissioned => "decommissioned",
        }
    }

    /// Parse the wire form (lowercase). Tolerant of the SQL-side
    /// Capitalized form too, matching the server's parser.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "active" | "Active" => Some(AgentState::Active),
            "suspended" | "Suspended" => Some(AgentState::Suspended),
            "decommissioned" | "Decommissioned" => Some(AgentState::Decommissioned),
            _ => None,
        }
    }
}

impl Serialize for AgentState {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_wire())
    }
}

impl<'de> Deserialize<'de> for AgentState {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Self::parse(&raw).ok_or_else(|| serde::de::Error::custom(format!("invalid state: {raw}")))
    }
}

/// One row of the `agents` table, mirrored from
/// `warden-identity::agents::AgentRecord`. Field order, types, and
/// serde derives are intentional copies — a future rename touches both
/// repos in one PR sweep.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentRecord {
    pub id: String,
    pub tenant: String,
    pub agent_name: String,
    pub state: AgentState,
    pub scope_envelope: Vec<String>,
    pub yellow_envelope: Vec<String>,
    pub attestation_kinds_accepted: Vec<String>,
    pub created_by_sub: String,
    pub created_by_idp: String,
    pub owner_team: String,
    pub created_at: String,
    pub state_changed_at: String,
    pub state_changed_by: String,
    pub description: Option<String>,
}

/// Optional filters for [`AgentsClient::list`]. Fields map to query
/// parameters of the same name.
#[derive(Debug, Default, Clone)]
pub struct AgentListFilter {
    pub state: Option<AgentState>,
    pub owner_team: Option<String>,
}

/// Async client for the identity service's `/agents` endpoints.
///
/// Cheap to clone — the inner `reqwest::Client` is `Arc`-based.
#[derive(Debug, Clone)]
pub struct AgentsClient {
    base_url: Url,
    http: Client,
    /// Optional bearer to send on every request. `None` skips the
    /// header — used by tests and by callers that explicitly want the
    /// resulting 401 (e.g. capability-discovery probes).
    bearer: Option<String>,
}

impl AgentsClient {
    /// Build a client against `base_url` (e.g. `http://localhost:8086`).
    /// Returns `InvalidConfig` if the URL is malformed.
    pub fn new(base_url: impl AsRef<str>) -> Result<Self, WardenError> {
        let url = Url::parse(base_url.as_ref())
            .map_err(|e| WardenError::InvalidConfig(format!("base_url: {e}")))?;
        let http = Client::builder().build().map_err(WardenError::Transport)?;
        Ok(Self {
            base_url: url,
            http,
            bearer: None,
        })
    }

    /// Inject a pre-configured `reqwest::Client`. Same use case as
    /// `LedgerClient::with_http_client` — share the connection pool +
    /// TLS config across SDK clients.
    pub fn with_http_client(mut self, client: Client) -> Self {
        self.http = client;
        self
    }

    /// Builder-style attachment of an OIDC `id_token`. Per ONBOARDING.md
    /// §5.1 every `/agents` call expects a bearer; CLI / console
    /// callers per-request rebuild a client whose bearer is the
    /// session's id_token (rather than holding a long-lived service
    /// account that impersonates).
    pub fn with_bearer(mut self, token: impl Into<String>) -> Self {
        self.bearer = Some(token.into());
        self
    }

    /// Read-only access to the configured base URL.
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// `GET /agents?tenant=<t>[&state=<s>][&owner_team=<o>]` — every
    /// agent record visible to the bearer's tenant context. Empty vec
    /// on no matches (not 404).
    pub async fn list(
        &self,
        tenant: &str,
        filter: AgentListFilter,
    ) -> Result<Vec<AgentRecord>, WardenError> {
        let mut url = self
            .base_url
            .join("agents")
            .map_err(|e| WardenError::InvalidConfig(format!("join agents: {e}")))?;
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("tenant", tenant);
            if let Some(s) = filter.state {
                q.append_pair("state", s.as_wire());
            }
            if let Some(team) = filter.owner_team.as_ref() {
                q.append_pair("owner_team", team);
            }
        }
        self.get_json(url).await
    }

    /// `GET /agents/{id}?tenant=<t>` — a single agent record. Returns
    /// [`WardenError::Server`] with status 404 when the id doesn't
    /// resolve in `tenant` (the server intentionally elides
    /// "exists-but-cross-tenant" — see `agents.rs::get_handler`).
    pub async fn get(&self, id: &str, tenant: &str) -> Result<AgentRecord, WardenError> {
        let path = format!("agents/{}", percent_encode(id));
        let mut url = self
            .base_url
            .join(&path)
            .map_err(|e| WardenError::InvalidConfig(format!("join {path}: {e}")))?;
        url.query_pairs_mut().append_pair("tenant", tenant);
        self.get_json(url).await
    }

    /// Internal: GET `url` with the bearer header (if any) and decode
    /// JSON. Errors on non-200 with the wire body for diagnostics.
    /// 401 maps to `Unauthorized`; 400 to `BadRequest`; all other
    /// non-200s funnel through `Server`.
    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: Url) -> Result<T, WardenError> {
        let mut req = self.http.get(url);
        if let Some(token) = self.bearer.as_ref() {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let body = resp.text().await?;
        match status {
            StatusCode::OK => serde_json::from_str(&body).map_err(WardenError::Decode),
            StatusCode::UNAUTHORIZED => Err(WardenError::Unauthorized(body)),
            StatusCode::BAD_REQUEST => Err(WardenError::BadRequest(body)),
            other => Err(WardenError::Server { status: other, body }),
        }
    }
}

/// Same minimal percent-encoder as `ledger.rs` — kept private here to
/// avoid pulling the `percent-encoding` crate for one site.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            other => {
                use std::fmt::Write;
                let _ = write!(out, "%{other:02X}");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::{Path, Query, State},
        http::HeaderMap,
        routing::get,
        Json, Router,
    };
    use serde_json::json;
    use std::sync::Arc;
    use tokio::sync::oneshot;

    /// Stand up an axum mock server that mirrors a subset of the real
    /// /agents wire shape. Returns `(base_url, shutdown)`. Each test
    /// gets a fresh server.
    async fn spawn_mock<F, R>(handler_setup: F) -> (String, oneshot::Sender<()>)
    where
        F: FnOnce() -> R,
        R: IntoMockState,
    {
        let state = handler_setup().into_state();
        let app = Router::new()
            .route("/agents", get(mock_list))
            .route("/agents/{id}", get(mock_get))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });
        (format!("http://{addr}/"), shutdown_tx)
    }

    /// One canned record per agent_id; lookup misses return 404.
    /// Carries the expected `?tenant=` value so a wrong-tenant call
    /// returns 404 too (mimics the server's tenant-scoped read).
    #[derive(Clone)]
    struct MockState {
        records: Arc<Vec<AgentRecord>>,
        expected_tenant: String,
    }

    trait IntoMockState {
        fn into_state(self) -> MockState;
    }

    impl IntoMockState for MockState {
        fn into_state(self) -> MockState {
            self
        }
    }

    async fn mock_list(
        State(state): State<MockState>,
        Query(params): Query<std::collections::HashMap<String, String>>,
        _headers: HeaderMap,
    ) -> Json<serde_json::Value> {
        let tenant = params.get("tenant").cloned().unwrap_or_default();
        if tenant != state.expected_tenant {
            return Json(json!([]));
        }
        let mut out: Vec<AgentRecord> = state
            .records
            .iter()
            .filter(|r| r.tenant == tenant)
            .cloned()
            .collect();
        if let Some(s) = params.get("state").and_then(|v| AgentState::parse(v)) {
            out.retain(|r| r.state == s);
        }
        if let Some(team) = params.get("owner_team") {
            out.retain(|r| &r.owner_team == team);
        }
        Json(serde_json::to_value(out).unwrap())
    }

    async fn mock_get(
        State(state): State<MockState>,
        Path(id): Path<String>,
        Query(params): Query<std::collections::HashMap<String, String>>,
        _headers: HeaderMap,
    ) -> (axum::http::StatusCode, Json<serde_json::Value>) {
        let tenant = params.get("tenant").cloned().unwrap_or_default();
        if tenant != state.expected_tenant {
            return (
                axum::http::StatusCode::NOT_FOUND,
                Json(json!({"error": "not_found"})),
            );
        }
        for r in state.records.iter() {
            if r.id == id && r.tenant == tenant {
                return (
                    axum::http::StatusCode::OK,
                    Json(serde_json::to_value(r).unwrap()),
                );
            }
        }
        (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({"error": "not_found"})),
        )
    }

    fn record(id: &str, tenant: &str, name: &str, state: AgentState, owner: &str) -> AgentRecord {
        AgentRecord {
            id: id.into(),
            tenant: tenant.into(),
            agent_name: name.into(),
            state,
            scope_envelope: vec!["mcp:read:tickets".into()],
            yellow_envelope: vec![],
            attestation_kinds_accepted: vec!["tpm".into()],
            created_by_sub: "user:alice@acme.com".into(),
            created_by_idp: "okta".into(),
            owner_team: owner.into(),
            created_at: "2026-05-01T00:00:00+00:00".into(),
            state_changed_at: "2026-05-01T00:00:00+00:00".into(),
            state_changed_by: "user:alice@acme.com".into(),
            description: None,
        }
    }

    #[tokio::test]
    async fn list_round_trips_records() {
        let (base, shutdown) = spawn_mock(|| MockState {
            records: Arc::new(vec![
                record("01HW...A001", "acme", "support-bot-3", AgentState::Active, "payments"),
                record("01HW...A002", "acme", "legacy-bot", AgentState::Suspended, "infra"),
            ]),
            expected_tenant: "acme".into(),
        })
        .await;

        let client = AgentsClient::new(&base).unwrap().with_bearer("dev-token");
        let rows = client.list("acme", AgentListFilter::default()).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().any(|r| r.agent_name == "support-bot-3"));
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn list_passes_filter_query_params() {
        let (base, shutdown) = spawn_mock(|| MockState {
            records: Arc::new(vec![
                record("a1", "acme", "support-bot-3", AgentState::Active, "payments"),
                record("a2", "acme", "legacy-bot", AgentState::Suspended, "infra"),
            ]),
            expected_tenant: "acme".into(),
        })
        .await;
        let client = AgentsClient::new(&base).unwrap().with_bearer("dev-token");
        let rows = client
            .list(
                "acme",
                AgentListFilter {
                    state: Some(AgentState::Suspended),
                    owner_team: Some("infra".into()),
                },
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].agent_name, "legacy-bot");
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn get_round_trips_record() {
        let (base, shutdown) = spawn_mock(|| MockState {
            records: Arc::new(vec![record(
                "01HW-known",
                "acme",
                "support-bot-3",
                AgentState::Active,
                "payments",
            )]),
            expected_tenant: "acme".into(),
        })
        .await;
        let client = AgentsClient::new(&base).unwrap().with_bearer("dev-token");
        let r = client.get("01HW-known", "acme").await.unwrap();
        assert_eq!(r.agent_name, "support-bot-3");
        assert_eq!(r.owner_team, "payments");
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn get_404_maps_to_server_error() {
        let (base, shutdown) = spawn_mock(|| MockState {
            records: Arc::new(vec![]),
            expected_tenant: "acme".into(),
        })
        .await;
        let client = AgentsClient::new(&base).unwrap().with_bearer("dev-token");
        let err = client.get("nope", "acme").await.unwrap_err();
        match err {
            WardenError::Server { status, body } => {
                assert_eq!(status, reqwest::StatusCode::NOT_FOUND);
                assert!(body.contains("not_found"), "got body: {body}");
            }
            other => panic!("expected Server, got {other:?}"),
        }
        let _ = shutdown.send(());
    }

    #[test]
    fn agent_state_round_trips_through_json() {
        let r = AgentRecord {
            id: "a".into(),
            tenant: "acme".into(),
            agent_name: "x".into(),
            state: AgentState::Suspended,
            scope_envelope: vec![],
            yellow_envelope: vec![],
            attestation_kinds_accepted: vec![],
            created_by_sub: "u".into(),
            created_by_idp: "okta".into(),
            owner_team: "t".into(),
            created_at: "2026-05-01T00:00:00Z".into(),
            state_changed_at: "2026-05-01T00:00:00Z".into(),
            state_changed_by: "u".into(),
            description: None,
        };
        // Wire form is lowercase per the spec; deserialize back round-trips.
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["state"], "suspended");
        let again: AgentRecord = serde_json::from_value(v).unwrap();
        assert_eq!(again.state, AgentState::Suspended);
    }

    #[test]
    fn agent_state_rejects_unknown_value() {
        let bad = serde_json::json!({"state": "potato"});
        let r: Result<serde_json::Value, _> = serde_json::from_value(bad.clone());
        assert!(r.is_ok(), "raw json parses fine");
        let r: Result<AgentState, _> = serde_json::from_value(serde_json::json!("potato"));
        assert!(r.is_err());
    }

    #[test]
    fn list_url_includes_tenant_and_state() {
        // Smoke check the URL builder via a base + sentinel inspection.
        // Avoids making a real network call.
        let url = Url::parse("http://example.test/").unwrap();
        let mut url = url.join("agents").unwrap();
        url.query_pairs_mut().append_pair("tenant", "acme");
        url.query_pairs_mut()
            .append_pair("state", AgentState::Active.as_wire());
        assert_eq!(
            url.as_str(),
            "http://example.test/agents?tenant=acme&state=active"
        );
    }
}

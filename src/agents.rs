//! Async client for the Warden Agent Onboarding (`/agents`) surface.
//!
//! Mirrors the `warden-identity` server-side handlers in
//! `agents.rs`: every call here corresponds 1:1 with a route there.
//! P2 ships the full lifecycle surface — `list`, `get`, `create`,
//! `suspend` / `unsuspend` / `decommission`, `envelope_narrow` /
//! `envelope_widen`, `attestation_kinds`, `transfer_owner_team`,
//! `set_description`, plus the helper `find_by_name` used by
//! `wardenctl agents create --if-absent` for idempotent IaC patterns.
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

/// Spec §5.2 — `POST /agents` request body. Borrowed-string fields
/// so the CLI / console can pass slices off the parsed args without
/// allocating; `Vec<String>` for the multi-value envelopes for the
/// same reason (`Cow<'_, [String]>` would let callers pass slices,
/// but multi-value clap args produce owned vecs anyway).
#[derive(Debug, Clone, Serialize)]
pub struct CreateAgentRequest<'a> {
    pub tenant: &'a str,
    pub agent_name: &'a str,
    pub owner_team: &'a str,
    #[serde(default)]
    pub scope_envelope: Vec<String>,
    #[serde(default)]
    pub yellow_envelope: Vec<String>,
    #[serde(default)]
    pub attestation_kinds: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<&'a str>,
    /// Spec §7.3 / P5 migration override. The migration CLI sets this to
    /// `system:migration:<operator_oidc_sub>` so the row's
    /// `created_by_sub` reflects bulk-enroll instead of the operator's
    /// own sub. Identity rejects any other prefix with
    /// `actor_sub_prefix_not_allowed`. `skip_serializing_if = None` keeps
    /// the wire shape identical for the common (non-migration) case.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_sub: Option<&'a str>,
}

/// Wire constant for the migration `actor_sub` prefix — must match
/// `warden-identity::agents::MIGRATION_ACTOR_SUB_PREFIX`. Duplicated
/// because there's no shared crate, per CLAUDE.md repo convention.
pub const MIGRATION_ACTOR_SUB_PREFIX: &str = "system:migration:";

/// Response shape for `POST /agents`: the registered record plus the
/// `spiffe_id_pattern` field. `flatten` mirrors the server's
/// `CreateAgentResponse` so callers can read `created.id` /
/// `created.state` directly off the top level.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AgentCreated {
    #[serde(flatten)]
    pub record: AgentRecord,
    pub spiffe_id_pattern: String,
}

/// Body for `POST /agents/{id}/envelope/narrow|widen`. Caller
/// supplies the *full new envelope* — the server diffs against the
/// current row and rejects on direction violation. Borrowed slices
/// to match `CreateAgentRequest`.
#[derive(Debug, Clone, Serialize)]
pub struct EnvelopeRequest<'a> {
    pub scope_envelope: &'a [String],
    pub yellow_envelope: &'a [String],
}

/// Request shape for the suspend / unsuspend / decommission
/// endpoints. `reason` is optional per spec §5.2.
#[derive(Debug, Clone, Serialize)]
pub struct LifecycleRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'a str>,
}

/// Response shape for the three state-machine endpoints — spec §5.2
/// "return `{ state, state_changed_at }`".
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct LifecycleResponse {
    pub state: AgentState,
    pub state_changed_at: String,
}

/// Compare a [`CreateAgentRequest`] against an existing
/// [`AgentRecord`] for the `wardenctl agents create --if-absent`
/// idempotency check. Returns `true` when the request would land the
/// row already in place (envelopes equal as sets, owner_team and
/// attestation_kinds match) — the CLI exits 0 in that case rather
/// than re-POSTing. Set semantics: order doesn't matter, duplicates
/// don't matter (the server canonicalizes both into sorted JSON
/// arrays in storage).
pub fn create_request_matches(req: &CreateAgentRequest<'_>, record: &AgentRecord) -> bool {
    if req.tenant != record.tenant
        || req.agent_name != record.agent_name
        || req.owner_team != record.owner_team
    {
        return false;
    }
    if !same_set(&req.scope_envelope, &record.scope_envelope)
        || !same_set(&req.yellow_envelope, &record.yellow_envelope)
        || !same_set(&req.attestation_kinds, &record.attestation_kinds_accepted)
    {
        return false;
    }
    // Description is intentionally not part of idempotency check —
    // operators routinely tweak descriptions without wanting the IaC
    // job to re-trip a 409. The CLI surfaces description as a
    // separate `wardenctl agents description` step.
    true
}

/// Order-insensitive, duplicate-insensitive equality on
/// `Vec<String>`. Sorted-clone comparison rather than a `HashSet`
/// pass to keep the helper allocation-light for the typical 1–10
/// element envelopes — both list_a and list_b are short.
fn same_set(a: &[String], b: &[String]) -> bool {
    let mut a: Vec<&str> = a.iter().map(String::as_str).collect();
    let mut b: Vec<&str> = b.iter().map(String::as_str).collect();
    a.sort_unstable();
    a.dedup();
    b.sort_unstable();
    b.dedup();
    a == b
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

    /// `true` when a bearer was attached via [`AgentsClient::with_bearer`].
    /// Used by warden-console's `/config` page to render
    /// `configured (sha256: ab12cd34)` vs `unset` without ever copying the
    /// raw token into handler scope. See also [`bearer_fingerprint`].
    ///
    /// [`bearer_fingerprint`]: AgentsClient::bearer_fingerprint
    pub fn has_bearer(&self) -> bool {
        self.bearer.is_some()
    }

    /// Non-invertible presence indicator for the attached bearer.
    /// Returns the first 8 hex characters of `sha256(token)` when a
    /// bearer is set, or `None` when unset (so `is_some()` doubles as
    /// the presence check — `has_bearer` is the more readable alias).
    ///
    /// **Redact-by-architecture.** The console renders this string
    /// directly; the raw token never leaves the SDK. SHA-256 with a
    /// 4-byte (8 hex char) prefix has ~4 billion possible values —
    /// enough to fingerprint "is this the same token I configured
    /// last week?" but not enough to recover the token itself.
    pub fn bearer_fingerprint(&self) -> Option<String> {
        // Manual hex format avoids pulling the `hex` crate just for
        // 4 bytes of formatting. `sha2::Sha256::digest` returns a
        // 32-byte `GenericArray`; we only need the first 4.
        use sha2::{Digest, Sha256};
        let token = self.bearer.as_ref()?;
        let digest = Sha256::digest(token.as_bytes());
        let mut out = String::with_capacity(8);
        for byte in &digest[..4] {
            use std::fmt::Write;
            let _ = write!(out, "{byte:02x}");
        }
        Some(out)
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

    /// Look up a record by `(tenant, agent_name)`. Used by
    /// `wardenctl agents create --if-absent` to decide between
    /// "create a new row" and "compare against existing." Returns
    /// `Ok(None)` when no match — distinct from a 404 for an unknown
    /// id, which surfaces as `Err(Server)`.
    pub async fn find_by_name(
        &self,
        tenant: &str,
        agent_name: &str,
    ) -> Result<Option<AgentRecord>, WardenError> {
        // The server doesn't expose `?agent_name=` so we filter
        // client-side. The list is bounded by tenant, which keeps
        // worst-case fan-out tied to a single tenant's registration
        // count — fine for IaC-shaped workflows (1-1000 rows).
        let rows = self.list(tenant, AgentListFilter::default()).await?;
        Ok(rows.into_iter().find(|r| r.agent_name == agent_name))
    }

    /// `POST /agents` — register a new agent. Body shape mirrors
    /// `warden-identity::agents::CreateAgentRequest` (spec §5.2).
    /// Returns the full record with the `spiffe_id_pattern` field
    /// surfaced under the same envelope.
    pub async fn create(&self, req: &CreateAgentRequest<'_>) -> Result<AgentCreated, WardenError> {
        let url = self.join("agents")?;
        self.post_json(url, req).await
    }

    /// `POST /agents/{id}/suspend` (spec §5.1). Owner-team or
    /// `agents:admin`.
    pub async fn suspend(
        &self,
        id: &str,
        tenant: &str,
        reason: Option<&str>,
    ) -> Result<LifecycleResponse, WardenError> {
        self.lifecycle_call(id, tenant, "suspend", reason).await
    }

    /// `POST /agents/{id}/unsuspend` (spec §5.1). Admin only.
    pub async fn unsuspend(
        &self,
        id: &str,
        tenant: &str,
        reason: Option<&str>,
    ) -> Result<LifecycleResponse, WardenError> {
        self.lifecycle_call(id, tenant, "unsuspend", reason).await
    }

    /// `POST /agents/{id}/decommission` (spec §5.1). Admin only,
    /// terminal — the row is preserved but its `(tenant, agent_name)`
    /// is permanently unreusable.
    pub async fn decommission(
        &self,
        id: &str,
        tenant: &str,
        reason: Option<&str>,
    ) -> Result<LifecycleResponse, WardenError> {
        self.lifecycle_call(id, tenant, "decommission", reason).await
    }

    /// `POST /agents/{id}/envelope/narrow`. Caller passes the *full
    /// new envelope*, not a diff (spec §5.2).
    pub async fn envelope_narrow(
        &self,
        id: &str,
        tenant: &str,
        envelope: EnvelopeRequest<'_>,
    ) -> Result<AgentRecord, WardenError> {
        let url = self.id_with_tenant(id, "envelope/narrow", tenant)?;
        self.post_json(url, &envelope).await
    }

    /// `POST /agents/{id}/envelope/widen`. Admin only.
    pub async fn envelope_widen(
        &self,
        id: &str,
        tenant: &str,
        envelope: EnvelopeRequest<'_>,
    ) -> Result<AgentRecord, WardenError> {
        let url = self.id_with_tenant(id, "envelope/widen", tenant)?;
        self.post_json(url, &envelope).await
    }

    /// `POST /agents/{id}/attestation-kinds`. Auth dispatched per
    /// direction (narrow = owner-team-or-admin; widen = admin only).
    pub async fn attestation_kinds(
        &self,
        id: &str,
        tenant: &str,
        kinds: &[String],
    ) -> Result<AgentRecord, WardenError> {
        let url = self.id_with_tenant(id, "attestation-kinds", tenant)?;
        let body = serde_json::json!({ "attestation_kinds": kinds });
        self.post_json(url, &body).await
    }

    /// `POST /agents/{id}/owner-team`. Admin only.
    pub async fn transfer_owner_team(
        &self,
        id: &str,
        tenant: &str,
        new_team: &str,
    ) -> Result<AgentRecord, WardenError> {
        let url = self.id_with_tenant(id, "owner-team", tenant)?;
        let body = serde_json::json!({ "owner_team": new_team });
        self.post_json(url, &body).await
    }

    /// `POST /agents/{id}/description`. Owner-team or admin. Pass
    /// `None` for `text` to clear the description.
    pub async fn set_description(
        &self,
        id: &str,
        tenant: &str,
        text: Option<&str>,
    ) -> Result<AgentRecord, WardenError> {
        let url = self.id_with_tenant(id, "description", tenant)?;
        let body = serde_json::json!({ "description": text });
        self.post_json(url, &body).await
    }

    /// Build a URL of the form `agents/{id}/<verb>?tenant=<t>`. The
    /// `verb` is appended verbatim — callers pass it as a constant
    /// (`"suspend"`, `"envelope/narrow"`, …) so the path-segment
    /// boundaries can't be confused.
    fn id_with_tenant(&self, id: &str, verb: &str, tenant: &str) -> Result<Url, WardenError> {
        let path = format!("agents/{}/{}", percent_encode(id), verb);
        let mut url = self
            .base_url
            .join(&path)
            .map_err(|e| WardenError::InvalidConfig(format!("join {path}: {e}")))?;
        url.query_pairs_mut().append_pair("tenant", tenant);
        Ok(url)
    }

    /// Relative path joiner used by writes that take their tenant in
    /// the body (currently just `POST /agents`).
    fn join(&self, suffix: &str) -> Result<Url, WardenError> {
        self.base_url
            .join(suffix)
            .map_err(|e| WardenError::InvalidConfig(format!("join {suffix}: {e}")))
    }

    async fn lifecycle_call(
        &self,
        id: &str,
        tenant: &str,
        verb: &str,
        reason: Option<&str>,
    ) -> Result<LifecycleResponse, WardenError> {
        let url = self.id_with_tenant(id, verb, tenant)?;
        let body = LifecycleRequest { reason };
        self.post_json(url, &body).await
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
        decode_response(status, body)
    }

    /// Internal: POST `url` with the bearer + JSON body, decode the
    /// response. Accepts 200 *and* 201 as success since the create
    /// endpoint emits 201 (spec §5.2 example shows 200; the server
    /// settled on 201 to match REST conventions — both shapes are
    /// in-band the same `T`).
    async fn post_json<B: Serialize, T: serde::de::DeserializeOwned>(
        &self,
        url: Url,
        body: &B,
    ) -> Result<T, WardenError> {
        let mut req = self.http.post(url).json(body);
        if let Some(token) = self.bearer.as_ref() {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let body = resp.text().await?;
        decode_response(status, body)
    }
}

/// Centralized status-code dispatch so `get_json` and `post_json`
/// never drift on what counts as a hit. 200 and 201 both map through
/// the JSON decoder; 4xx/5xx routes to typed errors.
fn decode_response<T: serde::de::DeserializeOwned>(
    status: StatusCode,
    body: String,
) -> Result<T, WardenError> {
    match status {
        StatusCode::OK | StatusCode::CREATED => {
            serde_json::from_str(&body).map_err(WardenError::Decode)
        }
        StatusCode::UNAUTHORIZED => Err(WardenError::Unauthorized(body)),
        StatusCode::BAD_REQUEST => Err(WardenError::BadRequest(body)),
        other => Err(WardenError::Server { status: other, body }),
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

    // ── P2: write-surface mock-server tests ──────────────────────────

    /// Mutable mock state — the write tests need to POST and read
    /// back. Wraps a `Mutex<Vec<AgentRecord>>` so the mock stays
    /// thread-friendly under axum's executor.
    #[derive(Clone)]
    struct WriteMockState {
        records: Arc<tokio::sync::Mutex<Vec<AgentRecord>>>,
    }

    fn fixture_record(name: &str) -> AgentRecord {
        AgentRecord {
            id: format!("01HW000-{name}"),
            tenant: "acme".into(),
            agent_name: name.into(),
            state: AgentState::Active,
            scope_envelope: vec!["mcp:read:tickets".into(), "mcp:write:tickets".into()],
            yellow_envelope: vec!["refund:<=50usd".into()],
            attestation_kinds_accepted: vec!["dev-mock".into()],
            created_by_sub: "user:alice@acme.com".into(),
            created_by_idp: "okta".into(),
            owner_team: "payments".into(),
            created_at: "2026-05-04T00:00:00Z".into(),
            state_changed_at: "2026-05-04T00:00:00Z".into(),
            state_changed_by: "user:alice@acme.com".into(),
            description: None,
        }
    }

    async fn spawn_write_mock(
        seeded: Vec<AgentRecord>,
    ) -> (String, oneshot::Sender<()>, WriteMockState) {
        let state = WriteMockState {
            records: Arc::new(tokio::sync::Mutex::new(seeded)),
        };
        let app = Router::new()
            .route("/agents", get(write_list).post(write_create))
            .route("/agents/{id}", get(write_get_one))
            .route("/agents/{id}/suspend", axum::routing::post(write_suspend))
            .route(
                "/agents/{id}/decommission",
                axum::routing::post(write_decommission),
            )
            .route(
                "/agents/{id}/owner-team",
                axum::routing::post(write_transfer),
            )
            .route(
                "/agents/{id}/envelope/narrow",
                axum::routing::post(write_narrow),
            )
            .with_state(state.clone());
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
        (format!("http://{addr}/"), shutdown_tx, state)
    }

    async fn write_list(
        State(state): State<WriteMockState>,
        Query(_params): Query<std::collections::HashMap<String, String>>,
        _headers: HeaderMap,
    ) -> Json<serde_json::Value> {
        let rows = state.records.lock().await.clone();
        Json(serde_json::to_value(rows).unwrap())
    }

    async fn write_get_one(
        State(state): State<WriteMockState>,
        Path(id): Path<String>,
        _headers: HeaderMap,
    ) -> (axum::http::StatusCode, Json<serde_json::Value>) {
        let rows = state.records.lock().await;
        for r in rows.iter() {
            if r.id == id {
                return (
                    axum::http::StatusCode::OK,
                    Json(serde_json::to_value(r).unwrap()),
                );
            }
        }
        (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({"error":"not_found"})),
        )
    }

    async fn write_create(
        State(state): State<WriteMockState>,
        _headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> (axum::http::StatusCode, Json<serde_json::Value>) {
        // Reject duplicate names with the spec error code so the
        // SDK tests can assert the typed `Server` mapping.
        let name = body["agent_name"].as_str().unwrap_or("").to_string();
        let mut rows = state.records.lock().await;
        if rows.iter().any(|r| r.agent_name == name) {
            return (
                axum::http::StatusCode::CONFLICT,
                Json(json!({"error":"agent_name_taken"})),
            );
        }
        // Build the record from request body; canned fields fill in
        // server-side defaults the real handler would compute.
        let record = AgentRecord {
            id: format!("01HW-mock-{name}"),
            tenant: body["tenant"].as_str().unwrap().into(),
            agent_name: name.clone(),
            state: AgentState::Active,
            scope_envelope: body["scope_envelope"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            yellow_envelope: body["yellow_envelope"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            attestation_kinds_accepted: body["attestation_kinds"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            created_by_sub: "user:test".into(),
            created_by_idp: "okta".into(),
            owner_team: body["owner_team"].as_str().unwrap_or("").into(),
            created_at: "2026-05-04T00:00:00Z".into(),
            state_changed_at: "2026-05-04T00:00:00Z".into(),
            state_changed_by: "user:test".into(),
            description: body["description"].as_str().map(String::from),
        };
        rows.push(record.clone());
        let response = json!({
            "id": record.id,
            "tenant": record.tenant,
            "agent_name": record.agent_name,
            "state": record.state.as_wire(),
            "scope_envelope": record.scope_envelope,
            "yellow_envelope": record.yellow_envelope,
            "attestation_kinds_accepted": record.attestation_kinds_accepted,
            "created_by_sub": record.created_by_sub,
            "created_by_idp": record.created_by_idp,
            "owner_team": record.owner_team,
            "created_at": record.created_at,
            "state_changed_at": record.state_changed_at,
            "state_changed_by": record.state_changed_by,
            "description": record.description,
            "spiffe_id_pattern":
                format!("spiffe://wd.test/tenant/{}/agent/{}/instance/*",
                    record.tenant, record.agent_name),
        });
        (axum::http::StatusCode::CREATED, Json(response))
    }

    async fn transition(
        state: WriteMockState,
        id: &str,
        target: AgentState,
    ) -> (axum::http::StatusCode, Json<serde_json::Value>) {
        let mut rows = state.records.lock().await;
        let Some(r) = rows.iter_mut().find(|r| r.id == id) else {
            return (
                axum::http::StatusCode::NOT_FOUND,
                Json(json!({"error":"not_found"})),
            );
        };
        if r.state == AgentState::Decommissioned && target != AgentState::Decommissioned {
            return (
                axum::http::StatusCode::CONFLICT,
                Json(json!({"error":"agent_decommissioned"})),
            );
        }
        r.state = target;
        r.state_changed_at = "2026-05-04T00:30:00Z".into();
        (
            axum::http::StatusCode::OK,
            Json(json!({
                "state": target.as_wire(),
                "state_changed_at": r.state_changed_at,
            })),
        )
    }

    async fn write_suspend(
        State(state): State<WriteMockState>,
        Path(id): Path<String>,
        _headers: HeaderMap,
        _body: axum::body::Bytes,
    ) -> (axum::http::StatusCode, Json<serde_json::Value>) {
        transition(state, &id, AgentState::Suspended).await
    }

    async fn write_decommission(
        State(state): State<WriteMockState>,
        Path(id): Path<String>,
        _headers: HeaderMap,
        _body: axum::body::Bytes,
    ) -> (axum::http::StatusCode, Json<serde_json::Value>) {
        transition(state, &id, AgentState::Decommissioned).await
    }

    async fn write_transfer(
        State(state): State<WriteMockState>,
        Path(id): Path<String>,
        _headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> (axum::http::StatusCode, Json<serde_json::Value>) {
        let team = body["owner_team"].as_str().unwrap_or("").to_string();
        let mut rows = state.records.lock().await;
        let Some(r) = rows.iter_mut().find(|r| r.id == id) else {
            return (
                axum::http::StatusCode::NOT_FOUND,
                Json(json!({"error":"not_found"})),
            );
        };
        r.owner_team = team;
        (
            axum::http::StatusCode::OK,
            Json(serde_json::to_value(r).unwrap()),
        )
    }

    async fn write_narrow(
        State(state): State<WriteMockState>,
        Path(id): Path<String>,
        _headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> (axum::http::StatusCode, Json<serde_json::Value>) {
        let new_scope: Vec<String> = body["scope_envelope"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let mut rows = state.records.lock().await;
        let Some(r) = rows.iter_mut().find(|r| r.id == id) else {
            return (
                axum::http::StatusCode::NOT_FOUND,
                Json(json!({"error":"not_found"})),
            );
        };
        // Server-side check: new ⊆ old.
        let old: std::collections::BTreeSet<&str> =
            r.scope_envelope.iter().map(String::as_str).collect();
        let new: std::collections::BTreeSet<&str> = new_scope.iter().map(String::as_str).collect();
        if !new.is_subset(&old) {
            let offenders: Vec<String> =
                new.difference(&old).map(|s| (*s).to_string()).collect();
            return (
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"error":"envelope_not_narrower","offenders":offenders})),
            );
        }
        r.scope_envelope = new_scope;
        (
            axum::http::StatusCode::OK,
            Json(serde_json::to_value(r).unwrap()),
        )
    }

    #[tokio::test]
    async fn create_round_trips() {
        let (base, shutdown, _state) = spawn_write_mock(vec![]).await;
        let client = AgentsClient::new(&base).unwrap().with_bearer("dev-token");
        let req = CreateAgentRequest {
            tenant: "acme",
            agent_name: "support-bot-3",
            owner_team: "payments",
            scope_envelope: vec!["mcp:read:tickets".into()],
            yellow_envelope: vec![],
            attestation_kinds: vec!["dev-mock".into()],
            description: Some("triage"),
            actor_sub: None,
        };
        let created = client.create(&req).await.unwrap();
        assert_eq!(created.record.agent_name, "support-bot-3");
        assert_eq!(created.record.state, AgentState::Active);
        assert!(created
            .spiffe_id_pattern
            .ends_with("/agent/support-bot-3/instance/*"));
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn create_409_maps_to_server_error() {
        let (base, shutdown, _state) =
            spawn_write_mock(vec![fixture_record("support-bot-3")]).await;
        let client = AgentsClient::new(&base).unwrap().with_bearer("dev-token");
        let req = CreateAgentRequest {
            tenant: "acme",
            agent_name: "support-bot-3",
            owner_team: "payments",
            scope_envelope: vec![],
            yellow_envelope: vec![],
            attestation_kinds: vec![],
            description: None,
            actor_sub: None,
        };
        let err = client.create(&req).await.unwrap_err();
        match err {
            crate::WardenError::Server { status, body } => {
                assert_eq!(status, reqwest::StatusCode::CONFLICT);
                assert!(body.contains("agent_name_taken"));
            }
            other => panic!("expected Server, got {other:?}"),
        }
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn suspend_and_decommission_chain() {
        let rec = fixture_record("support-bot-3");
        let id = rec.id.clone();
        let (base, shutdown, _state) = spawn_write_mock(vec![rec]).await;
        let client = AgentsClient::new(&base).unwrap().with_bearer("dev-token");
        let resp = client.suspend(&id, "acme", Some("incident")).await.unwrap();
        assert_eq!(resp.state, AgentState::Suspended);
        let resp = client
            .decommission(&id, "acme", Some("team disbanded"))
            .await
            .unwrap();
        assert_eq!(resp.state, AgentState::Decommissioned);
        // After decommission, suspend → 409 agent_decommissioned.
        let err = client.suspend(&id, "acme", None).await.unwrap_err();
        match err {
            crate::WardenError::Server { status, body } => {
                assert_eq!(status, reqwest::StatusCode::CONFLICT);
                assert!(body.contains("agent_decommissioned"));
            }
            other => panic!("expected Server, got {other:?}"),
        }
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn envelope_narrow_subset_succeeds_offenders_named_on_violation() {
        let rec = fixture_record("support-bot-3");
        let id = rec.id.clone();
        let (base, shutdown, _state) = spawn_write_mock(vec![rec]).await;
        let client = AgentsClient::new(&base).unwrap().with_bearer("dev-token");

        let smaller = vec!["mcp:read:tickets".into()];
        let yellow: Vec<String> = vec![];
        let updated = client
            .envelope_narrow(
                &id,
                "acme",
                EnvelopeRequest {
                    scope_envelope: &smaller,
                    yellow_envelope: &yellow,
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.scope_envelope, smaller);

        // Re-narrow with a scope that wasn't in the old envelope -
        // 422 with offender named.
        let bad = vec!["mcp:write:invoices".into()];
        let err = client
            .envelope_narrow(
                &id,
                "acme",
                EnvelopeRequest {
                    scope_envelope: &bad,
                    yellow_envelope: &yellow,
                },
            )
            .await
            .unwrap_err();
        match err {
            crate::WardenError::Server { status, body } => {
                assert_eq!(status, reqwest::StatusCode::UNPROCESSABLE_ENTITY);
                assert!(body.contains("envelope_not_narrower"));
                assert!(body.contains("mcp:write:invoices"));
            }
            other => panic!("expected Server, got {other:?}"),
        }
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn transfer_owner_team_round_trips() {
        let rec = fixture_record("support-bot-3");
        let id = rec.id.clone();
        let (base, shutdown, _state) = spawn_write_mock(vec![rec]).await;
        let client = AgentsClient::new(&base).unwrap().with_bearer("dev-token");
        let updated = client
            .transfer_owner_team(&id, "acme", "newteam")
            .await
            .unwrap();
        assert_eq!(updated.owner_team, "newteam");
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn find_by_name_returns_match_and_none() {
        let (base, shutdown, _state) =
            spawn_write_mock(vec![fixture_record("support-bot-3")]).await;
        let client = AgentsClient::new(&base).unwrap().with_bearer("dev-token");
        let found = client.find_by_name("acme", "support-bot-3").await.unwrap();
        assert!(found.is_some());
        let nope = client.find_by_name("acme", "no-such-bot").await.unwrap();
        assert!(nope.is_none());
        let _ = shutdown.send(());
    }

    #[test]
    fn create_request_serializes_migration_actor_sub_when_present() {
        // The migration CLI sets `actor_sub` to `system:migration:<sub>`;
        // identity validates the prefix and rejects anything else with
        // 403 actor_sub_prefix_not_allowed. Verify the wire body
        // round-trips the prefix byte-for-byte and skips the field for
        // the common case so the existing `/agents` callers stay clean.
        let mig = CreateAgentRequest {
            tenant: "acme",
            agent_name: "test-agent-007",
            owner_team: "payments",
            scope_envelope: vec!["mcp:read:tickets".into()],
            yellow_envelope: vec![],
            attestation_kinds: vec!["dev-mock".into()],
            description: None,
            actor_sub: Some("system:migration:user:alice@acme.com"),
        };
        let v = serde_json::to_value(&mig).unwrap();
        assert_eq!(
            v["actor_sub"], "system:migration:user:alice@acme.com",
            "migration prefix should ride on the wire when set",
        );

        let plain = CreateAgentRequest {
            tenant: "acme",
            agent_name: "test-agent-007",
            owner_team: "payments",
            scope_envelope: vec!["mcp:read:tickets".into()],
            yellow_envelope: vec![],
            attestation_kinds: vec!["dev-mock".into()],
            description: None,
            actor_sub: None,
        };
        let v = serde_json::to_value(&plain).unwrap();
        assert!(
            v.get("actor_sub").is_none(),
            "actor_sub must be omitted when None — keep the wire shape \
             identical for the common case",
        );

        // Spot-check the constant matches the prefix the test wrote.
        assert!(
            "system:migration:user:alice@acme.com".starts_with(MIGRATION_ACTOR_SUB_PREFIX),
            "constant must agree with wire usage",
        );
    }

    #[test]
    fn bearer_fingerprint_none_when_unset() {
        let client = AgentsClient::new("http://example.test/").unwrap();
        assert!(!client.has_bearer());
        assert!(client.bearer_fingerprint().is_none());
    }

    #[test]
    fn bearer_fingerprint_is_stable_and_8_hex_chars() {
        // Stable: the same token always produces the same fingerprint.
        // The console renders this string directly, so a non-deterministic
        // hash would make every page-load look like a credential rotation.
        let a = AgentsClient::new("http://example.test/")
            .unwrap()
            .with_bearer("dev-token");
        let b = AgentsClient::new("http://example.test/")
            .unwrap()
            .with_bearer("dev-token");
        let fa = a.bearer_fingerprint().unwrap();
        let fb = b.bearer_fingerprint().unwrap();
        assert_eq!(fa, fb, "fingerprint must be deterministic");
        assert_eq!(fa.len(), 8, "8 hex chars (4 bytes of sha256)");
        assert!(
            fa.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "must be lowercase hex; got {fa:?}",
        );
        assert!(a.has_bearer());
    }

    #[test]
    fn bearer_fingerprint_is_injective_on_different_tokens() {
        // Two distinct tokens must produce distinct fingerprints. A
        // collision in the wild is ~1/2^32, but the explicit assertion
        // catches a regression like "we accidentally fingerprinted the
        // base_url instead of the token".
        let a = AgentsClient::new("http://example.test/")
            .unwrap()
            .with_bearer("token-one");
        let b = AgentsClient::new("http://example.test/")
            .unwrap()
            .with_bearer("token-two");
        assert_ne!(a.bearer_fingerprint(), b.bearer_fingerprint());
    }

    #[test]
    fn bearer_fingerprint_known_value() {
        // Pin the algorithm: sha256("hello").hex()[..8] == "2cf24dba".
        // If this test ever changes, the console's "is this the same
        // token I saw yesterday?" diagnostic becomes meaningless.
        let client = AgentsClient::new("http://example.test/")
            .unwrap()
            .with_bearer("hello");
        assert_eq!(client.bearer_fingerprint().as_deref(), Some("2cf24dba"));
    }

    #[test]
    fn create_request_matches_is_set_insensitive() {
        let record = fixture_record("support-bot-3");
        // Same envelopes in different orders → match.
        let req = CreateAgentRequest {
            tenant: "acme",
            agent_name: "support-bot-3",
            owner_team: "payments",
            scope_envelope: vec!["mcp:write:tickets".into(), "mcp:read:tickets".into()],
            yellow_envelope: vec!["refund:<=50usd".into()],
            attestation_kinds: vec!["dev-mock".into()],
            description: None,
            actor_sub: None,
        };
        assert!(create_request_matches(&req, &record));

        // Add a duplicate — still matches (set semantics).
        let req = CreateAgentRequest {
            tenant: "acme",
            agent_name: "support-bot-3",
            owner_team: "payments",
            scope_envelope: vec![
                "mcp:read:tickets".into(),
                "mcp:write:tickets".into(),
                "mcp:read:tickets".into(),
            ],
            yellow_envelope: vec!["refund:<=50usd".into()],
            attestation_kinds: vec!["dev-mock".into()],
            description: Some("ignored field"),
            actor_sub: None,
        };
        assert!(create_request_matches(&req, &record));

        // Different owner_team → no match.
        let req = CreateAgentRequest {
            tenant: "acme",
            agent_name: "support-bot-3",
            owner_team: "infra",
            scope_envelope: vec!["mcp:read:tickets".into(), "mcp:write:tickets".into()],
            yellow_envelope: vec!["refund:<=50usd".into()],
            attestation_kinds: vec!["dev-mock".into()],
            description: None,
            actor_sub: None,
        };
        assert!(!create_request_matches(&req, &record));

        // Different scope envelope size → no match.
        let req = CreateAgentRequest {
            tenant: "acme",
            agent_name: "support-bot-3",
            owner_team: "payments",
            scope_envelope: vec!["mcp:read:tickets".into()],
            yellow_envelope: vec!["refund:<=50usd".into()],
            attestation_kinds: vec!["dev-mock".into()],
            description: None,
            actor_sub: None,
        };
        assert!(!create_request_matches(&req, &record));
    }
}

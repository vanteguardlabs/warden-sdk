//! Async client for `warden-policy-engine`'s console-policy-management
//! surface (warden-specs/TECH_SPEC.md#console-policy-management §5).
//!
//! Mirrors the server-side handlers in
//! `warden-policy-engine::write_api` and `lib.rs`: every method here
//! corresponds 1:1 with a route there. Used by `warden-console`'s
//! `/policies` UI and (eventually) by `wardenctl policies …`.
//!
//! ## Auth model
//!
//! `warden-policy-engine` does not terminate auth itself — it trusts
//! whoever can reach :8082, which in deployment is only the proxy and
//! console (internal-network mTLS). The `bearer` field is therefore
//! optional and unused by the server today; we keep it for symmetry
//! with `AgentsClient` and to be future-proof when policy-engine grows
//! a caller allowlist.
//!
//! ## Wire types
//!
//! [`PolicyRow`], [`PolicyVersionRow`], [`PolicyDetail`], [`MutationResponse`]
//! and the request bodies are duplicated verbatim from the server. The
//! "shared types are not in a common crate" repo invariant applies —
//! grep `warden-policy-engine`, `warden-sdk`, `warden-console`, and
//! `wardenctl` before any rename.

use std::sync::Arc;

use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};

use crate::WardenError;
use crate::http::{default_provider, decode_response, parse_base_url, percent_encode, HttpProvider, StaticHttpClient};

/// One row of the `policies` table — current state of a managed
/// policy file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRow {
    pub name: String,
    pub content_type: String,
    pub active: bool,
    pub current_version: i64,
    pub deleted_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// One row of `policy_versions` — append-only body history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyVersionRow {
    pub name: String,
    pub version: i64,
    pub body: String,
    pub body_sha256: String,
    pub reason: String,
    pub actor_sub: String,
    pub actor_idp: String,
    pub chain_seq: Option<i64>,
    pub created_at: String,
}

/// `GET /policies/{name}` envelope: `PolicyRow` flattened in,
/// plus the body of `current_version` so the console can render the
/// detail page in one round-trip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDetail {
    #[serde(flatten)]
    pub policy: PolicyRow,
    pub current_body: String,
    pub current_body_sha256: String,
}

/// Body of a successful mutation (`POST /policies`,
/// `PUT /policies/{name}`, etc.). Returned alongside `200`/`201`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationResponse {
    pub name: String,
    pub version: i64,
    pub body_sha256: String,
    pub current_version: i64,
    pub active: bool,
    pub event_kind: String,
}

/// Body of a 409 from `PUT /policies/{name}` (and similar). The
/// embedded `policy` carries the up-to-date state so the caller can
/// re-render their editor against it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictResponse {
    pub error: String,
    pub policy: PolicyRow,
}

// ── Request bodies ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct CreatePolicyRequest<'a> {
    pub name: &'a str,
    pub content_type: &'a str,
    pub body: &'a str,
    pub reason: &'a str,
    pub actor_sub: &'a str,
    pub actor_idp: &'a str,
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdatePolicyRequest<'a> {
    pub body: &'a str,
    pub reason: &'a str,
    pub actor_sub: &'a str,
    pub actor_idp: &'a str,
    pub expected_current_version: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct StateChangeRequest<'a> {
    pub reason: &'a str,
    pub actor_sub: &'a str,
    pub actor_idp: &'a str,
    pub expected_current_version: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RollbackRequest<'a> {
    pub reason: &'a str,
    pub actor_sub: &'a str,
    pub actor_idp: &'a str,
}

// ── Response wrappers (read endpoints) ────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoliciesListResponse {
    pub policies: Vec<PolicyRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionsListResponse {
    pub versions: Vec<PolicyVersionRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffResponse {
    pub name: String,
    pub from: i64,
    pub to: i64,
    pub diff: String,
}

// ── Client ────────────────────────────────────────────────────────────

/// Cheap to clone — the inner `reqwest::Client` is `Arc`-based, same
/// as `AgentsClient`. Enables `Arc<AppState>` patterns where the
/// console embeds the SDK client directly in shared state.
#[derive(Debug, Clone)]
pub struct PoliciesClient {
    base_url: Url,
    http: Arc<dyn HttpProvider>,
    bearer: Option<String>,
}

impl PoliciesClient {
    /// Build a client against `base_url` (e.g. `http://localhost:8082`).
    pub fn new(base_url: impl AsRef<str>) -> Result<Self, WardenError> {
        let url = parse_base_url(base_url.as_ref())?;
        let http = default_provider()?;
        Ok(Self {
            base_url: url,
            http,
            bearer: None,
        })
    }

    pub fn with_http_client(self, client: Client) -> Self {
        self.with_http_provider(Arc::new(StaticHttpClient::new(client)))
    }

    /// Inject a custom [`HttpProvider`] for hot-reloading credentials.
    /// See [`LedgerClient::with_http_provider`] for the trade-offs.
    pub fn with_http_provider(mut self, provider: Arc<dyn HttpProvider>) -> Self {
        self.http = provider;
        self
    }

    pub fn with_bearer(mut self, token: impl Into<String>) -> Self {
        self.bearer = Some(token.into());
        self
    }

    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    pub fn has_bearer(&self) -> bool {
        self.bearer.is_some()
    }

    // ── Read API ─────────────────────────────────────────────────

    /// `GET /policies?include_deleted=<bool>`. Default: hide soft-deleted.
    pub async fn list(
        &self,
        include_deleted: bool,
    ) -> Result<Vec<PolicyRow>, WardenError> {
        let mut url = self.join("policies")?;
        if include_deleted {
            url.query_pairs_mut().append_pair("include_deleted", "true");
        }
        let resp: PoliciesListResponse = self.get_json(url).await?;
        Ok(resp.policies)
    }

    /// `GET /policies/{name}` — current row + body.
    pub async fn get(&self, name: &str) -> Result<PolicyDetail, WardenError> {
        let url = self.join(&format!("policies/{}", percent_encode(name)))?;
        self.get_json(url).await
    }

    /// `GET /policies/{name}/versions` — newest first.
    pub async fn list_versions(
        &self,
        name: &str,
    ) -> Result<Vec<PolicyVersionRow>, WardenError> {
        let url = self.join(&format!(
            "policies/{}/versions",
            percent_encode(name)
        ))?;
        let resp: VersionsListResponse = self.get_json(url).await?;
        Ok(resp.versions)
    }

    /// `GET /policies/{name}/versions/{n}` — one historical version.
    pub async fn get_version(
        &self,
        name: &str,
        version: i64,
    ) -> Result<PolicyVersionRow, WardenError> {
        let url = self.join(&format!(
            "policies/{}/versions/{}",
            percent_encode(name),
            version
        ))?;
        self.get_json(url).await
    }

    /// `GET /policies/{name}/diff?from=N&to=M` — unified diff between
    /// two versions, suitable for rendering in the console's edit-
    /// confirmation modal.
    pub async fn diff(
        &self,
        name: &str,
        from: i64,
        to: i64,
    ) -> Result<DiffResponse, WardenError> {
        let mut url = self.join(&format!(
            "policies/{}/diff",
            percent_encode(name)
        ))?;
        url.query_pairs_mut()
            .append_pair("from", &from.to_string())
            .append_pair("to", &to.to_string());
        self.get_json(url).await
    }

    // ── Write API (Admin in the console) ─────────────────────────

    /// `POST /policies` — create a new managed policy. Returns
    /// 400 on regorus compile / JSON Schema error; 409 if `name`
    /// already exists.
    pub async fn create(
        &self,
        req: &CreatePolicyRequest<'_>,
    ) -> Result<MutationResponse, WardenError> {
        let url = self.join("policies")?;
        self.send_json(reqwest::Method::POST, url, req).await
    }

    /// `PUT /policies/{name}` — update body. 409 on
    /// `expected_current_version` mismatch carries [`ConflictResponse`]
    /// in `WardenError::Server.body`.
    pub async fn update(
        &self,
        name: &str,
        req: &UpdatePolicyRequest<'_>,
    ) -> Result<MutationResponse, WardenError> {
        let url = self.join(&format!("policies/{}", percent_encode(name)))?;
        self.send_json(reqwest::Method::PUT, url, req).await
    }

    pub async fn activate(
        &self,
        name: &str,
        req: &StateChangeRequest<'_>,
    ) -> Result<MutationResponse, WardenError> {
        let url = self.join(&format!(
            "policies/{}/activate",
            percent_encode(name)
        ))?;
        self.send_json(reqwest::Method::POST, url, req).await
    }

    pub async fn deactivate(
        &self,
        name: &str,
        req: &StateChangeRequest<'_>,
    ) -> Result<MutationResponse, WardenError> {
        let url = self.join(&format!(
            "policies/{}/deactivate",
            percent_encode(name)
        ))?;
        self.send_json(reqwest::Method::POST, url, req).await
    }

    /// `DELETE /policies/{name}` — soft delete. Body is a
    /// [`StateChangeRequest`] (reason + expected_current_version).
    pub async fn delete(
        &self,
        name: &str,
        req: &StateChangeRequest<'_>,
    ) -> Result<MutationResponse, WardenError> {
        let url = self.join(&format!("policies/{}", percent_encode(name)))?;
        self.send_json(reqwest::Method::DELETE, url, req).await
    }

    /// `POST /policies/{name}/rollback/{version}` — recreate the
    /// body of `version` as a new version.
    pub async fn rollback(
        &self,
        name: &str,
        version: i64,
        req: &RollbackRequest<'_>,
    ) -> Result<MutationResponse, WardenError> {
        let url = self.join(&format!(
            "policies/{}/rollback/{}",
            percent_encode(name),
            version
        ))?;
        self.send_json(reqwest::Method::POST, url, req).await
    }

    /// Helper for a console row that just received a 409 from
    /// `update`/`activate`/`deactivate`/`delete` — parses the embedded
    /// [`ConflictResponse`] out of [`WardenError::Server.body`].
    /// Returns `None` when the body isn't a `ConflictResponse` (e.g.
    /// the 409 came from `create`'s `name already exists` arm, which
    /// is plain text).
    pub fn parse_conflict(body: &str) -> Option<ConflictResponse> {
        serde_json::from_str(body).ok()
    }

    // ── Internal helpers ─────────────────────────────────────────

    fn join(&self, suffix: &str) -> Result<Url, WardenError> {
        self.base_url
            .join(suffix)
            .map_err(|e| WardenError::InvalidConfig(format!("join {suffix}: {e}")))
    }

    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        url: Url,
    ) -> Result<T, WardenError> {
        let mut req = self.http.client().get(url);
        if let Some(token) = self.bearer.as_ref() {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let body = resp.text().await?;
        decode_response(status, body)
    }

    async fn send_json<B: Serialize, T: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        url: Url,
        body: &B,
    ) -> Result<T, WardenError> {
        let mut req = self.http.client().request(method, url).json(body);
        if let Some(token) = self.bearer.as_ref() {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let body = resp.text().await?;
        decode_response(status, body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_malformed_base_url() {
        match PoliciesClient::new("not a url") {
            Ok(_) => panic!("expected InvalidConfig"),
            Err(WardenError::InvalidConfig(_)) => {}
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn parse_conflict_recovers_policy_row() {
        let body = serde_json::json!({
            "error": "version_conflict",
            "policy": {
                "name": "governance.rego",
                "content_type": "rego",
                "active": true,
                "current_version": 7,
                "deleted_at": null,
                "created_at": "2026-05-08T00:00:00Z",
                "updated_at": "2026-05-08T00:00:00Z"
            }
        })
        .to_string();
        let parsed = PoliciesClient::parse_conflict(&body).unwrap();
        assert_eq!(parsed.error, "version_conflict");
        assert_eq!(parsed.policy.current_version, 7);
        assert_eq!(parsed.policy.name, "governance.rego");
    }

    #[test]
    fn parse_conflict_returns_none_for_plain_text() {
        assert!(PoliciesClient::parse_conflict("policy already exists").is_none());
    }
}

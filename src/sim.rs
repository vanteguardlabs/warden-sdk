//! Async client for the warden-simulator admin HTTP surface.
//!
//! Three calls cover the operator surface needed by the
//! `warden-console` `/sim` panel:
//!
//! * [`SimClient::status`] — live snapshot: traffic multiplier, agent
//!   roster (cn + persona + λ + transient flag), and the latest stats
//!   summary.
//! * [`SimClient::set_multiplier`] — `POST /multiplier`. The simulator
//!   updates the shared atomic in place; agents pick up the new value
//!   on their next inter-arrival.
//! * [`SimClient::add_agents`] — `POST /agents`. Mints a transient
//!   `<persona>-tN` agent and spawns its traffic loop.
//!
//! The simulator's admin surface has no auth — same dev-only posture
//! as the CA-private-key bind mount. The console relies on network
//! isolation (compose internal network) for access control. **Do not
//! deploy this client against a production simulator.**

use std::sync::Arc;

use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};

use crate::WardenError;
use crate::http::{default_provider, decode_response, parse_base_url, HttpProvider, StaticHttpClient};

/// One row in the live agent roster — mirrors the simulator's
/// internal `AgentRecord`. `transient=false` for the boot roster,
/// `true` for agents spawned via `POST /agents`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimAgentRecord {
    pub cn: String,
    pub persona: String,
    pub rate_lambda: f64,
    #[serde(default)]
    pub transient: bool,
}

/// Snapshot of the simulator's `Stats`. `None` for the latency
/// percentiles when no requests have been recorded yet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimStats {
    pub sent: u64,
    pub ok: u64,
    pub denied: u64,
    pub error: u64,
    pub success_pct: f64,
    pub p50_ms: Option<f64>,
    pub p95_ms: Option<f64>,
}

/// Response body of `GET /status` on the simulator's admin server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimStatus {
    pub traffic_multiplier: f64,
    /// Whether the simulator is currently firing requests. Older
    /// simulator builds (pre run-flag) didn't emit this field;
    /// `#[serde(default)]` resolves to `false` (paused) for those.
    /// That matches the new boot default and keeps the console safe
    /// against version skew during a rolling upgrade.
    #[serde(default)]
    pub running: bool,
    /// HIL auto-decision sidecar state. `None` means the sidecar
    /// wasn't configured at boot (no `--hil-url` on the simulator) —
    /// the console renders an "off" placeholder and disables the
    /// toggle. `Some(true/false)` is enabled / paused. The simulator
    /// emits this with `serde(skip_serializing_if = is_none)`, so
    /// older simulator payloads omit the field entirely; `serde(default)`
    /// here fills it back in as `None`.
    #[serde(default)]
    pub auto_decide: Option<bool>,
    pub agents: Vec<SimAgentRecord>,
    pub stats: SimStats,
}

/// Async client for the simulator admin HTTP surface.
///
/// Cheap to clone — the inner `reqwest::Client` is `Arc`-based.
#[derive(Debug, Clone)]
pub struct SimClient {
    base_url: Url,
    http: Arc<dyn HttpProvider>,
}

impl SimClient {
    /// Build a client against `base_url` (e.g.
    /// `http://simulator:9100`). Returns `InvalidConfig` if the URL
    /// is malformed.
    pub fn new(base_url: impl AsRef<str>) -> Result<Self, WardenError> {
        let url = parse_base_url(base_url.as_ref())?;
        let http = default_provider()?;
        Ok(Self { base_url: url, http })
    }

    /// Inject a pre-configured `reqwest::Client`. Same use case as
    /// `WardenClientBuilder::http_client` — lets callers configure
    /// timeouts / proxy / TLS once and reuse.
    pub fn with_http_client(self, client: Client) -> Self {
        self.with_http_provider(Arc::new(StaticHttpClient::new(client)))
    }

    /// Inject a custom [`HttpProvider`] for hot-reloading credentials.
    /// See [`LedgerClient::with_http_provider`] for the trade-offs.
    pub fn with_http_provider(mut self, provider: Arc<dyn HttpProvider>) -> Self {
        self.http = provider;
        self
    }

    /// Read-only access to the configured base URL. Mirrors
    /// `AgentsClient::base_url` so the warden-console `/config` page
    /// can surface the simulator's admin URL on its "Backends" card
    /// without having to plumb the raw env var alongside the client.
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// `GET /status` — current multiplier + agent roster + stats.
    pub async fn status(&self) -> Result<SimStatus, WardenError> {
        self.get_json("status").await
    }

    /// `POST /multiplier` — update the simulator's traffic multiplier
    /// in place. Returns the post-update [`SimStatus`] so the caller
    /// can render the new state without a follow-up `status()` call.
    pub async fn set_multiplier(&self, multiplier: f64) -> Result<SimStatus, WardenError> {
        self.post_json("multiplier", &serde_json::json!({ "traffic_multiplier": multiplier }))
            .await
    }

    /// `POST /running` — flip the simulator's start/stop flag.
    /// Returns the post-update [`SimStatus`] so the caller can render
    /// the new badge without a follow-up `status()` call.
    pub async fn set_running(&self, running: bool) -> Result<SimStatus, WardenError> {
        self.post_json("running", &serde_json::json!({ "running": running }))
            .await
    }

    /// `POST /auto-decide` — pause or resume the simulator's HIL
    /// auto-decision sidecar. Returns the post-update [`SimStatus`].
    /// When the simulator wasn't booted with `--hil-url`, the server
    /// answers 409 Conflict and this surfaces as
    /// [`WardenError::Server`] with the explanation in the body.
    pub async fn set_auto_decide(&self, enabled: bool) -> Result<SimStatus, WardenError> {
        self.post_json("auto-decide", &serde_json::json!({ "enabled": enabled }))
            .await
    }

    /// `POST /agents` — mint and spawn `count` transient agents of
    /// the named persona. Returns the CNs of the spawned agents on
    /// success.
    pub async fn add_agents(
        &self,
        persona: &str,
        count: usize,
    ) -> Result<Vec<String>, WardenError> {
        // The simulator returns `{ spawned: [...] }`; project to the
        // inner Vec so callers don't carry the wrapper.
        #[derive(Deserialize)]
        struct Wrap {
            spawned: Vec<String>,
        }
        let w: Wrap = self
            .post_json("agents", &serde_json::json!({ "persona": persona, "count": count }))
            .await?;
        Ok(w.spawned)
    }

    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<T, WardenError> {
        let endpoint = self
            .base_url
            .join(path)
            .map_err(|e| WardenError::InvalidConfig(format!("join {path}: {e}")))?;
        let resp = self.http.client().get(endpoint).send().await?;
        let status = resp.status();
        let body = resp.text().await?;
        decode_response(status, body)
    }

    async fn post_json<B: Serialize, T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, WardenError> {
        let endpoint = self
            .base_url
            .join(path)
            .map_err(|e| WardenError::InvalidConfig(format!("join {path}: {e}")))?;
        let resp = self.http.client().post(endpoint).json(body).send().await?;
        let status = resp.status();
        let body = resp.text().await?;
        decode_response(status, body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sim_status_decodes_canonical_payload() {
        let raw = r#"{
            "traffic_multiplier": 2.5,
            "running": true,
            "auto_decide": true,
            "agents": [
                {"cn": "cs-bot-1", "persona": "cs-bot", "rate_lambda": 0.3, "transient": false},
                {"cn": "cs-bot-t1", "persona": "cs-bot", "rate_lambda": 0.3, "transient": true}
            ],
            "stats": {
                "sent": 100, "ok": 95, "denied": 4, "error": 1,
                "success_pct": 95.0,
                "p50_ms": 18.0, "p95_ms": 3100.0
            }
        }"#;
        let parsed: SimStatus = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.traffic_multiplier, 2.5);
        assert!(parsed.running);
        assert_eq!(parsed.auto_decide, Some(true));
        assert_eq!(parsed.agents.len(), 2);
        assert!(!parsed.agents[0].transient);
        assert!(parsed.agents[1].transient);
        assert_eq!(parsed.stats.sent, 100);
        assert_eq!(parsed.stats.p50_ms, Some(18.0));
    }

    #[test]
    fn sim_status_auto_decide_defaults_none_when_field_missing() {
        // Simulator omits `auto_decide` when the sidecar isn't
        // configured (skip_serializing_if). Older builds didn't emit
        // it at all. Both shapes deserialize to `None` here.
        let raw = r#"{
            "traffic_multiplier": 1.0,
            "running": false,
            "agents": [],
            "stats": {"sent": 0, "ok": 0, "denied": 0, "error": 0, "success_pct": 0.0, "p50_ms": null, "p95_ms": null}
        }"#;
        let parsed: SimStatus = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.auto_decide, None);
    }

    #[test]
    fn sim_status_running_defaults_false_when_field_missing() {
        // Pre run-flag simulator builds don't emit `running`. The
        // `#[serde(default)]` resolves it to `false` so the console's
        // Start/Stop button shows the safe (paused) state until the
        // simulator is actually upgraded.
        let raw = r#"{
            "traffic_multiplier": 1.0,
            "agents": [],
            "stats": {"sent": 0, "ok": 0, "denied": 0, "error": 0, "success_pct": 0.0, "p50_ms": null, "p95_ms": null}
        }"#;
        let parsed: SimStatus = serde_json::from_str(raw).unwrap();
        assert!(!parsed.running);
    }

    #[test]
    fn sim_agent_record_defaults_transient_false_for_legacy_payload() {
        // Older simulator builds (pre-Phase-4) won't emit `transient`.
        // The `#[serde(default)]` should resolve it to `false`.
        let raw = r#"{"cn": "cs-bot-1", "persona": "cs-bot", "rate_lambda": 0.3}"#;
        let parsed: SimAgentRecord = serde_json::from_str(raw).unwrap();
        assert!(!parsed.transient);
    }

    #[test]
    fn sim_client_surfaces_configured_base_url() {
        // The warden-console /config page renders the simulator's base
        // URL on its "Backends (optional)" card; this getter is what
        // the handler reads. Round-trip the URL string through the
        // client without losing the trailing slash.
        let client = SimClient::new("http://simulator:9100/").unwrap();
        assert_eq!(client.base_url().as_str(), "http://simulator:9100/");
    }

    #[test]
    fn sim_stats_handles_no_requests_yet() {
        let raw = r#"{"sent": 0, "ok": 0, "denied": 0, "error": 0, "success_pct": 0.0, "p50_ms": null, "p95_ms": null}"#;
        let parsed: SimStats = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.sent, 0);
        assert!(parsed.p50_ms.is_none());
    }
}

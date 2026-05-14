//! Async client for the proxy `POST /mcp` surface.
//!
//! Two ergonomic call sites:
//!
//! * [`WardenClient::call_tool`] — the common case. Builds a
//!   JSON-RPC `tools/call` body around `name` + `arguments` and posts
//!   it. Returns the upstream JSON on 200, a [`WardenError::Veto`] on
//!   403, or one of the other [`WardenError`] arms.
//! * [`WardenClient::send_jsonrpc`] — escape hatch for non-tool
//!   methods (`tools/list`, etc.). Same return semantics.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use reqwest::{Client, StatusCode, Url};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::WardenError;
use crate::http::{default_provider, parse_base_url, HttpProvider, StaticHttpClient};

/// Authentication mode for the proxy.
///
/// `None` is the warden-lite "open access" default. `Bearer` is the
/// token shape both warden-lite and the full edition's proxy use for
/// HTTP-only deployments. mTLS / OIDC / SPIFFE will land as new
/// variants in a future minor — `#[non_exhaustive]` reserves the
/// right to add them without it being a breaking change.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Auth {
    /// Send no auth headers. Matches a warden-lite started without
    /// `--token` / `WARDEN_LITE_TOKEN`.
    None,
    /// Send `Authorization: Bearer <token>`.
    Bearer(String),
}

/// Async client for the proxy `POST /mcp` surface.
///
/// Cheap to clone — the inner `Arc<dyn HttpProvider>` is `Arc`-based.
#[derive(Debug, Clone)]
pub struct WardenClient {
    base_url: Url,
    auth: Auth,
    http: Arc<dyn HttpProvider>,
    next_id: Arc<AtomicU64>,
}

/// Two-step builder: validate the URL once, then attach optional
/// settings, then build. Surfaces caller misuse (a typo in the base
/// URL, an unsupported auth combo) before any network call.
#[derive(Debug)]
pub struct WardenClientBuilder {
    base_url: Url,
    auth: Auth,
    http: Option<Arc<dyn HttpProvider>>,
}

impl WardenClient {
    /// Start building a client. Returns `Err(InvalidConfig)` if
    /// `base_url` doesn't parse as a URL.
    ///
    /// `base_url` should be the proxy's origin — the SDK appends
    /// `/mcp` itself.
    pub fn builder(base_url: impl AsRef<str>) -> Result<WardenClientBuilder, WardenError> {
        let url = parse_base_url(base_url.as_ref())?;
        Ok(WardenClientBuilder {
            base_url: url,
            auth: Auth::None,
            http: None,
        })
    }

    /// `POST /mcp` with a JSON-RPC `tools/call` body.
    ///
    /// Wire shape:
    /// ```json
    /// { "jsonrpc": "2.0", "id": <auto>, "method": "tools/call",
    ///   "params": { "name": "<name>", "arguments": <arguments> } }
    /// ```
    /// Returns the upstream JSON on 200, [`WardenError::Veto`] on a
    /// structured 403, [`WardenError::Unauthorized`] on 401,
    /// [`WardenError::BadRequest`] on 400, or one of the other
    /// [`WardenError`] arms.
    pub async fn call_tool(
        &self,
        name: &str,
        arguments: Value,
    ) -> Result<Value, WardenError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": { "name": name, "arguments": arguments },
        });
        self.send_raw(body).await
    }

    /// `POST /mcp` with an arbitrary JSON-RPC body. Use this for
    /// methods other than `tools/call` (`tools/list`, custom RPCs,
    /// etc.).
    pub async fn send_jsonrpc(
        &self,
        method: &str,
        params: Value,
    ) -> Result<Value, WardenError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        self.send_raw(body).await
    }

    /// Internal: post `body` to `<base_url>/mcp` and dispatch on
    /// status. Public methods build `body` and delegate here so the
    /// status-handling logic lives in one place.
    async fn send_raw(&self, body: Value) -> Result<Value, WardenError> {
        let endpoint = self
            .base_url
            .join("mcp")
            .map_err(|e| WardenError::InvalidConfig(format!("join /mcp: {e}")))?;

        let mut req = self.http.client().post(endpoint).json(&body);
        if let Auth::Bearer(token) = &self.auth {
            req = req.bearer_auth(token);
        }

        let resp = req.send().await?;
        let status = resp.status();
        let raw = resp.text().await?;

        match status {
            StatusCode::OK => decode_json_body(&raw),
            StatusCode::FORBIDDEN => Err(parse_veto(&raw)),
            StatusCode::UNAUTHORIZED => Err(WardenError::Unauthorized(raw)),
            StatusCode::BAD_REQUEST => Err(WardenError::BadRequest(raw)),
            other => Err(WardenError::Server { status: other, body: raw }),
        }
    }
}

impl WardenClientBuilder {
    /// Attach an [`Auth`] mode. Defaults to [`Auth::None`].
    pub fn auth(mut self, auth: Auth) -> Self {
        self.auth = auth;
        self
    }

    /// Inject a pre-configured `reqwest::Client`. Useful when callers
    /// want to set custom timeouts, proxies, or TLS roots; otherwise a
    /// default client is constructed at build time.
    pub fn http_client(mut self, client: Client) -> Self {
        self.http = Some(Arc::new(StaticHttpClient::new(client)));
        self
    }

    /// Inject a custom [`HttpProvider`] for hot-reloading credentials.
    /// See [`crate::LedgerClient::with_http_provider`] for the
    /// trade-offs against `http_client`.
    pub fn http_provider(mut self, provider: Arc<dyn HttpProvider>) -> Self {
        self.http = Some(provider);
        self
    }

    /// Construct the client. Builds a default `reqwest::Client` if
    /// neither `http_client(...)` nor `http_provider(...)` was called.
    pub fn build(self) -> Result<WardenClient, WardenError> {
        let http = match self.http {
            Some(p) => p,
            None => default_provider()?,
        };
        Ok(WardenClient {
            base_url: self.base_url,
            auth: self.auth,
            http,
            next_id: Arc::new(AtomicU64::new(1)),
        })
    }
}

/// Mirror of warden-lite's `DenyResponse`. Used only inside
/// `parse_veto`; we project into [`WardenError::Veto`] before handing
/// the value back to the caller.
#[derive(Debug, Deserialize)]
struct DenyResponse {
    #[serde(default)]
    reasons: Vec<String>,
    #[serde(default)]
    review_reasons: Vec<String>,
    #[serde(default)]
    intent_category: String,
}

/// Parse a 403 body into a `WardenError::Veto`. If the body is JSON
/// matching `DenyResponse`, populate the structured fields; if not
/// (full-edition `warden-proxy` returns plain text), only `raw` is
/// set. Either way we return `WardenError::Veto`, never `Decode` —
/// callers shouldn't have to special-case the proxy edition.
fn parse_veto(raw: &str) -> WardenError {
    match serde_json::from_str::<DenyResponse>(raw) {
        Ok(d) => WardenError::Veto {
            intent_category: d.intent_category,
            reasons: d.reasons,
            review_reasons: d.review_reasons,
            raw: raw.to_owned(),
        },
        Err(_) => WardenError::Veto {
            intent_category: String::new(),
            reasons: Vec::new(),
            review_reasons: Vec::new(),
            raw: raw.to_owned(),
        },
    }
}

/// Decode a 200 body. Surfaces a `Decode` error if the body isn't
/// JSON — not expected from a real proxy, but keeps us from panicking
/// on a misconfigured upstream.
fn decode_json_body(raw: &str) -> Result<Value, WardenError> {
    serde_json::from_str(raw).map_err(WardenError::Decode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_veto_with_structured_body() {
        let body = r#"{
            "error": "security_violation",
            "reasons": ["Direct execution of SQL queries is prohibited."],
            "review_reasons": [],
            "intent_category": "DangerousTool"
        }"#;
        match parse_veto(body) {
            WardenError::Veto { intent_category, reasons, review_reasons, raw } => {
                assert_eq!(intent_category, "DangerousTool");
                assert_eq!(reasons.len(), 1);
                assert!(review_reasons.is_empty());
                assert_eq!(raw, body);
            }
            other => panic!("expected Veto, got {other:?}"),
        }
    }

    #[test]
    fn parse_veto_with_plain_text_body() {
        // Mirrors what full-edition warden-proxy returns today.
        let body = "Security Violation: shell_exec is denied for this agent";
        match parse_veto(body) {
            WardenError::Veto { intent_category, reasons, review_reasons, raw } => {
                // Structured fields stay empty; raw carries the full body.
                assert!(intent_category.is_empty());
                assert!(reasons.is_empty());
                assert!(review_reasons.is_empty());
                assert_eq!(raw, body);
            }
            other => panic!("expected Veto, got {other:?}"),
        }
    }

    #[test]
    fn parse_veto_with_partial_body_keeps_present_fields() {
        // Body has `intent_category` but is missing `reasons`. The
        // `#[serde(default)]` attributes mean the missing field
        // becomes an empty Vec, not a parse error.
        let body = r#"{ "intent_category": "Velocity" }"#;
        match parse_veto(body) {
            WardenError::Veto { intent_category, reasons, .. } => {
                assert_eq!(intent_category, "Velocity");
                assert!(reasons.is_empty());
            }
            other => panic!("expected Veto, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn builder_rejects_invalid_url() {
        let err = WardenClient::builder("not a url").unwrap_err();
        match err {
            WardenError::InvalidConfig(msg) => assert!(msg.contains("base_url")),
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }
}

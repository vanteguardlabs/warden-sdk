//! Shared HTTP helpers for the per-service client modules.
//!
//! Centralizes the two pieces every client used to copy: a minimal
//! path-segment percent-encoder (we don't pull `percent-encoding` for
//! one site each) and the status-code → typed-error dispatch every
//! authenticated client uses on its decode path. `WardenClient` keeps
//! its own dispatch because of the FORBIDDEN → `Veto` parse step;
//! `LedgerClient` keeps its own because it predates this module and
//! has no 401/400 surface to dispatch on.
//!
//! Also defines [`HttpProvider`] — the indirection point every per-service
//! client uses to fetch its `reqwest::Client` per request. Static deployments
//! wrap a single Client in [`StaticHttpClient`]; integrators with hot-reloading
//! credentials (workload-SVID refresh, for example) implement the trait
//! against their own ArcSwap-backed Client store. The trait keeps the SDK
//! itself dependency-free of any specific refresh mechanism.

use std::fmt::Debug;
use std::sync::Arc;

use reqwest::{Client, StatusCode};
use url::Url;

use crate::WardenError;

/// Source of a `reqwest::Client` for a per-request hot path.
///
/// Implementors return the *current* client every call — never cache the
/// `Arc<Client>` across requests, since the whole point is to let
/// credential-rotation machinery swap out the underlying TLS identity
/// between calls without disturbing in-flight requests (reqwest's
/// connection pool retains the old identity for any connection that
/// hasn't idled out).
///
/// Cost is one `Arc::clone` per call: cheap, no rebuild on hot path.
pub trait HttpProvider: Debug + Send + Sync {
    /// Snapshot of the active client. Callers do one network request per
    /// returned `Arc<Client>`.
    fn client(&self) -> Arc<Client>;
}

/// Wraps a single `reqwest::Client` so static deployments (no
/// hot-reload) keep working through the [`HttpProvider`] indirection.
///
/// Built once at config time; `client()` is a `Arc::clone` of the
/// stored `Arc<Client>`.
#[derive(Debug, Clone)]
pub struct StaticHttpClient {
    inner: Arc<Client>,
}

impl StaticHttpClient {
    /// Wrap a pre-built `reqwest::Client`. Use this when the caller owns
    /// TLS / proxy / timeout config and isn't plumbing a credential
    /// rotation system into the SDK.
    pub fn new(client: Client) -> Self {
        Self { inner: Arc::new(client) }
    }
}

impl HttpProvider for StaticHttpClient {
    fn client(&self) -> Arc<Client> {
        Arc::clone(&self.inner)
    }
}

/// Internal: build the default plain-HTTP `StaticHttpClient` for a
/// per-service client's `new()` constructor.
pub(crate) fn default_provider() -> Result<Arc<dyn HttpProvider>, WardenError> {
    let client = Client::builder().build().map_err(WardenError::Transport)?;
    Ok(Arc::new(StaticHttpClient::new(client)))
}

/// Parse a base URL and normalize it for use with `Url::join`.
///
/// `Url::join("relative")` follows RFC 3986 reference resolution: if the
/// base path doesn't end with `/`, the last segment is *replaced*, not
/// appended to. So `Url::parse("http://h/api").join("mcp")` yields
/// `http://h/mcp` and silently drops the `/api` prefix. Forcing a
/// trailing slash makes every subsequent `join` behave as append, which
/// is what every caller in this crate actually wants.
pub(crate) fn parse_base_url(s: &str) -> Result<Url, WardenError> {
    let mut url = Url::parse(s)
        .map_err(|e| WardenError::InvalidConfig(format!("base_url: {e}")))?;
    if !url.path().ends_with('/') {
        let with_slash = format!("{}/", url.path());
        url.set_path(&with_slash);
    }
    Ok(url)
}

/// Centralized status-code dispatch. 200/201 pass through the JSON
/// decoder; 401/400 route to typed errors; everything else (incl. 409,
/// 422, 5xx) lands in `Server` so the caller can branch on the body.
pub(crate) fn decode_response<T: serde::de::DeserializeOwned>(
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

/// Percent-encode a path or query segment. Unreserved chars per RFC
/// 3986 ride through; everything else gets `%HH`'d.
pub(crate) fn percent_encode(s: &str) -> String {
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

    #[test]
    fn percent_encode_passes_unreserved() {
        assert_eq!(percent_encode("abc-XYZ_0.9~"), "abc-XYZ_0.9~");
    }

    #[test]
    fn percent_encode_escapes_path_specials() {
        assert_eq!(percent_encode("a/b?c#d"), "a%2Fb%3Fc%23d");
        assert_eq!(percent_encode("hello world"), "hello%20world");
    }

    #[test]
    fn decode_response_routes_typed_4xx_arms() {
        let r: Result<serde_json::Value, _> =
            decode_response(StatusCode::UNAUTHORIZED, "missing bearer".into());
        assert!(matches!(r, Err(WardenError::Unauthorized(_))));

        let r: Result<serde_json::Value, _> =
            decode_response(StatusCode::BAD_REQUEST, "missing field".into());
        assert!(matches!(r, Err(WardenError::BadRequest(_))));

        let r: Result<serde_json::Value, _> =
            decode_response(StatusCode::CONFLICT, "version_conflict".into());
        match r {
            Err(WardenError::Server { status, .. }) => {
                assert_eq!(status, StatusCode::CONFLICT);
            }
            other => panic!("expected Server, got {other:?}"),
        }
    }

    #[test]
    fn parse_base_url_appends_trailing_slash_to_path_prefix() {
        let u = parse_base_url("http://h/api").unwrap();
        assert_eq!(u.path(), "/api/");
        assert_eq!(u.join("mcp").unwrap().as_str(), "http://h/api/mcp");
    }

    #[test]
    fn parse_base_url_leaves_origin_only_url_unchanged() {
        let u = parse_base_url("http://localhost:8088").unwrap();
        assert_eq!(u.path(), "/");
        assert_eq!(u.join("mcp").unwrap().as_str(), "http://localhost:8088/mcp");
    }

    #[test]
    fn parse_base_url_rejects_garbage() {
        assert!(matches!(
            parse_base_url("not a url"),
            Err(WardenError::InvalidConfig(_))
        ));
    }

    #[test]
    fn decode_response_decodes_200_and_201_through_serde() {
        #[derive(serde::Deserialize, Debug, PartialEq)]
        struct Body {
            ok: bool,
        }
        let r: Result<Body, _> =
            decode_response(StatusCode::OK, r#"{"ok":true}"#.into());
        assert_eq!(r.unwrap(), Body { ok: true });
        let r: Result<Body, _> =
            decode_response(StatusCode::CREATED, r#"{"ok":false}"#.into());
        assert_eq!(r.unwrap(), Body { ok: false });
    }
}

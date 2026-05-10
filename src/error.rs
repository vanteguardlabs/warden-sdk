//! Crate-level error type.
//!
//! `WardenError` covers the four wire outcomes a caller actually has to
//! distinguish — security veto, auth failure, transport failure, and
//! "anything else from the server" — plus an explicit `Decode` arm for
//! cases where the server returned a status we expect to be parseable
//! but the body wasn't.

use thiserror::Error;

/// All errors a `WardenClient` or `LedgerClient` call can return.
///
/// Match arms a caller will typically care about:
///
/// * [`WardenError::Veto`] — the security pipeline rejected the
///   request. The four fields mirror `warden-lite`'s structured 403
///   body (`{ error, reasons, review_reasons, intent_category }`).
///   `raw` is the full body verbatim — set on every veto, the *only*
///   populated field when the server is full-edition `warden-proxy`,
///   which today returns a plain-text 403.
/// * [`WardenError::Unauthorized`] — bearer token missing or wrong
///   (HTTP 401). Carries the server's body string for diagnostics.
/// * [`WardenError::BadRequest`] — the request didn't parse as
///   JSON-RPC on the server side (HTTP 400). Almost always a caller
///   bug, not a runtime condition.
/// * [`WardenError::Server`] — anything else: 5xx, 503, an unexpected
///   status. Carries status + body so the caller can decide whether to
///   retry.
/// * [`WardenError::Transport`] / [`WardenError::Decode`] — the request
///   never made it to a verdict, or the response body didn't match the
///   shape we expect for that status. Both are typically retryable.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WardenError {
    /// Security pipeline rejected the request (HTTP 403).
    ///
    /// Populated from the structured 403 body emitted by
    /// `warden-lite`'s `DenyResponse`:
    /// ```json
    /// { "error": "security_violation",
    ///   "reasons": [...], "review_reasons": [...],
    ///   "intent_category": "..." }
    /// ```
    /// When the server is full-edition `warden-proxy` (which returns
    /// plain text), only `raw` is meaningful and the structured fields
    /// are empty defaults.
    #[error("warden veto ({intent_category}): {raw}")]
    Veto {
        intent_category: String,
        reasons: Vec<String>,
        review_reasons: Vec<String>,
        /// Full 403 body verbatim. Always set so callers don't lose
        /// information when the server emits a non-JSON 403.
        raw: String,
    },

    /// Bearer token missing or invalid (HTTP 401).
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// Server rejected the request as malformed (HTTP 400).
    #[error("bad request: {0}")]
    BadRequest(String),

    /// Any other non-success status from the server.
    #[error("server returned {status}: {body}")]
    Server {
        status: reqwest::StatusCode,
        body: String,
    },

    /// Transport-level failure: DNS, TCP, TLS, timeout, etc.
    /// `?` on a `reqwest::Error` produces this variant via `#[from]`.
    #[error(transparent)]
    Transport(#[from] reqwest::Error),

    /// Response body didn't match the expected shape for its status.
    /// E.g. 403 with a JSON body that didn't contain `error` /
    /// `reasons` — we fall back to `Veto { raw }` rather than this
    /// variant in that case, but a malformed audit response would
    /// surface here.
    #[error(transparent)]
    Decode(#[from] serde_json::Error),

    /// Caller-side construction failure — e.g. the `base_url` passed to
    /// `WardenClient::builder` wasn't a valid URL.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
}

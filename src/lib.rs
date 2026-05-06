//! Async Rust client for Agent Warden.
//!
//! This crate is the OIDC/SPIFFE-aware client lib called out in the
//! Tier-2 GTM plan, paired with `warden-lite`: lite is the OSS proxy
//! you put in front of an agent, this SDK is what an external app calls
//! when it needs to talk to that proxy without relearning the wire
//! contract on every integration.
//!
//! Two thin clients live here:
//!
//! * [`WardenClient`] — wraps the proxy's `POST /mcp` surface. Returns
//!   either the upstream JSON-RPC response or a typed
//!   [`WardenError::Veto`] parsed from the structured 403 body that
//!   `warden-lite` emits. The full-edition `warden-proxy` returns a
//!   plain-text 403 today; the verbatim body is preserved on the
//!   `Veto.raw` field so callers don't lose information either way.
//!
//! * [`LedgerClient`] — wraps the ledger's `/audit/correlation/{id}`,
//!   `/audit/{agent_id}`, and `/verify` endpoints with typed mirrors of
//!   the server-side [`LedgerEntry`] and [`VerifyResult`] structs.
//!
//! Auth is currently [`Auth::None`] or [`Auth::Bearer`]; mTLS / OIDC /
//! SPIFFE land in a future minor.
//!
//! # Quick start
//!
//! ```no_run
//! use warden_sdk::{Auth, WardenClient, WardenError};
//! use serde_json::json;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let client = WardenClient::builder("http://localhost:8088")?
//!     .auth(Auth::Bearer("dev-token".into()))
//!     .build()?;
//!
//! match client.call_tool("search", json!({"q": "rust async"})).await {
//!     Ok(reply)              => println!("{}", reply),
//!     Err(WardenError::Veto { intent_category, reasons, .. }) => {
//!         eprintln!("blocked ({}): {:?}", intent_category, reasons);
//!     }
//!     Err(e)                 => return Err(e.into()),
//! }
//! # Ok(()) }
//! ```
//!
//! # Rust idioms in this crate
//!
//! Annotations for readers coming from other languages:
//!
//! * `pub use foo::{Bar, Baz};` re-exports nested-module items at the
//!   crate root so callers write `warden_sdk::Bar` instead of
//!   `warden_sdk::foo::Bar`.
//! * `#[derive(thiserror::Error, Debug)]` auto-implements
//!   `std::error::Error` and `Display` — the `#[error("...")]`
//!   attribute on each variant is the Display string.
//! * `#[non_exhaustive]` on a public enum reserves the right to add
//!   variants in a future minor without it being a breaking change.
//!   Callers that `match` exhaustively must include `_ => ...`.
//! * `impl From<reqwest::Error> for WardenError` enables `?` to convert
//!   transport errors into our crate-level error transparently.
//! * `serde_json::Value` is the open-content escape hatch — used here
//!   for upstream responses (whose shape we deliberately don't model)
//!   and for `policy_decision`, which the server stores as nullable
//!   JSON.
//! * `chrono::DateTime<Utc>` with the `serde` feature deserializes
//!   from the ISO-8601 string the ledger emits, identical to the
//!   server's own `LedgerEntry`.
//! * Builder pattern: `Client::builder(url)?.auth(...).build()?`.
//!   Two-step construction lets us validate the URL once and surface
//!   misuse (auth on a bad URL) before any network call.
//! * `IntoUrl` (a reqwest trait) accepts both `&str` and `Url`; we
//!   constrain to that bound on builder constructors so callers can
//!   pass either without an explicit conversion.

mod agents;
mod client;
mod error;
mod ledger;
mod sim;

pub use agents::{
    create_request_matches, AgentCreated, AgentListFilter, AgentRecord, AgentState, AgentsClient,
    CreateAgentRequest, EnvelopeRequest, LifecycleRequest, LifecycleResponse,
    MIGRATION_ACTOR_SUB_PREFIX,
};
pub use client::{Auth, WardenClient, WardenClientBuilder};
pub use error::WardenError;
pub use ledger::{
    ExportRecord, LedgerClient, LedgerEntry, LifecycleRow, RegulatoryExportOptions, VerifyResult,
};
pub use sim::{SimAgentRecord, SimClient, SimStats, SimStatus};

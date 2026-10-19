//! Strongly-typed error type for the entire authentication flow.
//!
//! Every fallible operation in this crate returns [`Result`] carrying this
//! enum. The library code contains **no** `unwrap()`/`expect()` on fallible
//! paths, so no panic can ever escape across the FFI boundary.
//! [`AuthenticationError::code`] provides a stable machine-readable
//! identifier that is convenient to branch on from Dart.

use serde::Serialize;
use thiserror::Error;

/// Errors that can occur during authentication, network I/O, macaroon
/// handling, or session state transitions.
// Manual `Serialize` impl below emits the flat, Dart-facing contract.
// `Deserialize` is retained (never used on the Rust side, but required
// as a field type of `MachineEvent::Failed`).
// Both `Serialize` and `Deserialize` are implemented manually below so
// the wire format is symmetric (flat `kind`/`detail`/`status`).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AuthenticationError {
    /// A network-level failure (DNS, TLS, timeout, connection reset).
    #[error("network error: {0}")]
    Network(String),

    /// The server returned an unexpected HTTP status.
    #[error("server returned HTTP {status}: {message}")]
    Http {
        /// HTTP status code.
        status: u16,
        /// Human readable message (usually extracted from the server JSON body).
        message: String,
    },

    /// The server returned 2xx but the body was missing a required field.
    #[error("invalid response from server: {0}")]
    InvalidResponse(String),

    /// A macaroon string could not be parsed (bad base64, unknown format,
    /// malformed packet stream).
    #[error("cannot parse macaroon: {0}")]
    MacaroonParse(String),

    /// The store-issued root macaroon carries no third-party caveat pointing
    /// at the SSO discharge endpoint.
    #[error("root macaroon has no SSO discharge caveat")]
    NoDischargeCaveat,

    /// Ubuntu One rejected the credentials (wrong password, or a bad/expired
    /// 2FA code).
    #[error("credentials rejected by Ubuntu One: {0}")]
    CredentialsRejected(String),

    /// The SSO server demands a 2FA one-time code. The interactive state
    /// machine catches this and pauses for UI input; raw API consumers see it
    /// here.
    #[error("two-factor authentication code required")]
    TwoFactorRequired,

    /// An operation was attempted in a state where it is not allowed.
    #[error("operation not allowed in state: {0}")]
    InvalidStateTransition(String),

    /// No session exists / the session is not active.
    #[error("no active authentication session")]
    NoActiveSession,

    /// The user cancelled the session.
    #[error("authentication session was cancelled")]
    SessionCancelled,

    /// The secure storage backend failed.
    #[error("secure storage error: {0}")]
    Storage(String),
}

impl AuthenticationError {
    /// Stable machine-readable identifier of the error variant
    /// (e.g. `"two_factor_required"`).
    pub fn code(&self) -> &'static str {
        match self {
            Self::Network(_) => "network",
            Self::Http { .. } => "http",
            Self::InvalidResponse(_) => "invalid_response",
            Self::MacaroonParse(_) => "macaroon_parse",
            Self::NoDischargeCaveat => "no_discharge_caveat",
            Self::CredentialsRejected(_) => "credentials_rejected",
            Self::TwoFactorRequired => "two_factor_required",
            Self::InvalidStateTransition(_) => "invalid_state_transition",
            Self::NoActiveSession => "no_active_session",
            Self::SessionCancelled => "session_cancelled",
            Self::Storage(_) => "storage",
        }
    }
}

impl Serialize for AuthenticationError {
    /// Flat, Dart-facing wire contract (matches the FFI docstring and the Dart
    /// `SnapstoreAuthError.from` parser):
    ///   `{ "kind": "<snake_case>", "detail": "<human string>" }`
    /// and for the `http` variant an additional top-level `"status": <int>`.
    ///
    /// (The old derived `tag`/`content` form nested the `http` payload as an
    /// *object* under `detail`, which Dart read as a non-string and surfaced
    /// as `HTTP null` + raw JSON. This override fixes that at the source.)
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let (kind, detail, status) = match self {
            Self::Network(m) => (self.code(), m.as_str(), None),
            Self::Http { status, message } => (self.code(), message.as_str(), Some(*status)),
            Self::InvalidResponse(m) => (self.code(), m.as_str(), None),
            Self::MacaroonParse(m) => (self.code(), m.as_str(), None),
            Self::NoDischargeCaveat => (
                self.code(),
                "root macaroon has no SSO discharge caveat",
                None,
            ),
            Self::CredentialsRejected(m) => (self.code(), m.as_str(), None),
            Self::TwoFactorRequired => (
                self.code(),
                "two-factor authentication code required",
                None,
            ),
            Self::InvalidStateTransition(m) => (self.code(), m.as_str(), None),
            Self::NoActiveSession => (
                self.code(),
                "no active authentication session",
                None,
            ),
            Self::SessionCancelled => (
                self.code(),
                "authentication session was cancelled",
                None,
            ),
            Self::Storage(m) => (self.code(), m.as_str(), None),
        };

        #[derive(serde::Serialize)]
        struct Wire<'a> {
            kind: &'a str,
            detail: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            status: Option<u16>,
        }
        Wire { kind, detail, status }.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for AuthenticationError {
    /// Symmetric with the flat [`Serialize`] impl above:
    /// `{ "kind": "...", "detail": "...", "status"?: <int> }`.
    fn deserialize<D: serde::Deserializer<'de>>(
        d: D,
    ) -> std::result::Result<Self, D::Error> {
        use serde::de::Error as _;

        #[derive(serde::Deserialize)]
        struct Wire {
            kind: String,
            detail: String,
            #[serde(default)]
            status: Option<u16>,
        }
        let w = Wire::deserialize(d)?;
        match w.kind.as_str() {
            "network" => Ok(Self::Network(w.detail)),
            "http" => Ok(Self::Http { status: w.status.unwrap_or(0), message: w.detail }),
            "invalid_response" => Ok(Self::InvalidResponse(w.detail)),
            "macaroon_parse" => Ok(Self::MacaroonParse(w.detail)),
            "no_discharge_caveat" => Ok(Self::NoDischargeCaveat),
            "credentials_rejected" => Ok(Self::CredentialsRejected(w.detail)),
            "two_factor_required" => Ok(Self::TwoFactorRequired),
            "invalid_state_transition" => Ok(Self::InvalidStateTransition(w.detail)),
            "no_active_session" => Ok(Self::NoActiveSession),
            "session_cancelled" => Ok(Self::SessionCancelled),
            "storage" => Ok(Self::Storage(w.detail)),
            other => Err(D::Error::custom(format!("unknown error kind: {other}"))),
        }
    }
}

impl From<reqwest::Error> for AuthenticationError {
    fn from(err: reqwest::Error) -> Self {
        // Keep the enum self-contained (all fields are strings) so it
        // serializes cleanly across the FFI boundary. Include the source
        // chain (e.g. the OS connect error) — it is the only useful
        // diagnostic for network failures.
        use std::error::Error as _;
        let mut detail = err.to_string();
        let mut src = err.source();
        while let Some(s) = src {
            detail.push_str(": ");
            detail.push_str(&s.to_string());
            src = s.source();
        }
        AuthenticationError::Network(detail)
    }
}

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, AuthenticationError>;

#[cfg(test)]
mod error_wire_tests {
    use super::AuthenticationError;

    #[test]
    fn flat_error_shape_matches_the_dart_contract() {
        // Regression test for the `HTTP null` bug: the `http` variant must
        // serialize as flat `{"kind","detail","status"}` (string detail,
        // top-level status), NOT as `{"kind","detail":{...object...}}`.
        let http = AuthenticationError::Http {
            status: 404,
            message: "macaroon request failed".into(),
        };
        let json = serde_json::to_string(&http).expect("serialize");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["kind"], "http");
        assert_eq!(v["detail"], "macaroon request failed");
        assert_eq!(v["status"], 404);

        // Unit variants must NOT carry a stray `status` key.
        let net = AuthenticationError::Network("dns failure".into());
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&net).unwrap()).unwrap();
        assert_eq!(v["kind"], "network");
        assert_eq!(v["detail"], "dns failure");
        assert!(v.get("status").is_none());

        // Round-trip (symmetric Deserialize).
        let back: AuthenticationError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, http);
    }
}

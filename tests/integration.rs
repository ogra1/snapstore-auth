
//! End-to-end tests of the interactive login flow against an in-process
//! HTTP server that emulates the Snap Store + Ubuntu One endpoints,
//! including the 2FA (OTP-required) interruption.

use snapstore_auth::auth_core::{AuthConfig, AuthRuntime};
use serial_test::serial;
use snapstore_auth::error::AuthenticationError;
use snapstore_auth::state::MachineEvent;
use base64::Engine as _;

/// The v1 binary root macaroon from the unit tests (has the SSO caveat).
const ROOT_MACAROON: &str = "MDAyY2xvY2F0aW9uIGh0dHBzOi8vZGFzaGJvYXJkLnNuYXBjcmFmdC5pbwowMDE5aWRlbnRpZmllciByb290LWlkLTEKMDAxMGNpZCBjaWQtMDAxCjAwNTF2aWQgDVQZMibgN_0yFc5ogte1xjxpKc5XmjPtPUWWYjviSULNh5-nmPcN1s6-h-c8qSgmFQvO8Iy__a9fehkpatZve0PCpRiUI3hNCjAwMzhjbCBodHRwczovL2xvZ2luLnVidW50dS5jb20vYXBpL3YyL3Rva2Vucy9kaXNjaGFyZ2UKMDAyZnNpZ25hdHVyZSC0CqFfWTisBnfUsDI0y9i5xkTUuL-BFCOwFXL2EJj9dwo";
/// An unsigned v1 binary discharge macaroon.
const DISCHARGE_MACAROON: &str = "MDAyNmxvY2F0aW9uIGh0dHBzOi8vbG9naW4udWJ1bnR1LmNvbQowMDFiaWRlbnRpZmllciBkaXNjaGFyZ2UtMQowMDBmc2lnbmF0dXJlIAo";

/// reqwest's default client honors `HTTP_PROXY`/`http_proxy` for ALL
/// requests, *including loopback*, unless `NO_PROXY` exempts the host.
/// Launchpad build containers run behind a firewall proxy, so without this
/// the tests' traffic to the in-process fake store (127.0.0.1) would be
/// routed to the proxy, which answers with a 403 (Squid refuses to proxy
/// to localhost). Always exempt the loopback addresses.
fn exempt_loopback_from_proxy() {
    let existing = std::env::var("NO_PROXY")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_default();
    let mut parts: Vec<&str> =
        existing.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
    for h in ["127.0.0.1", "localhost", "::1"] {
        if !parts.iter().any(|e| *e == h) {
            parts.push(h);
        }
    }
    let val = parts.join(",");
    if !val.is_empty() {
        std::env::set_var("NO_PROXY", &val);
        std::env::set_var("no_proxy", &val);
    }
}

/// Start a tiny HTTP server emulating store + SSO.
///
/// * `two_factor`: when true, the first discharge (no otp) returns the
///   401 twofactor-required shape; a discharge with `otp == "654321"`
///   succeeds.
/// * `password`: the password the SSO accepts (anything else → 401 bad
///   credentials).
/// * Returns (store_url, login_url, port).
async fn start_fake_store(two_factor: bool, password: &str) -> (String, String, u16) {
    use tokio::net::TcpListener;

    // Must run before any reqwest client is created (the AuthRuntime builds
    // its client in `spawn`, which every test does after this helper).
    exempt_loopback_from_proxy();

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();

    let password_owned = password.to_string();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let pw = password_owned.clone();
            tokio::spawn(async move {
                let _ = handle_client(&mut sock, two_factor, &pw).await;
            });
        }
    });

    (
        format!("http://127.0.0.1:{port}"),
        format!("http://127.0.0.1:{port}"),
        port,
    )
}

async fn handle_client(
    sock: &mut tokio::net::TcpStream,
    two_factor: bool,
    password: &str,
) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = [0u8; 16384];
    let n = sock.read(&mut buf).await?;
    let req = String::from_utf8_lossy(&buf[..n]).to_string();
    let head = req.lines().next().unwrap_or("");
    let path = head.split(' ').nth(1).unwrap_or("");
    // Read body (Content-Length based).
    let req_lower = req.to_ascii_lowercase();
    let content_length = req_lower
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let body_start = req.find("\r\n\r\n").map(|i| i + 4).unwrap_or(req.len());
    let mut body = req[body_start..].to_string();
    while body.len() < content_length {
        let mut extra = [0u8; 1024];
        let k = sock.read(&mut extra).await?;
        if k == 0 {
            break;
        }
        body.push_str(&String::from_utf8_lossy(&extra[..k]));
    }
    let body = body[..content_length.min(body.len())].to_string();

    let (status, json) = match path {
        "/dev/api/acl/" => (
            200,
            format!(
                "{{\"macaroon\": \"{}\"}}",
                ROOT_MACAROON
            ),
        ),
        "/api/v2/tokens/discharge" => {
            let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
            let pwd = v.get("password").and_then(|p| p.as_str()).unwrap_or("");
            let otp = v.get("otp").and_then(|o| o.as_str()).unwrap_or("");
            if two_factor && otp.is_empty() {
                (
                    401,
                    r#"{"code": "TWOFACTOR_REQUIRED", "message": "OTP required", "error_list": [{"code": "twofactor-required", "message": "OTP required"}]}"#.to_string(),
                )
            } else if pwd != password {
                (
                    401,
                    r#"{"code": "BAD_CREDENTIALS", "message": "Invalid password", "error_list": [{"code": "invalid-credentials", "message": "Invalid password"}]}"#.to_string(),
                )
            } else if two_factor && otp != "654321" {
                (
                    401,
                    r#"{"code": "TWOFACTOR_REQUIRED", "message": "OTP required", "error_list": [{"code": "twofactor-required", "message": "OTP required"}]}"#.to_string(),
                )
            } else {
                (
                    200,
                    format!("{{\"discharge_macaroon\": \"{}\"}}", DISCHARGE_MACAROON),
                )
            }
        }
        "/api/v2/tokens/whoami" => (
            200,
            r#"{"account":{"id":"DEADBEEF1234","email":"test@example.com","username":"test","display-name":"Test User"},"permissions":["package_access"],"channels":null,"expires":"2026-10-15T12:00:00+00:00"}"#
                .to_string(),
        ),
        _ => (404, r#"{"message": "not found"}"#.to_string()),
    };

    let reason = match status {
        200 => "OK",
        401 => "Unauthorized",
        404 => "Not Found",
        _ => "Error",
    };
    let resp = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json}",
        json.len()
    );
    sock.write_all(resp.as_bytes()).await?;
    Ok(())
}

/// Collect machine events as typed values.
fn parse_events(json_lines: &str) -> Vec<MachineEvent> {
    json_lines
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

#[serial]
#[serial]
#[tokio::test]
async fn login_without_2fa_succeeds_and_persists() {
    let (store_url, login_url, _port) = start_fake_store(false, "correct-password").await;
    let config = AuthConfig {
        store_url,
        login_url,
        user_agent: "test".into(),
        ..Default::default()
    };
    let rt = AuthRuntime::spawn(config);
    rt.start_login().expect("start");

    // Wait for NeedsCredentials.
    wait_for_state(&rt, &["needs_credentials"]).await;
    rt.submit_credentials("user@example.com", "correct-password")
        .expect("creds");

    // Wait for success.
    wait_for_state(&rt, &["succeeded"]).await;
    let events = parse_events(&rt.drain_events());
    let succeeded = events
        .iter()
        .find(|e| matches!(e, MachineEvent::Succeeded { .. }))
        .expect("succeeded event");
    if let MachineEvent::Succeeded {
        email,
        used_two_factor,
        credentials_json,
    } = succeeded
    {
        assert_eq!(email, "user@example.com");
        assert!(!used_two_factor);
        let creds: snapstore_auth::storage::Credentials =
            serde_json::from_str(credentials_json).expect("creds json");
        assert_eq!(creds.root, ROOT_MACAROON);
        assert_eq!(creds.discharge, DISCHARGE_MACAROON);
    }

    // The header must match what pymacaroons produces.
    let header = rt.authorization_header().expect("header");
    assert!(header.starts_with("Macaroon root=MDAyY2xv"));
    assert!(header.contains("discharge=MDAyNmxvY2F0aW9u"));

    // whoami works with the persisted creds.
    let info = rt.whoami().await.expect("whoami");
    assert_eq!(info.email, "test@example.com");
    assert_eq!(info.id, "DEADBEEF1234");
    assert_eq!(info.username, "test");
    assert_eq!(info.display_name, "Test User");
    assert_eq!(info.permissions, vec!["package_access"]);

    // Logout clears storage.
    rt.logout().expect("logout");
    wait_for_state(&rt, &["idle"]).await;
    assert!(rt.authorization_header().is_err());
}

#[serial]
#[serial]
#[tokio::test]
async fn login_with_2fa_pauses_and_resumes() {
    let (store_url, login_url, _port) = start_fake_store(true, "correct-password").await;
    let config = AuthConfig {
        store_url,
        login_url,
        user_agent: "test".into(),
        ..Default::default()
    };
    let rt = AuthRuntime::spawn(config);
    rt.start_login().expect("start");

    wait_for_state(&rt, &["needs_credentials"]).await;
    rt.submit_credentials("user@example.com", "correct-password")
        .expect("creds");

    // The driver must pause, emitting Needs2FACode.
    wait_for_state(&rt, &["needs_2fa_code"]).await;
    let events = parse_events(&rt.drain_events());
    assert!(
        events.iter().any(|e| matches!(e, MachineEvent::Needs2FACode)),
        "expected a Needs2FACode event, got {events:?}"
    );

    // Submit the 2FA code.
    rt.submit_2fa_code("654321").expect("2fa");
    wait_for_state(&rt, &["succeeded"]).await;

    let events = parse_events(&rt.drain_events());
    let succeeded = events
        .iter()
        .find(|e| matches!(e, MachineEvent::Succeeded { .. }))
        .expect("succeeded");
    if let MachineEvent::Succeeded { used_two_factor, .. } = succeeded {
        assert!(*used_two_factor);
    }
}

#[serial]
#[serial]
#[tokio::test]
async fn wrong_password_is_a_typed_error() {
    let (store_url, login_url, _port) = start_fake_store(false, "correct-password").await;
    let config = AuthConfig {
        store_url,
        login_url,
        user_agent: "test".into(),
        ..Default::default()
    };
    let rt = AuthRuntime::spawn(config);
    rt.start_login().expect("start");
    wait_for_state(&rt, &["needs_credentials"]).await;
    rt.submit_credentials("user@example.com", "wrong-password")
        .expect("creds");
    wait_for_state(&rt, &["idle"]).await;
    let events = parse_events(&rt.drain_events());
    let failed = events
        .iter()
        .find(|e| matches!(e, MachineEvent::Failed { .. }))
        .expect("failed event");
    if let MachineEvent::Failed { error } = failed {
        assert!(
            matches!(error, AuthenticationError::CredentialsRejected(_)),
            "expected CredentialsRejected, got {error:?}"
        );
    }
}

#[serial]
#[serial]
#[tokio::test]
async fn cancel_mid_flow_returns_to_idle() {
    let (store_url, login_url, _port) = start_fake_store(false, "p").await;
    let config = AuthConfig {
        store_url,
        login_url,
        user_agent: "test".into(),
        ..Default::default()
    };
    let rt = AuthRuntime::spawn(config);
    rt.start_login().expect("start");
    wait_for_state(&rt, &["needs_credentials"]).await;
    rt.cancel().expect("cancel");
    wait_for_state(&rt, &["idle"]).await;
    let events = parse_events(&rt.drain_events());
    assert!(events
        .iter()
        .any(|e| matches!(e, MachineEvent::Cancelled { .. })));
}

/// Poll the runtime until it reaches one of the given states (with a
/// generous timeout so slow CI doesn't flake).
async fn wait_for_state(rt: &AuthRuntime, states: &[&str]) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if states.contains(&rt.state().as_str()) {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for state {states:?}; current: {}",
            rt.state().as_str()
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// The base64 fixture must survive our (de)serialization untouched — a
/// regression guard for the v1 binary parser.
#[test]
fn fixtures_are_valid_v1_binary() {
    assert!(snapstore_auth::macaroon::Macaroon::parse(ROOT_MACAROON).is_ok());
    assert!(snapstore_auth::macaroon::Macaroon::parse(DISCHARGE_MACAROON).is_ok());
    let _ = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(ROOT_MACAROON)
        .expect("b64");
}

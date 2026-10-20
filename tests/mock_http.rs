//! Repro: shared runtime reqwest -> the python mock store (real socket).
use snapstore_auth::auth_core::{AuthConfig, AuthRuntime};
use snapstore_auth::runtime;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Spawn `tool/mock_store.py` on `port` and wait for it to accept
/// connections. The caller must `kill()` the returned child.
fn spawn_mock_store(port: u16, extra_args: &[&str]) -> Child {
    let mut args: Vec<String> = vec![
        // Overridable via SNAPSTORE_AUTH_MOCK_STORE; defaults to this repo's copy (run from the repo root).
        std::env::var("SNAPSTORE_AUTH_MOCK_STORE")
            .unwrap_or_else(|_| "tool/mock_store.py".to_string()),
        "--port".to_string(),
        port.to_string(),
    ];
    args.extend(extra_args.iter().map(|s| s.to_string()));

    let child = Command::new("python3")
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn mock");

    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(10) {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    child
}

#[test]
fn runtime_http_reaches_python_mock() {
    let mut child = spawn_mock_store(8499, &["--two-factor", "--password", "s3cret"]);

    let out = runtime::block_on(async {
        let r = reqwest::Client::new()
            .get("http://127.0.0.1:8499/api/v2/tokens/whoami")
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = r.status().as_u16();
        Ok::<u16, String>(status)
    });
    child.kill().ok();
    match out {
        Ok(status) => println!("GOT STATUS {status} (expect 401)"),
        Err(e) => panic!("request failed: {e}"),
    }
}

/// End-to-end: log in against the real python mock process (not the
/// in-process Rust fake server used by `tests/integration.rs`), then
/// exercise `AuthRuntime::request` — the generic authenticated-request
/// escape hatch — against the mock's `/__echo` endpoint.
#[tokio::test]
async fn request_generic_escape_hatch_against_python_mock() {
    let mut child = spawn_mock_store(8500, &["--password", "s3cret"]);

    let config = AuthConfig {
        store_url: "http://127.0.0.1:8500".to_string(),
        login_url: "http://127.0.0.1:8500".to_string(),
        user_agent: "test".into(),
        ..Default::default()
    };
    let rt = AuthRuntime::spawn(config);
    let result = async {
        rt.start_login().expect("start");
        let t0 = Instant::now();
        while rt.state().as_str() != "needs_credentials" {
            if t0.elapsed() > Duration::from_secs(5) {
                panic!("timed out waiting for needs_credentials");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        rt.submit_credentials("user@example.com", "s3cret")
            .expect("creds");
        let t0 = Instant::now();
        while rt.state().as_str() != "succeeded" {
            if t0.elapsed() > Duration::from_secs(5) {
                panic!("timed out waiting for succeeded");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // 2xx: body + content-type + method + path echoed verbatim.
        let ok = rt
            .request(
                "POST",
                "/__echo/widgets?status=201",
                Some(r#"{"name":"widget"}"#),
                None,
            )
            .await
            .expect("request ok");
        assert_eq!(ok.status, 201);
        let echoed: serde_json::Value = serde_json::from_str(&ok.body).expect("echo json");
        assert_eq!(echoed["method"], "POST");
        assert_eq!(echoed["path"], "/__echo/widgets");
        assert_eq!(echoed["body"], r#"{"name":"widget"}"#);
        assert_eq!(echoed["content_type"], "application/json");

        // Non-2xx passes through as `Ok` too — the caller decides.
        let not_found = rt
            .request("GET", "/__echo/missing?status=404", None, None)
            .await
            .expect("request not found");
        assert_eq!(not_found.status, 404);
    }
    .await;

    child.kill().ok();
    result
}

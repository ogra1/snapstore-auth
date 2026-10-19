//! Repro: shared runtime reqwest -> the python mock store (real socket).
use snapstore_auth::runtime;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn runtime_http_reaches_python_mock() {
    let mut child = Command::new("python3")
        .args([
            // Overridable via SNAPSTORE_AUTH_MOCK_STORE; defaults to this repo's copy (run from the repo root).
            std::env::var("SNAPSTORE_AUTH_MOCK_STORE").unwrap_or_else(|_| "tool/mock_store.py".to_string()).leak(),
            "--port",
            "8499",
            "--two-factor",
            "--password",
            "s3cret",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn mock");
    // Wait for the port.
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(10) {
        if std::net::TcpStream::connect("127.0.0.1:8499").is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

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

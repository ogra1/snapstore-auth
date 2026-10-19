//! The shared, long-lived Tokio runtime behind the FFI boundary.
//!
//! The Flutter UI thread must never block on the Rust side. All async work
//! (the login driver task, `whoami()`, any future store API call) runs on a
//! **multithreaded** Tokio runtime created once here. FFI entry points are
//! plain synchronous functions that either:
//!
//! * only send a command to the driver (non-blocking channel `send`), or
//! * run an async operation to completion via [`block_on`].
//!
//! [`block_on`] is deadlock-safe by construction: it **spawns** the future
//! on the runtime and waits for the result over a oneshot channel, so the
//! FFI thread never blocks a runtime worker thread (the classic
//! `Runtime::block_on`-inside-a-runtime-task deadlock is impossible).

use std::sync::OnceLock;

static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

/// The process-wide multithreaded runtime.
///
/// Created lazily on first use. Worker threads default to the number of
/// available cores, so network I/O and the driver task never contend for
/// the UI thread.
pub fn runtime() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to start tokio runtime")
    })
}

/// Run an async block to completion on the shared runtime **without
/// blocking a worker thread**.
///
/// The future is spawned as a task; the caller waits on a oneshot
/// receiver. Use this from FFI threads (the Flutter platform thread),
/// never from inside a task that runs on this same runtime.
pub fn block_on<F>(future: F) -> F::Output
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    let (tx, rx) = tokio::sync::oneshot::channel::<F::Output>();
    runtime().spawn(async move {
        let out = future.await;
        let _ = tx.send(out);
    });
    // Waiting on a oneshot Receiver is a std `Sync` wait — safe from any
    // thread, including the Flutter UI thread.
    match rx.blocking_recv() {
        Ok(out) => out,
        // The task panicked; surface it as a typed failure is not possible
        // here (Output may not be an error type), so fall back to a
        // controlled panic message. A task panic in this crate means a
        // logic bug; it must not silently vanish.
        Err(_) => panic!("async task on the auth runtime failed"),
    }
}

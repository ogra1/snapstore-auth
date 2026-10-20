# snapstore-auth

Interactive Ubuntu One SSO (email + password + 2FA) login with **macaroon
issuance for the Snap Store**, plus authenticated account / brand-store /
signing-key API calls — as a self-contained Rust backend with a first-class
Dart FFI client. Built to be shared between Flutter apps (it started life in
the [Ubuntu Core model builder](https://github.com/ogra1/ubuntu-core-model-builder)).

## Layout

| Path | What it is |
|---|---|
| `Cargo.toml`, `src/` | The Rust crate (`snapstore-auth`) — a `cdylib`/`staticlib`/`rlib` producing `libsnapstore_auth.so`. Pure-Rust TLS (reqwest + rustls; **no OpenSSL**), links only libc/libm/libgcc_s. |
| `lib/snapstore_auth_dart.dart` | The Dart package **`snapstore_auth_dart`** — the `dart:ffi` client (`lib/src/snapstore_auth_client.dart`): the auth state machine, login/restore/import flows, and the authenticated store API. |
| `tool/mock_store.py` | A tiny stdlib-only mock Snap Store / Ubuntu One SSO server for tests (macaroon discharge, whoami, account, brand-store catalog, account-key registration; 2FA on/off; expired-macaroon mode for testing recovery paths). |
| `tests/` | Rust integration tests (against the mock store). |
| `example/build_for_flutter.sh` | Builds the cdylib and stages it where a Flutter app's FFI client probes. |

The Rust side is MIT-licensed; the Dart package inherits the terms of the
consuming project (it is consumed via a git dependency, not pub.dev).

## How the native library is found (Dart)

The Dart client loads `libsnapstore_auth`, in this order:

1. `$SNAPSTORE_AUTH_LIB` — explicit path (tests, CI, manual builds);
2. next to the executable (`Platform.resolvedExecutable` dir, `./lib/`), then the working directory;
3. standard system library paths.

So a Flutter app just needs the `.so` built and placed next to its binary —
no `dart:ffi` configuration, no codegen, no `flutter_rust_bridge`/UniFFI.

## Consuming from a Flutter app

**Dart (pubspec.yaml)** — pin the client:

```yaml
dependencies:
  snapstore_auth_dart:
    git:
      url: https://github.com/ogra1/snapstore-auth
      ref: <commit-or-tag>
```

```dart
import 'package:snapstore_auth_dart/snapstore_auth_dart.dart';
// SnapstoreAuthSession, AuthState, SnapstoreAuthError, ...
```

**Native library (build time)** — one part/step that runs
`cargo build --release` in this repo and primes
`target/release/libsnapstore_auth.so` next to the app binary (a classic snap
part can additionally set `SNAPSTORE_AUTH_LIB` in the app environment).

**Tests** — point the app's test runner at a local build and the mock store:

```
SNAPSTORE_AUTH_LIB=/path/to/libsnapstore_auth.so flutter test
python3 <repo>/tool/mock_store.py --port 8471 --two-factor --password s3cret
```

## Using the mock store

```
python3 tool/mock_store.py --port 8471 --two-factor --password s3cret --good-code 654321
```

Flags:

- `--port` (default 8471)
- `--two-factor` / `--no-two-factor` — first OTP-less discharge answers
  `401 twofactor-required` vs. validating the password directly
- `--password`, `--good-code` — the accepted credentials
- `--reject-macaroon` — start with authenticated endpoints answering
  `401 "macaroon is expired"` (login still works)

Test-only control endpoints (not part of the real store API):

- `POST /__reject` — toggle the reject-macaroon mode at runtime
  (log in against a healthy store, then simulate expiry)
- `GET  /__registered` — the account-key assertions recorded so far
- `*    /__echo/<anything>?status=<code>` — echoes
  `{method, path, body, content_type}` (auth required)

## Versioning

Pin by git commit/tag in the consuming app. Breaking changes to the C ABI
(`auth_*` symbols) or the Dart API require a bump of `version` in
`pubspec.yaml` and `Cargo.toml` together.

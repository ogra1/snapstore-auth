/// Dart FFI client for the `libsnapstore_auth` Rust backend: interactive
/// Ubuntu One SSO login (email + password + 2FA) with macaroon issuance for
/// the Snap Store, and authenticated account / brand-store / signing-key
/// API calls.
///
/// The native library is loaded per the rules in [snapstore_auth_client]
/// (`SNAPSTORE_AUTH_LIB` override, next to the executable, system paths).
library snapstore_auth;

export 'src/snapstore_auth_client.dart';

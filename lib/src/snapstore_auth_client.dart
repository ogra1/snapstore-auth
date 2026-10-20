// ---------------------------------------------------------------------------
// snapstore_auth_client.dart
//
// Vendored, app-local FFI client for the `snapstore-auth` Rust crate
// (library `libsnapstore_auth`). The original hand-written binding
// (snapstore_auth_bindings.dart) is included verbatim below this header and
// extended with:
//
//   * the two extra C symbols added for the model builder integration:
//       auth_store_snaps(handle, store_id, out_err) -> *c_char (JSON)
//       auth_import_exported_login(handle, raw, out_err) -> bool
//   * the `SnapstoreAuthSession` lifecycle helper (init / restore /
//     re-login / logout on the single process-wide runtime).
//
// Keep this file in sync with the Rust crate when its FFI surface changes.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// snapstore_auth_bindings.dart
//
// Hand-written `dart:ffi` bindings for the `snapstore-auth` Rust crate
// (library `libsnapstore_auth`, C-ABI surface `crate::ffi`).
//
// This is the *minimal-binding* form: a thin, fully typed layer over the C
// functions — no code generator (flutter_rust_bridge / UniFFI) required.
// Every value crossing the boundary is a plain machine word (opaque handle,
// C string, bool, u32), which is exactly what the Rust side exports.
//
// C-ABI surface (all `#[no_mangle] extern "C"`):
//   auth_runtime_init(store_url, login_url, permissions, storage_key,
//                     out_err)            -> opaque handle (NULL on error)
//   auth_runtime_get()                    -> handle (process-wide)
//   auth_state(handle, out_err)           -> *c_char   (state string)
//   auth_pending_events(handle)           -> u32
//   auth_drain_events(handle)             -> *c_char   (JSON lines, \n joined)
//   auth_start_login(handle, out_err)     -> bool
//   auth_submit_credentials(handle,
//                           email, password, out_err)  -> bool
//   auth_submit_2fa_code(handle,
//                        code, out_err)                -> bool
//   auth_restore_credentials(handle,
//                            json, out_err)            -> bool
//   auth_logout(handle, out_err)          -> bool
//   auth_cancel(handle, out_err)          -> bool
//   auth_authorization_header(handle,
//                             out_err)                 -> *c_char
//   auth_whoami(handle, out_err)          -> *c_char   (account JSON:
//                                                 {id,email,username,
//                                                  display_name,permissions,
//                                                  channels,expires})
//   auth_account_info(handle, out_err)     -> *c_char   (full /dev/api/account
//                                                 JSON: account_id,
//                                                 account_keys[], stores[],
//                                                 snaps[], ...)
//   auth_register_key(handle,
//                     account_key_request, out_err) -> bool
//   auth_free_string(ptr)
//
// String ownership protocol
//   * Every `*mut c_char` RETURNED by the library is Rust-heap-allocated and
//     MUST be released with `auth_free_string` exactly once — the helpers
//     here do that automatically.
//   * Every string Dart PASSES is copied by Rust before the call returns.
//
// Threading
//   All calls are safe from the Dart main isolate: the Rust side parks async
//   work on its own multithreaded Tokio runtime, so the Flutter UI thread is
//   never blocked. Exception: [SnapstoreAuth.whoami] blocks the calling
//   isolate for the duration of the HTTP request (bounded by the ~30 s
//   timeout) — run it on a background isolate in production.
//
// FFI conventions used here (verified against Dart 3.13 / package:ffi 2.2):
//   * `lookupFunction<NS, DS>` takes *plain function types* for both the
//     native and Dart sides (not the older `NativeFunction<...>` wrapper).
//   * Native-side scalar types use `dart:ffi` names (`Void`, `Bool`,
//     `Uint32`); the Dart side uses `void`, `bool`, `int`.
//   * `calloc` (an `Allocator`) and `Pointer<Utf8>.toDartString()` come from
//     `package:ffi`.
// ---------------------------------------------------------------------------

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';

import 'package:ffi/ffi.dart'; // calloc (Allocator), Utf8, Utf8Pointer

// ──────────────────────────────────────────────────────────────────────────
// 1. Library loading
// ──────────────────────────────────────────────────────────────────────────

/// Locate `libsnapstore_auth.so` / `snapstore_auth.dll` /
/// `libsnapstore_auth.dylib`.
///
/// Resolution order:
///  1. `SNAPSTORE_AUTH_LIB` environment variable (full path — handy in
///     tests / CI / `flutter run`).
///  2. Default dynamic-loader search path (`LD_LIBRARY_PATH`, or the
///     directory of the executable).
///
/// In a Flutter app the native library is usually shipped as a plugin asset
/// (or via CMake/Gradle); resolve its absolute path and set the env var, or
/// pass the path through your wrapper.
final DynamicLibrary snapstoreAuthLibrary = () {
  // 1. Explicit override (tests / CI / manual builds).
  final String? envPath = Platform.environment['SNAPSTORE_AUTH_LIB'];
  if (envPath != null && envPath.isNotEmpty) {
    return DynamicLibrary.open(envPath);
  }
  // 2. Probes: working directory and the executable's directory (the app
  //    bundles `libsnapstore_auth.so` next to the binary — see
  //    scripts/build_rust_backend.sh), then standard system paths.
  final String exeDir = (() {
    try {
      return File(Platform.resolvedExecutable).parent.path;
    } catch (_) {
      return '.';
    }
  })();
  const names = <String>[
    'libsnapstore_auth.so',
    'lib/libsnapstore_auth.so',
    'linux/rust/libsnapstore_auth.so',
  ];
  for (final String dir in <String>['.', exeDir, '/usr/local/lib', '/usr/lib']) {
    for (final String n in names) {
      final String p = dir.endsWith('/') ? '$dir$n' : '$dir/$n';
      try {
        if (File(p).existsSync()) {
          return DynamicLibrary.open(p);
        }
      } catch (_) {}
    }
  }
  // 3. Last resort: plain loader search (LD_LIBRARY_PATH).
  return DynamicLibrary.open('libsnapstore_auth.so');
}();

/// The opaque runtime handle (C `*mut AuthRuntimeHandle` == `*mut c_void`).
typedef OpaquePtr = Pointer<Void>;
/// A C `c_char` pointer (NUL-terminated UTF-8).
typedef CString = Pointer<Int8>;
/// An out-parameter slot for an error C string (`**mut c_char`).
typedef ErrOut = Pointer<CString>;

// ──────────────────────────────────────────────────────────────────────────
// 2. Function signatures
//
//    Where the native and Dart signatures are identical (all pointer and
//    opaque types are the same on both sides), a single typedef is reused
//    for both type-arguments of `lookupFunction`. Where a scalar differs
//    (`Bool`/`bool`, `Void`/`void`, `Uint32`/`int`), two typedefs are used.
// ──────────────────────────────────────────────────────────────────────────

// -- auth_runtime_init ------------------------------------------------------
typedef TInit = OpaquePtr Function(
    CString, CString, CString, CString, ErrOut);

// -- auth_runtime_get -------------------------------------------------------
typedef TGet = OpaquePtr Function();

// -- auth_state / auth_authorization_header / auth_whoami -------------------
typedef TStringOut = CString Function(OpaquePtr, ErrOut);

// -- auth_pending_events (native u32, dart int) -----------------------------
typedef TPendingNative = Uint32 Function(OpaquePtr);
typedef TPendingDart = int Function(OpaquePtr);

// -- auth_drain_events ------------------------------------------------------
typedef TDrain = CString Function(OpaquePtr);

// -- bool commands, no string arg (start_login / logout / cancel) -----------
typedef TBoolCmdNative = Bool Function(OpaquePtr, ErrOut);
typedef TBoolCmdDart = bool Function(OpaquePtr, ErrOut);

// -- bool commands, one string arg (submit_2fa_code / restore_credentials) --
typedef TStrCmdNative = Bool Function(OpaquePtr, CString, ErrOut);
typedef TStrCmdDart = bool Function(OpaquePtr, CString, ErrOut);

// -- auth_submit_credentials (two string args) ------------------------------
typedef TCredsNative =
    Bool Function(OpaquePtr, CString, CString, ErrOut);
typedef TCredsDart = bool Function(OpaquePtr, CString, CString, ErrOut);

// -- auth_register_key (bool; one string arg) ------------------------------
// (same shape as submit_2fa_code / restore_credentials)

// -- auth_free_string (native Void, dart void) ------------------------------
typedef TFreeNative = Void Function(CString);
typedef TFreeDart = void Function(CString);

/// Looked-up FFI functions. Obtain one via [SnapstoreAuthBindings.load].
final class SnapstoreAuthBindings {
  SnapstoreAuthBindings._(DynamicLibrary lib)
      : init = lib.lookupFunction<TInit, TInit>('auth_runtime_init'),
        runtimeGet = lib.lookupFunction<TGet, TGet>('auth_runtime_get'),
        state = lib.lookupFunction<TStringOut, TStringOut>('auth_state'),
        pendingEvents =
            lib.lookupFunction<TPendingNative, TPendingDart>(
                'auth_pending_events'),
        drainEvents =
            lib.lookupFunction<TDrain, TDrain>('auth_drain_events'),
        startLogin =
            lib.lookupFunction<TBoolCmdNative, TBoolCmdDart>(
                'auth_start_login'),
        submitCredentials = lib.lookupFunction<TCredsNative, TCredsDart>(
            'auth_submit_credentials'),
        submit2faCode =
            lib.lookupFunction<TStrCmdNative, TStrCmdDart>(
                'auth_submit_2fa_code'),
        restoreCredentials =
            lib.lookupFunction<TStrCmdNative, TStrCmdDart>(
                'auth_restore_credentials'),
        logout = lib.lookupFunction<TBoolCmdNative, TBoolCmdDart>(
            'auth_logout'),
        cancel = lib.lookupFunction<TBoolCmdNative, TBoolCmdDart>(
            'auth_cancel'),
        authorizationHeader = lib.lookupFunction<TStringOut, TStringOut>(
            'auth_authorization_header'),
        whoami = lib.lookupFunction<TStringOut, TStringOut>('auth_whoami'),
        accountInfo = lib.lookupFunction<TStringOut, TStringOut>(
            'auth_account_info'),
        registerKey = lib.lookupFunction<TStrCmdNative, TStrCmdDart>(
            'auth_register_key'),
        freeString =
            lib.lookupFunction<TFreeNative, TFreeDart>('auth_free_string');

  final TInit init;
  final TGet runtimeGet;
  final TStringOut state;
  final TPendingDart pendingEvents;
  final TDrain drainEvents;
  final TBoolCmdDart startLogin;
  final TCredsDart submitCredentials;
  final TStrCmdDart submit2faCode;
  final TStrCmdDart restoreCredentials;
  final TBoolCmdDart logout;
  final TBoolCmdDart cancel;
  final TStringOut authorizationHeader;
  final TStringOut whoami;
  final TStringOut accountInfo;
  final TStrCmdDart registerKey;
  final TFreeDart freeString;

  /// Look up all symbols in [lib] (defaults to [snapstoreAuthLibrary]).
  static SnapstoreAuthBindings load([DynamicLibrary? lib]) =>
      SnapstoreAuthBindings._(lib ?? snapstoreAuthLibrary);
}

// ──────────────────────────────────────────────────────────────────────────
// 3. Errors
// ──────────────────────────────────────────────────────────────────────────

/// A typed error returned by the Rust layer.
///
/// The Rust `AuthenticationError` enum serializes as
/// `{"kind": "<snake_case>", "detail": "..."}`; the `http` variant adds a
/// numeric `status` field.
final class SnapstoreAuthError implements Exception {
  const SnapstoreAuthError({
    required this.kind,
    required this.detail,
    this.httpStatus,
  });

  /// Stable machine-readable identifier: `network`, `http`,
  /// `invalid_response`, `macaroon_parse`, `no_discharge_caveat`,
  /// `credentials_rejected`, `two_factor_required`,
  /// `invalid_state_transition`, `no_active_session`, `session_cancelled`,
  /// `storage`, or `internal` (unrecognized payload).
  final String kind;

  /// Human-readable description.
  final String detail;

  /// Populated only for `kind == 'http'`.
  final int? httpStatus;

  /// The operation was rejected because the machine was in the wrong state.
  bool get isInvalidState => kind == 'invalid_state_transition';

  /// Ubuntu One rejected the credentials or 2FA code.
  bool get isCredentialsRejected => kind == 'credentials_rejected';

  /// True when the account requires 2FA (normally surfaced as the
  /// `needs_2fa_code` event rather than an error).
  bool get isTwoFactorRequired => kind == 'two_factor_required';

  /// Map a raw error JSON payload (or raw text) onto a typed error.
  static SnapstoreAuthError from(String? json,
      {String fallback = 'internal'}) {
    if (json == null || json.isEmpty) {
      return SnapstoreAuthError(kind: fallback, detail: fallback);
    }
    try {
      final Object? v = jsonDecode(json);
      if (v is Map) {
        return SnapstoreAuthError(
          kind: v['kind'] is String ? v['kind'] as String : fallback,
          detail: v['detail'] is String ? v['detail'] as String : json,
          httpStatus: v['status'] is int ? v['status'] as int : null,
        );
      }
    } on FormatException {
      // Not JSON — fall through and surface the raw text.
    }
    return SnapstoreAuthError(kind: fallback, detail: json);
  }

  @override
  String toString() =>
      'SnapstoreAuthError($kind'
      '${httpStatus != null ? ', HTTP $httpStatus' : ''}): $detail';
}

// ──────────────────────────────────────────────────────────────────────────
// 4. Machine state
// ──────────────────────────────────────────────────────────────────────────

/// Snapshot of the authentication state machine.
/// The wire values are a stable contract (Rust `MachineState::as_str`).
enum AuthState {
  idle('idle'),
  needsCredentials('needs_credentials'),
  working('working'),
  needs2faCode('needs_2fa_code'),
  succeeded('succeeded'),
  cancelled('cancelled');

  const AuthState(this.wire);

  /// The exact string `auth_state()` returns.
  final String wire;

  static AuthState fromWire(String s) {
    for (final AuthState v in values) {
      if (v.wire == s) return v;
    }
    // Unknown wire value (forward-compat): degrade, don't throw.
    return AuthState.idle;
  }
}

// ──────────────────────────────────────────────────────────────────────────
// 5. Machine events (Rust → Dart)
//
//    Rust `MachineEvent` is serde tag-encoded: {"type": "...", ...fields}
// ──────────────────────────────────────────────────────────────────────────

/// Events emitted *up* from the Rust state machine.
sealed class MachineEvent {
  const MachineEvent();

  /// Decode one JSON line from [SnapstoreAuth.drainEvents].
  /// Returns `null` for unknown shapes (forward-compat: skip, don't fail).
  static MachineEvent? fromJsonLine(String line) {
    Object? v;
    try {
      v = jsonDecode(line);
    } on FormatException {
      return null; // malformed line — skip, don't fail the drain loop
    }
    if (v is! Map) return null;
    return _decode(v);
  }

  static MachineEvent? _decode(Map v) {
    switch (v['type']) {
      case 'needs_credentials':
        return const NeedsCredentialsEvent();
      case 'needs_2fa_code':
        return const Needs2faCodeEvent();
      case 'succeeded':
        if (v['email'] is! String || v['credentials_json'] is! String) {
          return null;
        }
        return SucceededEvent(
          email: v['email'] as String,
          usedTwoFactor:
              v['used_two_factor'] is bool ? v['used_two_factor'] as bool : false,
          credentialsJson: v['credentials_json'] as String,
        );
      case 'logged_out':
        return const LoggedOutEvent();
      case 'cancelled':
        return CancelledEvent(
            reason: v['reason'] is String ? v['reason'] as String : '');
      case 'failed':
        final Object? err = v['error'];
        final String errJson = err is Map
            ? jsonEncode(err)
            : (err is String
                ? err
                : jsonEncode(const <String, Object?>{}));
        return FailedEvent(error: SnapstoreAuthError.from(errJson));
      default:
        return null;
    }
  }
}

/// The machine is waiting for an Ubuntu One email + password.
final class NeedsCredentialsEvent extends MachineEvent {
  const NeedsCredentialsEvent();
}

/// The machine is waiting for a 2FA one-time code (TOTP / SMS).
final class Needs2faCodeEvent extends MachineEvent {
  const Needs2faCodeEvent();
}

/// Login finished successfully.
///
/// The macaroon pair is persisted on the Rust side for the lifetime of the
/// process AND carried in [credentialsJson] so Dart can durably persist it
/// via `flutter_secure_storage` (Keychain / Keystore / libsecret).
final class SucceededEvent extends MachineEvent {
  const SucceededEvent({
    required this.email,
    required this.usedTwoFactor,
    required this.credentialsJson,
  });

  /// The email the session is bound to.
  final String email;

  /// `true` when a 2FA code was required and supplied.
  final bool usedTwoFactor;

  /// `{"root":"...","discharge":"..."}` — save this exact string and pass
  /// it back to [SnapstoreAuth.restoreCredentials] on the next launch.
  final String credentialsJson;
}

/// The user ended the session.
final class LoggedOutEvent extends MachineEvent {
  const LoggedOutEvent();
}

/// The flow was aborted (by the user, or the UI disconnected).
final class CancelledEvent extends MachineEvent {
  const CancelledEvent({required this.reason});
  final String reason;
}

/// A terminal error occurred; the machine is back in [AuthState.idle].
final class FailedEvent extends MachineEvent {
  const FailedEvent({required this.error});
  final SnapstoreAuthError error;
}

// ──────────────────────────────────────────────────────────────────────────
// 6. The runtime handle
// ──────────────────────────────────────────────────────────────────────────

/// A handle to the process-wide `AuthRuntime` on the Rust side.
///
/// The Rust runtime is a process global (one per app): [SnapstoreAuth.init]
/// creates it and returns a handle; [SnapstoreAuth.instance] re-fetches it.
/// The Dart handle object is cheap and never needs to be freed.
final class SnapstoreAuth {
  SnapstoreAuth._(this._bindings, this._handle);

  final SnapstoreAuthBindings _bindings;
  final OpaquePtr _handle;

  static SnapstoreAuthBindings? _bound;

  /// Initialize the process-wide authentication runtime.
  ///
  /// Empty/`null` arguments fall back to the Rust-side defaults:
  ///   * `store_url`:   `https://dashboard.snapcraft.io`
  ///   * `login_url`:   `https://login.ubuntu.com`
  ///   * `permissions`: full snapcraft ACL (package_access, package_manage,
  ///     package_metrics, package_push, package_register, package_release,
  ///     package_update, store_admin)
  ///   * `storage_key`: `snapstore-credentials`
  ///
  /// [permissions] is comma-separated, e.g. `'package_push,package_release'`
  /// or `'account-view-packages'` for a read-only token.
  ///
  /// Throws [SnapstoreAuthError] if the runtime cannot be created.
  static SnapstoreAuth init({
    String? storeUrl,
    String? loginUrl,
    String? permissions,
    String? storageKey,
  }) {
    final SnapstoreAuthBindings b = SnapstoreAuthBindings.load();
    final ErrOut errOut = calloc.allocate<CString>(1);
    final CString aStore = _toCString(storeUrl ?? '');
    final CString aLogin = _toCString(loginUrl ?? '');
    final CString aPerms = _toCString(permissions ?? '');
    final CString aKey = _toCString(storageKey ?? '');
    OpaquePtr handle;
    try {
      handle = b.init(aStore, aLogin, aPerms, aKey, errOut);
    } finally {
      _freeCString(aStore);
      _freeCString(aLogin);
      _freeCString(aPerms);
      _freeCString(aKey);
    }
    if (handle == nullptr) {
      throw SnapstoreAuthError.from(_takeCString(b, errOut.value));
    }
    calloc.free(errOut);
    _bound = b;
    return SnapstoreAuth._(b, handle);
  }

  /// Re-fetch the process-wide runtime after [init].
  /// Throws [StateError] when nothing has been initialized.
  static SnapstoreAuth get instance {
    final SnapstoreAuthBindings? b = _bound;
    if (b == null) {
      throw StateError('SnapstoreAuth.init() has not been called yet');
    }
    final OpaquePtr h = b.runtimeGet();
    if (h == nullptr) {
      throw StateError('no active snapstore-auth runtime on the Rust side');
    }
    return SnapstoreAuth._(b, h);
  }

  // -- state / events -------------------------------------------------------

  /// Current machine state (non-blocking, O(1)).
  AuthState get state {
    final ErrOut errOut = calloc.allocate<CString>(1);
    final CString s = _bindings.state(_handle, errOut);
    if (s == nullptr) {
      throw SnapstoreAuthError.from(_takeCString(_bindings, errOut.value));
    }
    final String wire = _takeCString(_bindings, s)!;
    calloc.free(errOut);
    return AuthState.fromWire(wire);
  }

  /// Number of unread machine events (polling hint for UI loops).
  int get pendingEventCount => _bindings.pendingEvents(_handle);

  /// Drain all machine events produced since the last call (FIFO order),
  /// decoded into typed [MachineEvent]s.
  ///
  /// Call this after every command AND on a short timer (100–300 ms) if you
  /// want push-like behaviour without a platform channel.
  List<MachineEvent> drainEvents() {
    final CString raw = _bindings.drainEvents(_handle);
    if (raw == nullptr) return const [];
    final String text = _takeCString(_bindings, raw)!;
    if (text.isEmpty) return const [];
    return text
        .split('\n')
        .where((l) => l.isNotEmpty)
        .map(MachineEvent.fromJsonLine)
        .whereType<MachineEvent>()
        .toList(growable: false);
  }

  // -- commands (Dart → Rust) ------------------------------------------------

  /// Begin the login flow. Valid in [AuthState.idle].
  /// Emits [NeedsCredentialsEvent] on the event stream.
  void startLogin() => _boolCmd(_bindings.startLogin);

  /// Submit the Ubuntu One email + password.
  /// Valid in [AuthState.needsCredentials]. The password is held in Rust
  /// memory only for the duration of the discharge request(s).
  void submitCredentials(String email, String password) {
    final CString aEmail = _toCString(email);
    final CString aPassword = _toCString(password);
    try {
      _cmdCreds(_bindings.submitCredentials, aEmail, aPassword);
    } finally {
      _freeCString(aEmail);
      _freeCString(aPassword);
    }
  }

  /// Submit the 2FA one-time code (TOTP / SMS).
  /// Valid in [AuthState.needs2faCode]. A wrong/expired code produces
  /// another [Needs2faCodeEvent]; a rejected password produces a
  /// [FailedEvent] with `kind == 'credentials_rejected'`.
  void submit2faCode(String code) {
    final CString aCode = _toCString(code);
    try {
      _strCmd(_bindings.submit2faCode, aCode);
    } finally {
      _freeCString(aCode);
    }
  }

  /// Restore persisted credentials after an app relaunch.
  /// [json] must be exactly the [SucceededEvent.credentialsJson] string you
  /// saved in Flutter Secure Storage. Valid in [AuthState.idle]; the pair is
  /// validated (parse + bind) before the machine reports
  /// [AuthState.succeeded].
  void restoreCredentials(String json) {
    final CString aJson = _toCString(json);
    try {
      _strCmd(_bindings.restoreCredentials, aJson);
    } finally {
      _freeCString(aJson);
    }
  }

  /// End the session and clear the Rust-side credential store.
  /// Valid in [AuthState.succeeded]. Emits [LoggedOutEvent].
  void logout() => _boolCmd(_bindings.logout);

  /// Abort the current flow. Valid in any state. Emits [CancelledEvent].
  void cancel() => _boolCmd(_bindings.cancel);

  // -- authenticated API helpers ----------------------------------------------

  /// The `Authorization` header value for Snap Store API calls:
  /// `Macaroon root=..., discharge=...`. Valid in [AuthState.succeeded].
  String authorizationHeader() {
    final ErrOut errOut = calloc.allocate<CString>(1);
    final CString s = _bindings.authorizationHeader(_handle, errOut);
    if (s == nullptr) {
      throw SnapstoreAuthError.from(_takeCString(_bindings, errOut.value));
    }
    final String out = _takeCString(_bindings, s)!;
    calloc.free(errOut);
    return out;
  }

  /// `GET {store}/api/v2/tokens/whoami` with the persisted credentials.
  ///
  /// ⚠️ This call BLOCKS the current isolate until the HTTP request
  /// completes (bounded by the Rust-side timeout, ~30 s). In a Flutter app
  /// call it from a background isolate:
  /// ```dart
  /// final name = await Isolate.run(() => auth.whoami());
  /// ```
  /// The account the current session is bound to (blocking; see [whoami]).
  AccountInfo whoami() {
    final String json = _strOut(_bindings.whoami);
    final AccountInfo a = AccountInfo.fromJson(json);
    // Back-compat convenience: expose the email as a plain string via
    // [whoamiName] when callers only want a display value.
    return a;
  }

  /// Convenience: a short human-readable label for the current account.
  String whoamiName() {
    final AccountInfo a = whoami();
    return a.displayName.isNotEmpty ? a.displayName : a.username;
  }

  /// `GET {store}/dev/api/account` — the full account object.
  ///
  /// Returns the raw JSON (a `Map`) — the same document
  /// `snapcraft keys` and brand-store listings consume.
  /// Contains `account_id`, `account_keys[]` (name +
  /// `public-key-sha3-384`), `stores[]` (id/name/roles), `snaps[]`, ...
  /// Valid in [AuthState.succeeded]. Blocking — run on a background isolate.
  Map<String, Object?> accountInfoRaw() {
    final String json = _strOut(_bindings.accountInfo);
    return _asMap(json);
  }

  /// Registered signing keys, parsed from [accountInfoRaw].
  /// Replaces the `snapcraft keys` shell-out for the *registered* half.
  List<RegisteredKey> registeredKeys() {
    return RegisteredKey.parseAll(_asList(accountInfoRaw()['account_keys']));
  }

  /// Brand stores the account can access, parsed from [accountInfoRaw].
  /// Replaces the former `surl` CLI shell-out for store listings.
  List<BrandStore> brandStores() {
    return BrandStore.parseAll(_asList(accountInfoRaw()['stores']));
  }

  /// `POST {store}/dev/api/account/account-key` — register a serialized
  /// `account-key` assertion (what `snapcraft register-key` uploads).
  ///
  /// [accountKeyRequest] is the assertion text produced on the host with
  /// `snap export-key <name> <account-id>` (local GPG keyring — stays a
  /// shell-out; only the upload moves into Rust).
  ///
  /// Throws [SnapstoreAuthError] on failure. Valid in
  /// [AuthState.succeeded]. Blocking — run on a background isolate.
  void registerKey(String accountKeyRequest) {
    final CString aReq = _toCString(accountKeyRequest);
    try {
      _strCmd(_bindings.registerKey, aReq);
    } finally {
      _freeCString(aReq);
    }
  }

  // -- out-param string helper ------------------------------------------------

  String _strOut(TStringOut fn) {
    final ErrOut errOut = calloc.allocate<CString>(1);
    final CString s = fn(_handle, errOut);
    if (s == nullptr) {
      throw SnapstoreAuthError.from(_takeCString(_bindings, errOut.value));
    }
    final String out = _takeCString(_bindings, s)!;
    calloc.free(errOut);
    return out;
  }

  Map<String, Object?> _asMap(String json) {
    final Object? v = jsonDecode(json);
    if (v is! Map) {
      throw const SnapstoreAuthError(
          kind: 'invalid_response',
          detail: 'expected a JSON object from the store');
    }
    return v.cast<String, Object?>();
  }

  List<Object?> _asList(Object? v) =>
      v is List ? v : const <Object?>[];

  // -- command plumbing --------------------------------------------------------

  void _boolCmd(TBoolCmdDart fn) {
    final ErrOut errOut = calloc.allocate<CString>(1);
    final bool ok = fn(_handle, errOut);
    final CString errStr = errOut.value;
    calloc.free(errOut);
    if (!ok) throw SnapstoreAuthError.from(_takeCString(_bindings, errStr));
  }

  void _strCmd(TStrCmdDart fn, CString arg) {
    final ErrOut errOut = calloc.allocate<CString>(1);
    final bool ok = fn(_handle, arg, errOut);
    final CString errStr = errOut.value;
    calloc.free(errOut);
    if (!ok) throw SnapstoreAuthError.from(_takeCString(_bindings, errStr));
  }

  void _cmdCreds(TCredsDart fn, CString a, CString b) {
    final ErrOut errOut = calloc.allocate<CString>(1);
    final bool ok = fn(_handle, a, b, errOut);
    final CString errStr = errOut.value;
    calloc.free(errOut);
    if (!ok) throw SnapstoreAuthError.from(_takeCString(_bindings, errStr));
  }
}

// ──────────────────────────────────────────────────────────────────────────
// 6b. Account / key / store models (parsed from the store's JSON)
// ──────────────────────────────────────────────────────────────────────────

/// The account a session is bound to (parsed from `whoami`).
final class AccountInfo {
  const AccountInfo({
    required this.id,
    required this.email,
    required this.username,
    required this.displayName,
    required this.permissions,
    required this.channels,
    required this.expires,
  });

  /// Developer/account id — use as the model assertion's `brand-id`.
  final String id;
  final String email;
  final String username;

  /// Human-readable display name (may be empty).
  final String displayName;

  /// ACLs the macaroon was granted (empty = unrestricted).
  final List<String> permissions;

  /// Channel restrictions (empty = unrestricted).
  final List<String> channels;

  /// Macaroon expiry (ISO-8601, may be empty).
  final String expires;

  /// Parse the JSON returned by [SnapstoreAuth.whoami].
  ///
  /// NOTE: this is the *Rust serde* serialization of `AccountInfo`
  /// (flat, snake_case: `id`, `email`, `username`, `display_name`,
  /// `permissions`, `channels`, `expires`) — not the raw store document.
  factory AccountInfo.fromJson(String json) {
    final Object? v = jsonDecode(json);
    if (v is! Map) {
      throw const SnapstoreAuthError(
          kind: 'invalid_response', detail: 'whoami: not a JSON object');
    }
    final m = v.cast<String, Object?>();
    String str(String k) => m[k] is String ? m[k] as String : '';
    List<String> strs(String k) => m[k] is List
        ? (m[k] as List).whereType<String>().toList()
        : const <String>[];
    return AccountInfo(
      id: str('id'),
      email: str('email'),
      username: str('username'),
      displayName: str('display_name'),
      permissions: strs('permissions'),
      channels: strs('channels'),
      expires: str('expires'),
    );
  }

  @override
  String toString() => 'AccountInfo($email, id=$id, username=$username)';
}

/// A signing key registered with the store
/// (`/dev/api/account` → `account_keys[]`).
final class RegisteredKey {
  const RegisteredKey({
    required this.name,
    required this.publicKeySha384,
    this.createdAt,
  });

  final String name;

  /// SHA3-384 fingerprint of the public key (matches the second column of
  /// `snap keys` output, so local↔registered correlation is a string match).
  final String publicKeySha384;
  final String? createdAt;

  static List<RegisteredKey> parseAll(List<Object?> entries) {
    final out = <RegisteredKey>[];
    for (final Object? e in entries) {
      if (e is! Map) continue;
      final m = e.cast<String, Object?>();
      final name = m['name'] is String ? m['name'] as String : '';
      final fp = m['public-key-sha3-384'] is String
          ? m['public-key-sha3-384'] as String
          : '';
      if (name.isEmpty && fp.isEmpty) continue;
      out.add(RegisteredKey(
        name: name,
        publicKeySha384: fp,
        createdAt: m['created-at'] is String ? m['created-at'] as String : null,
      ));
    }
    return out;
  }

  @override
  String toString() => 'RegisteredKey($name, $publicKeySha384)';
}

/// A brand store the account can access (`/dev/api/account` → `stores[]`).
/// A brand store the account can access.
final class BrandStore {
  const BrandStore({required this.id, this.name, this.roles = const []});

  final String id;
  final String? name;
  final List<String> roles;

  /// The global store; the model's `store` field should be omitted for it.
  bool get isGlobal => id == 'ubuntu';

  static List<BrandStore> parseAll(List<Object?> entries) {
    final out = <BrandStore>[];
    for (final Object? e in entries) {
      if (e is! Map) continue;
      final m = e.cast<String, Object?>();
      final id = m['id'] is String ? m['id'] as String : '';
      if (id.isEmpty) continue;
      out.add(BrandStore(
        id: id,
        name: m['name'] is String ? m['name'] as String : null,
        roles: m['roles'] is List
            ? (m['roles'] as List).map((Object? r) => r.toString()).toList()
            : const <String>[],
      ));
    }
    return out;
  }

  @override
  String toString() => 'BrandStore($id${name != null ? ', $name' : ''})';
}

// ──────────────────────────────────────────────────────────────────────────
// 7. C-string plumbing
//
//    Dart → Rust: Dart allocates (calloc), Rust copies before returning.
//    Rust → Dart: Rust allocates, Dart reads then calls auth_free_string.
// ──────────────────────────────────────────────────────────────────────────

/// Allocate a NUL-terminated UTF-8 string owned by Dart.
CString _toCString(String s) {
  final List<int> bytes = utf8.encode(s);
  final Pointer<Uint8> mem = calloc.allocate<Uint8>(bytes.length + 1);
  mem.asTypedList(bytes.length).setAll(0, bytes);
  mem[bytes.length] = 0;
  return mem.cast<Int8>();
}

/// Free a Dart-owned C string produced by [_toCString].
void _freeCString(CString ptr) {
  if (ptr == nullptr) return;
  calloc.free(ptr.cast<Uint8>());
}

/// Read and free a Rust-allocated C string (returned by the library).
String? _takeCString(SnapstoreAuthBindings b, CString ptr) {
  if (ptr == nullptr) return null;
  final String s = ptr.cast<Utf8>().toDartString();
  b.freeString(ptr);
  return s;
}

// ──────────────────────────────────────────────────────────────────────────
// 8. Model-builder additions (new C symbols + session lifecycle helper)
// ──────────────────────────────────────────────────────────────────────────

// -- auth_store_snaps (CString out; one string arg) -------------------------
typedef TStoreSnapsNative = CString Function(OpaquePtr, CString, ErrOut);
typedef TStoreSnapsDart = CString Function(OpaquePtr, CString, ErrOut);

// -- auth_import_exported_login (bool; one string arg) ----------------------
typedef TImportNative = Bool Function(OpaquePtr, CString, ErrOut);
typedef TImportDart = bool Function(OpaquePtr, CString, ErrOut);

// -- auth_request (CString out; method/path/body/content_type, the last two
//    nullable) -------------------------------------------------------------
typedef TRequestNative = CString Function(
    OpaquePtr, CString, CString, CString, CString, ErrOut);
typedef TRequestDart = CString Function(
    OpaquePtr, CString, CString, CString, CString, ErrOut);

/// Looked-up handles to the extra C symbols. Resolved lazily so that
/// older `libsnapstore_auth` builds (without the symbols) still fail only
/// when the extra functions are actually used.
final class SnapstoreAuthExtras {
  SnapstoreAuthExtras._()
      : storeSnaps = snapstoreAuthLibrary.lookupFunction<TStoreSnapsNative,
              TStoreSnapsDart>('auth_store_snaps'),
        importExportedLogin = snapstoreAuthLibrary.lookupFunction<TImportNative,
            TImportDart>('auth_import_exported_login'),
        request = snapstoreAuthLibrary
            .lookupFunction<TRequestNative, TRequestDart>('auth_request');

  final TStoreSnapsDart storeSnaps;
  final TImportDart importExportedLogin;
  final TRequestDart request;

  static SnapstoreAuthExtras? _instance;

  static SnapstoreAuthExtras get instance {
    _instance ??= SnapstoreAuthExtras._();
    return _instance!;
  }
}

/// Raw result of [SnapstoreAuthModelBuilder.request] — the generic
/// authenticated-call escape hatch. Mirrors Rust's `ApiResponse`: the HTTP
/// response is carried verbatim, 2xx or not, with no interpretation of the
/// status or body — the caller decides what success means.
final class StoreApiResponse {
  const StoreApiResponse({required this.status, required this.body});

  /// HTTP status code, e.g. `200`, `404`.
  final int status;

  /// Raw response body (not parsed — may be JSON, plain text, or empty).
  final String body;

  @override
  String toString() => 'StoreApiResponse($status, ${body.length} bytes)';
}

extension SnapstoreAuthModelBuilder on SnapstoreAuth {
  /// `GET {store}/api/v2/stores/{storeId}/snaps` — a brand store's catalog.
  ///
  /// Blocking (bounded by the Rust-side HTTP timeout) — call from a
  /// background isolate:
  /// ```dart
  /// final raw = await Isolate.run(() => auth.storeSnapsRaw('my-store'));
  /// ```
  Map<String, Object?> storeSnapsRaw(String storeId) {
    final ErrOut errOut = calloc.allocate<CString>(1);
    final CString aStore = _toCString(storeId);
    CString s;
    try {
      s = SnapstoreAuthExtras.instance.storeSnaps(_handle, aStore, errOut);
    } finally {
      _freeCString(aStore);
    }
    if (s == nullptr) {
      throw SnapstoreAuthError.from(_takeCString(_bindings, errOut.value));
    }
    final String out = _takeCString(_bindings, s)!;
    calloc.free(errOut);
    final Object? v = jsonDecode(out);
    if (v is! Map) {
      throw const SnapstoreAuthError(
          kind: 'invalid_response',
          detail: 'store snaps: expected a JSON object');
    }
    return v.cast<String, Object?>();
  }

  /// Generic authenticated store API call — the escape hatch for apps that
  /// need store endpoints beyond the fixed helpers above ([whoami],
  /// [storeSnapsRaw], `register_key`, etc.). `path` is resolved against the
  /// configured store URL; `method` is any HTTP verb (`'GET'`, `'POST'`,
  /// ...). `contentType` defaults to `application/json` when omitted.
  ///
  /// Returns the raw [StoreApiResponse] for **any** HTTP response, 2xx or
  /// not — this call does not interpret or validate the response; the
  /// caller decides what success means. Only transport-level failures
  /// (DNS, TLS, timeout) throw [SnapstoreAuthError].
  ///
  /// Blocking (bounded by the Rust-side HTTP timeout) — call from a
  /// background isolate:
  /// ```dart
  /// final resp = await Isolate.run(
  ///     () => auth.request('GET', '/dev/api/account/snaps'));
  /// ```
  StoreApiResponse request(
    String method,
    String path, {
    String? body,
    String? contentType,
  }) {
    final ErrOut errOut = calloc.allocate<CString>(1);
    final CString aMethod = _toCString(method);
    final CString aPath = _toCString(path);
    final CString aBody = body == null ? nullptr : _toCString(body);
    final CString aContentType =
        contentType == null ? nullptr : _toCString(contentType);
    CString s;
    try {
      s = SnapstoreAuthExtras.instance
          .request(_handle, aMethod, aPath, aBody, aContentType, errOut);
    } finally {
      _freeCString(aMethod);
      _freeCString(aPath);
      _freeCString(aBody);
      _freeCString(aContentType);
    }
    if (s == nullptr) {
      throw SnapstoreAuthError.from(_takeCString(_bindings, errOut.value));
    }
    final String out = _takeCString(_bindings, s)!;
    calloc.free(errOut);
    final Object? v = jsonDecode(out);
    if (v is! Map || v['status'] is! int || v['body'] is! String) {
      throw const SnapstoreAuthError(
          kind: 'invalid_response',
          detail: 'request: expected a JSON {status, body} object');
    }
    return StoreApiResponse(
      status: v['status'] as int,
      body: v['body'] as String,
    );
  }

  /// Import a `snapcraft export-login --acls <acls> <file>` credential
  /// payload (the file's text content). The Rust side validates the
  /// macaroon pair and drives the state machine through the same
  /// `RestoreCredentials` path as a startup restore: on success the
  /// machine ends in `succeeded` (drain events to get the fresh
  /// `credentials_json` for Secure Storage); on validation failure it ends
  /// back in `idle` with a `failed` event.
  ///
  /// Local work only (no network) — safe on any isolate.
  void importExportedLogin(String raw) {
    final ErrOut errOut = calloc.allocate<CString>(1);
    final CString aRaw = _toCString(raw);
    try {
      final bool ok = SnapstoreAuthExtras.instance
          .importExportedLogin(_handle, aRaw, errOut);
      final CString errStr = errOut.value;
      calloc.free(errOut);
      if (!ok) throw SnapstoreAuthError.from(_takeCString(_bindings, errStr));
    } finally {
      _freeCString(aRaw);
    }
  }
}

/// Lifecycle helper for the single process-wide Rust auth runtime.
///
/// The Rust runtime is process-global: `auth_runtime_init` returns the
/// same handle for the second and later calls, and the driver task (patched
/// to stay alive) parks in `Idle` / `Succeeded` between flows. This class
/// wraps that contract:
///
///   * [init]        — create (or re-fetch) the runtime;
///   * [restore]     — load a persisted credential pair at startup;
///   * [login]       — interactive email + 2FA login via UI prompts;
///   * [logout]      — clear the in-process session;
///   * [isAvailable] — `false` when the native library cannot be loaded
///                     (the app can then fall back to snapcraft).
///
/// This class never persists anything: the app stores
/// [SucceededEvent.credentialsJson] in Secure Storage itself.
///
/// The login loop is *state-driven*: it reads [SnapstoreAuth.state] and
/// presents the matching prompt; the prompt itself performs the FFI submit
/// and only resolves once that phase has settled. Machine events are only
/// drained in terminal states, so a `succeeded` event always survives for
/// the caller to persist.
final class SnapstoreAuthSession {
  SnapstoreAuthSession._(this._auth) {
    current = this;
  }

  final SnapstoreAuth _auth;

  /// The live session (set by [init]), or `null` when uninitialized.
  static SnapstoreAuthSession? current;

  /// `true` when the native library can be loaded at all.
  static bool isAvailable() {
    try {
      // Touching the top-level handle triggers the `DynamicLibrary.open`;
      // `load()` then resolves every FFI symbol.
      snapstoreAuthLibrary;
      SnapstoreAuthBindings.load();
      return true;
    } catch (_) {
      return false;
    }
  }

  /// `true` when a session is active in-process (machine is `succeeded`).
  static bool get hasActiveSession =>
      current != null && current!._auth.state == AuthState.succeeded;

  /// Initialize (or re-fetch) the process-wide runtime.
  ///
  /// [permissions] is the ACL list requested for *new* logins (comma
  /// separated); restoring an existing pair is unaffected by it.
  static Future<SnapstoreAuthSession> init({
    required String permissions,
    String? storeUrl,
    String? loginUrl,
  }) async {
    final SnapstoreAuth auth;
    final existing = current;
    if (existing != null) {
      // The runtime is process-global and configured on first init;
      // later calls reuse it.
      auth = existing._auth;
    } else {
      // `SnapstoreAuth.init` looks up FFI symbols: do it off the UI
      // isolate (harmless, but keeps the main isolate clean on failure).
      auth = await Isolate.run(() => SnapstoreAuth.init(
            storeUrl: storeUrl,
            loginUrl: loginUrl,
            permissions: permissions,
          ));
    }
    return SnapstoreAuthSession._(auth);
  }

  /// The underlying [SnapstoreAuth] (for the authenticated API helpers).
  SnapstoreAuth get auth => _auth;

  /// Restore a persisted credential pair (the `credentials_json` string
  /// from a previous [SucceededEvent], e.g. from Secure Storage).
  ///
  /// Resolves `true` when the machine ends in `succeeded`, `false` when the
  /// pair is missing, unparseable or invalid (the machine is back in
  /// `idle`). No network is involved — the Rust side validates the pair
  /// locally (parse + bind).
  Future<bool> restore(String credentialsJson) async {
    final auth = _auth;
    final s0 = auth.state;
    if (s0 == AuthState.succeeded) return true;
    if (s0 != AuthState.idle) {
      auth.cancel();
      await _waitForState(const {AuthState.idle}, const Duration(seconds: 5));
    }
    // Clear stale events so the one consumed below is unambiguously the
    // verdict of THIS restore.
    auth.drainEvents();
    try {
      auth.restoreCredentials(credentialsJson);
    } catch (_) {
      return false;
    }
    // Wait for the driver's verdict. Waiting on state alone is racy: the
    // state is `idle` both before the driver picks the event up AND after
    // a failed restore, so only the emitted event (Succeeded / Failed) or
    // the state moving to `succeeded` is a reliable signal.
    final deadline = DateTime.now().add(const Duration(seconds: 10));
    while (DateTime.now().isBefore(deadline)) {
      for (final e in auth.drainEvents()) {
        if (e is SucceededEvent) return true;
        if (e is FailedEvent) return false;
      }
      if (auth.state == AuthState.succeeded) return true;
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
    return auth.state == AuthState.succeeded;
  }

  /// Run the interactive login: start the flow and drive the state loop,
  /// presenting [promptCredentials] / [promptTwoFactor] as the machine
  /// requests them. Each prompt performs the FFI submit itself and resolves
  /// `true` when its phase settled (hand-off / success) or `false` when the
  /// user cancelled.
  ///
  /// Returns the terminal state:
  ///   * [AuthState.succeeded] — logged in; drain events to get the
  ///     [SucceededEvent] with the `credentials_json` to persist;
  ///   * [AuthState.idle] — the user cancelled a prompt or the flow failed.
  Future<AuthState> login({
    required Future<bool> Function() promptCredentials,
    required Future<bool> Function() promptTwoFactor,
  }) async {
    final auth = _auth;
    final s0 = auth.state;
    if (s0 == AuthState.succeeded) {
      auth.logout();
      await _waitForState(const {AuthState.idle}, const Duration(seconds: 5));
    } else if (s0 != AuthState.idle) {
      auth.cancel();
      await _waitForState(const {AuthState.idle}, const Duration(seconds: 5));
    }
    try {
      auth.startLogin();
    } catch (_) {
      return AuthState.idle;
    }

    // The Rust driver picks up `startLogin` on its own task, so the
    // machine may still read `idle` for a moment AFTER the call returns.
    // `idle` is only a terminal verdict once the flow has visibly started
    // (we observed a non-idle state); an initial `idle` just means "the
    // driver has not run yet" and must not end the login. If the machine
    // never leaves `idle`, bound the wait so a dead driver still fails
    // fast.
    var seenNonIdle = false;
    final startedAt = DateTime.now();
    final deadline = startedAt.add(const Duration(minutes: 5));
    while (DateTime.now().isBefore(deadline)) {
      final s = auth.state;
      if (s != AuthState.idle) seenNonIdle = true;
      if (s == AuthState.succeeded) return s;
      if (s == AuthState.idle) {
        if (seenNonIdle) {
          // Terminal: cancel/failure already surfaced by the prompt.
          // Clear the buffer so no stale event leaks into the next flow.
          auth.drainEvents();
          return s;
        }
        if (DateTime.now().difference(startedAt) >
            const Duration(seconds: 10)) {
          auth.drainEvents();
          return s;
        }
      }
      if (s == AuthState.needsCredentials) {
        final ok = await promptCredentials();
        if (!ok) {
          _settleCancelled();
          return AuthState.idle;
        }
        continue;
      }
      if (s == AuthState.needs2faCode) {
        final ok = await promptTwoFactor();
        if (!ok) {
          _settleCancelled();
          return AuthState.idle;
        }
        continue;
      }
      // `working`: give the driver a moment, then re-check.
      await Future<void>.delayed(const Duration(milliseconds: 120));
    }
    // Safety net: give up and settle back to idle.
    _settleCancelled();
    return AuthState.idle;
  }

  /// Clear the in-process session (machine back to `idle`).
  Future<void> logout() async {
    if (_auth.state != AuthState.succeeded) return;
    try {
      _auth.logout();
    } catch (_) {
      return;
    }
    await _waitForState(const {AuthState.idle}, const Duration(seconds: 5));
  }

  void _settleCancelled() {
    try {
      _auth.cancel();
    } catch (_) {}
    // The machine settles asynchronously; a later flow start waits for
    // `idle` explicitly, so no need to block here.
  }

  Future<AuthState> _waitForState(
      Set<AuthState> targets, Duration timeout) async {
    final deadline = DateTime.now().add(timeout);
    while (DateTime.now().isBefore(deadline)) {
      final s = _auth.state;
      if (targets.contains(s)) return s;
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
    return _auth.state;
  }
}

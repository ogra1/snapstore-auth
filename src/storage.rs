//! Credential persistence.
//!
//! The Rust backend never touches platform keychains itself — it exposes a
//! [`CredentialsStore`] trait. The default implementation
//! ([`InMemoryStore`]) keeps the pair in process memory, which is enough
//! for the login flow: [`MachineEvent::Succeeded`] carries
//! `credentials_json` **up to Dart**, and the Dart side writes it to
//! `flutter_secure_storage` (iOS Keychain / Android Keystore /
//! Linux libsecret). On the next app launch the Dart side reads the string
//! back and hands it to `restore_credentials()`.
//!
//! A platform-native backend (e.g. one that shells out to
//! `secret-tool`/Keychain, or reads `SNAPCRAFT_STORE_CREDENTIALS`) can be
//! plugged in by implementing the trait and passing it in
//! [`crate::auth_core::AuthConfig::store`].

use crate::error::Result;
use serde::{Deserialize, Serialize};

/// The persisted credential pair: the store-issued root macaroon and the
/// SSO-issued (discharged) macaroon, both in their original serialized
/// form (v1 binary, base64url — exactly what `craft-store` stores).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credentials {
    /// Serialized root macaroon (from `/dev/api/acl/`).
    pub root: String,
    /// Serialized discharge macaroon (from `/api/v2/tokens/discharge`).
    pub discharge: String,
}

/// Abstraction over where credentials are kept.
///
/// All methods are `Send + Sync` so a single store can back the driver
/// task and the FFI side concurrently.
pub trait CredentialsStore: Send + Sync {
    /// Persist `creds` under `key`.
    fn save(&self, key: &str, creds: &Credentials) -> Result<()>;
    /// Load credentials previously saved under `key` (`None` when absent).
    fn load(&self, key: &str) -> Result<Option<Credentials>>;
    /// Remove credentials stored under `key`.
    fn delete(&self, key: &str) -> Result<()>;
}

/// In-process storage. Simple, testable, and safe (no secrets on disk).
///
/// The *secure* copy is the one Dart writes to Flutter Secure Storage;
/// this store only needs to survive for the lifetime of the login session
/// and for `authorization_header()`/`whoami()` calls while the app runs.
#[derive(Default)]
pub struct InMemoryStore {
    inner: std::sync::Mutex<std::collections::HashMap<String, Credentials>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        InMemoryStore::default()
    }
}

impl CredentialsStore for InMemoryStore {
    fn save(&self, key: &str, creds: &Credentials) -> Result<()> {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.insert(key.to_string(), creds.clone());
        Ok(())
    }

    fn load(&self, key: &str) -> Result<Option<Credentials>> {
        let guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(guard.get(key).cloned())
    }

    fn delete(&self, key: &str) -> Result<()> {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.remove(key);
        Ok(())
    }
}

/// Example: a file-backed store (NOT secure — for development only).
///
/// Shows how a platform backend would be implemented; swap in
/// `secret-tool`, the OS keychain, or a FFI callback to Dart in production.
#[derive(Debug)]
pub struct FileStore {
    dir: std::path::PathBuf,
}

impl FileStore {
    pub fn new(dir: impl Into<std::path::PathBuf>) -> Self {
        FileStore { dir: dir.into() }
    }
}

impl CredentialsStore for FileStore {
    fn save(&self, key: &str, creds: &Credentials) -> Result<()> {
        let json = serde_json::to_string(creds)
            .map_err(|e| crate::error::AuthenticationError::Storage(e.to_string()))?;
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| crate::error::AuthenticationError::Storage(e.to_string()))?;
        let mut path = self.dir.clone();
        path.push(sanitize_key(key));
        std::fs::write(&path, json)
            .map_err(|e| crate::error::AuthenticationError::Storage(e.to_string()))
    }

    fn load(&self, key: &str) -> Result<Option<Credentials>> {
        let mut path = self.dir.clone();
        path.push(sanitize_key(key));
        if !path.exists() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|e| crate::error::AuthenticationError::Storage(e.to_string()))?;
        serde_json::from_str(&text)
            .map(Some)
            .map_err(|e| crate::error::AuthenticationError::Storage(e.to_string()))
    }

    fn delete(&self, key: &str) -> Result<()> {
        let mut path = self.dir.clone();
        path.push(sanitize_key(key));
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(crate::error::AuthenticationError::Storage(e.to_string())),
        }
    }
}

/// Keep storage keys filesystem-safe.
fn sanitize_key(key: &str) -> String {
    key.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
            c
        } else {
            '_'
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_roundtrip() {
        let store = InMemoryStore::new();
        let creds = Credentials {
            root: "root".into(),
            discharge: "discharge".into(),
        };
        assert_eq!(store.load("k").expect("load"), None);
        store.save("k", &creds).expect("save");
        assert_eq!(store.load("k").expect("load"), Some(creds.clone()));
        store.delete("k").expect("delete");
        assert_eq!(store.load("k").expect("load"), None);
    }

    #[test]
    fn file_store_roundtrip() {
        let dir = std::env::temp_dir().join(format!("snapstore-auth-test-{}", std::process::id()));
        let store = FileStore::new(&dir);
        let creds = Credentials {
            root: "root".into(),
            discharge: "discharge".into(),
        };
        store.save("key with spaces!", &creds).expect("save");
        assert_eq!(store.load("key with spaces!").expect("load"), Some(creds));
        store.delete("key with spaces!").expect("delete");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn credentials_serialize_stably() {
        let creds = Credentials {
            root: "r".into(),
            discharge: "d".into(),
        };
        let json = serde_json::to_string(&creds).expect("ser");
        assert!(json.contains("\"root\":\"r\""));
        let back: Credentials = serde_json::from_str(&json).expect("de");
        assert_eq!(back, creds);
    }
}

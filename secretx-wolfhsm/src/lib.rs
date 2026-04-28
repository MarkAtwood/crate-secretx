//! wolfHSM secure element backend for secretx.
//!
//! URI: `secretx:wolfhsm:<label>[?server=<addr>]`
//!
//! - `label` — NVM object label (1–24 bytes, UTF-8). Identifies the data
//!   object on the wolfHSM server.
//! - `server` — (optional) wolfHSM server address. Falls back to the
//!   `WOLFHSM_SERVER` environment variable if absent.
//!   Format: `host:port` for TCP (e.g. `127.0.0.1:8080`) or `/path` for UDS.
//!
//! # Transport
//!
//! The server address is parsed at first use, not at `from_uri` construction
//! time. If neither `?server=` nor `WOLFHSM_SERVER` is set when `get()`,
//! `refresh()`, or `put()` is called, the call returns
//! [`SecretError::Unavailable`].
//!
//! # SecretStore and WritableSecretStore
//!
//! Data objects are stored as raw bytes on the wolfHSM NVM under a 24-byte
//! label. `get()` scans NVM objects for the matching label and reads the data.
//! The numeric NVM ID is cached after the first scan to avoid round-trips on
//! subsequent calls. `refresh()` invalidates that cache and re-scans.
//!
//! `put()` overwrites an existing object (same label → same NVM ID) or creates
//! a new one (first unused NVM ID). wolfHSM NVM overwrite is not atomic: the
//! old object is deleted before the new one is added. If the add fails after a
//! successful delete, [`SecretError::Backend`] is returned and the data is
//! lost. This matches the wolfhsm crate's documented `nvm_overwrite` contract.
//!
//! # SigningBackend
//!
//! Returns [`SecretError::Unavailable`]. The wolfhsm 0.1.0 crate does not
//! expose an API to load a persistent committed ECC key from NVM by label
//! (`EccP256Key::load_from_nvm`). When that API is available, signing will be
//! implemented here.
//!
//! # Integration test status
//!
//! Requires a running wolfHSM server or simulator. Set `WOLFHSM_SERVER` before
//! running integration tests.

use secretx_core::{
    SecretError, SecretStore, SecretUri, SecretValue, SigningAlgorithm, SigningBackend,
    WritableSecretStore,
};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use wolfhsm::{Client, NvmId, Transport};

const BACKEND: &str = "wolfhsm";

/// Maximum NVM label length in bytes (`WH_NVM_LABEL_LEN` from wolfHSM headers).
const NVM_LABEL_MAX: usize = 24;

/// `WH_ERROR_NOTFOUND` from `wolfhsm/wh_error.h`.
const WH_ERROR_NOTFOUND: i32 = -2104;

// ── Internal state ────────────────────────────────────────────────────────────

struct WolfHsmState {
    /// Connected client. `None` until first use.
    client: Option<Client>,
    /// Cached NVM ID for this backend's label. Avoids O(n) scan per call.
    cached_nvm_id: Option<NvmId>,
}

// ── Public backend struct ─────────────────────────────────────────────────────

/// Backend that reads and writes wolfHSM NVM data objects by label.
///
/// Construct with [`WolfHsmBackend::from_uri`].
pub struct WolfHsmBackend {
    label: String,
    /// Configured server address (`?server=` value, may be empty).
    server: String,
    state: Arc<Mutex<WolfHsmState>>,
}

impl WolfHsmBackend {
    /// Construct from a `secretx:wolfhsm:<label>[?server=<addr>]` URI.
    ///
    /// Validates URI syntax only; no network call is made.
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        let parsed = SecretUri::parse(uri)?;
        if parsed.backend() != BACKEND {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `wolfhsm`, got `{}`",
                parsed.backend()
            )));
        }
        let label = parsed.path().to_owned();
        if label.is_empty() {
            return Err(SecretError::InvalidUri(
                "wolfhsm URI requires a label: secretx:wolfhsm:<label>".into(),
            ));
        }
        if label.len() > NVM_LABEL_MAX {
            return Err(SecretError::InvalidUri(format!(
                "wolfhsm label must be ≤ {NVM_LABEL_MAX} bytes, got {} bytes",
                label.len()
            )));
        }
        if parsed.param("field").is_some() {
            return Err(SecretError::InvalidUri(
                "wolfhsm stores raw bytes and does not support `?field=`; \
                 remove the field selector from the URI"
                    .into(),
            ));
        }
        let server = parsed.param("server").unwrap_or("").to_owned();
        Ok(Self {
            label,
            server,
            state: Arc::new(Mutex::new(WolfHsmState {
                client: None,
                cached_nvm_id: None,
            })),
        })
    }
}

// ── Error helpers ─────────────────────────────────────────────────────────────

fn backend_err(e: wolfhsm::Error) -> SecretError {
    SecretError::Backend {
        backend: BACKEND,
        source: Box::new(e),
    }
}

fn join_err(e: tokio::task::JoinError) -> SecretError {
    SecretError::Backend {
        backend: BACKEND,
        source: e.into(),
    }
}

fn poison_err() -> SecretError {
    SecretError::Backend {
        backend: BACKEND,
        source: "wolfhsm state mutex poisoned".into(),
    }
}

// ── Connection helpers ────────────────────────────────────────────────────────

fn resolve_server(configured: &str) -> Result<String, SecretError> {
    if !configured.is_empty() {
        return Ok(configured.to_owned());
    }
    std::env::var("WOLFHSM_SERVER").map_err(|_| SecretError::Unavailable {
        backend: BACKEND,
        source: "no wolfHSM server configured: \
                 set WOLFHSM_SERVER env var or add ?server=<addr> to the URI"
            .into(),
    })
}

fn make_transport(addr: &str) -> Result<Transport, SecretError> {
    if addr.starts_with('/') {
        return Ok(Transport::Uds {
            path: addr.to_owned(),
        });
    }
    if let Some((host, port_str)) = addr.rsplit_once(':') {
        let port: u16 = port_str.parse().map_err(|_| {
            SecretError::InvalidUri(format!(
                "wolfhsm server `{addr}`: port `{port_str}` is not a valid u16"
            ))
        })?;
        return Ok(Transport::Tcp {
            ip: host.to_owned(),
            port,
        });
    }
    Err(SecretError::InvalidUri(format!(
        "wolfhsm server `{addr}` must be `host:port` (TCP) or `/path` (UDS)"
    )))
}

/// Ensure `state.client` is connected, connecting if necessary.
///
/// Returns a reference to the client. Any earlier connection error is retried
/// on the next call — a poisoned `state.client = None` signals reconnect.
fn ensure_connected<'a>(
    state: &'a mut WolfHsmState,
    server: &str,
) -> Result<&'a mut Client, SecretError> {
    if state.client.is_none() {
        let addr = resolve_server(server)?;
        let transport = make_transport(&addr)?;
        let client = Client::connect(transport, 1).map_err(|e| SecretError::Unavailable {
            backend: BACKEND,
            source: Box::new(e),
        })?;
        state.client = Some(client);
    }
    Ok(state.client.as_mut().unwrap())
}

// ── NVM scan helpers ──────────────────────────────────────────────────────────

/// Scan all NVM data objects for one whose label matches `label`.
///
/// Returns the first matching [`NvmId`], or `None` if not found.
/// `WH_ERROR_NOTFOUND` from `nvm_metadata` is treated as a stale list entry
/// and skipped rather than propagated.
fn find_by_label(client: &mut Client, label: &str) -> Result<Option<NvmId>, SecretError> {
    let ids = client.nvm_list().map_err(backend_err)?;
    for id in ids {
        match client.nvm_metadata(id) {
            Ok(meta) => {
                if meta.label_str() == Some(label) {
                    return Ok(Some(id));
                }
            }
            Err(wolfhsm::Error::Wh { code }) if code == WH_ERROR_NOTFOUND => continue,
            Err(e) => return Err(backend_err(e)),
        }
    }
    Ok(None)
}

/// Find the first NVM ID in `1..=u16::MAX` not currently in use.
///
/// Used when creating a brand-new NVM object (no existing ID to reuse).
fn find_free_id(client: &mut Client) -> Result<NvmId, SecretError> {
    let used: HashSet<u16> = client
        .nvm_list()
        .map_err(backend_err)?
        .into_iter()
        .map(u16::from)
        .collect();
    for n in 1u16..=u16::MAX {
        if !used.contains(&n) {
            return Ok(NvmId::new(n));
        }
    }
    Err(SecretError::Backend {
        backend: BACKEND,
        source: "wolfHSM NVM is full; no free NVM ID available".into(),
    })
}

/// Return the NVM ID for `label`, using `state.cached_nvm_id` when valid.
///
/// Validates the cached ID before returning it (stale after NVM delete/recreate).
/// Falls back to a full label scan if the cache misses or is stale.
fn get_cached_or_scan(state: &mut WolfHsmState, label: &str) -> Result<NvmId, SecretError> {
    if let Some(cached) = state.cached_nvm_id {
        let still_valid = {
            let client = state.client.as_mut().unwrap();
            match client.nvm_metadata(cached) {
                Ok(meta) => meta.label_str() == Some(label),
                Err(wolfhsm::Error::Wh { code }) if code == WH_ERROR_NOTFOUND => false,
                Err(e) => return Err(backend_err(e)),
            }
        };
        if still_valid {
            return Ok(cached);
        }
        state.cached_nvm_id = None;
    }

    let id = {
        let client = state.client.as_mut().unwrap();
        find_by_label(client, label)?.ok_or(SecretError::NotFound)?
    };
    state.cached_nvm_id = Some(id);
    Ok(id)
}

// ── SecretStore ───────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl SecretStore for WolfHsmBackend {
    async fn get(&self) -> Result<SecretValue, SecretError> {
        let state_arc = Arc::clone(&self.state);
        let label = self.label.clone();
        let server = self.server.clone();

        tokio::task::spawn_blocking(move || {
            let mut guard = state_arc.lock().map_err(|_| poison_err())?;
            ensure_connected(&mut guard, &server)?;
            let id = get_cached_or_scan(&mut guard, &label)?;
            let bytes = {
                let client = guard.client.as_mut().unwrap();
                client.nvm_read(id, 0).map_err(backend_err)?
            };
            Ok(SecretValue::new(bytes))
        })
        .await
        .map_err(join_err)?
    }

    async fn refresh(&self) -> Result<SecretValue, SecretError> {
        {
            let mut guard = self.state.lock().map_err(|_| poison_err())?;
            guard.cached_nvm_id = None;
        }
        self.get().await
    }
}

// ── WritableSecretStore ───────────────────────────────────────────────────────

#[async_trait::async_trait]
impl WritableSecretStore for WolfHsmBackend {
    async fn put(&self, value: SecretValue) -> Result<(), SecretError> {
        let state_arc = Arc::clone(&self.state);
        let label = self.label.clone();
        let server = self.server.clone();
        let bytes = value.into_bytes();

        tokio::task::spawn_blocking(move || {
            let mut guard = state_arc.lock().map_err(|_| poison_err())?;
            ensure_connected(&mut guard, &server)?;

            let maybe_id = {
                let client = guard.client.as_mut().unwrap();
                find_by_label(client, &label)?
            };

            match maybe_id {
                Some(id) => {
                    // Overwrite: wolfhsm deletes then re-adds at the same ID.
                    {
                        let client = guard.client.as_mut().unwrap();
                        client
                            .nvm_overwrite(id, 0, 0, &label, bytes.as_ref())
                            .map_err(backend_err)?;
                    }
                    guard.cached_nvm_id = Some(id);
                }
                None => {
                    // New object: find a free NVM ID.
                    let free_id = {
                        let client = guard.client.as_mut().unwrap();
                        find_free_id(client)?
                    };
                    {
                        let client = guard.client.as_mut().unwrap();
                        client
                            .nvm_add(free_id, 0, 0, &label, bytes.as_ref())
                            .map_err(backend_err)?;
                    }
                    guard.cached_nvm_id = Some(free_id);
                }
            }
            Ok(())
        })
        .await
        .map_err(join_err)?
    }
}

// ── SigningBackend ────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl SigningBackend for WolfHsmBackend {
    async fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, SecretError> {
        Err(signing_unavailable(&self.label))
    }

    async fn public_key_der(&self) -> Result<Vec<u8>, SecretError> {
        Err(signing_unavailable(&self.label))
    }

    fn algorithm(&self) -> Result<SigningAlgorithm, SecretError> {
        Err(signing_unavailable(&self.label))
    }
}

fn signing_unavailable(label: &str) -> SecretError {
    SecretError::Unavailable {
        backend: BACKEND,
        source: format!(
            "wolfHSM SigningBackend not yet implemented (label: {label}): \
             the wolfhsm 0.1.0 crate does not expose an API to load a \
             persistent NVM key by label; waiting for EccP256Key::load_from_nvm"
        )
        .into(),
    }
}

// ── Inventory registrations ───────────────────────────────────────────────────

inventory::submit!(secretx_core::BackendRegistration {
    name: BACKEND,
    factory: |uri: &str| {
        WolfHsmBackend::from_uri(uri)
            .map(|b| std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::SecretStore>)
    },
});

inventory::submit!(secretx_core::WritableBackendRegistration {
    name: BACKEND,
    factory: |uri: &str| {
        WolfHsmBackend::from_uri(uri).map(|b| {
            std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::WritableSecretStore>
        })
    },
});

inventory::submit!(secretx_core::SigningBackendRegistration {
    name: BACKEND,
    factory: |uri: &str| {
        WolfHsmBackend::from_uri(uri)
            .map(|b| std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::SigningBackend>)
    },
});

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_uri_ok() {
        let b = WolfHsmBackend::from_uri("secretx:wolfhsm:my-key").unwrap();
        assert_eq!(b.label, "my-key");
        assert_eq!(b.server, "");
    }

    #[test]
    fn from_uri_with_server_param() {
        let b =
            WolfHsmBackend::from_uri("secretx:wolfhsm:my-key?server=127.0.0.1:8080").unwrap();
        assert_eq!(b.label, "my-key");
        assert_eq!(b.server, "127.0.0.1:8080");
    }

    #[test]
    fn from_uri_wrong_backend() {
        assert!(matches!(
            WolfHsmBackend::from_uri("secretx:file:foo"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_missing_label() {
        assert!(matches!(
            WolfHsmBackend::from_uri("secretx:wolfhsm"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_label_too_long() {
        // 25 bytes — one over the 24-byte NVM label limit.
        let uri = "secretx:wolfhsm:aaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(uri.len() - "secretx:wolfhsm:".len(), 25);
        assert!(matches!(
            WolfHsmBackend::from_uri(uri),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_label_max_length_ok() {
        // Exactly 24 bytes — should succeed.
        let uri = "secretx:wolfhsm:aaaaaaaaaaaaaaaaaaaaaaaa";
        assert_eq!(uri.len() - "secretx:wolfhsm:".len(), 24);
        WolfHsmBackend::from_uri(uri).unwrap();
    }

    #[test]
    fn from_uri_field_selector_rejected() {
        assert!(matches!(
            WolfHsmBackend::from_uri("secretx:wolfhsm:my-key?field=password"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[tokio::test]
    async fn get_no_server_returns_unavailable() {
        // No ?server= and WOLFHSM_SERVER not set → Unavailable.
        // Guard against the test environment having WOLFHSM_SERVER set.
        if std::env::var("WOLFHSM_SERVER").is_ok() {
            return; // skip: live server present, this test is not meaningful
        }
        let b = WolfHsmBackend::from_uri("secretx:wolfhsm:test-key").unwrap();
        assert!(matches!(
            b.get().await,
            Err(SecretError::Unavailable {
                backend: "wolfhsm",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn sign_returns_unavailable() {
        let b = WolfHsmBackend::from_uri("secretx:wolfhsm:test-key").unwrap();
        assert!(matches!(
            b.sign(b"data").await,
            Err(SecretError::Unavailable {
                backend: "wolfhsm",
                ..
            })
        ));
    }

    #[test]
    fn algorithm_returns_unavailable() {
        let b = WolfHsmBackend::from_uri("secretx:wolfhsm:test-key").unwrap();
        assert!(matches!(
            b.algorithm(),
            Err(SecretError::Unavailable {
                backend: "wolfhsm",
                ..
            })
        ));
    }
}

//! wolfHSM secure element backend for secretx.
//!
//! URI: `secretx:wolfhsm:<label>[?server=<addr>][?client_id=<n>]`
//!
//! - `label` — NVM object label (1–24 bytes, UTF-8). Identifies the data
//!   object on the wolfHSM server.
//! - `server` — (optional) wolfHSM server address. Falls back to the
//!   `WOLFHSM_SERVER` environment variable if absent.
//!   Format: `host:port` for TCP (e.g. `127.0.0.1:8080`) or `/path` for UDS.
//! - `client_id` — (optional) wolfHSM client ID (0–255, default 1). wolfHSM
//!   uses the client ID to namespace NVM objects and keys. Two clients with
//!   the same `client_id` share the same NVM namespace on the server.
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
//! Returns [`SecretError::Unavailable`]. The wolfhsm crate does not yet expose
//! an API to load a persistent committed ECC key from NVM by label
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

/// `WH_ERROR_NOTFOUND` from `wolfhsm/wh_error.h` line 60.
///
/// Returned when an NVM object or key with the given ID does not exist on the
/// server.  Treated as a stale-list sentinel in [`find_by_label`]: if
/// `nvm_metadata` returns this code for an ID from `nvm_list`, the entry is
/// skipped rather than propagated as an error.
const WH_ERROR_NOTFOUND: i32 = -2104;

// ── Internal state ────────────────────────────────────────────────────────────

struct WolfHsmState {
    /// Connected client. `None` until first use.
    client: Option<Client>,
    /// Cached NVM ID for this backend's label. Avoids O(n) scan per call.
    cached_nvm_id: Option<NvmId>,
}

impl WolfHsmState {
    /// Returns a mutable reference to the connected [`Client`].
    ///
    /// # Panics
    ///
    /// Panics if `client` is `None`. Always call [`ensure_connected`] before
    /// this method.
    fn connected_client(&mut self) -> &mut Client {
        self.client
            .as_mut()
            .expect("wolfhsm: connected_client called before ensure_connected")
    }
}

// ── Public backend struct ─────────────────────────────────────────────────────

/// Backend that reads and writes wolfHSM NVM data objects by label.
///
/// Construct with [`WolfHsmBackend::from_uri`].
pub struct WolfHsmBackend {
    label: String,
    /// Configured server address (`?server=` value, may be empty).
    server: String,
    /// wolfHSM client ID (0–255). Defaults to 1.
    client_id: u8,
    state: Arc<Mutex<WolfHsmState>>,
}

impl WolfHsmBackend {
    /// Construct from a `secretx:wolfhsm:<label>[?server=<addr>][?client_id=<n>]` URI.
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
        // Validate the ?server= address at construction time (pure parsing, no
        // I/O). WOLFHSM_SERVER from the environment is validated lazily at
        // first use because it is not known until then.
        if !server.is_empty() {
            make_transport(&server)?;
        }
        let client_id: u8 = match parsed.param("client_id") {
            None => 1,
            Some(s) => s.parse().map_err(|_| {
                SecretError::InvalidUri(format!(
                    "wolfhsm `?client_id={s}` is not a valid u8 (0–255)"
                ))
            })?,
        };
        Ok(Self {
            label,
            server,
            client_id,
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
    // Unix domain socket: any path starting with '/'.
    if addr.starts_with('/') {
        return Ok(Transport::Uds {
            path: addr.to_owned(),
        });
    }

    // IPv6 bracket notation: [::1]:8080 → ip="::1", port=8080.
    // The brackets are stripped because wolfhsm's TCP connect expects a bare
    // IP address, not URL-style bracket notation.
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some((host, port_str)) = rest.split_once("]:") {
            let port = parse_tcp_port(addr, port_str)?;
            return Ok(Transport::Tcp {
                ip: host.to_owned(),
                port,
            });
        }
        return Err(SecretError::InvalidUri(format!(
            "wolfhsm server `{addr}`: malformed IPv6 bracket address; expected `[<ip>]:<port>`"
        )));
    }

    // IPv4 / hostname: host:port.
    if let Some((host, port_str)) = addr.rsplit_once(':') {
        let port = parse_tcp_port(addr, port_str)?;
        return Ok(Transport::Tcp {
            ip: host.to_owned(),
            port,
        });
    }

    Err(SecretError::InvalidUri(format!(
        "wolfhsm server `{addr}` must be `host:port` (TCP), `[<ip>]:<port>` (IPv6 TCP), \
         or `/path` (UDS)"
    )))
}

/// Parse and validate a TCP port string for wolfhsm.
///
/// wolfhsm's C TCP transport stores the port as `i16`, so values above 32767
/// are rejected at `Client::connect` time.  Catching the limit here returns
/// [`SecretError::InvalidUri`] (a permanent configuration error) rather than
/// [`SecretError::Unavailable`] (which implies retriability).
fn parse_tcp_port(addr: &str, port_str: &str) -> Result<u16, SecretError> {
    let port: u16 = port_str.parse().map_err(|_| {
        SecretError::InvalidUri(format!(
            "wolfhsm server `{addr}`: port `{port_str}` is not a valid u16"
        ))
    })?;
    if port > 32767 {
        return Err(SecretError::InvalidUri(format!(
            "wolfhsm server `{addr}`: port {port} exceeds 32767 \
             (wolfhsm C transport uses i16 for port numbers)"
        )));
    }
    Ok(port)
}

/// Ensure `state.client` is connected, connecting if necessary.
///
/// Returns a reference to the client. Any earlier connection error is retried
/// on the next call — a poisoned `state.client = None` signals reconnect.
fn ensure_connected<'a>(
    state: &'a mut WolfHsmState,
    server: &str,
    client_id: u8,
) -> Result<&'a mut Client, SecretError> {
    if state.client.is_none() {
        let addr = resolve_server(server)?;
        let transport = make_transport(&addr)?;
        let client =
            Client::connect(transport, client_id).map_err(|e| SecretError::Unavailable {
                backend: BACKEND,
                source: Box::new(e),
            })?;
        state.client = Some(client);
    }
    Ok(state.connected_client())
}

// ── NVM scan helpers ──────────────────────────────────────────────────────────

/// Scan all NVM data objects for one whose label matches `label`.
///
/// Returns `(found_id, all_ids)` where `all_ids` is the full list from
/// `nvm_list`.  The list is returned unconditionally so the caller can pass
/// it to [`find_free_id_from_list`] on a miss, avoiding a second round-trip.
///
/// `WH_ERROR_NOTFOUND` from `nvm_metadata` is treated as a stale list entry
/// and skipped rather than propagated.
///
/// # Panics
///
/// Panics if `state.client` is `None`. Call [`ensure_connected`] first.
fn find_by_label(
    client: &mut Client,
    label: &str,
) -> Result<(Option<NvmId>, Vec<NvmId>), SecretError> {
    let ids = client.nvm_list().map_err(backend_err)?;
    let mut found = None;
    for &id in &ids {
        match client.nvm_metadata(id) {
            Ok(meta) => {
                if meta.label_str() == Some(label) {
                    found = Some(id);
                    break;
                }
            }
            Err(wolfhsm::Error::Wh { code }) if code == WH_ERROR_NOTFOUND => continue,
            Err(e) => return Err(backend_err(e)),
        }
    }
    Ok((found, ids))
}

/// Find the first NVM ID in `1..=u16::MAX` not present in `ids`.
///
/// `ids` is the full list returned by a recent `nvm_list` call, passed in to
/// avoid a redundant round-trip to the server.
///
/// ID 0 is excluded: `WH_KEYID_ERASED = 0x0000` (wolfhsm/wh_keyid.h:38) is
/// the sentinel "no ID" value and cannot be used for real objects.
///
/// # TOCTOU note
///
/// Another client with the same `client_id` may allocate the returned ID
/// between this call and the subsequent `nvm_add`.  If `nvm_add` fails,
/// propagate [`SecretError::Backend`] — do not retry automatically.  wolfHSM
/// has no atomic find-or-allocate API, so the gap is inherent to the protocol.
fn find_free_id_from_list(ids: Vec<NvmId>) -> Result<NvmId, SecretError> {
    let used: HashSet<u16> = ids.into_iter().map(u16::from).collect();
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

/// Result of [`find_cached_or_scan`].
///
/// The `NotFound` variant carries the full NVM ID list so that `put()` can
/// pass it directly to [`find_free_id_from_list`] without issuing a second
/// `nvm_list` round-trip.
enum FindResult {
    /// Object exists at this NVM ID.
    Found(NvmId),
    /// Object not found; the full current NVM ID list is enclosed.
    NotFound(Vec<NvmId>),
}

/// Find the NVM ID for `label`, using the cache when valid.
///
/// Returns [`FindResult::Found`] if the object exists (from cache or full
/// scan), or [`FindResult::NotFound`] with the full ID list if absent.
/// Updates `state.cached_nvm_id` on hit; clears it on cache miss.
///
/// # Panics
///
/// Panics if `state.client` is `None`. Call [`ensure_connected`] first.
fn find_cached_or_scan(state: &mut WolfHsmState, label: &str) -> Result<FindResult, SecretError> {
    // Validate cache before trusting it: another client may have deleted and
    // recreated the object under a different NVM ID.
    if let Some(cached) = state.cached_nvm_id {
        let still_valid = {
            match state.connected_client().nvm_metadata(cached) {
                Ok(meta) => meta.label_str() == Some(label),
                Err(wolfhsm::Error::Wh { code }) if code == WH_ERROR_NOTFOUND => false,
                Err(e) => return Err(backend_err(e)),
            }
        };
        if still_valid {
            return Ok(FindResult::Found(cached));
        }
        state.cached_nvm_id = None;
    }

    let (id_opt, ids) = find_by_label(state.connected_client(), label)?;
    match id_opt {
        Some(id) => {
            state.cached_nvm_id = Some(id);
            Ok(FindResult::Found(id))
        }
        None => Ok(FindResult::NotFound(ids)),
    }
}

/// Return the NVM ID for `label`, returning [`SecretError::NotFound`] if absent.
///
/// Thin wrapper over [`find_cached_or_scan`].
///
/// # Panics
///
/// Panics if `state.client` is `None`. Call [`ensure_connected`] first.
fn get_cached_or_scan(state: &mut WolfHsmState, label: &str) -> Result<NvmId, SecretError> {
    match find_cached_or_scan(state, label)? {
        FindResult::Found(id) => Ok(id),
        FindResult::NotFound(_) => Err(SecretError::NotFound),
    }
}

// ── SecretStore ───────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl SecretStore for WolfHsmBackend {
    async fn get(&self) -> Result<SecretValue, SecretError> {
        let state_arc = Arc::clone(&self.state);
        let label = self.label.clone();
        let server = self.server.clone();
        let client_id = self.client_id;

        tokio::task::spawn_blocking(move || {
            let mut guard = state_arc.lock().map_err(|_| poison_err())?;
            ensure_connected(&mut guard, &server, client_id)?;
            let id = get_cached_or_scan(&mut guard, &label)?;
            let bytes = guard
                .connected_client()
                .nvm_read(id, 0)
                .map_err(backend_err)?;
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
        let client_id = self.client_id;
        let bytes = value.into_bytes();

        tokio::task::spawn_blocking(move || {
            let mut guard = state_arc.lock().map_err(|_| poison_err())?;
            ensure_connected(&mut guard, &server, client_id)?;

            match find_cached_or_scan(&mut guard, &label)? {
                FindResult::Found(id) => {
                    // Overwrite: wolfhsm deletes then re-adds at the same ID.
                    guard
                        .connected_client()
                        .nvm_overwrite(id, 0, 0, &label, bytes.as_ref())
                        .map_err(backend_err)?;
                    // find_cached_or_scan already set cached_nvm_id = Some(id);
                    // this write is defensive — makes the cache invariant visible
                    // at the call site and guards against future refactors that
                    // move or bypass find_cached_or_scan.
                    guard.cached_nvm_id = Some(id);
                }
                FindResult::NotFound(ids) => {
                    // New object: pick a free NVM ID from the list that
                    // find_cached_or_scan already fetched, avoiding a second
                    // nvm_list round-trip to the server.
                    // TOCTOU: another client with the same client_id may
                    // allocate this ID between find_free_id_from_list and
                    // nvm_add — wolfHSM has no atomic allocate API.  If
                    // nvm_add fails, propagate Backend; do not retry blindly.
                    let free_id = find_free_id_from_list(ids)?;
                    guard
                        .connected_client()
                        .nvm_add(free_id, 0, 0, &label, bytes.as_ref())
                        .map_err(backend_err)?;
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
             the wolfhsm crate does not yet expose EccP256Key::load_from_nvm; \
             signing will be implemented once that API is available"
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
        assert_eq!(b.client_id, 1);
    }

    #[test]
    fn from_uri_with_server_param() {
        let b = WolfHsmBackend::from_uri("secretx:wolfhsm:my-key?server=127.0.0.1:8080").unwrap();
        assert_eq!(b.label, "my-key");
        assert_eq!(b.server, "127.0.0.1:8080");
    }

    #[test]
    fn from_uri_with_client_id_param() {
        let b = WolfHsmBackend::from_uri("secretx:wolfhsm:my-key?client_id=7").unwrap();
        assert_eq!(b.client_id, 7);
    }

    #[test]
    fn from_uri_client_id_out_of_range() {
        assert!(matches!(
            WolfHsmBackend::from_uri("secretx:wolfhsm:my-key?client_id=256"),
            Err(SecretError::InvalidUri(_))
        ));
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
    fn from_uri_server_param_invalid_port_rejected_at_construction() {
        // ?server= is validated eagerly at from_uri() — not lazily at get().
        // Port > 32767 must be caught here, not at runtime.
        assert!(matches!(
            WolfHsmBackend::from_uri("secretx:wolfhsm:my-key?server=host:40000"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_field_selector_rejected() {
        assert!(matches!(
            WolfHsmBackend::from_uri("secretx:wolfhsm:my-key?field=password"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    // ── make_transport ────────────────────────────────────────────────────────

    #[test]
    fn transport_uds() {
        let t = make_transport("/run/wolfhsm.sock").unwrap();
        assert!(matches!(t, Transport::Uds { path } if path == "/run/wolfhsm.sock"));
    }

    #[test]
    fn transport_tcp_ipv4() {
        let t = make_transport("127.0.0.1:8080").unwrap();
        assert!(matches!(t, Transport::Tcp { ip, port } if ip == "127.0.0.1" && port == 8080));
    }

    #[test]
    fn transport_tcp_hostname() {
        let t = make_transport("myhost:1234").unwrap();
        assert!(matches!(t, Transport::Tcp { ip, port } if ip == "myhost" && port == 1234));
    }

    #[test]
    fn transport_tcp_ipv6_bracket() {
        let t = make_transport("[::1]:8080").unwrap();
        assert!(matches!(t, Transport::Tcp { ip, port } if ip == "::1" && port == 8080));
    }

    #[test]
    fn transport_tcp_ipv6_full_bracket() {
        let t = make_transport("[2001:db8::1]:443").unwrap();
        assert!(matches!(t, Transport::Tcp { ip, port } if ip == "2001:db8::1" && port == 443));
    }

    #[test]
    fn transport_invalid_no_port() {
        assert!(matches!(
            make_transport("localhostonly"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn transport_invalid_port_not_u16() {
        assert!(matches!(
            make_transport("host:notaport"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn transport_invalid_port_overflow() {
        assert!(matches!(
            make_transport("host:65536"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn transport_invalid_ipv6_malformed() {
        assert!(matches!(
            make_transport("[::1]"), // missing port
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn transport_tcp_port_too_high_ipv4() {
        // wolfhsm C transport uses i16; ports > 32767 must be InvalidUri, not
        // Unavailable (which implies retriability).
        assert!(matches!(
            make_transport("host:32768"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn transport_tcp_port_max_valid_ipv4() {
        // 32767 == i16::MAX — the highest port wolfhsm accepts.
        let t = make_transport("host:32767").unwrap();
        assert!(matches!(t, Transport::Tcp { port, .. } if port == 32767));
    }

    #[test]
    fn transport_tcp_port_too_high_ipv6() {
        assert!(matches!(
            make_transport("[::1]:40000"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn transport_tcp_port_max_valid_ipv6() {
        let t = make_transport("[::1]:32767").unwrap();
        assert!(matches!(t, Transport::Tcp { port, .. } if port == 32767));
    }

    // ── SecretStore / SigningBackend (no server) ──────────────────────────────

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

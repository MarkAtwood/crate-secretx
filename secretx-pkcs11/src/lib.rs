//! PKCS#11 HSM backend for secretx.
//!
//! Requires a **PKCS#11 v2.40+** compliant library. Older libraries may work
//! for basic `get`/`put` operations but `public_key_der()` relies on
//! `CKA_PUBLIC_KEY_INFO`, which was introduced in v2.40.
//!
//! URI: `secretx:pkcs11:<slot>/<label>[?lib=<path>&pin=<pin>]`
//!
//! - `slot`  — numeric index into the list of slots that have a token present
//!   (e.g. `0` for the first slot).
//! - `label` — the `CKA_LABEL` of the target object.
//! - `lib`   — path to the PKCS#11 shared library.  Falls back to the
//!   `PKCS11_LIB` environment variable if omitted.
//! - `pin`   — token PIN for login.  Falls back to the `PKCS11_PIN`
//!   environment variable if omitted.  Use `?pin=` when multiple tokens
//!   with different PINs are in use.
//!
//! # Supported algorithms
//!
//! | Key type | Algorithm | Mechanism |
//! |----------|-----------|-----------|
//! | EC P-256 | `EcdsaP256Sha256` | `CKM_ECDSA_SHA256` |
//! | RSA-2048 | `RsaPss2048Sha256` | `CKM_SHA256_RSA_PKCS_PSS` (MGF1-SHA-256, salt=32) |
//!
//! Other key types and sizes (e.g. P-384, RSA-4096) are rejected at runtime.
//!
//! # Examples
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), secretx_core::SecretError> {
//! use secretx_pkcs11::Pkcs11Backend;
//! use secretx_core::SecretStore;
//!
//! let store = Pkcs11Backend::from_uri(
//!     "secretx:pkcs11:0/my-data?lib=/usr/lib/softhsm/libsofthsm2.so",
//! )?;
//! let value = store.get().await?;
//! # Ok(())
//! # }
//! ```

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use cryptoki::error::{Error as CkError, RvError};
use secretx_core::{
    SecretError, SecretStore, SecretUri, SecretValue, SigningAlgorithm, SigningBackend,
    WritableSecretStore,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use zeroize::{Zeroize, Zeroizing};

const BACKEND: &str = "pkcs11";

/// Process-wide cache of initialized PKCS#11 contexts, keyed by canonical
/// library path.  PKCS#11 spec (v2.40 §5.4) requires `C_Initialize` to be
/// called exactly once per process per library.  Subsequent `from_uri` calls
/// for the same `.so` reuse the existing `Arc<Pkcs11>`.
fn pkcs11_ctx_cache() -> &'static Mutex<HashMap<PathBuf, Arc<Pkcs11>>> {
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, Arc<Pkcs11>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Classify a cryptoki error as transient ([`SecretError::Unavailable`]) or
/// permanent ([`SecretError::Backend`]).
///
/// Transient: device/token/session gone (may reconnect), or generic failures
/// that the PKCS#11 spec says "may succeed on retry".
/// Permanent: auth failures, bad templates, unsupported mechanisms, etc.
fn classify_ck(e: CkError) -> SecretError {
    let is_transient = matches!(
        &e,
        CkError::Pkcs11(
            RvError::DeviceError
                | RvError::DeviceRemoved
                | RvError::TokenNotPresent
                | RvError::TokenNotRecognized
                | RvError::SessionClosed
                | RvError::SessionHandleInvalid
                | RvError::SessionCount
                | RvError::FunctionFailed
                | RvError::GeneralError
                | RvError::HostMemory
                | RvError::DeviceMemory,
            _
        )
    );
    if is_transient {
        SecretError::Unavailable {
            backend: BACKEND,
            source: e.into(),
        }
    } else {
        SecretError::Backend {
            backend: BACKEND,
            source: e.into(),
        }
    }
}

/// Shorthand for constructing a [`SecretError::Backend`] with `backend: "pkcs11"`.
fn pkcs11_err(msg: impl Into<String>) -> SecretError {
    SecretError::Backend {
        backend: BACKEND,
        source: msg.into().into(),
    }
}

/// Extract the first attribute matching a variant from a list of attributes.
///
/// Usage: `extract_attr!(attrs, Attribute::Value(v) => v.clone())`
///
/// Returns `None` if no attribute matches.
macro_rules! extract_attr {
    ($attrs:expr, $pat:pat => $expr:expr) => {
        $attrs.into_iter().find_map(|attr| match attr {
            $pat => Some($expr),
            _ => None,
        })
    };
}

/// PKCS#11 backend that implements both [`SecretStore`] and [`SigningBackend`].
///
/// Secrets are stored as `CKO_DATA` objects; signing keys are `CKO_PRIVATE_KEY`
/// objects.  Both are matched by `CKA_LABEL`.
pub struct Pkcs11Backend {
    ctx: Arc<Pkcs11>,
    slot: cryptoki::slot::Slot,
    label: String,
    user_pin: Option<Zeroizing<String>>,
    /// Canonical path of the PKCS#11 library, used to look up the cache entry
    /// in [`pkcs11_ctx_cache`] during [`Drop`].
    lib_path: PathBuf,
    /// Cached read-only session, opened lazily on first use and reused across
    /// operations.  Wrapped in `Arc<Mutex<_>>` so `spawn_blocking` closures can
    /// borrow it without `&self` being `'static`.
    ro_session: Arc<Mutex<Option<cryptoki::session::Session>>>,
    // Cached algorithm, populated by sign() on first call.  algorithm() reads
    // this cache but never performs I/O itself.
    // Arc<OnceLock> so the cache can be shared with spawn_blocking closures
    // without requiring &self to be 'static.
    algorithm_cache: Arc<std::sync::OnceLock<SigningAlgorithm>>,
}

impl std::fmt::Debug for Pkcs11Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pkcs11Backend")
            .field("lib_path", &self.lib_path)
            .field("slot", &self.slot)
            .field("label", &self.label)
            .field("has_pin", &self.user_pin.is_some())
            .finish_non_exhaustive()
    }
}

impl Drop for Pkcs11Backend {
    /// Close the cached session (if any) and, when this is the last backend
    /// using a given PKCS#11 library, remove the context from the process-wide
    /// cache and call `C_Finalize`.
    fn drop(&mut self) {
        // Drop the cached session first so C_CloseSession runs while the
        // context is still alive.
        if let Ok(mut guard) = self.ro_session.lock() {
            drop(guard.take());
        }

        // Try to remove the context from the cache.  If we're the sole
        // remaining owner (strong_count == 2: us + cache), removing from
        // the cache drops the cache's Arc, leaving ours as the only one.
        // Arc::try_unwrap then succeeds and we can call finalize().
        if let Ok(mut cache) = pkcs11_ctx_cache().lock() {
            if Arc::strong_count(&self.ctx) == 2 {
                if let Some(removed) = cache.remove(&self.lib_path) {
                    drop(cache); // release the lock before finalize
                    // removed + self.ctx are the only two Arcs.  self.ctx
                    // will be dropped after this fn returns, so try_unwrap
                    // on `removed` succeeds.
                    if let Ok(ctx) = Arc::try_unwrap(removed) {
                        let _ = ctx.finalize();
                    }
                }
            }
        }
    }
}

impl Pkcs11Backend {
    /// Construct from a `secretx:pkcs11:<slot>/<label>[?lib=<path>]` URI.
    ///
    /// The PKCS#11 library is loaded and initialised on the first call for a
    /// given library path; subsequent calls reuse the existing context
    /// (PKCS#11 spec requires exactly one `C_Initialize` per process per
    /// library).  No session is opened until a trait method is called.
    ///
    /// **Blocking**: the first call for a given library path performs `dlopen`,
    /// `C_Initialize`, and slot enumeration — synchronous operations that may
    /// take hundreds of milliseconds for network-backed HSMs (CloudHSM,
    /// GCP KMS PKCS#11).  Wrap the first call in
    /// [`tokio::task::spawn_blocking`] if calling from an async context.
    ///
    /// # Errors
    ///
    /// - [`SecretError::InvalidUri`] — wrong backend, missing or non-numeric
    ///   slot, empty label, or missing `?lib=` with no `PKCS11_LIB` env var.
    /// - [`SecretError::Backend`] — PKCS#11 library load (`C_Initialize`)
    ///   failed, or the requested slot index exceeds the number of tokens.
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        Self::from_parsed_uri(&SecretUri::parse(uri)?)
    }

    /// Construct from a pre-parsed [`SecretUri`].
    pub fn from_parsed_uri(parsed: &SecretUri) -> Result<Self, SecretError> {
        if parsed.backend() != "pkcs11" {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `pkcs11`, got `{}`",
                parsed.backend()
            )));
        }

        // path is "<slot>/<label>"
        let (slot_str, label) = split_path(parsed.path())?;

        let slot_idx: usize = slot_str.parse().map_err(|_| {
            SecretError::InvalidUri(format!(
                "pkcs11 slot must be a non-negative integer, got `{slot_str}`"
            ))
        })?;

        let lib_path = parsed
            .param("lib")
            .map(|s| s.to_string())
            .or_else(|| std::env::var("PKCS11_LIB").ok())
            .ok_or_else(|| {
                SecretError::InvalidUri(
                    "pkcs11 URI requires `?lib=<path>` or the `PKCS11_LIB` env var".into(),
                )
            })?;

        let canon = std::fs::canonicalize(&lib_path).unwrap_or_else(|_| PathBuf::from(&lib_path));
        let ctx = {
            let mut cache = pkcs11_ctx_cache()
                .lock()
                .map_err(|_| pkcs11_err("pkcs11 context cache mutex poisoned"))?;
            if let Some(existing) = cache.get(&canon) {
                Arc::clone(existing)
            } else {
                let new_ctx = Pkcs11::new(&lib_path).map_err(classify_ck)?;
                new_ctx
                    .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
                    .map_err(classify_ck)?;
                let arc = Arc::new(new_ctx);
                cache.insert(canon.clone(), Arc::clone(&arc));
                arc
            }
        };

        let slots = ctx
            .get_slots_with_token()
            .map_err(classify_ck)?;
        let slot = slots
            .get(slot_idx)
            .copied()
            .ok_or_else(|| {
                pkcs11_err(format!(
                    "slot index {slot_idx} not found (only {} slot(s) with a token)",
                    slots.len()
                ))
            })?;

        // Per-URI ?pin= takes precedence over the process-global PKCS11_PIN
        // env var, allowing multi-token apps to supply different PINs.
        let user_pin = parsed
            .param("pin")
            .map(|p| Zeroizing::new(p.to_owned()))
            .or_else(|| std::env::var("PKCS11_PIN").ok().map(Zeroizing::new));

        Ok(Self {
            ctx,
            slot,
            label: label.to_string(),
            user_pin,
            lib_path: canon,
            ro_session: Arc::new(Mutex::new(None)),
            algorithm_cache: Arc::new(std::sync::OnceLock::new()),
        })
    }

    /// Find the unique object matching `class` and `CKA_LABEL == label`.
    ///
    /// Returns [`SecretError::NotFound`] if no match, or [`SecretError::Backend`]
    /// if more than one match (ambiguous — operator must clean up duplicates).
    fn find_object(
        session: &cryptoki::session::Session,
        label: &str,
        class: ObjectClass,
    ) -> Result<cryptoki::object::ObjectHandle, SecretError> {
        let template = vec![
            Attribute::Class(class),
            Attribute::Label(label.as_bytes().to_vec()),
        ];
        let handles = session
            .find_objects(&template)
            .map_err(classify_ck)?;
        if handles.len() > 1 {
            return Err(pkcs11_err(format!(
                "found {} objects with label `{label}` and class {class:?}; \
                 expected exactly one (clean up duplicates on the token)",
                handles.len()
            )));
        }
        handles.into_iter().next().ok_or(SecretError::NotFound)
    }

    /// Read `CKA_MODULUS_BITS` from an RSA private key and verify the key size.
    ///
    /// Only 2048-bit RSA keys are supported (maps to `RsaPss2048Sha256`).
    fn detect_rsa_algorithm(
        session: &cryptoki::session::Session,
        handle: cryptoki::object::ObjectHandle,
    ) -> Result<SigningAlgorithm, SecretError> {
        let attrs = session
            .get_attributes(handle, &[AttributeType::ModulusBits])
            .map_err(classify_ck)?;

        let bits = extract_attr!(attrs, Attribute::ModulusBits(b) => b).ok_or_else(|| {
            pkcs11_err("RSA private key is missing CKA_MODULUS_BITS; cannot determine key size")
        })?;

        if u64::from(bits) == 2048 {
            Ok(SigningAlgorithm::RsaPss2048Sha256)
        } else {
            Err(pkcs11_err(format!(
                "unsupported RSA key size: {bits} bits; only 2048-bit RSA is supported"
            )))
        }
    }

    /// Read `CKA_EC_PARAMS` from an EC private key and map to a [`SigningAlgorithm`].
    ///
    /// Only P-256 (`prime256v1`, OID `1.2.840.10045.3.1.7`) is supported.
    fn detect_ec_algorithm(
        session: &cryptoki::session::Session,
        handle: cryptoki::object::ObjectHandle,
    ) -> Result<SigningAlgorithm, SecretError> {
        // P-256 named-curve OID DER: OBJECT IDENTIFIER 1.2.840.10045.3.1.7
        const P256_OID: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

        let ec_attrs = session
            .get_attributes(handle, &[AttributeType::EcParams])
            .map_err(classify_ck)?;

        let params = extract_attr!(ec_attrs, Attribute::EcParams(p) => p)
            .ok_or_else(|| pkcs11_err("EC private key is missing CKA_EC_PARAMS"))?;

        if params == P256_OID {
            Ok(SigningAlgorithm::EcdsaP256Sha256)
        } else {
            Err(pkcs11_err(format!(
                "unsupported EC curve (CKA_EC_PARAMS = {:02x?}); only P-256 is supported",
                params
            )))
        }
    }
}

/// Open a read-only PKCS#11 session, logging in with `user_pin` if provided.
///
/// Called from both the `&self` methods and from `spawn_blocking` closures
/// (where `Arc<Pkcs11>` is captured by value rather than borrowed from `self`).
fn pkcs11_ro_session(
    ctx: &Pkcs11,
    slot: cryptoki::slot::Slot,
    user_pin: Option<&Zeroizing<String>>,
) -> Result<cryptoki::session::Session, SecretError> {
    let session = ctx
        .open_ro_session(slot)
        .map_err(classify_ck)?;
    if let Some(pin) = user_pin {
        let auth = AuthPin::new(pin.as_str().into());
        session
            .login(UserType::User, Some(&auth))
            .map_err(classify_ck)?;
    }
    Ok(session)
}

/// Open a read-write PKCS#11 session, logging in with `user_pin` if provided.
fn pkcs11_rw_session(
    ctx: &Pkcs11,
    slot: cryptoki::slot::Slot,
    user_pin: Option<&Zeroizing<String>>,
) -> Result<cryptoki::session::Session, SecretError> {
    let session = ctx
        .open_rw_session(slot)
        .map_err(classify_ck)?;
    if let Some(pin) = user_pin {
        let auth = AuthPin::new(pin.as_str().into());
        session
            .login(UserType::User, Some(&auth))
            .map_err(classify_ck)?;
    }
    Ok(session)
}

/// Take the cached read-only session or open a new one.
///
/// Callers must return the session via [`return_ro_session`] after use so
/// subsequent operations can reuse it.
fn take_ro_session(
    cache: &Mutex<Option<cryptoki::session::Session>>,
    ctx: &Pkcs11,
    slot: cryptoki::slot::Slot,
    user_pin: Option<&Zeroizing<String>>,
) -> Result<cryptoki::session::Session, SecretError> {
    let cached = cache
        .lock()
        .map_err(|_| pkcs11_err("session cache mutex poisoned"))?
        .take();
    if let Some(s) = cached {
        return Ok(s);
    }
    pkcs11_ro_session(ctx, slot, user_pin)
}

/// Return a session to the cache for reuse.
fn return_ro_session(
    cache: &Mutex<Option<cryptoki::session::Session>>,
    session: cryptoki::session::Session,
) {
    if let Ok(mut guard) = cache.lock() {
        *guard = Some(session);
    }
}

/// Map a [`tokio::task::JoinError`] to a [`SecretError::Backend`].
fn map_join_err(e: tokio::task::JoinError) -> SecretError {
    pkcs11_err(format!("task join error: {e}"))
}

/// Detect the signing algorithm of the private key with `label` in the given slot.
///
/// Opens a read-only session, finds the `CKO_PRIVATE_KEY` object by label, and
/// reads `CKA_KEY_TYPE`.  For EC keys, also inspects `CKA_EC_PARAMS` to confirm
/// the curve is P-256.
///
/// Extracted as a free function so it can be called from `spawn_blocking` closures
/// that own `Arc<Pkcs11>` rather than borrowing `&self`.
fn pkcs11_detect_algorithm(
    ctx: &Pkcs11,
    slot: cryptoki::slot::Slot,
    label: &str,
    user_pin: Option<&Zeroizing<String>>,
) -> Result<SigningAlgorithm, SecretError> {
    let session = pkcs11_ro_session(ctx, slot, user_pin)?;
    let handle = Pkcs11Backend::find_object(&session, label, ObjectClass::PRIVATE_KEY)?;

    let attrs = session
        .get_attributes(handle, &[AttributeType::KeyType])
        .map_err(classify_ck)?;

    let kt = extract_attr!(attrs, Attribute::KeyType(kt) => kt)
        .ok_or_else(|| pkcs11_err("could not determine key type from CKA_KEY_TYPE"))?;

    match kt {
        KeyType::EC => Pkcs11Backend::detect_ec_algorithm(&session, handle),
        KeyType::RSA => Pkcs11Backend::detect_rsa_algorithm(&session, handle),
        _ => Err(pkcs11_err(format!(
            "unsupported key type: {kt}; this backend supports only EC P-256 and RSA-2048"
        ))),
    }
}

/// Split a path of the form `<slot>/<label>` into its two parts.
fn split_path(path: &str) -> Result<(&str, &str), SecretError> {
    let (slot, label) = path.split_once('/').ok_or_else(|| {
        SecretError::InvalidUri("pkcs11 URI path must be `<slot>/<label>`".into())
    })?;
    if slot.is_empty() || label.is_empty() {
        return Err(SecretError::InvalidUri(
            "pkcs11 URI path must be `<slot>/<label>`".into(),
        ));
    }
    Ok((slot, label))
}

#[async_trait::async_trait]
impl SecretStore for Pkcs11Backend {
    /// Retrieve a `CKO_DATA` object whose `CKA_LABEL` equals the label in the URI.
    ///
    /// All PKCS#11 calls are dispatched via `tokio::task::spawn_blocking` to
    /// avoid blocking the async executor.
    async fn get(&self) -> Result<SecretValue, SecretError> {
        let ctx = Arc::clone(&self.ctx);
        let slot = self.slot;
        let label = self.label.clone();
        let user_pin = self.user_pin.clone();
        let sess_cache = Arc::clone(&self.ro_session);

        tokio::task::spawn_blocking(move || -> Result<SecretValue, SecretError> {
            let session = take_ro_session(&sess_cache, &ctx, slot, user_pin.as_ref())?;
            let result = (|| {
                let handle = Pkcs11Backend::find_object(&session, &label, ObjectClass::DATA)?;
                let attrs = session
                    .get_attributes(handle, &[AttributeType::Value])
                    .map_err(classify_ck)?;
                extract_attr!(attrs, Attribute::Value(bytes) => SecretValue::new(bytes))
                    .ok_or_else(|| pkcs11_err("CKA_VALUE attribute missing on data object"))
            })();
            return_ro_session(&sess_cache, session);
            result
        })
        .await
        .map_err(map_join_err)?
    }

    /// Re-fetch the secret from the HSM (no caching layer here).
    async fn refresh(&self) -> Result<SecretValue, SecretError> {
        self.get().await
    }
}

#[async_trait::async_trait]
impl WritableSecretStore for Pkcs11Backend {
    /// Create or replace a `CKO_DATA` object with `CKA_LABEL == label`.
    ///
    /// # Atomicity
    ///
    /// PKCS#11 has no atomic replace primitive.  This implementation collects
    /// the handles of any existing objects **before** creating the new one,
    /// creates the new object, then destroys the old handles.
    ///
    /// - If `create_object` fails, the existing secret is unmodified.
    /// - If `destroy_object` fails after the new object is committed, `put`
    ///   returns `Ok(())` — the write succeeded. The duplicate object is
    ///   cleaned up on the next successful `put`.
    /// - **Data loss is not possible** with this ordering.
    /// - **Indeterminate read**: while a stale duplicate object exists, the
    ///   next `get()` may return either the old or the new value (PKCS#11 does
    ///   not define object enumeration order). This resolves on the next
    ///   successful `put()` which removes all stale handles.
    ///
    /// **Multi-writer concurrency**: concurrent `put()` calls from separate
    /// processes (or separate `Pkcs11Backend` instances) are not serialised.
    /// PKCS#11 does not provide advisory locking. If two writers race, both
    /// may create new objects before either destroys the old ones, leaving
    /// duplicate objects on the token. The next single-writer `put()` cleans
    /// up all stale handles. If multi-writer atomicity is required, use an
    /// external coordination mechanism (e.g. a file lock or database row lock).
    ///
    /// All PKCS#11 calls are dispatched via `tokio::task::spawn_blocking` to
    /// avoid blocking the async executor.
    async fn put(&self, value: SecretValue) -> Result<(), SecretError> {
        let ctx = Arc::clone(&self.ctx);
        let slot = self.slot;
        let label = self.label.clone();
        let user_pin = self.user_pin.clone();
        let secret_bytes = value.as_bytes().to_vec();

        tokio::task::spawn_blocking(move || -> Result<(), SecretError> {
            let session = pkcs11_rw_session(&ctx, slot, user_pin.as_ref())?;

            // Collect handles of existing objects BEFORE creating the new one.
            // A creation failure will then leave the existing secret intact.
            let template_search = vec![
                Attribute::Class(ObjectClass::DATA),
                Attribute::Label(label.as_bytes().to_vec()),
            ];
            let existing =
                session
                    .find_objects(&template_search)
                    .map_err(classify_ck)?;

            // Create the new object first.  Any failure here leaves `existing` intact.
            let mut template_create = vec![
                Attribute::Class(ObjectClass::DATA),
                Attribute::Token(true),
                Attribute::Label(label.as_bytes().to_vec()),
                Attribute::Value(secret_bytes),
            ];
            let create_result = session.create_object(&template_create);

            // Zero the plaintext copy unconditionally — on both success and error
            // paths.  cryptoki takes &[Attribute] (not ownership), so the Vec<u8>
            // is still accessible here.
            for attr in &mut template_create {
                if let Attribute::Value(ref mut bytes) = attr {
                    bytes.zeroize();
                }
            }

            create_result.map_err(classify_ck)?;

            // Best-effort cleanup: destroy old objects now that the new one is committed.
            // If destroy_object fails the write has still succeeded — the new value is
            // live in the HSM and get() will return it.  A duplicate object will remain
            // until the next successful put() collects it.  Do NOT return Err here:
            // doing so falsely signals that the write failed, and a caller retry would
            // create yet another duplicate.
            //
            // NOTE: destroy failures are currently invisible (no logging
            // infrastructure).  If duplicates accumulate, the next get() will
            // return SecretError::Backend with a "found N objects" message
            // from find_object's duplicate check — that is the observable signal.
            for handle in existing {
                let _ = session.destroy_object(handle);
            }

            Ok(())
        })
        .await
        .map_err(map_join_err)?
    }
}

#[async_trait::async_trait]
impl SigningBackend for Pkcs11Backend {
    /// Sign `message` with the `CKO_PRIVATE_KEY` object matching `self.label`.
    ///
    /// The mechanism is chosen based on the key type:
    /// - EC keys  → `CKM_ECDSA_SHA256`
    /// - RSA keys → `CKM_SHA256_RSA_PKCS_PSS` with SHA-256 / MGF1-SHA-256 / salt=32
    ///
    /// All PKCS#11 calls are dispatched via `tokio::task::spawn_blocking` to
    /// avoid blocking the async executor.  Algorithm detection (cold `OnceLock`)
    /// also happens inside the blocking task on the first call.
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SecretError> {
        // Fast path: if the algorithm was already detected, avoid an extra read
        // from the OnceLock inside the closure.
        let algo_if_known = self.algorithm_cache.get().copied();

        let ctx = Arc::clone(&self.ctx);
        let slot = self.slot;
        let label = self.label.clone();
        let user_pin = self.user_pin.clone();
        let algo_cache = Arc::clone(&self.algorithm_cache);
        let sess_cache = Arc::clone(&self.ro_session);
        let message = message.to_vec();

        tokio::task::spawn_blocking(move || -> Result<Vec<u8>, SecretError> {
            // Resolve algorithm — detect from HSM on first call, read from cache thereafter.
            let algo = if let Some(algo) = algo_if_known {
                algo
            } else {
                let detected = pkcs11_detect_algorithm(&ctx, slot, &label, user_pin.as_ref())?;
                // Best-effort cache: if another thread raced us, discard our result.
                let _ = algo_cache.set(detected);
                detected
            };

            let session = take_ro_session(&sess_cache, &ctx, slot, user_pin.as_ref())?;
            let result = (|| {
                let handle =
                    Pkcs11Backend::find_object(&session, &label, ObjectClass::PRIVATE_KEY)?;
                match algo {
                    SigningAlgorithm::EcdsaP256Sha256 => session
                        .sign(&Mechanism::EcdsaSha256, handle, &message)
                        .map_err(classify_ck),
                    SigningAlgorithm::RsaPss2048Sha256 => {
                        let pss = PkcsPssParams {
                            hash_alg: MechanismType::SHA256,
                            mgf: PkcsMgfType::MGF1_SHA256,
                            s_len: 32u64.into(),
                        };
                        session
                            .sign(&Mechanism::Sha256RsaPkcsPss(pss), handle, &message)
                            .map_err(classify_ck)
                    }
                    _ => Err(pkcs11_err(format!("unsupported signing algorithm: {algo:?}"))),
                }
            })();
            return_ro_session(&sess_cache, session);
            result
        })
        .await
        .map_err(map_join_err)?
    }

    /// Return the DER-encoded `SubjectPublicKeyInfo` of the matching public key.
    ///
    /// Reads `CKA_PUBLIC_KEY_INFO` from the `CKO_PUBLIC_KEY` object (PKCS#11
    /// v2.40+ tokens store the SPKI directly in this attribute).
    ///
    /// **Limitation**: tokens that do not populate `CKA_PUBLIC_KEY_INFO` (some
    /// older YubiHSM, Nitrokey, or pre-v2.40 firmware) will return an error.
    /// A future version may fall back to constructing SPKI from raw attributes.
    ///
    /// All PKCS#11 calls are dispatched via `tokio::task::spawn_blocking` to
    /// avoid blocking the async executor.
    async fn public_key_der(&self) -> Result<Vec<u8>, SecretError> {
        let ctx = Arc::clone(&self.ctx);
        let slot = self.slot;
        let label = self.label.clone();
        let user_pin = self.user_pin.clone();
        let sess_cache = Arc::clone(&self.ro_session);

        tokio::task::spawn_blocking(move || -> Result<Vec<u8>, SecretError> {
            let session = take_ro_session(&sess_cache, &ctx, slot, user_pin.as_ref())?;
            let result = (|| {
                let handle =
                    Pkcs11Backend::find_object(&session, &label, ObjectClass::PUBLIC_KEY)?;
                let attrs = session
                    .get_attributes(handle, &[AttributeType::PublicKeyInfo])
                    .map_err(classify_ck)?;
                extract_attr!(attrs, Attribute::PublicKeyInfo(der) => der).ok_or_else(|| {
                    pkcs11_err(
                        "CKA_PUBLIC_KEY_INFO attribute missing on public key object; \
                         this token may not populate SPKI (older YubiHSM, Nitrokey, \
                         or pre-PKCS#11-v2.40 firmware)",
                    )
                })
            })();
            return_ro_session(&sess_cache, session);
            result
        })
        .await
        .map_err(map_join_err)?
    }

    /// Returns the cached algorithm, or errors if the cache is cold.
    ///
    /// This method never performs HSM I/O.  Call [`sign`](SigningBackend::sign)
    /// or [`public_key_der`](SigningBackend::public_key_der) first to detect
    /// the key type and warm the cache.
    fn algorithm(&self) -> Result<SigningAlgorithm, SecretError> {
        self.algorithm_cache
            .get()
            .copied()
            .ok_or_else(|| {
                pkcs11_err(
                    "algorithm not yet detected; call sign() or public_key_der() first \
                     to warm the cache",
                )
            })
    }
}

inventory::submit!(secretx_core::BackendRegistration::new(
    "pkcs11",
    |uri: &secretx_core::SecretUri| {
        let b = Pkcs11Backend::from_parsed_uri(uri)?;
        Ok(Arc::new(b) as Arc<dyn secretx_core::SecretStore>)
    },
));

inventory::submit!(secretx_core::SigningBackendRegistration::new(
    "pkcs11",
    |uri: &secretx_core::SecretUri| {
        let b = Pkcs11Backend::from_parsed_uri(uri)?;
        Ok(Arc::new(b) as Arc<dyn secretx_core::SigningBackend>)
    },
));

inventory::submit!(secretx_core::WritableBackendRegistration::new(
    "pkcs11",
    |uri: &secretx_core::SecretUri| {
        let b = Pkcs11Backend::from_parsed_uri(uri)?;
        Ok(Arc::new(b) as Arc<dyn secretx_core::WritableSecretStore>)
    },
));

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialize tests that mutate process-global env vars.
    /// `std::env::remove_var` / `set_var` are not thread-safe; without this
    /// lock, parallel test threads race on `PKCS11_LIB`.
    static ENV_LOCK: std::sync::LazyLock<std::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(()));

    // ── URI parsing (no HSM required) ─────────────────────────────────────────

    #[test]
    fn uri_parse_with_lib_param() {
        let _guard = ENV_LOCK.lock().unwrap();
        // Set no env var to ensure the param is the source.
        std::env::remove_var("PKCS11_LIB");
        // We can't call from_uri successfully without the library, so just test
        // SecretUri parsing directly.
        let u = SecretUri::parse("secretx:pkcs11:0/my-key?lib=/usr/lib/softhsm/libsofthsm2.so")
            .unwrap();
        assert_eq!(u.backend(), "pkcs11");
        assert_eq!(u.path(), "0/my-key");
        assert_eq!(u.param("lib"), Some("/usr/lib/softhsm/libsofthsm2.so"));
    }

    #[test]
    fn uri_parse_slot_and_label() {
        let u = SecretUri::parse("secretx:pkcs11:2/signing-key?lib=/tmp/lib.so").unwrap();
        assert_eq!(u.path(), "2/signing-key");
    }

    #[test]
    fn split_path_ok() {
        let (slot, label) = split_path("0/my-label").unwrap();
        assert_eq!(slot, "0");
        assert_eq!(label, "my-label");
    }

    #[test]
    fn split_path_missing_slash() {
        assert!(matches!(
            split_path("noslash"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn split_path_empty_slot() {
        assert!(matches!(
            split_path("/label"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn split_path_empty_label() {
        assert!(matches!(split_path("0/"), Err(SecretError::InvalidUri(_))));
    }

    #[test]
    fn split_path_label_with_slashes() {
        // PKCS#11 CKA_LABEL can contain '/' — preserve the full label.
        let (slot, label) = split_path("0/some/nested/label").unwrap();
        assert_eq!(slot, "0");
        assert_eq!(label, "some/nested/label");
    }

    #[test]
    fn from_uri_wrong_backend() {
        assert!(matches!(
            Pkcs11Backend::from_uri("secretx:env:FOO"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_missing_lib_no_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        // Ensure neither source of the library path is present.
        std::env::remove_var("PKCS11_LIB");
        let result = Pkcs11Backend::from_uri("secretx:pkcs11:0/my-key");
        assert!(
            matches!(result, Err(SecretError::InvalidUri(_))),
            "expected InvalidUri"
        );
    }

    #[test]
    fn from_uri_non_numeric_slot() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("PKCS11_LIB");
        let result = Pkcs11Backend::from_uri("secretx:pkcs11:abc/label?lib=/tmp/x.so");
        assert!(
            matches!(result, Err(SecretError::InvalidUri(_))),
            "expected InvalidUri for non-numeric slot"
        );
    }

    // ── Integration tests (require PKCS11_LIB + SECRETX_PKCS11_TEST=1) ───────

    #[tokio::test]
    async fn integration_get_data_object() {
        if std::env::var("SECRETX_PKCS11_TEST").as_deref() != Ok("1") {
            eprintln!("skipped: set SECRETX_PKCS11_TEST=1 to run");
            return;
        }
        let Ok(lib) = std::env::var("PKCS11_LIB") else {
            eprintln!("skipped: PKCS11_LIB not set");
            return;
        };
        let label =
            std::env::var("PKCS11_TEST_DATA_LABEL").unwrap_or_else(|_| "test-data".to_string());
        let uri = format!("secretx:pkcs11:0/{label}?lib={lib}");
        let backend = Pkcs11Backend::from_uri(&uri).expect("from_uri should succeed");
        let value = backend.get().await.expect("get should succeed");
        assert!(
            !value.as_bytes().is_empty(),
            "retrieved value should be non-empty"
        );
    }

    #[tokio::test]
    async fn integration_sign() {
        if std::env::var("SECRETX_PKCS11_TEST").as_deref() != Ok("1") {
            eprintln!("skipped: set SECRETX_PKCS11_TEST=1 to run");
            return;
        }
        let Ok(lib) = std::env::var("PKCS11_LIB") else {
            eprintln!("skipped: PKCS11_LIB not set");
            return;
        };
        let label =
            std::env::var("PKCS11_TEST_KEY_LABEL").unwrap_or_else(|_| "test-key".to_string());
        let uri = format!("secretx:pkcs11:0/{label}?lib={lib}");
        let backend = Pkcs11Backend::from_uri(&uri).expect("from_uri should succeed");
        let message = b"hello world";
        let sig = backend.sign(message).await.expect("sign should succeed");
        assert!(!sig.is_empty(), "signature should be non-empty");

        let algo = backend
            .algorithm()
            .expect("algorithm should be determinable");
        let pub_der = backend
            .public_key_der()
            .await
            .expect("public_key_der should succeed");
        match algo {
            SigningAlgorithm::EcdsaP256Sha256 => {
                use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
                use p256::pkcs8::DecodePublicKey;
                let vk = VerifyingKey::from_public_key_der(&pub_der)
                    .expect("P-256 VerifyingKey from DER failed");
                let sig = Signature::from_bytes(sig.as_slice().into())
                    .expect("P-256 Signature decode failed");
                vk.verify(message, &sig)
                    .expect("P-256 signature verification failed");
            }
            SigningAlgorithm::RsaPss2048Sha256 => {
                use rsa::pkcs8::DecodePublicKey;
                use rsa::pss::VerifyingKey;
                use rsa::signature::Verifier;
                let pub_key = rsa::RsaPublicKey::from_public_key_der(&pub_der)
                    .expect("RSA public key from DER failed");
                let vk = VerifyingKey::<sha2::Sha256>::new(pub_key);
                let sig = rsa::pss::Signature::try_from(sig.as_slice())
                    .expect("RSA-PSS Signature decode failed");
                vk.verify(message, &sig)
                    .expect("RSA-PSS signature verification failed");
            }
            _ => panic!("unexpected signing algorithm: {algo:?}"),
        }
    }
}

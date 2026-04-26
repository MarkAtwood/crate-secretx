//! PKCS#11 HSM backend for secretx.
//!
//! URI: `secretx:pkcs11:<slot>/<label>[?lib=<pkcs11-lib-path>]`
//!
//! - `slot`  — numeric index into the list of slots that have a token present
//!   (e.g. `0` for the first slot).
//! - `label` — the `CKA_LABEL` of the target object.
//! - `lib`   — path to the PKCS#11 shared library.  Falls back to the
//!   `PKCS11_LIB` environment variable if omitted.
//!
//! An optional `PKCS11_PIN` environment variable supplies the user PIN for
//! sessions that require login (read/write and signing).
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
use secretx_core::{
    SecretError, SecretStore, SecretUri, SecretValue, SigningAlgorithm, SigningBackend,
    WritableSecretStore,
};
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

/// PKCS#11 backend that implements both [`SecretStore`] and [`SigningBackend`].
///
/// Secrets are stored as `CKO_DATA` objects; signing keys are `CKO_PRIVATE_KEY`
/// objects.  Both are matched by `CKA_LABEL`.
pub struct Pkcs11Backend {
    ctx: Arc<Pkcs11>,
    slot: cryptoki::slot::Slot,
    label: String,
    user_pin: Option<Zeroizing<String>>,
    // Cached result of detect_algorithm(). Populated on first call to algorithm().
    // Arc<OnceLock> so the cache can be shared with spawn_blocking closures without
    // requiring &self to be 'static.
    algorithm_cache: Arc<std::sync::OnceLock<SigningAlgorithm>>,
}

impl Pkcs11Backend {
    /// Construct from a `secretx:pkcs11:<slot>/<label>[?lib=<path>]` URI.
    ///
    /// This call loads the PKCS#11 library and initialises it.  No session is
    /// opened until a trait method is called.
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        let parsed = SecretUri::parse(uri)?;
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

        let ctx = Pkcs11::new(&lib_path).map_err(|e| SecretError::Backend {
            backend: "pkcs11",
            source: e.into(),
        })?;
        ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| SecretError::Backend {
                backend: "pkcs11",
                source: e.into(),
            })?;

        let slots = ctx
            .get_slots_with_token()
            .map_err(|e| SecretError::Backend {
                backend: "pkcs11",
                source: e.into(),
            })?;
        let slot = slots
            .get(slot_idx)
            .copied()
            .ok_or_else(|| SecretError::Backend {
                backend: "pkcs11",
                source: format!(
                    "slot index {slot_idx} not found (only {} slot(s) with a token)",
                    slots.len()
                )
                .into(),
            })?;

        let user_pin = std::env::var("PKCS11_PIN").ok().map(Zeroizing::new);

        Ok(Self {
            ctx: Arc::new(ctx),
            slot,
            label,
            user_pin,
            algorithm_cache: Arc::new(std::sync::OnceLock::new()),
        })
    }

    /// Find the first object matching `class` and `CKA_LABEL == label`.
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
            .map_err(|e| SecretError::Backend {
                backend: "pkcs11",
                source: e.into(),
            })?;
        handles.into_iter().next().ok_or(SecretError::NotFound)
    }

    /// Determine the key algorithm stored under `self.label`.
    ///
    /// Inspects `CKA_KEY_TYPE` of the `CKO_PRIVATE_KEY` object. For EC keys,
    /// also reads `CKA_EC_PARAMS` and verifies the curve is P-256.
    fn detect_algorithm(&self) -> Result<SigningAlgorithm, SecretError> {
        pkcs11_detect_algorithm(&self.ctx, self.slot, &self.label, &self.user_pin)
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
            .map_err(|e| SecretError::Backend {
                backend: "pkcs11",
                source: e.into(),
            })?;

        for ec_attr in ec_attrs {
            if let Attribute::EcParams(params) = ec_attr {
                if params == P256_OID {
                    return Ok(SigningAlgorithm::EcdsaP256Sha256);
                }
                return Err(SecretError::Backend {
                    backend: "pkcs11",
                    source: format!(
                        "unsupported EC curve (CKA_EC_PARAMS = {:02x?}); only P-256 is supported",
                        params
                    )
                    .into(),
                });
            }
        }

        Err(SecretError::Backend {
            backend: "pkcs11",
            source: "EC private key is missing CKA_EC_PARAMS".into(),
        })
    }
}

/// Open a read-only PKCS#11 session, logging in with `user_pin` if provided.
///
/// Called from both the `&self` methods and from `spawn_blocking` closures
/// (where `Arc<Pkcs11>` is captured by value rather than borrowed from `self`).
fn pkcs11_ro_session(
    ctx: &Pkcs11,
    slot: cryptoki::slot::Slot,
    user_pin: &Option<Zeroizing<String>>,
) -> Result<cryptoki::session::Session, SecretError> {
    let session = ctx
        .open_ro_session(slot)
        .map_err(|e| SecretError::Backend {
            backend: "pkcs11",
            source: e.into(),
        })?;
    if let Some(pin) = user_pin {
        let auth = AuthPin::new(pin.as_str().into());
        session
            .login(UserType::User, Some(&auth))
            .map_err(|e| SecretError::Backend {
                backend: "pkcs11",
                source: e.into(),
            })?;
    }
    Ok(session)
}

/// Open a read-write PKCS#11 session, logging in with `user_pin` if provided.
fn pkcs11_rw_session(
    ctx: &Pkcs11,
    slot: cryptoki::slot::Slot,
    user_pin: &Option<Zeroizing<String>>,
) -> Result<cryptoki::session::Session, SecretError> {
    let session = ctx
        .open_rw_session(slot)
        .map_err(|e| SecretError::Backend {
            backend: "pkcs11",
            source: e.into(),
        })?;
    if let Some(pin) = user_pin {
        let auth = AuthPin::new(pin.as_str().into());
        session
            .login(UserType::User, Some(&auth))
            .map_err(|e| SecretError::Backend {
                backend: "pkcs11",
                source: e.into(),
            })?;
    }
    Ok(session)
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
    user_pin: &Option<Zeroizing<String>>,
) -> Result<SigningAlgorithm, SecretError> {
    let session = pkcs11_ro_session(ctx, slot, user_pin)?;
    let handle = Pkcs11Backend::find_object(&session, label, ObjectClass::PRIVATE_KEY)?;

    let attrs = session
        .get_attributes(handle, &[AttributeType::KeyType])
        .map_err(|e| SecretError::Backend {
            backend: "pkcs11",
            source: e.into(),
        })?;

    for attr in attrs {
        if let Attribute::KeyType(kt) = attr {
            if kt == KeyType::EC {
                return Pkcs11Backend::detect_ec_algorithm(&session, handle);
            } else if kt == KeyType::RSA {
                return Ok(SigningAlgorithm::RsaPss2048Sha256);
            } else {
                return Err(SecretError::Backend {
                    backend: "pkcs11",
                    source: format!("unsupported key type: {kt}").into(),
                });
            }
        }
    }

    Err(SecretError::Backend {
        backend: "pkcs11",
        source: "could not determine key type from CKA_KEY_TYPE".into(),
    })
}

/// Split a path of the form `<slot>/<label>` into its two parts.
fn split_path(path: &str) -> Result<(&str, String), SecretError> {
    match path.find('/') {
        Some(i) => {
            let slot = &path[..i];
            let label = &path[i + 1..];
            if slot.is_empty() || label.is_empty() {
                Err(SecretError::InvalidUri(
                    "pkcs11 URI path must be `<slot>/<label>`".into(),
                ))
            } else {
                Ok((slot, label.to_string()))
            }
        }
        None => Err(SecretError::InvalidUri(
            "pkcs11 URI path must be `<slot>/<label>`".into(),
        )),
    }
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

        tokio::task::spawn_blocking(move || -> Result<SecretValue, SecretError> {
            let session = pkcs11_ro_session(&ctx, slot, &user_pin)?;
            let handle = Pkcs11Backend::find_object(&session, &label, ObjectClass::DATA)?;

            let attrs = session
                .get_attributes(handle, &[AttributeType::Value])
                .map_err(|e| SecretError::Backend {
                    backend: "pkcs11",
                    source: e.into(),
                })?;

            for attr in attrs {
                if let Attribute::Value(bytes) = attr {
                    return Ok(SecretValue::new(bytes));
                }
            }

            Err(SecretError::Backend {
                backend: "pkcs11",
                source: "CKA_VALUE attribute missing on data object".into(),
            })
        })
        .await
        .map_err(|e| SecretError::Backend {
            backend: "pkcs11",
            source: format!("task join error: {e}").into(),
        })?
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
    /// All PKCS#11 calls are dispatched via `tokio::task::spawn_blocking` to
    /// avoid blocking the async executor.
    async fn put(&self, value: SecretValue) -> Result<(), SecretError> {
        let ctx = Arc::clone(&self.ctx);
        let slot = self.slot;
        let label = self.label.clone();
        let user_pin = self.user_pin.clone();
        // Copy secret bytes into an owned Vec for the closure.  The Vec is
        // zeroized inside the closure after create_object commits the value.
        let secret_bytes = value.as_bytes().to_vec();

        tokio::task::spawn_blocking(move || -> Result<(), SecretError> {
            let session = pkcs11_rw_session(&ctx, slot, &user_pin)?;

            // Collect handles of existing objects BEFORE creating the new one.
            // A creation failure will then leave the existing secret intact.
            let template_search = vec![
                Attribute::Class(ObjectClass::DATA),
                Attribute::Label(label.as_bytes().to_vec()),
            ];
            let existing =
                session
                    .find_objects(&template_search)
                    .map_err(|e| SecretError::Backend {
                        backend: "pkcs11",
                        source: e.into(),
                    })?;

            // Create the new object first.  Any failure here leaves `existing` intact.
            let mut template_create = vec![
                Attribute::Class(ObjectClass::DATA),
                Attribute::Token(true),
                Attribute::Label(label.as_bytes().to_vec()),
                Attribute::Value(secret_bytes),
            ];
            session
                .create_object(&template_create)
                .map_err(|e| SecretError::Backend {
                    backend: "pkcs11",
                    source: e.into(),
                })?;

            // Zero the plaintext copy in the template now that create_object has
            // committed the value to the HSM.  cryptoki takes &[Attribute] (not
            // ownership), so the Vec<u8> is still accessible here.
            for attr in &mut template_create {
                if let Attribute::Value(ref mut bytes) = attr {
                    bytes.zeroize();
                }
            }

            // Best-effort cleanup: destroy old objects now that the new one is committed.
            // If destroy_object fails the write has still succeeded — the new value is
            // live in the HSM and get() will return it.  A duplicate object will remain
            // until the next successful put() collects it.  Do NOT return Err here:
            // doing so falsely signals that the write failed, and a caller retry would
            // create yet another duplicate.
            for handle in existing {
                let _ = session.destroy_object(handle);
            }

            Ok(())
        })
        .await
        .map_err(|e| SecretError::Backend {
            backend: "pkcs11",
            source: format!("task join error: {e}").into(),
        })?
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
    /// avoid blocking the async executor.  Algorithm detection (cold OnceLock)
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
        let message = message.to_vec();

        tokio::task::spawn_blocking(move || -> Result<Vec<u8>, SecretError> {
            // Resolve algorithm — detect from HSM on first call, read from cache thereafter.
            let algo = if let Some(algo) = algo_if_known {
                algo
            } else {
                let detected = pkcs11_detect_algorithm(&ctx, slot, &label, &user_pin)?;
                // Best-effort cache: if another thread raced us, discard our result.
                let _ = algo_cache.set(detected);
                detected
            };

            let session = pkcs11_ro_session(&ctx, slot, &user_pin)?;
            let handle = Pkcs11Backend::find_object(&session, &label, ObjectClass::PRIVATE_KEY)?;

            match algo {
                SigningAlgorithm::EcdsaP256Sha256 => session
                    .sign(&Mechanism::EcdsaSha256, handle, &message)
                    .map_err(|e| SecretError::Backend {
                        backend: "pkcs11",
                        source: e.into(),
                    }),
                SigningAlgorithm::RsaPss2048Sha256 => {
                    let pss = PkcsPssParams {
                        hash_alg: MechanismType::SHA256,
                        mgf: PkcsMgfType::MGF1_SHA256,
                        s_len: 32u64.into(),
                    };
                    session
                        .sign(&Mechanism::Sha256RsaPkcsPss(pss), handle, &message)
                        .map_err(|e| SecretError::Backend {
                            backend: "pkcs11",
                            source: e.into(),
                        })
                }
                _ => Err(SecretError::Backend {
                    backend: "pkcs11",
                    source: format!("unsupported signing algorithm: {algo:?}").into(),
                }),
            }
        })
        .await
        .map_err(|e| SecretError::Backend {
            backend: "pkcs11",
            source: format!("task join error: {e}").into(),
        })?
    }

    /// Return the DER-encoded SubjectPublicKeyInfo of the matching public key.
    ///
    /// Reads `CKA_PUBLIC_KEY_INFO` from the `CKO_PUBLIC_KEY` object (PKCS#11
    /// v2.40+ tokens store the SPKI directly in this attribute).
    ///
    /// All PKCS#11 calls are dispatched via `tokio::task::spawn_blocking` to
    /// avoid blocking the async executor.
    async fn public_key_der(&self) -> Result<Vec<u8>, SecretError> {
        let ctx = Arc::clone(&self.ctx);
        let slot = self.slot;
        let label = self.label.clone();
        let user_pin = self.user_pin.clone();

        tokio::task::spawn_blocking(move || -> Result<Vec<u8>, SecretError> {
            let session = pkcs11_ro_session(&ctx, slot, &user_pin)?;
            let handle = Pkcs11Backend::find_object(&session, &label, ObjectClass::PUBLIC_KEY)?;

            let attrs = session
                .get_attributes(handle, &[AttributeType::PublicKeyInfo])
                .map_err(|e| SecretError::Backend {
                    backend: "pkcs11",
                    source: e.into(),
                })?;

            for attr in attrs {
                if let Attribute::PublicKeyInfo(der) = attr {
                    return Ok(der);
                }
            }

            Err(SecretError::Backend {
                backend: "pkcs11",
                source: "CKA_PUBLIC_KEY_INFO attribute missing on public key object".into(),
            })
        })
        .await
        .map_err(|e| SecretError::Backend {
            backend: "pkcs11",
            source: format!("task join error: {e}").into(),
        })?
    }

    /// Returns the algorithm based on `CKA_KEY_TYPE` of the private key object.
    ///
    /// Returns `Err` if the HSM is unreachable or no private key object with
    /// this label exists.  The result is cached after the first successful call
    /// so subsequent invocations do not open an HSM session.
    ///
    /// Note: this is a synchronous method (required by the `SigningBackend` trait).
    /// On the first call (cold cache) it opens an HSM session, which blocks the
    /// current thread.  When called from async code, prefer calling `sign()` or
    /// `public_key_der()` directly — those methods dispatch all HSM I/O via
    /// `spawn_blocking` and populate the cache as a side effect.
    fn algorithm(&self) -> Result<SigningAlgorithm, SecretError> {
        // Return the cached value if a previous call succeeded.
        if let Some(&algo) = self.algorithm_cache.get() {
            return Ok(algo);
        }
        let algo = self.detect_algorithm()?;
        // Best-effort cache: if another thread raced us, discard our result.
        let _ = self.algorithm_cache.set(algo);
        Ok(algo)
    }
}

inventory::submit!(secretx_core::BackendRegistration {
    name: "pkcs11",
    factory: |uri: &str| {
        Pkcs11Backend::from_uri(uri)
            .map(|b| std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::SecretStore>)
    },
});

inventory::submit!(secretx_core::SigningBackendRegistration {
    name: "pkcs11",
    factory: |uri: &str| {
        Pkcs11Backend::from_uri(uri)
            .map(|b| std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::SigningBackend>)
    },
});

inventory::submit!(secretx_core::WritableBackendRegistration {
    name: "pkcs11",
    factory: |uri: &str| {
        Pkcs11Backend::from_uri(uri).map(|b| {
            std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::WritableSecretStore>
        })
    },
});

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── URI parsing (no HSM required) ─────────────────────────────────────────

    #[test]
    fn uri_parse_with_lib_param() {
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
            return;
        }
        let lib = match std::env::var("PKCS11_LIB") {
            Ok(v) => v,
            Err(_) => {
                eprintln!("PKCS11_LIB not set; skipping integration test");
                return;
            }
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
            return;
        }
        let lib = match std::env::var("PKCS11_LIB") {
            Ok(v) => v,
            Err(_) => return,
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

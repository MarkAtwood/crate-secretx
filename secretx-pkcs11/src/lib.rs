//! PKCS#11 HSM backend for secretx.
//!
//! URI: `secretx://pkcs11/<slot>/<label>[?lib=<pkcs11-lib-path>]`
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
//!     "secretx://pkcs11/0/my-data?lib=/usr/lib/softhsm/libsofthsm2.so",
//! )?;
//! let value = store.get("").await?;
//! # Ok(())
//! # }
//! ```

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use secretx_core::{SecretError, SecretStore, SecretUri, SecretValue, SigningAlgorithm, SigningBackend};
use std::sync::Arc;
use zeroize::Zeroizing;

/// PKCS#11 backend that implements both [`SecretStore`] and [`SigningBackend`].
///
/// Secrets are stored as `CKO_DATA` objects; signing keys are `CKO_PRIVATE_KEY`
/// objects.  Both are matched by `CKA_LABEL`.
pub struct Pkcs11Backend {
    ctx: Arc<Pkcs11>,
    slot: cryptoki::slot::Slot,
    label: String,
    user_pin: Option<Zeroizing<String>>,
}

impl Pkcs11Backend {
    /// Construct from a `secretx://pkcs11/<slot>/<label>[?lib=<path>]` URI.
    ///
    /// This call loads the PKCS#11 library and initialises it.  No session is
    /// opened until a trait method is called.
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        let parsed = SecretUri::parse(uri)?;
        if parsed.backend != "pkcs11" {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `pkcs11`, got `{}`",
                parsed.backend
            )));
        }

        // path is "<slot>/<label>"
        let (slot_str, label) = split_path(&parsed.path)?;

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

        let slots = ctx.get_slots_with_token().map_err(|e| SecretError::Backend {
            backend: "pkcs11",
            source: e.into(),
        })?;
        let slot = slots.get(slot_idx).copied().ok_or_else(|| {
            SecretError::Backend {
                backend: "pkcs11",
                source: format!("slot index {slot_idx} not found (only {} slot(s) with a token)", slots.len()).into(),
            }
        })?;

        let user_pin = std::env::var("PKCS11_PIN").ok().map(Zeroizing::new);

        Ok(Self {
            ctx: Arc::new(ctx),
            slot,
            label,
            user_pin,
        })
    }

    /// Open a read-only session, logging in if a PIN is configured.
    fn ro_session(&self) -> Result<cryptoki::session::Session, SecretError> {
        let session = self.ctx.open_ro_session(self.slot).map_err(|e| {
            SecretError::Backend {
                backend: "pkcs11",
                source: e.into(),
            }
        })?;
        if let Some(pin) = &self.user_pin {
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

    /// Open a read-write session, logging in if a PIN is configured.
    fn rw_session(&self) -> Result<cryptoki::session::Session, SecretError> {
        let session = self.ctx.open_rw_session(self.slot).map_err(|e| {
            SecretError::Backend {
                backend: "pkcs11",
                source: e.into(),
            }
        })?;
        if let Some(pin) = &self.user_pin {
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

    /// Find the first object matching `class` and `CKA_LABEL == self.label`.
    fn find_object(
        session: &cryptoki::session::Session,
        label: &str,
        class: ObjectClass,
    ) -> Result<cryptoki::object::ObjectHandle, SecretError> {
        let template = vec![
            Attribute::Class(class),
            Attribute::Label(label.as_bytes().to_vec()),
        ];
        let handles = session.find_objects(&template).map_err(|e| {
            SecretError::Backend {
                backend: "pkcs11",
                source: e.into(),
            }
        })?;
        handles.into_iter().next().ok_or(SecretError::NotFound)
    }

    /// Determine the key algorithm stored under `self.label`.
    ///
    /// Inspects the `CKA_KEY_TYPE` attribute of the `CKO_PRIVATE_KEY` object.
    fn detect_algorithm(&self) -> Result<SigningAlgorithm, SecretError> {
        let session = self.ro_session()?;
        let handle = Self::find_object(&session, &self.label, ObjectClass::PRIVATE_KEY)?;

        let attrs = session
            .get_attributes(handle, &[AttributeType::KeyType])
            .map_err(|e| SecretError::Backend {
                backend: "pkcs11",
                source: e.into(),
            })?;

        for attr in attrs {
            if let Attribute::KeyType(kt) = attr {
                if kt == KeyType::EC {
                    return Ok(SigningAlgorithm::EcdsaP256Sha256);
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
    /// The `name` parameter is ignored — the label is fixed at construction time.
    async fn get(&self, _name: &str) -> Result<SecretValue, SecretError> {
        let session = self.ro_session()?;
        let handle = Self::find_object(&session, &self.label, ObjectClass::DATA)?;

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
    }

    /// Create or replace a `CKO_DATA` object with `CKA_LABEL == label`.
    async fn put(&self, _name: &str, value: SecretValue) -> Result<(), SecretError> {
        let session = self.rw_session()?;

        // Destroy any existing object with this label so we can re-create it.
        let template_search = vec![
            Attribute::Class(ObjectClass::DATA),
            Attribute::Label(self.label.as_bytes().to_vec()),
        ];
        let existing = session.find_objects(&template_search).map_err(|e| {
            SecretError::Backend {
                backend: "pkcs11",
                source: e.into(),
            }
        })?;
        for handle in existing {
            session.destroy_object(handle).map_err(|e| SecretError::Backend {
                backend: "pkcs11",
                source: e.into(),
            })?;
        }

        let data = value.as_bytes().to_vec();
        let template_create = vec![
            Attribute::Class(ObjectClass::DATA),
            Attribute::Token(true),
            Attribute::Label(self.label.as_bytes().to_vec()),
            Attribute::Value(data),
        ];
        session.create_object(&template_create).map_err(|e| SecretError::Backend {
            backend: "pkcs11",
            source: e.into(),
        })?;

        Ok(())
    }

    /// Re-fetch the secret from the HSM (no caching layer here).
    async fn refresh(&self, name: &str) -> Result<SecretValue, SecretError> {
        self.get(name).await
    }
}

#[async_trait::async_trait]
impl SigningBackend for Pkcs11Backend {
    /// Sign `message` with the `CKO_PRIVATE_KEY` object matching `self.label`.
    ///
    /// The mechanism is chosen based on the key type:
    /// - EC keys  → `CKM_ECDSA_SHA256`
    /// - RSA keys → `CKM_SHA256_RSA_PKCS_PSS` with SHA-256 / MGF1-SHA-256 / salt=32
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SecretError> {
        let session = self.ro_session()?;
        let handle = Self::find_object(&session, &self.label, ObjectClass::PRIVATE_KEY)?;

        let attrs = session
            .get_attributes(handle, &[AttributeType::KeyType])
            .map_err(|e| SecretError::Backend {
                backend: "pkcs11",
                source: e.into(),
            })?;

        let key_type = attrs
            .into_iter()
            .find_map(|a| if let Attribute::KeyType(kt) = a { Some(kt) } else { None })
            .ok_or_else(|| SecretError::Backend {
                backend: "pkcs11",
                source: "could not determine CKA_KEY_TYPE for signing key".into(),
            })?;

        let sig = if key_type == KeyType::EC {
            session
                .sign(&Mechanism::EcdsaSha256, handle, message)
                .map_err(|e| SecretError::Backend {
                    backend: "pkcs11",
                    source: e.into(),
                })?
        } else if key_type == KeyType::RSA {
            let pss = PkcsPssParams {
                hash_alg: MechanismType::SHA256,
                mgf: PkcsMgfType::MGF1_SHA256,
                s_len: 32u64.into(),
            };
            session
                .sign(&Mechanism::Sha256RsaPkcsPss(pss), handle, message)
                .map_err(|e| SecretError::Backend {
                    backend: "pkcs11",
                    source: e.into(),
                })?
        } else {
            return Err(SecretError::Backend {
                backend: "pkcs11",
                source: format!("unsupported key type for signing: {key_type}").into(),
            });
        };

        Ok(sig)
    }

    /// Return the DER-encoded SubjectPublicKeyInfo of the matching public key.
    ///
    /// Reads `CKA_PUBLIC_KEY_INFO` from the `CKO_PUBLIC_KEY` object (PKCS#11
    /// v2.40+ tokens store the SPKI directly in this attribute).
    async fn public_key_der(&self) -> Result<Vec<u8>, SecretError> {
        let session = self.ro_session()?;
        let handle = Self::find_object(&session, &self.label, ObjectClass::PUBLIC_KEY)?;

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
    }

    /// Returns the algorithm based on `CKA_KEY_TYPE` of the private key object.
    fn algorithm(&self) -> SigningAlgorithm {
        self.detect_algorithm()
            .unwrap_or(SigningAlgorithm::EcdsaP256Sha256)
    }
}

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
        let u = SecretUri::parse(
            "secretx://pkcs11/0/my-key?lib=/usr/lib/softhsm/libsofthsm2.so",
        )
        .unwrap();
        assert_eq!(u.backend, "pkcs11");
        assert_eq!(u.path, "0/my-key");
        assert_eq!(u.param("lib"), Some("/usr/lib/softhsm/libsofthsm2.so"));
    }

    #[test]
    fn uri_parse_slot_and_label() {
        let u = SecretUri::parse("secretx://pkcs11/2/signing-key?lib=/tmp/lib.so").unwrap();
        assert_eq!(u.path, "2/signing-key");
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
        assert!(matches!(
            split_path("0/"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_wrong_backend() {
        assert!(matches!(
            Pkcs11Backend::from_uri("secretx://env/FOO"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_missing_lib_no_env() {
        // Ensure neither source of the library path is present.
        std::env::remove_var("PKCS11_LIB");
        let result = Pkcs11Backend::from_uri("secretx://pkcs11/0/my-key");
        assert!(
            matches!(result, Err(SecretError::InvalidUri(_))),
            "expected InvalidUri"
        );
    }

    #[test]
    fn from_uri_non_numeric_slot() {
        std::env::remove_var("PKCS11_LIB");
        let result = Pkcs11Backend::from_uri("secretx://pkcs11/abc/label?lib=/tmp/x.so");
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
        let label = std::env::var("PKCS11_TEST_DATA_LABEL")
            .unwrap_or_else(|_| "test-data".to_string());
        let uri = format!("secretx://pkcs11/0/{label}?lib={lib}");
        let backend = Pkcs11Backend::from_uri(&uri).expect("from_uri should succeed");
        let value = backend.get("").await.expect("get should succeed");
        assert!(!value.as_bytes().is_empty(), "retrieved value should be non-empty");
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
        let label = std::env::var("PKCS11_TEST_KEY_LABEL")
            .unwrap_or_else(|_| "test-key".to_string());
        let uri = format!("secretx://pkcs11/0/{label}?lib={lib}");
        let backend = Pkcs11Backend::from_uri(&uri).expect("from_uri should succeed");
        let sig = backend.sign(b"hello world").await.expect("sign should succeed");
        assert!(!sig.is_empty(), "signature should be non-empty");
    }
}

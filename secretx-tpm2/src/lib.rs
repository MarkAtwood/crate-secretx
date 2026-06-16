//! TPM 2.0 backend for secretx.
//!
//! Supports two modes of operation:
//!
//! - **NV index** — read/write secrets in TPM non-volatile storage.
//!   URI: `secretx:tpm2:nv/<index>` (e.g. `secretx:tpm2:nv/0x01000001`)
//!
//! - **Signing key** — sign with a persistent TPM-resident key.
//!   URI: `secretx:tpm2:key/<handle>[?algorithm=ecdsa-p256|rsa-pss-2048]`
//!   (e.g. `secretx:tpm2:key/0x81000001?algorithm=ecdsa-p256`)
//!
//! # TCTI configuration
//!
//! The TPM transport is configured via the `?tcti=` query parameter.
//! Common values:
//!
//! - `device:/dev/tpmrm0` — kernel resource manager (default on Linux)
//! - `device:/dev/tpm0` — raw device (requires exclusive access)
//! - `swtpm:host=127.0.0.1,port=2321` — software TPM simulator
//! - `tabrmd` — TPM2 access broker daemon
//!
//! If no TCTI is specified, the crate defaults to `device:/dev/tpmrm0`.
//!
//! # Authorization
//!
//! All operations use a null-auth HMAC session (`execute_with_nullauth_session`).
//! NV indices and keys must be provisioned with empty owner-hierarchy
//! authorization. Password-protected or policy-bound objects are not yet
//! supported.
//!
//! # Examples
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), secretx_core::SecretError> {
//! use secretx_tpm2::Tpm2Backend;
//! use secretx_core::SecretStore;
//!
//! // Read a secret from NV index 0x01000001
//! let store = Tpm2Backend::from_uri("secretx:tpm2:nv/0x01000001")?;
//! let value = store.get().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # System requirements
//!
//! Requires `libtss2-esys` installed on the system.
//! On Debian/Ubuntu: `apt install libtss2-dev`.
//! On Fedora: `dnf install tpm2-tss-devel`.

use std::str::FromStr;
use std::sync::Arc;

use secretx_core::{
    SecretError, SecretStore, SecretUri, SecretValue, SigningAlgorithm, SigningBackend,
    WritableSecretStore,
};
use sha2::{Digest as _, Sha256};
use tss_esapi::{
    Context, TctiNameConf,
    handles::{KeyHandle, NvIndexHandle, TpmHandle},
    interface_types::resource_handles::NvAuth,
    structures::{MaxNvBuffer, SignatureScheme},
};
use zeroize::Zeroizing;

const BACKEND: &str = "tpm2";
const DEFAULT_TCTI: &str = "device:/dev/tpmrm0";

/// TPM 2.0 operation mode.
#[derive(Debug, Clone)]
enum Mode {
    /// Read/write NV index.
    Nv { index: u32 },
    /// Sign with persistent key.
    Sign { handle: u32, algorithm: SigningAlgorithm },
}

/// TPM 2.0 backend for secretx.
///
/// Each operation opens a fresh ESAPI context because `Context` is `!Send`
/// and cannot be shared across `spawn_blocking` boundaries. TPM context
/// creation is cheap (a few syscalls).
///
/// # Authorization
///
/// All operations use a null-auth HMAC session. NV indices and keys must
/// be provisioned with empty owner-hierarchy authorization.
pub struct Tpm2Backend {
    mode: Mode,
    tcti: String,
}

impl std::fmt::Debug for Tpm2Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tpm2Backend")
            .field("mode", &self.mode)
            .field("tcti", &self.tcti)
            .finish_non_exhaustive()
    }
}

impl Tpm2Backend {
    /// Construct from a `secretx:tpm2:...` URI string.
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        Self::from_parsed_uri(&SecretUri::parse(uri)?)
    }

    /// Construct from a pre-parsed [`SecretUri`].
    pub fn from_parsed_uri(parsed: &SecretUri) -> Result<Self, SecretError> {
        if parsed.backend() != "tpm2" {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `tpm2`, got `{}`",
                parsed.backend()
            )));
        }

        let path = parsed.path();
        if path.is_empty() {
            return Err(SecretError::InvalidUri(
                "tpm2 URI requires a path: secretx:tpm2:nv/<index> or secretx:tpm2:key/<handle>"
                    .into(),
            ));
        }

        let tcti = parsed
            .param("tcti")
            .unwrap_or(DEFAULT_TCTI)
            .to_owned();

        let mode = if let Some(hex) = path.strip_prefix("nv/") {
            let index = parse_hex_u32(hex, "NV index")?;
            validate_nv_index(index)?;
            Mode::Nv { index }
        } else if let Some(rest) = path.strip_prefix("key/") {
            let handle = parse_hex_u32(rest, "key handle")?;
            validate_persistent_handle(handle)?;
            let algorithm = match parsed.param("algorithm") {
                Some("ecdsa-p256") | None => SigningAlgorithm::EcdsaP256Sha256,
                Some("rsa-pss-2048") => SigningAlgorithm::RsaPss2048Sha256,
                Some(other) => {
                    return Err(SecretError::InvalidUri(format!(
                        "unknown algorithm `{other}`; expected `ecdsa-p256` or `rsa-pss-2048`"
                    )));
                }
            };
            Mode::Sign { handle, algorithm }
        } else {
            return Err(SecretError::InvalidUri(format!(
                "tpm2 URI path must start with `nv/` or `key/`, got `{path}`"
            )));
        };

        Ok(Self { mode, tcti })
    }

    /// Returns `true` if this backend is in NV index mode.
    fn is_nv(&self) -> bool {
        matches!(self.mode, Mode::Nv { .. })
    }

    /// Returns `true` if this backend is in signing key mode.
    fn is_sign(&self) -> bool {
        matches!(self.mode, Mode::Sign { .. })
    }
}

fn parse_hex_u32(s: &str, label: &str) -> Result<u32, SecretError> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u32::from_str_radix(s, 16).map_err(|_| {
        SecretError::InvalidUri(format!("invalid {label}: expected hex like 0x01000001"))
    })
}

fn validate_nv_index(index: u32) -> Result<(), SecretError> {
    if !(0x0100_0000..=0x01FF_FFFF).contains(&index) {
        return Err(SecretError::InvalidUri(format!(
            "NV index 0x{index:08X} out of range (must be 0x01000000..0x01FFFFFF)"
        )));
    }
    Ok(())
}

fn validate_persistent_handle(handle: u32) -> Result<(), SecretError> {
    if !(0x8100_0000..=0x81FF_FFFF).contains(&handle) {
        return Err(SecretError::InvalidUri(format!(
            "persistent handle 0x{handle:08X} out of range (must be 0x81000000..0x81FFFFFF)"
        )));
    }
    Ok(())
}

fn open_context(tcti: &str) -> Result<Context, SecretError> {
    let tcti_conf = TctiNameConf::from_str(tcti).map_err(|e| SecretError::Backend {
        backend: BACKEND,
        source: format!("invalid TCTI config `{tcti}`: {e}").into(),
    })?;
    Context::new(tcti_conf).map_err(|e| SecretError::Unavailable {
        backend: BACKEND,
        source: format!("failed to connect to TPM: {e}").into(),
    })
}

/// Classify a TSS error as transient (Unavailable) or permanent (Backend).
fn map_tpm_error(e: tss_esapi::Error) -> SecretError {
    let msg = e.to_string();
    let lower = msg.to_ascii_lowercase();
    // Resource manager busy, retry, or connection errors are transient.
    if lower.contains("retry")
        || lower.contains("yielded")
        || lower.contains("resource")
        || lower.contains("tcti")
        || lower.contains("i/o error")
    {
        return SecretError::Unavailable {
            backend: BACKEND,
            source: msg.into(),
        };
    }
    SecretError::Backend {
        backend: BACKEND,
        source: msg.into(),
    }
}

// ── SecretStore (NV read) ────────────────────────────────────────────────────

#[async_trait::async_trait]
impl SecretStore for Tpm2Backend {
    async fn get(&self) -> Result<SecretValue, SecretError> {
        let Mode::Nv { index } = self.mode else {
            return Err(SecretError::Backend {
                backend: BACKEND,
                source: "get() is only supported on NV index URIs (secretx:tpm2:nv/...)".into(),
            });
        };

        let tcti = self.tcti.clone();

        tokio::task::spawn_blocking(move || {
            let mut context = open_context(&tcti)?;

            let nv_idx = tss_esapi::handles::NvIndexTpmHandle::new(index)
                .map_err(map_tpm_error)?;
            let nv_handle = context
                .tr_from_tpm_public(TpmHandle::NvIndex(nv_idx))
                .map_err(map_tpm_error)?;
            let nv_index_handle = NvIndexHandle::from(nv_handle);

            let (nv_public, _name) = context.nv_read_public(nv_index_handle)
                .map_err(map_tpm_error)?;
            // NV data size is defined as UINT16 in the TPM 2.0 spec (Part 2,
            // TPMS_NV_PUBLIC.dataSize), so the cast is within range.
            let data_size = u16::try_from(nv_public.data_size()).map_err(|_| {
                SecretError::Backend {
                    backend: BACKEND,
                    source: format!(
                        "NV data size {} exceeds u16::MAX",
                        nv_public.data_size()
                    ).into(),
                }
            })?;

            let data: MaxNvBuffer = context
                .execute_with_nullauth_session(|ctx| {
                    ctx.nv_read(NvAuth::Owner, nv_index_handle, data_size, 0)
                })
                .map_err(map_tpm_error)?;

            Ok(SecretValue::new(data.value().to_vec()))
        })
        .await
        .map_err(|e| SecretError::Backend {
            backend: BACKEND,
            source: format!("TPM task panicked: {e}").into(),
        })?
    }

    async fn refresh(&self) -> Result<SecretValue, SecretError> {
        self.get().await
    }
}

// ── WritableSecretStore (NV write) ───────────────────────────────────────────

#[async_trait::async_trait]
impl WritableSecretStore for Tpm2Backend {
    async fn put(&self, value: SecretValue) -> Result<(), SecretError> {
        let Mode::Nv { index } = self.mode else {
            return Err(SecretError::Backend {
                backend: BACKEND,
                source: "put() is only supported on NV index URIs (secretx:tpm2:nv/...)".into(),
            });
        };

        let tcti = self.tcti.clone();
        let bytes = value.into_bytes();

        tokio::task::spawn_blocking(move || {
            let mut context = open_context(&tcti)?;

            let nv_idx = tss_esapi::handles::NvIndexTpmHandle::new(index)
                .map_err(map_tpm_error)?;
            let nv_handle = context
                .tr_from_tpm_public(TpmHandle::NvIndex(nv_idx))
                .map_err(map_tpm_error)?;
            let nv_index_handle = NvIndexHandle::from(nv_handle);

            // Wrap in Zeroizing so the copy is zeroed on drop.
            let owned = Zeroizing::new(bytes.to_vec());
            let data = MaxNvBuffer::try_from(owned.as_slice().to_vec()).map_err(|e| {
                SecretError::Backend {
                    backend: BACKEND,
                    source: format!("data too large for NV index: {e}").into(),
                }
            })?;

            context
                .execute_with_nullauth_session(|ctx| {
                    ctx.nv_write(NvAuth::Owner, nv_index_handle, data, 0)
                })
                .map_err(map_tpm_error)?;

            Ok(())
        })
        .await
        .map_err(|e| SecretError::Backend {
            backend: BACKEND,
            source: format!("TPM task panicked: {e}").into(),
        })?
    }
}

// ── SigningBackend ────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl SigningBackend for Tpm2Backend {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SecretError> {
        let Mode::Sign { handle, algorithm } = self.mode else {
            return Err(SecretError::Backend {
                backend: BACKEND,
                source: "sign() is only supported on key URIs (secretx:tpm2:key/...)".into(),
            });
        };

        let tcti = self.tcti.clone();
        // Hash in software so there is no message-size limit from MaxBuffer.
        let hash = Sha256::digest(message);
        let digest_bytes = hash.to_vec();

        tokio::task::spawn_blocking(move || {
            let mut context = open_context(&tcti)?;

            let persistent = tss_esapi::handles::PersistentTpmHandle::new(handle)
                .map_err(map_tpm_error)?;
            let obj_handle = context
                .tr_from_tpm_public(TpmHandle::Persistent(persistent))
                .map_err(map_tpm_error)?;
            let key_handle = KeyHandle::from(obj_handle);

            let digest = tss_esapi::structures::Digest::try_from(digest_bytes)
                .map_err(|e| SecretError::Backend {
                    backend: BACKEND,
                    source: format!("failed to create digest: {e}").into(),
                })?;

            // For unrestricted keys, pass a null-hierarchy hashcheck ticket.
            // The TPM accepts Null hierarchy for externally-computed digests
            // on unrestricted signing keys.
            let validation = tss_esapi::structures::HashcheckTicket::try_from(
                tss_esapi::tss2_esys::TPMT_TK_HASHCHECK {
                    tag: tss_esapi::constants::tss::TPM2_ST_HASHCHECK,
                    hierarchy: tss_esapi::constants::tss::TPM2_RH_NULL,
                    digest: tss_esapi::tss2_esys::TPM2B_DIGEST {
                        size: 0,
                        buffer: [0u8; 64],
                    },
                },
            )
            .map_err(map_tpm_error)?;

            let signature = context
                .execute_with_nullauth_session(|ctx| {
                    ctx.sign(key_handle, digest, SignatureScheme::Null, validation)
                })
                .map_err(map_tpm_error)?;

            normalize_signature(algorithm, &signature)
        })
        .await
        .map_err(|e| SecretError::Backend {
            backend: BACKEND,
            source: format!("TPM task panicked: {e}").into(),
        })?
    }

    async fn public_key_der(&self) -> Result<Vec<u8>, SecretError> {
        let Mode::Sign { handle, .. } = self.mode else {
            return Err(SecretError::Backend {
                backend: BACKEND,
                source: "public_key_der() is only supported on key URIs (secretx:tpm2:key/...)"
                    .into(),
            });
        };

        let tcti = self.tcti.clone();

        tokio::task::spawn_blocking(move || {
            let mut context = open_context(&tcti)?;

            let persistent = tss_esapi::handles::PersistentTpmHandle::new(handle)
                .map_err(map_tpm_error)?;
            let obj_handle = context
                .tr_from_tpm_public(TpmHandle::Persistent(persistent))
                .map_err(map_tpm_error)?;
            let key_handle = KeyHandle::from(obj_handle);

            let (public, _name, _qname) = context
                .read_public(key_handle)
                .map_err(map_tpm_error)?;

            // Convert TPM Public to SubjectPublicKeyInfo (SPKI) via the
            // tss-esapi abstraction, then serialize to DER.
            let spki = picky_asn1_x509::SubjectPublicKeyInfo::try_from(public)
                .map_err(|e| SecretError::Backend {
                    backend: BACKEND,
                    source: format!("failed to extract SPKI from TPM public key: {e}").into(),
                })?;
            picky_asn1_der::to_vec(&spki).map_err(|e| SecretError::Backend {
                backend: BACKEND,
                source: format!("failed to DER-encode SPKI: {e}").into(),
            })
        })
        .await
        .map_err(|e| SecretError::Backend {
            backend: BACKEND,
            source: format!("TPM task panicked: {e}").into(),
        })?
    }

    /// Returns the signing algorithm for this key.
    ///
    /// This is a permanent property of the URI — it does not require TPM
    /// access. Returns `SecretError::Backend` if called on an NV-mode URI.
    fn algorithm(&self) -> Result<SigningAlgorithm, SecretError> {
        match self.mode {
            Mode::Sign { algorithm, .. } => Ok(algorithm),
            Mode::Nv { .. } => Err(SecretError::Backend {
                backend: BACKEND,
                source: "algorithm() is only supported on key URIs (secretx:tpm2:key/...)".into(),
            }),
        }
    }
}

/// Normalize TPM signature output to secretx's canonical byte formats.
///
/// - ECDSA P-256: 64 bytes (r || s), 32 bytes each, big-endian, zero-padded
/// - RSA-PSS 2048: 256 bytes, big-endian
fn normalize_signature(
    algorithm: SigningAlgorithm,
    sig: &tss_esapi::structures::Signature,
) -> Result<Vec<u8>, SecretError> {
    use tss_esapi::structures::Signature as TpmSig;

    match (algorithm, sig) {
        (SigningAlgorithm::EcdsaP256Sha256, TpmSig::EcDsa(ecc)) => {
            let r = ecc.signature_r().value();
            let s = ecc.signature_s().value();
            let mut out = vec![0u8; 64];
            // Right-align (zero-pad) each component to 32 bytes
            let r_offset = 32usize.saturating_sub(r.len());
            let s_offset = 32usize.saturating_sub(s.len());
            out[r_offset..32].copy_from_slice(&r[r.len().saturating_sub(32)..]);
            out[32 + s_offset..64].copy_from_slice(&s[s.len().saturating_sub(32)..]);
            Ok(out)
        }
        (SigningAlgorithm::RsaPss2048Sha256, TpmSig::RsaPss(rsa)) => {
            Ok(rsa.signature().value().to_vec())
        }
        _ => Err(SecretError::AlgorithmMismatch {
            expected: algorithm_label(algorithm),
            actual: format!("{:?}", sig.algorithm()),
        }),
    }
}

fn algorithm_label(algo: SigningAlgorithm) -> &'static str {
    match algo {
        SigningAlgorithm::EcdsaP256Sha256 => "ecdsa-p256",
        SigningAlgorithm::RsaPss2048Sha256 => "rsa-pss-2048",
        SigningAlgorithm::Ed25519 => "ed25519",
        // SigningAlgorithm is #[non_exhaustive]; future variants get a
        // descriptive fallback rather than a bare "unknown".
        _ => "unsupported-algorithm",
    }
}

// ── Inventory registration (URI dispatch) ────────────────────────────────────
//
// NV-mode URIs register as SecretStore + WritableSecretStore.
// Key-mode URIs register as SigningBackend.
// Each factory rejects URIs for the wrong mode at construction time.

inventory::submit!(secretx_core::BackendRegistration::new(
    "tpm2",
    |uri: &secretx_core::SecretUri| {
        let b = Tpm2Backend::from_parsed_uri(uri)?;
        if !b.is_nv() {
            return Err(SecretError::InvalidUri(
                "tpm2 key URIs are signing-only; use from_signing_uri for secretx:tpm2:key/..."
                    .into(),
            ));
        }
        Ok(Arc::new(b) as Arc<dyn secretx_core::SecretStore>)
    },
));

inventory::submit!(secretx_core::WritableBackendRegistration::new(
    "tpm2",
    |uri: &secretx_core::SecretUri| {
        let b = Tpm2Backend::from_parsed_uri(uri)?;
        if !b.is_nv() {
            return Err(SecretError::InvalidUri(
                "tpm2 key URIs are signing-only; use from_signing_uri for secretx:tpm2:key/..."
                    .into(),
            ));
        }
        Ok(Arc::new(b) as Arc<dyn secretx_core::WritableSecretStore>)
    },
));

inventory::submit!(secretx_core::SigningBackendRegistration::new(
    "tpm2",
    |uri: &secretx_core::SecretUri| {
        let b = Tpm2Backend::from_parsed_uri(uri)?;
        if !b.is_sign() {
            return Err(SecretError::InvalidUri(
                "tpm2 NV URIs do not support signing; use from_uri for secretx:tpm2:nv/..."
                    .into(),
            ));
        }
        Ok(Arc::new(b) as Arc<dyn secretx_core::SigningBackend>)
    },
));

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_uri_nv_ok() {
        let b = Tpm2Backend::from_uri("secretx:tpm2:nv/0x01000001").unwrap();
        assert!(matches!(b.mode, Mode::Nv { index: 0x0100_0001 }));
        assert_eq!(b.tcti, DEFAULT_TCTI);
    }

    #[test]
    fn from_uri_key_ok() {
        let b = Tpm2Backend::from_uri("secretx:tpm2:key/0x81000001").unwrap();
        assert!(matches!(
            b.mode,
            Mode::Sign { handle: 0x8100_0001, algorithm: SigningAlgorithm::EcdsaP256Sha256 }
        ));
    }

    #[test]
    fn from_uri_key_rsa_pss() {
        let b = Tpm2Backend::from_uri("secretx:tpm2:key/0x81000002?algorithm=rsa-pss-2048")
            .unwrap();
        assert!(matches!(
            b.mode,
            Mode::Sign { handle: 0x8100_0002, algorithm: SigningAlgorithm::RsaPss2048Sha256 }
        ));
    }

    #[test]
    fn from_uri_custom_tcti() {
        let b = Tpm2Backend::from_uri("secretx:tpm2:nv/0x01000001?tcti=swtpm:port=2321")
            .unwrap();
        assert_eq!(b.tcti, "swtpm:port=2321");
    }

    #[test]
    fn from_uri_wrong_backend() {
        assert!(matches!(
            Tpm2Backend::from_uri("secretx:file:foo"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_empty_path() {
        assert!(matches!(
            Tpm2Backend::from_uri("secretx:tpm2"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_bad_prefix() {
        assert!(matches!(
            Tpm2Backend::from_uri("secretx:tpm2:seal/0x81000001"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_bad_hex() {
        assert!(matches!(
            Tpm2Backend::from_uri("secretx:tpm2:nv/notahex"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_nv_index_out_of_range() {
        assert!(matches!(
            Tpm2Backend::from_uri("secretx:tpm2:nv/0x81000001"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_persistent_handle_out_of_range() {
        assert!(matches!(
            Tpm2Backend::from_uri("secretx:tpm2:key/0x01000001"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_unknown_algorithm() {
        assert!(matches!(
            Tpm2Backend::from_uri("secretx:tpm2:key/0x81000001?algorithm=ed25519"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn debug_does_not_leak_internals() {
        let b = Tpm2Backend::from_uri("secretx:tpm2:nv/0x01000001").unwrap();
        let dbg = format!("{b:?}");
        assert!(dbg.contains("Tpm2Backend"));
        assert!(dbg.contains("Nv"));
    }

    #[test]
    fn validate_nv_index_boundaries() {
        assert!(validate_nv_index(0x0100_0000).is_ok());
        assert!(validate_nv_index(0x01FF_FFFF).is_ok());
        assert!(validate_nv_index(0x00FF_FFFF).is_err());
        assert!(validate_nv_index(0x0200_0000).is_err());
    }

    #[test]
    fn validate_persistent_handle_boundaries() {
        assert!(validate_persistent_handle(0x8100_0000).is_ok());
        assert!(validate_persistent_handle(0x81FF_FFFF).is_ok());
        assert!(validate_persistent_handle(0x80FF_FFFF).is_err());
        assert!(validate_persistent_handle(0x8200_0000).is_err());
    }

    #[test]
    fn is_nv_and_is_sign_correct() {
        let nv = Tpm2Backend::from_uri("secretx:tpm2:nv/0x01000001").unwrap();
        assert!(nv.is_nv());
        assert!(!nv.is_sign());

        let key = Tpm2Backend::from_uri("secretx:tpm2:key/0x81000001").unwrap();
        assert!(key.is_sign());
        assert!(!key.is_nv());
    }
}

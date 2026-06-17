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
//! # Limitations
//!
//! - **Unrestricted signing keys only.** The `sign()` implementation uses a
//!   null-hierarchy hashcheck ticket for externally-computed digests, which
//!   the TPM rejects for restricted signing keys (`TPM_RC_TICKET`).
//!
//! - **NV read/write is single-shot.** Each operation issues one TPM command,
//!   limited by the TPM's `MAX_NV_BUFFER_SIZE` (typically 1024–2048 bytes,
//!   TPM-dependent). NV indices larger than this limit will fail at runtime.
//!   Most secrets fit comfortably; if yours doesn't, use the `file` backend.
//!
//! # Supported algorithms
//!
//! | URI `?algorithm=`  | Key type | Curve / Size | Hash   | Signature format          |
//! |--------------------|----------|--------------|--------|---------------------------|
//! | `ecdsa-p256` (default) | ECC  | NIST P-256   | SHA-256 | 64 bytes: `r \|\| s`      |
//! | `rsa-pss-2048`     | RSA      | 2048-bit     | SHA-256 | 256 bytes, big-endian     |
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
#[derive(Debug)]
pub struct Tpm2Backend {
    mode: Mode,
    tcti: String,
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

/// Parse a hex string (with optional `0x`/`0X` prefix) into a `u32`.
fn parse_hex_u32(s: &str, label: &str) -> Result<u32, SecretError> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u32::from_str_radix(s, 16).map_err(|_| {
        SecretError::InvalidUri(format!("invalid {label}: expected hex like 0x01000001"))
    })
}

/// Verify `index` falls in the TPM 2.0 owner NV range (`0x01000000..=0x01FFFFFF`).
fn validate_nv_index(index: u32) -> Result<(), SecretError> {
    if !(0x0100_0000..=0x01FF_FFFF).contains(&index) {
        return Err(SecretError::InvalidUri(format!(
            "NV index 0x{index:08X} out of range (must be 0x01000000..0x01FFFFFF)"
        )));
    }
    Ok(())
}

/// Verify `handle` falls in the TPM 2.0 persistent object range (`0x81000000..=0x81FFFFFF`).
fn validate_persistent_handle(handle: u32) -> Result<(), SecretError> {
    if !(0x8100_0000..=0x81FF_FFFF).contains(&handle) {
        return Err(SecretError::InvalidUri(format!(
            "persistent handle 0x{handle:08X} out of range (must be 0x81000000..0x81FFFFFF)"
        )));
    }
    Ok(())
}

/// Open a fresh ESAPI context for the given TCTI configuration string.
fn open_context(tcti: &str) -> Result<Context, SecretError> {
    let tcti_conf = TctiNameConf::from_str(tcti).map_err(|e| SecretError::Backend {
        backend: BACKEND,
        source: format!("invalid TCTI config `{tcti}`: {e}").into(),
    })?;
    Context::new(tcti_conf).map_err(|e| SecretError::Unavailable {
        backend: BACKEND,
        source: e.into(),
    })
}

/// Map a `spawn_blocking` join error to [`SecretError::Backend`].
fn map_join_err(e: tokio::task::JoinError) -> SecretError {
    SecretError::Backend {
        backend: BACKEND,
        source: e.into(),
    }
}

/// Classify a TSS error as transient (Unavailable) or permanent (Backend).
fn map_tpm_error(e: tss_esapi::Error) -> SecretError {
    use tss_esapi::constants::response_code::Tss2ResponseCodeKind;

    let is_transient = match &e {
        tss_esapi::Error::Tss2Error(rc) => matches!(
            rc.kind(),
            Some(
                Tss2ResponseCodeKind::Retry
                    | Tss2ResponseCodeKind::Yielded
                    | Tss2ResponseCodeKind::NvRate
                    | Tss2ResponseCodeKind::NvUnavailable
                    | Tss2ResponseCodeKind::Memory
                    | Tss2ResponseCodeKind::ObjectMemory
                    | Tss2ResponseCodeKind::SessionMemory
                    | Tss2ResponseCodeKind::ObjectHandles
                    | Tss2ResponseCodeKind::SessionHandles
                    | Tss2ResponseCodeKind::Canceled
            )
        ),
        // Wrapper errors (bad params, missing auth) are permanent.
        tss_esapi::Error::WrapperError(_) => false,
    };

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

/// Construct a null-hierarchy hashcheck ticket for externally-computed digests.
///
/// The TPM accepts this ticket for unrestricted signing keys; restricted
/// keys will reject it with `TPM_RC_TICKET`.
fn null_hashcheck_ticket() -> Result<tss_esapi::structures::HashcheckTicket, SecretError> {
    tss_esapi::structures::HashcheckTicket::try_from(tss_esapi::tss2_esys::TPMT_TK_HASHCHECK {
        tag: tss_esapi::constants::tss::TPM2_ST_HASHCHECK,
        hierarchy: tss_esapi::constants::tss::TPM2_RH_NULL,
        digest: tss_esapi::tss2_esys::TPM2B_DIGEST {
            size: 0,
            buffer: [0u8; 64],
        },
    })
    .map_err(map_tpm_error)
}

// ── SecretStore (NV read) ────────────────────────────────────────────────────

#[async_trait::async_trait]
impl SecretStore for Tpm2Backend {
    /// Read the full contents of the NV index.
    ///
    /// Opens a fresh ESAPI context, reads `nv_public.data_size()` bytes
    /// at offset 0 using a null-auth HMAC session.
    ///
    /// Returns `SecretError::Backend` if called on a signing-key URI.
    async fn get(&self) -> Result<SecretValue, SecretError> {
        let Mode::Nv { index } = self.mode else {
            return Err(SecretError::Backend {
                backend: BACKEND,
                source: "get() requires an NV index URI (secretx:tpm2:nv/...); this is a signing key URI"
                    .into(),
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
        .map_err(map_join_err)?
    }

    /// Re-reads the NV index (equivalent to [`get`](SecretStore::get)).
    async fn refresh(&self) -> Result<SecretValue, SecretError> {
        self.get().await
    }
}

// ── WritableSecretStore (NV write) ───────────────────────────────────────────

#[async_trait::async_trait]
impl WritableSecretStore for Tpm2Backend {
    /// Write `value` to the NV index.
    ///
    /// The data length must exactly match the NV index's defined size
    /// (set at NV index creation time). A size mismatch returns
    /// `SecretError::Backend`. The maximum single-shot write is bounded
    /// by the TPM's `MAX_NV_BUFFER_SIZE` (typically 1024–2048 bytes,
    /// hardware-dependent).
    ///
    /// Returns `SecretError::Backend` if called on a signing-key URI.
    async fn put(&self, value: SecretValue) -> Result<(), SecretError> {
        let Mode::Nv { index } = self.mode else {
            return Err(SecretError::Backend {
                backend: BACKEND,
                source: "put() requires an NV index URI (secretx:tpm2:nv/...); this is a signing key URI"
                    .into(),
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

            // Verify data length matches the NV index's defined size.
            // TPM NV indices have a fixed size; a short write leaves stale
            // bytes visible to subsequent reads.
            let (nv_public, _name) = context.nv_read_public(nv_index_handle)
                .map_err(map_tpm_error)?;
            let defined_size = nv_public.data_size();
            if bytes.len() != defined_size {
                return Err(SecretError::Backend {
                    backend: BACKEND,
                    source: format!(
                        "data length {} does not match NV index defined size {}",
                        bytes.len(),
                        defined_size,
                    ).into(),
                });
            }

            // Convert directly from the Zeroizing<Vec<u8>> slice to avoid
            // creating a plain Vec<u8> that wouldn't be zeroed on drop.
            let data = MaxNvBuffer::try_from(bytes.as_slice()).map_err(|e| {
                SecretError::Backend {
                    backend: BACKEND,
                    source: format!("data too large for NV buffer: {e}").into(),
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
        .map_err(map_join_err)?
    }
}

// ── SigningBackend ────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl SigningBackend for Tpm2Backend {
    /// Sign `message` with the persistent TPM key.
    ///
    /// Hashes `message` with SHA-256 in software, then sends the digest
    /// to the TPM for signing. Uses a null-hierarchy hashcheck ticket
    /// (unrestricted signing keys only — restricted keys will return
    /// `TPM_RC_TICKET`).
    ///
    /// Returns `SecretError::Backend` if called on an NV-index URI.
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SecretError> {
        let Mode::Sign { handle, algorithm } = self.mode else {
            return Err(SecretError::Backend {
                backend: BACKEND,
                source: "sign() requires a key URI (secretx:tpm2:key/...); this is an NV index URI"
                    .into(),
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

            // Validate the TPM key's algorithm/curve/size matches the URI.
            let (public, _, _) = context.read_public(key_handle).map_err(map_tpm_error)?;
            validate_key_type(algorithm, &public)?;

            let digest = tss_esapi::structures::Digest::try_from(digest_bytes)
                .map_err(|e| SecretError::Backend {
                    backend: BACKEND,
                    source: format!("failed to create digest: {e}").into(),
                })?;

            let validation = null_hashcheck_ticket()?;

            let signature = context
                .execute_with_nullauth_session(|ctx| {
                    ctx.sign(key_handle, digest, SignatureScheme::Null, validation)
                })
                .map_err(map_tpm_error)?;

            normalize_signature(algorithm, &signature)
        })
        .await
        .map_err(map_join_err)?
    }

    /// Export the public key as DER-encoded SubjectPublicKeyInfo (SPKI).
    ///
    /// Opens a fresh ESAPI context, reads the public area of the
    /// persistent key, validates algorithm/curve/scheme, and serializes
    /// to DER via `picky-asn1-der`.
    ///
    /// Returns `SecretError::Backend` if called on an NV-index URI.
    async fn public_key_der(&self) -> Result<Vec<u8>, SecretError> {
        let Mode::Sign { handle, algorithm } = self.mode else {
            return Err(SecretError::Backend {
                backend: BACKEND,
                source: "public_key_der() requires a key URI (secretx:tpm2:key/...); this is an NV index URI"
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

            // Verify the TPM key type matches the URI's ?algorithm= param.
            validate_key_type(algorithm, &public)?;

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
        .map_err(map_join_err)?
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
                source: "algorithm() requires a key URI (secretx:tpm2:key/...); this is an NV index URI"
                    .into(),
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
            // P-256 components are at most 32 bytes; reject anything larger.
            if r.len() > 32 || s.len() > 32 {
                return Err(SecretError::Backend {
                    backend: BACKEND,
                    source: format!(
                        "ECDSA P-256 component too large: r={} s={} bytes",
                        r.len(),
                        s.len(),
                    )
                    .into(),
                });
            }
            // Right-align (zero-pad) each component to 32 bytes.
            let mut out = vec![0u8; 64];
            out[32 - r.len()..32].copy_from_slice(r);
            out[64 - s.len()..64].copy_from_slice(s);
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

/// Human-readable label for a [`SigningAlgorithm`], used in error messages.
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

/// Verify the TPM key's actual type, curve, and size match the URI's
/// `?algorithm=` parameter.
fn validate_key_type(
    expected: SigningAlgorithm,
    public: &tss_esapi::structures::Public,
) -> Result<(), SecretError> {
    use tss_esapi::interface_types::{ecc::EccCurve, key_bits::RsaKeyBits};
    use tss_esapi::structures::{EccScheme, Public, RsaScheme};

    match (expected, public) {
        (SigningAlgorithm::EcdsaP256Sha256, Public::Ecc { parameters, .. }) => {
            if parameters.ecc_curve() != EccCurve::NistP256 {
                return Err(SecretError::AlgorithmMismatch {
                    expected: "ecdsa-p256",
                    actual: format!("TPM key uses curve {:?}", parameters.ecc_curve()),
                });
            }
            // Null scheme means the key accepts any scheme at sign time.
            if !matches!(parameters.ecc_scheme(), EccScheme::EcDsa(_) | EccScheme::Null) {
                return Err(SecretError::AlgorithmMismatch {
                    expected: "ecdsa-p256 (ECDSA scheme)",
                    actual: format!("TPM key uses scheme {:?}", parameters.ecc_scheme()),
                });
            }
        }
        (SigningAlgorithm::RsaPss2048Sha256, Public::Rsa { parameters, .. }) => {
            if parameters.key_bits() != RsaKeyBits::Rsa2048 {
                return Err(SecretError::AlgorithmMismatch {
                    expected: "rsa-pss-2048",
                    actual: format!("TPM key is RSA-{:?}", parameters.key_bits()),
                });
            }
            if !matches!(parameters.rsa_scheme(), RsaScheme::RsaPss(_) | RsaScheme::Null) {
                return Err(SecretError::AlgorithmMismatch {
                    expected: "rsa-pss-2048 (RSA-PSS scheme)",
                    actual: format!("TPM key uses scheme {:?}", parameters.rsa_scheme()),
                });
            }
        }
        _ => {
            let actual = match public {
                Public::Ecc { .. } => "ECC",
                Public::Rsa { .. } => "RSA",
                _ => "unsupported key type",
            };
            return Err(SecretError::AlgorithmMismatch {
                expected: algorithm_label(expected),
                actual: format!("TPM key is {actual}"),
            });
        }
    }
    Ok(())
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

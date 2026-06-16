//! Adapter bridging [`secretx_core::SigningBackend`] to [`signature::Signer`].
//!
//! `SigningBackend` is async and returns raw `Vec<u8>` bytes. RustCrypto's
//! `Signer<S>` is sync and returns typed signatures. This crate bridges the
//! gap with per-algorithm adapter types that validate the algorithm at
//! construction and run the async signing operation on a dedicated thread.
//!
//! # Features
//!
//! Enable features matching the algorithms you need:
//!
//! | Feature | Adapter type | Signature type |
//! |---------|-------------|----------------|
//! | `ed25519` | [`Ed25519Signer`] | `ed25519::Signature` |
//! | `ecdsa-p256` | [`EcdsaP256Signer`] | `p256::ecdsa::Signature` |
//! | `rsa-pss` | [`RsaPss2048Signer`] | `rsa::pss::Signature` (2048-bit only) |
//!
//! # Example
//!
//! ```rust,no_run
//! # #[cfg(feature = "ed25519")]
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use secretx_signature::Ed25519Signer;
//! use signature::Signer;
//!
//! # let backend: std::sync::Arc<dyn secretx_core::SigningBackend> = todo!();
//! // backend: Arc<dyn SigningBackend> from secretx::from_signing_uri
//! let signer = Ed25519Signer::new(backend)?;
//!
//! // try_sign returns Result; sign panics on error (see ## Panics).
//! let sig: ed25519::Signature = signer.try_sign(b"hello")?;
//! # Ok(())
//! # }
//! ```
//!
//! # Async bridging
//!
//! Each `try_sign` call bridges the underlying async `SigningBackend::sign`
//! into a synchronous context. If called outside a tokio runtime, a
//! current-thread runtime is created on the calling thread. If called inside
//! an existing tokio runtime, a scoped thread is spawned with its own runtime
//! to avoid a nested `block_on` panic. Both paths are safe from any calling
//! context (sync, async, nested runtimes). The overhead is negligible compared
//! to the cost of an HSM or KMS signing operation.
//!
//! # Relationship to the umbrella crate
//!
//! This crate is **not** part of the [`secretx`] umbrella — add it as a direct
//! dependency. The umbrella handles backend dispatch; this crate is a downstream
//! consumer that wraps the resulting [`SigningBackend`] for the RustCrypto
//! [`signature`] ecosystem.
//!
//! # Dependency versions
//!
//! This crate's public API exposes types from [`signature`] v2 and
//! [`secretx_core`]. Callers must use compatible major versions of these
//! crates.

pub use secretx_core::{SecretError, SigningBackend};

#[cfg(any(feature = "ed25519", feature = "ecdsa-p256", feature = "rsa-pss"))]
use std::{fmt, sync::Arc};

#[cfg(any(feature = "ed25519", feature = "ecdsa-p256", feature = "rsa-pss"))]
use secretx_core::SigningAlgorithm;

/// Run an async signing operation synchronously.
///
/// If no tokio runtime is active, creates a current-thread runtime on the
/// calling thread. If a tokio runtime is already active, spawns a scoped
/// thread with its own runtime to avoid a nested `block_on` panic.
#[cfg(any(feature = "ed25519", feature = "ecdsa-p256", feature = "rsa-pss"))]
fn sign_sync(backend: &Arc<dyn SigningBackend>, msg: &[u8]) -> Result<Vec<u8>, SecretError> {
    if tokio::runtime::Handle::try_current().is_err() {
        return tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| SecretError::Backend {
                backend: "signature-adapter",
                source: e.into(),
            })?
            .block_on(backend.sign(msg));
    }

    std::thread::scope(|s| {
        s.spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| SecretError::Backend {
                    backend: "signature-adapter",
                    source: e.into(),
                })?
                .block_on(backend.sign(msg))
        })
        .join()
        // Panic payload (Box<dyn Any + Send>) can't be reliably downcasted to a message.
        .unwrap_or_else(|_| {
            Err(SecretError::Backend {
                backend: "signature-adapter",
                source: "signing thread panicked".into(),
            })
        })
    })
}

// ── Ed25519 ──────────────────────────────────────────────────────────────────

/// Adapter wrapping a [`SigningBackend`] as a `Signer<ed25519::Signature>`.
///
/// Validates at construction that the backend's algorithm is Ed25519.
#[cfg(feature = "ed25519")]
#[derive(Clone)]
pub struct Ed25519Signer {
    backend: Arc<dyn SigningBackend>,
}

#[cfg(feature = "ed25519")]
impl fmt::Debug for Ed25519Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519Signer").finish_non_exhaustive()
    }
}

#[cfg(feature = "ed25519")]
impl Ed25519Signer {
    /// Wrap a `SigningBackend` as a `Signer<ed25519::Signature>`.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::AlgorithmMismatch`] if the backend's algorithm
    /// is not Ed25519. Also propagates any error from
    /// [`SigningBackend::algorithm`] (e.g. `Backend`, `Unavailable`).
    pub fn new(backend: Arc<dyn SigningBackend>) -> Result<Self, SecretError> {
        match backend.algorithm()? {
            SigningAlgorithm::Ed25519 => Ok(Self { backend }),
            other => Err(SecretError::AlgorithmMismatch {
                expected: "Ed25519",
                actual: format!("{other:?}"),
            }),
        }
    }

    /// Unwrap, returning the inner `SigningBackend`.
    pub fn into_inner(self) -> Arc<dyn SigningBackend> {
        self.backend
    }
}

#[cfg(feature = "ed25519")]
impl signature::Signer<ed25519::Signature> for Ed25519Signer {
    /// Sign `msg` synchronously by bridging to the async `SigningBackend`.
    ///
    /// See [Async bridging](crate#async-bridging) for threading details.
    ///
    /// # Panics
    ///
    /// The default `sign()` method panics if `try_sign` returns an error
    /// (e.g. backend unavailable, network failure). Use `try_sign` in
    /// production code.
    fn try_sign(&self, msg: &[u8]) -> Result<ed25519::Signature, signature::Error> {
        let bytes = sign_sync(&self.backend, msg).map_err(signature::Error::from_source)?;
        ed25519::Signature::from_slice(&bytes)
    }
}

// ── ECDSA P-256 ──────────────────────────────────────────────────────────────

/// Adapter wrapping a [`SigningBackend`] as a `Signer<p256::ecdsa::Signature>`.
///
/// Validates at construction that the backend's algorithm is ECDSA P-256.
/// The backend must return signatures as 64 bytes of fixed-size `r || s`
/// (two 32-byte big-endian scalars), not DER-encoded. This is the format
/// specified by [`SigningBackend::sign`].
#[cfg(feature = "ecdsa-p256")]
#[derive(Clone)]
pub struct EcdsaP256Signer {
    backend: Arc<dyn SigningBackend>,
}

#[cfg(feature = "ecdsa-p256")]
impl fmt::Debug for EcdsaP256Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaP256Signer").finish_non_exhaustive()
    }
}

#[cfg(feature = "ecdsa-p256")]
impl EcdsaP256Signer {
    /// Wrap a `SigningBackend` as a `Signer<p256::ecdsa::Signature>`.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::AlgorithmMismatch`] if the backend's algorithm
    /// is not ECDSA P-256. Also propagates any error from
    /// [`SigningBackend::algorithm`] (e.g. `Backend`, `Unavailable`).
    pub fn new(backend: Arc<dyn SigningBackend>) -> Result<Self, SecretError> {
        match backend.algorithm()? {
            SigningAlgorithm::EcdsaP256Sha256 => Ok(Self { backend }),
            other => Err(SecretError::AlgorithmMismatch {
                expected: "EcdsaP256Sha256",
                actual: format!("{other:?}"),
            }),
        }
    }

    /// Unwrap, returning the inner `SigningBackend`.
    pub fn into_inner(self) -> Arc<dyn SigningBackend> {
        self.backend
    }
}

#[cfg(feature = "ecdsa-p256")]
impl signature::Signer<p256::ecdsa::Signature> for EcdsaP256Signer {
    /// Sign `msg` synchronously by bridging to the async `SigningBackend`.
    ///
    /// See [Async bridging](crate#async-bridging) for threading details.
    ///
    /// # Panics
    ///
    /// The default `sign()` method panics if `try_sign` returns an error.
    /// Use `try_sign` in production code.
    fn try_sign(&self, msg: &[u8]) -> Result<p256::ecdsa::Signature, signature::Error> {
        let bytes = sign_sync(&self.backend, msg).map_err(signature::Error::from_source)?;
        p256::ecdsa::Signature::from_slice(&bytes)
    }
}

// ── RSA-PSS 2048 ─────────────────────────────────────────────────────────────

/// RSA-PSS 2048 expected signature length in bytes.
#[cfg(feature = "rsa-pss")]
const RSA_2048_SIG_LEN: usize = 256;

/// Adapter wrapping a [`SigningBackend`] as a `Signer<rsa::pss::Signature>`.
///
/// Validates at construction that the backend's algorithm is RSA-PSS 2048.
/// The expected signature length is 256 bytes (2048 bits).
#[cfg(feature = "rsa-pss")]
#[derive(Clone)]
pub struct RsaPss2048Signer {
    backend: Arc<dyn SigningBackend>,
}

#[cfg(feature = "rsa-pss")]
impl fmt::Debug for RsaPss2048Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaPss2048Signer").finish_non_exhaustive()
    }
}

#[cfg(feature = "rsa-pss")]
impl RsaPss2048Signer {
    /// Wrap a `SigningBackend` as a `Signer<rsa::pss::Signature>`.
    ///
    /// Only accepts backends with `SigningAlgorithm::RsaPss2048Sha256`
    /// (2048-bit RSA keys producing 256-byte signatures).
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::AlgorithmMismatch`] if the backend's algorithm
    /// is not RSA-PSS 2048. Also propagates any error from
    /// [`SigningBackend::algorithm`] (e.g. `Backend`, `Unavailable`).
    pub fn new(backend: Arc<dyn SigningBackend>) -> Result<Self, SecretError> {
        match backend.algorithm()? {
            SigningAlgorithm::RsaPss2048Sha256 => Ok(Self { backend }),
            other => Err(SecretError::AlgorithmMismatch {
                expected: "RsaPss2048Sha256",
                actual: format!("{other:?}"),
            }),
        }
    }

    /// Unwrap, returning the inner `SigningBackend`.
    pub fn into_inner(self) -> Arc<dyn SigningBackend> {
        self.backend
    }
}

#[cfg(feature = "rsa-pss")]
impl signature::Signer<rsa::pss::Signature> for RsaPss2048Signer {
    /// Sign `msg` synchronously by bridging to the async `SigningBackend`.
    ///
    /// See [Async bridging](crate#async-bridging) for threading details.
    /// Validates that the backend returns exactly 256 bytes (RSA-2048).
    ///
    /// # Panics
    ///
    /// The default `sign()` method panics if `try_sign` returns an error.
    /// Use `try_sign` in production code.
    fn try_sign(&self, msg: &[u8]) -> Result<rsa::pss::Signature, signature::Error> {
        let bytes = sign_sync(&self.backend, msg).map_err(signature::Error::from_source)?;
        if bytes.len() != RSA_2048_SIG_LEN {
            return Err(signature::Error::from_source(SecretError::Backend {
                backend: "signature-adapter",
                source: format!(
                    "RSA-PSS 2048 signature must be {RSA_2048_SIG_LEN} bytes, got {}",
                    bytes.len()
                )
                .into(),
            }));
        }
        rsa::pss::Signature::try_from(bytes.as_slice())
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

// Compile-time proof that adapter types are Send + Sync.
#[cfg(feature = "ed25519")]
const _: () = { fn _assert() where Ed25519Signer: Send + Sync {} };
#[cfg(feature = "ecdsa-p256")]
const _: () = { fn _assert() where EcdsaP256Signer: Send + Sync {} };
#[cfg(feature = "rsa-pss")]
const _: () = { fn _assert() where RsaPss2048Signer: Send + Sync {} };

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use secretx_core::{SigningAlgorithm, SigningBackend};
    use std::sync::Arc;

    struct MockBackend {
        algo: SigningAlgorithm,
        sig_bytes: Vec<u8>,
    }

    #[async_trait]
    impl SigningBackend for MockBackend {
        async fn sign(&self, _msg: &[u8]) -> Result<Vec<u8>, SecretError> {
            Ok(self.sig_bytes.clone())
        }
        async fn public_key_der(&self) -> Result<Vec<u8>, SecretError> {
            Ok(vec![])
        }
        fn algorithm(&self) -> Result<SigningAlgorithm, SecretError> {
            Ok(self.algo)
        }
    }

    fn mock(algo: SigningAlgorithm, sig_bytes: Vec<u8>) -> Arc<dyn SigningBackend> {
        Arc::new(MockBackend { algo, sig_bytes })
    }

    // ── Ed25519 ──────────────────────────────────────────────────────────────

    #[cfg(feature = "ed25519")]
    mod ed25519_tests {
        use super::*;
        use signature::Signer;

        #[test]
        fn rejects_wrong_algorithm() {
            let backend = mock(SigningAlgorithm::EcdsaP256Sha256, vec![]);
            let err = Ed25519Signer::new(backend).unwrap_err();
            assert!(matches!(err, SecretError::AlgorithmMismatch { .. }));
        }

        #[test]
        fn accepts_correct_algorithm() {
            let backend = mock(SigningAlgorithm::Ed25519, vec![0u8; 64]);
            assert!(Ed25519Signer::new(backend).is_ok());
        }

        #[test]
        fn sign_parses_64_byte_signature() {
            let backend = mock(SigningAlgorithm::Ed25519, vec![42u8; 64]);
            let signer = Ed25519Signer::new(backend).unwrap();
            let sig = signer.try_sign(b"msg").unwrap();
            assert_eq!(sig.to_bytes(), [42u8; 64]);
        }

        #[test]
        fn sign_rejects_wrong_length() {
            let backend = mock(SigningAlgorithm::Ed25519, vec![0u8; 32]);
            let signer = Ed25519Signer::new(backend).unwrap();
            assert!(signer.try_sign(b"msg").is_err());
        }

        #[test]
        fn into_inner_returns_backend() {
            let backend = mock(SigningAlgorithm::Ed25519, vec![0u8; 64]);
            let signer = Ed25519Signer::new(backend).unwrap();
            let recovered = signer.into_inner();
            assert_eq!(recovered.algorithm().unwrap(), SigningAlgorithm::Ed25519);
        }

        #[test]
        fn debug_impl_does_not_leak_key_material() {
            let backend = mock(SigningAlgorithm::Ed25519, vec![0u8; 64]);
            let signer = Ed25519Signer::new(backend).unwrap();
            let dbg = format!("{signer:?}");
            assert!(dbg.contains("Ed25519Signer"));
        }

        /// Sign with a real local-signing Ed25519 key and verify with
        /// ed25519-dalek. Oracle: ed25519-dalek's independent Verifier impl.
        #[test]
        fn sign_verify_with_local_signing_backend() {
            use pkcs8::EncodePrivateKey;

            let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xAB; 32]);
            let der = signing_key.to_pkcs8_der().unwrap();

            // Unique path per thread to avoid races under parallel test execution.
            let tmp = std::env::temp_dir().join(format!(
                "secretx-sig-test-ed25519-{:?}.der",
                std::thread::current().id()
            ));

            // RAII guard so panics still clean up the temp file.
            struct Cleanup<'a>(&'a std::path::Path);
            impl Drop for Cleanup<'_> {
                fn drop(&mut self) {
                    let _ = std::fs::remove_file(self.0);
                }
            }

            std::fs::write(&tmp, der.as_bytes()).unwrap();
            let _guard = Cleanup(&tmp);

            let uri = format!(
                "secretx:local-signing:{}?algorithm=ed25519",
                tmp.display()
            );
            let backend: Arc<dyn SigningBackend> = Arc::new(
                secretx_local_signing::LocalSigningBackend::from_uri(&uri).unwrap(),
            );

            let signer = Ed25519Signer::new(backend).unwrap();
            let msg = b"test message for ed25519 adapter";
            let sig: ed25519::Signature = signer.try_sign(msg).unwrap();

            // Verify with independent oracle: ed25519-dalek Verifier
            use ed25519_dalek::Verifier;
            let vk = signing_key.verifying_key();
            let dalek_sig = ed25519_dalek::Signature::from_bytes(&sig.to_bytes());
            vk.verify(msg, &dalek_sig).expect("signature verification failed");
        }
    }

    // ── ECDSA P-256 ──────────────────────────────────────────────────────────

    #[cfg(feature = "ecdsa-p256")]
    mod p256_tests {
        use super::*;
        use signature::Signer;

        #[test]
        fn rejects_wrong_algorithm() {
            let backend = mock(SigningAlgorithm::Ed25519, vec![]);
            let err = EcdsaP256Signer::new(backend).unwrap_err();
            assert!(matches!(err, SecretError::AlgorithmMismatch { .. }));
        }

        #[test]
        fn accepts_correct_algorithm() {
            let backend = mock(SigningAlgorithm::EcdsaP256Sha256, vec![1u8; 64]);
            assert!(EcdsaP256Signer::new(backend).is_ok());
        }

        #[test]
        fn sign_parses_64_byte_signature() {
            // Valid P-256 r||s: both scalars must be in [1, n-1].
            // Use small valid scalars: r=1, s=1 (32 bytes each, big-endian).
            let mut sig_bytes = vec![0u8; 64];
            sig_bytes[31] = 1; // r = 1
            sig_bytes[63] = 1; // s = 1
            let backend = mock(SigningAlgorithm::EcdsaP256Sha256, sig_bytes);
            let signer = EcdsaP256Signer::new(backend).unwrap();
            assert!(signer.try_sign(b"msg").is_ok());
        }

        #[test]
        fn sign_rejects_wrong_length() {
            let backend = mock(SigningAlgorithm::EcdsaP256Sha256, vec![1u8; 32]);
            let signer = EcdsaP256Signer::new(backend).unwrap();
            assert!(signer.try_sign(b"msg").is_err());
        }
    }

    // ── RSA-PSS ──────────────────────────────────────────────────────────────

    #[cfg(feature = "rsa-pss")]
    mod rsa_tests {
        use super::*;
        use signature::Signer;

        #[test]
        fn rejects_wrong_algorithm() {
            let backend = mock(SigningAlgorithm::Ed25519, vec![]);
            let err = RsaPss2048Signer::new(backend).unwrap_err();
            assert!(matches!(err, SecretError::AlgorithmMismatch { .. }));
        }

        #[test]
        fn accepts_correct_algorithm() {
            let backend = mock(SigningAlgorithm::RsaPss2048Sha256, vec![0u8; 256]);
            assert!(RsaPss2048Signer::new(backend).is_ok());
        }

        #[test]
        fn sign_parses_256_byte_signature() {
            let backend = mock(SigningAlgorithm::RsaPss2048Sha256, vec![0xAB; 256]);
            let signer = RsaPss2048Signer::new(backend).unwrap();
            let sig = signer.try_sign(b"msg").unwrap();
            use signature::SignatureEncoding;
            assert_eq!(sig.to_bytes().len(), 256);
        }

        #[test]
        fn sign_rejects_wrong_size_signature() {
            // 128 bytes = RSA-1024, must be rejected
            let backend = mock(SigningAlgorithm::RsaPss2048Sha256, vec![0xAB; 128]);
            let signer = RsaPss2048Signer::new(backend).unwrap();
            assert!(signer.try_sign(b"msg").is_err());
        }
    }
}

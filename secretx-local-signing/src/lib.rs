//! Local file-based signing backend for secretx.
//!
//! Loads a private key from a file (PKCS#8 DER) and implements [`SigningBackend`]
//! for Ed25519, ECDSA P-256/SHA-256, and RSA-PSS-2048/SHA-256.
//!
//! # URI format
//!
//! ```text
//! secretx:local-signing:<key_path>?algorithm=<algo>
//! ```
//!
//! Where `<algo>` is one of `ed25519`, `p256`, or `rsa-pss-2048`, and
//! `<key_path>` is the path to the PKCS#8 DER-encoded private key file.
//! Use a leading `/` for absolute paths:
//!
//! ```text
//! secretx:local-signing:/etc/secrets/ed25519.der?algorithm=ed25519
//! secretx:local-signing:relative/key.der?algorithm=p256
//! secretx:local-signing:/etc/secrets/rsa.der?algorithm=rsa-pss-2048
//! ```
//!
//! # Example
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), secretx_core::SecretError> {
//! use secretx_local_signing::LocalSigningBackend;
//! use secretx_core::SigningBackend;
//!
//! let backend = LocalSigningBackend::from_uri(
//!     "secretx:local-signing:/etc/secrets/ed25519.der?algorithm=ed25519",
//! )?;
//! let sig = backend.sign(b"hello world").await?;
//! # Ok(())
//! # }
//! ```

use ed25519_dalek::pkcs8::DecodePrivateKey as Ed25519DecodePrivateKey;
use secretx_core::{SecretError, SecretUri, SigningAlgorithm, SigningBackend};
use signature::{SignatureEncoding, Signer};
use zeroize::Zeroizing;

// ── Key storage ───────────────────────────────────────────────────────────────

enum LocalKey {
    Ed25519(ed25519_dalek::SigningKey),
    P256(p256::ecdsa::SigningKey),
    // Wrapped in Arc so sign() can clone the Arc (a pointer copy) for
    // spawn_blocking rather than cloning the full RSA key material on every
    // call.  SigningKey<Sha256> implements ZeroizeOnDrop, so the key is
    // zeroed when the last Arc drops — either when LocalSigningBackend is
    // dropped (after any in-flight sign tasks complete) or when the sign
    // task's clone drops, whichever is last.
    RsaPss2048(std::sync::Arc<rsa::pss::SigningKey<sha2::Sha256>>),
}

// ── Backend ───────────────────────────────────────────────────────────────────

/// Signing backend that loads a private key from a local file.
///
/// Construct with [`LocalSigningBackend::from_uri`].
pub struct LocalSigningBackend {
    inner: LocalKey,
    algorithm: SigningAlgorithm,
}

impl LocalSigningBackend {
    /// Construct from a `secretx:local-signing:<path>?algorithm=<algo>` URI.
    ///
    /// Reads and parses the key file eagerly. Does not retain raw key bytes
    /// after construction — they are zeroed when the local `Zeroizing` buffer
    /// is dropped.
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        let parsed = SecretUri::parse(uri)?;
        if parsed.backend() != "local-signing" {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `local-signing`, got `{}`",
                parsed.backend()
            )));
        }
        if parsed.path().is_empty() {
            return Err(SecretError::InvalidUri(
                "local-signing URI requires a key path: \
                 secretx:local-signing:<path>?algorithm=<algo>"
                    .into(),
            ));
        }
        let algo_str = parsed.param("algorithm").ok_or_else(|| {
            SecretError::InvalidUri(
                "local-signing URI requires `?algorithm=<algo>` query parameter".into(),
            )
        })?;

        // Validate algorithm string before doing any I/O so unknown algorithms
        // always return InvalidUri, not a Backend/NotFound error.
        validate_algorithm(algo_str)?;

        // Read key bytes into a zeroizing buffer so raw material is cleared
        // after parsing regardless of success or failure.
        let key_bytes: Zeroizing<Vec<u8>> = std::fs::read(parsed.path())
            .map(Zeroizing::new)
            .map_err(|e| match e.kind() {
                // NotFound maps to SecretError::NotFound so callers that check
                // for a missing key (e.g. to fall back to another backend) see
                // the same error variant as every other backend.
                std::io::ErrorKind::NotFound => SecretError::NotFound,
                _ => SecretError::Backend {
                    backend: "local-signing",
                    source: e.into(),
                },
            })?;

        let (inner, algorithm) = parse_key(algo_str, &key_bytes)?;
        Ok(Self { inner, algorithm })
    }
}

fn validate_algorithm(algo_str: &str) -> Result<(), SecretError> {
    match algo_str {
        "ed25519" | "p256" | "rsa-pss-2048" => Ok(()),
        other => Err(SecretError::InvalidUri(format!(
            "unknown algorithm `{other}`; supported: ed25519, p256, rsa-pss-2048"
        ))),
    }
}

fn parse_key(
    algo_str: &str,
    key_bytes: &[u8],
) -> Result<(LocalKey, SigningAlgorithm), SecretError> {
    match algo_str {
        "ed25519" => {
            let key = ed25519_dalek::SigningKey::from_pkcs8_der(key_bytes).map_err(|e| {
                SecretError::Backend {
                    backend: "local-signing",
                    source: format!("ed25519 PKCS#8 parse error: {e}").into(),
                }
            })?;
            Ok((LocalKey::Ed25519(key), SigningAlgorithm::Ed25519))
        }
        "p256" => {
            use p256::pkcs8::DecodePrivateKey as _;
            let key = p256::ecdsa::SigningKey::from_pkcs8_der(key_bytes).map_err(|e| {
                SecretError::Backend {
                    backend: "local-signing",
                    source: format!("P-256 PKCS#8 parse error: {e}").into(),
                }
            })?;
            Ok((LocalKey::P256(key), SigningAlgorithm::EcdsaP256Sha256))
        }
        "rsa-pss-2048" => {
            use pkcs8::DecodePrivateKey as _;
            let key = rsa::RsaPrivateKey::from_pkcs8_der(key_bytes).map_err(|e| {
                SecretError::Backend {
                    backend: "local-signing",
                    source: format!("RSA PKCS#8 parse error: {e}").into(),
                }
            })?;
            // Wrap in Arc so sign() can clone the Arc (pointer copy) rather
            // than the full key material on every spawn_blocking call.
            let signing_key = std::sync::Arc::new(rsa::pss::SigningKey::<sha2::Sha256>::new(key));
            Ok((
                LocalKey::RsaPss2048(signing_key),
                SigningAlgorithm::RsaPss2048Sha256,
            ))
        }
        // validate_algorithm() already rejected every other value before
        // parse_key() is called, so this arm is unreachable.
        other => unreachable!("algorithm `{other}` was already rejected by validate_algorithm"),
    }
}

// ── SigningBackend impl ───────────────────────────────────────────────────────

#[async_trait::async_trait]
impl SigningBackend for LocalSigningBackend {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SecretError> {
        match &self.inner {
            LocalKey::Ed25519(key) => {
                let sig: ed25519_dalek::Signature = key.sign(message);
                Ok(sig.to_bytes().to_vec())
            }
            LocalKey::P256(key) => {
                let sig: p256::ecdsa::Signature = key.sign(message);
                Ok(sig.to_bytes().to_vec())
            }
            LocalKey::RsaPss2048(signing_key) => {
                // RSA-2048 PSS signing takes ~1-3 ms of CPU.  Running it on
                // the tokio executor thread would block all other tasks for
                // that duration, so it is offloaded to a blocking thread pool
                // via spawn_blocking.  Ed25519 and P-256 are fast (~10 µs)
                // and do not need this treatment.
                // Cloning the Arc is a pointer copy — the RSA key material is
                // not duplicated.
                let key_clone = std::sync::Arc::clone(signing_key);
                let msg = message.to_vec();
                tokio::task::spawn_blocking(move || -> Vec<u8> {
                    let sig: rsa::pss::Signature = key_clone.sign(&msg);
                    sig.to_bytes().to_vec()
                })
                .await
                .map_err(|e| SecretError::Backend {
                    backend: "local-signing",
                    source: format!("RSA sign task panicked: {e}").into(),
                })
            }
        }
    }

    async fn public_key_der(&self) -> Result<Vec<u8>, SecretError> {
        use pkcs8::EncodePublicKey;
        match &self.inner {
            LocalKey::Ed25519(key) => {
                let vk = key.verifying_key();
                vk.to_public_key_der()
                    .map(|d| d.to_vec())
                    .map_err(|e| SecretError::Backend {
                        backend: "local-signing",
                        source: format!("Ed25519 public key encode error: {e}").into(),
                    })
            }
            LocalKey::P256(key) => {
                let vk = key.verifying_key();
                vk.to_public_key_der()
                    .map(|d| d.to_vec())
                    .map_err(|e| SecretError::Backend {
                        backend: "local-signing",
                        source: format!("P-256 public key encode error: {e}").into(),
                    })
            }
            LocalKey::RsaPss2048(signing_key) => {
                use rsa::pkcs8::EncodePublicKey as RsaEncodePublicKey;
                // Deref through Arc → &SigningKey; then SigningKey::as_ref()
                // → &RsaPrivateKey; RsaPublicKey implements From<&RsaPrivateKey>.
                // The explicit UFCS is required to disambiguate from the
                // blanket AsRef<Self> impl.
                let sk: &rsa::pss::SigningKey<sha2::Sha256> = signing_key;
                let priv_key = <rsa::pss::SigningKey<_> as AsRef<rsa::RsaPrivateKey>>::as_ref(sk);
                let pub_key = rsa::RsaPublicKey::from(priv_key);
                pub_key
                    .to_public_key_der()
                    .map(|d| d.to_vec())
                    .map_err(|e| SecretError::Backend {
                        backend: "local-signing",
                        source: format!("RSA public key encode error: {e}").into(),
                    })
            }
        }
    }

    fn algorithm(&self) -> Result<SigningAlgorithm, SecretError> {
        Ok(self.algorithm)
    }
}

inventory::submit!(secretx_core::SigningBackendRegistration {
    name: "local-signing",
    factory: |uri: &str| {
        LocalSigningBackend::from_uri(uri)
            .map(|b| std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::SigningBackend>)
    },
});

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Test key paths — generated once with openssl and stored in /tmp at test time.
    // These paths are stable for the test environment; CI must pre-generate them.
    const ED25519_KEY: &str = "/tmp/secretx-test-keys/ed25519.der";
    const P256_KEY: &str = "/tmp/secretx-test-keys/p256.der";
    const RSA_KEY: &str = "/tmp/secretx-test-keys/rsa.der";

    fn ed25519_uri() -> String {
        format!("secretx:local-signing:{ED25519_KEY}?algorithm=ed25519")
    }
    fn p256_uri() -> String {
        format!("secretx:local-signing:{P256_KEY}?algorithm=p256")
    }
    fn rsa_uri() -> String {
        format!("secretx:local-signing:{RSA_KEY}?algorithm=rsa-pss-2048")
    }

    /// Load a backend from a URI, skipping the test (returning early) if the
    /// key file is absent.  Panics on any other error so real failures are not
    /// silently swallowed.
    ///
    /// Generate test keys once with:
    /// ```text
    /// mkdir -p /tmp/secretx-test-keys
    /// openssl genpkey -algorithm ed25519 -outform DER \
    ///     -out /tmp/secretx-test-keys/ed25519.der
    /// openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    ///     -outform DER -out /tmp/secretx-test-keys/p256.der
    /// openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    ///     -outform DER -out /tmp/secretx-test-keys/rsa.der
    /// ```
    /// Without those files the integration tests skip cleanly.
    macro_rules! load_or_skip {
        ($uri:expr) => {
            match LocalSigningBackend::from_uri(&$uri) {
                Ok(b) => b,
                Err(SecretError::NotFound) => return, // key files absent; skip
                Err(e) => panic!("from_uri failed unexpectedly: {e}"),
            }
        };
    }

    // ── from_uri parsing ──────────────────────────────────────────────────────

    #[test]
    fn from_uri_wrong_backend() {
        assert!(matches!(
            LocalSigningBackend::from_uri("secretx:file:/tmp/key.der?algorithm=ed25519"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_missing_path() {
        assert!(matches!(
            LocalSigningBackend::from_uri("secretx:local-signing?algorithm=ed25519"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_missing_algorithm_param() {
        assert!(matches!(
            LocalSigningBackend::from_uri("secretx:local-signing:/tmp/key.der"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_unknown_algorithm() {
        // Key file doesn't need to exist for algorithm rejection.
        assert!(matches!(
            LocalSigningBackend::from_uri("secretx:local-signing:/tmp/key.der?algorithm=elgamal"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    // A valid URI pointing to a non-existent file must return NotFound, not
    // Backend, so callers using NotFound to trigger a fallback path see the
    // right error variant.
    #[test]
    fn from_uri_nonexistent_file_returns_not_found() {
        let result = LocalSigningBackend::from_uri(
            "secretx:local-signing:/nonexistent/path/that/will/never/exist.der?algorithm=ed25519",
        );
        assert!(
            matches!(result, Err(SecretError::NotFound)),
            "missing key file must return NotFound"
        );
    }

    // ── Ed25519 ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn ed25519_loads_and_signs() {
        let backend = load_or_skip!(ed25519_uri());
        assert_eq!(
            backend.algorithm().expect("algorithm"),
            SigningAlgorithm::Ed25519
        );

        let message = b"hello, ed25519";
        let sig_bytes = backend.sign(message).await.expect("sign failed");
        assert_eq!(sig_bytes.len(), 64, "Ed25519 signature must be 64 bytes");

        // Verify using the verifying key derived from the same signing key —
        // independent path through the library's verification code.
        let pub_der = backend
            .public_key_der()
            .await
            .expect("public_key_der failed");
        assert!(!pub_der.is_empty());

        // Round-trip: decode the public key DER and verify the signature.
        use ed25519_dalek::pkcs8::DecodePublicKey;
        use ed25519_dalek::Verifier;
        let vk = ed25519_dalek::VerifyingKey::from_public_key_der(&pub_der)
            .expect("VerifyingKey from DER failed");
        let sig = ed25519_dalek::Signature::from_bytes(
            sig_bytes.as_slice().try_into().expect("sig length wrong"),
        );
        vk.verify(message, &sig)
            .expect("Ed25519 signature verification failed");
    }

    #[tokio::test]
    async fn ed25519_different_messages_differ() {
        let backend = load_or_skip!(ed25519_uri());
        let s1 = backend.sign(b"message one").await.unwrap();
        let s2 = backend.sign(b"message two").await.unwrap();
        assert_ne!(s1, s2);
    }

    // ── P-256 ────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn p256_loads_and_signs() {
        let backend = load_or_skip!(p256_uri());
        assert_eq!(
            backend.algorithm().expect("algorithm"),
            SigningAlgorithm::EcdsaP256Sha256
        );

        let message = b"hello, p256";
        let sig_bytes = backend.sign(message).await.expect("sign failed");
        assert!(!sig_bytes.is_empty(), "P-256 signature must not be empty");

        let pub_der = backend
            .public_key_der()
            .await
            .expect("public_key_der failed");
        assert!(!pub_der.is_empty());

        // Verify using P-256 verifying key decoded from the DER.
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
        use p256::pkcs8::DecodePublicKey;
        let vk = VerifyingKey::from_public_key_der(&pub_der)
            .expect("P-256 VerifyingKey from DER failed");
        let sig = Signature::from_bytes(sig_bytes.as_slice().into())
            .expect("P-256 Signature decode failed");
        vk.verify(message, &sig)
            .expect("P-256 signature verification failed");
    }

    #[tokio::test]
    async fn p256_different_messages_differ() {
        let backend = load_or_skip!(p256_uri());
        let s1 = backend.sign(b"message one").await.unwrap();
        let s2 = backend.sign(b"message two").await.unwrap();
        assert_ne!(s1, s2);
    }

    // ── RSA-PSS-2048 ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn rsa_pss_loads_and_signs() {
        let backend = load_or_skip!(rsa_uri());
        assert_eq!(
            backend.algorithm().expect("algorithm"),
            SigningAlgorithm::RsaPss2048Sha256
        );

        let message = b"hello, rsa-pss";
        let sig_bytes = backend.sign(message).await.expect("sign failed");
        assert_eq!(
            sig_bytes.len(),
            256,
            "RSA-2048 PSS signature must be 256 bytes"
        );

        let pub_der = backend
            .public_key_der()
            .await
            .expect("public_key_der failed");
        assert!(!pub_der.is_empty());

        // Verify using RSA-PSS verifying key decoded from the DER.
        use rsa::pkcs8::DecodePublicKey;
        use rsa::pss::VerifyingKey;
        use rsa::signature::Verifier;
        let pub_key = rsa::RsaPublicKey::from_public_key_der(&pub_der)
            .expect("RSA public key from DER failed");
        let vk = VerifyingKey::<sha2::Sha256>::new(pub_key);
        let sig = rsa::pss::Signature::try_from(sig_bytes.as_slice())
            .expect("RSA-PSS Signature decode failed");
        vk.verify(message, &sig)
            .expect("RSA-PSS signature verification failed");
    }

    #[tokio::test]
    async fn rsa_pss_different_messages_differ() {
        let backend = load_or_skip!(rsa_uri());
        let s1 = backend.sign(b"message one").await.unwrap();
        let s2 = backend.sign(b"message two").await.unwrap();
        assert_ne!(s1, s2);
    }

    // RSA-PSS is randomized so two signatures of the same message differ.
    #[tokio::test]
    async fn rsa_pss_same_message_randomized() {
        let backend = load_or_skip!(rsa_uri());
        let s1 = backend.sign(b"same message").await.unwrap();
        let s2 = backend.sign(b"same message").await.unwrap();
        // PSS is probabilistic — signatures should differ with overwhelming probability.
        assert_ne!(s1, s2, "RSA-PSS should produce randomized signatures");
    }

    // ── public_key_der is stable ──────────────────────────────────────────────

    #[tokio::test]
    async fn ed25519_public_key_der_stable() {
        let b = load_or_skip!(ed25519_uri());
        let d1 = b.public_key_der().await.unwrap();
        let d2 = b.public_key_der().await.unwrap();
        assert_eq!(d1, d2);
    }
}

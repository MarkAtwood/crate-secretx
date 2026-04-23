//! Local file-based signing backend for secretx.
//!
//! Loads a private key from a file (PKCS#8 DER) and implements [`SigningBackend`]
//! for Ed25519, ECDSA P-256/SHA-256, and RSA-PSS-2048/SHA-256.
//!
//! # URI format
//!
//! ```text
//! secretx://local-signing/<key_path>?algorithm=<algo>
//! ```
//!
//! Where `<algo>` is one of `ed25519`, `p256`, or `rsa-pss-2048`, and
//! `<key_path>` is the path to the PKCS#8 DER-encoded private key file.
//! Use a double slash for absolute paths:
//!
//! ```text
//! secretx://local-signing//etc/secrets/ed25519.der?algorithm=ed25519
//! secretx://local-signing/relative/key.der?algorithm=p256
//! secretx://local-signing//etc/secrets/rsa.der?algorithm=rsa-pss-2048
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
//!     "secretx://local-signing//etc/secrets/ed25519.der?algorithm=ed25519",
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
    RsaPss2048(rsa::RsaPrivateKey),
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
    /// Construct from a `secretx://local-signing/<path>?algorithm=<algo>` URI.
    ///
    /// Reads and parses the key file eagerly. Does not retain raw key bytes
    /// after construction — they are zeroed when the local `Zeroizing` buffer
    /// is dropped.
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        let parsed = SecretUri::parse(uri)?;
        if parsed.backend != "local-signing" {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `local-signing`, got `{}`",
                parsed.backend
            )));
        }
        if parsed.path.is_empty() {
            return Err(SecretError::InvalidUri(
                "local-signing URI requires a key path: \
                 secretx://local-signing/<path>?algorithm=<algo>"
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
        let key_bytes: Zeroizing<Vec<u8>> = std::fs::read(&parsed.path)
            .map(Zeroizing::new)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => SecretError::Backend {
                    backend: "local-signing",
                    source: format!("key file not found: {}", parsed.path).into(),
                },
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
            Ok((
                LocalKey::RsaPss2048(key),
                SigningAlgorithm::RsaPss2048Sha256,
            ))
        }
        other => Err(SecretError::InvalidUri(format!(
            "unknown algorithm `{other}`; supported: ed25519, p256, rsa-pss-2048"
        ))),
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
            LocalKey::RsaPss2048(key) => {
                // rsa::pss::SigningKey<Sha256> implements signature::Signer when
                // the `getrandom` feature is enabled (uses OsRng internally).
                let signing_key = rsa::pss::SigningKey::<sha2::Sha256>::new(key.clone());
                let sig: rsa::pss::Signature = signing_key.sign(message);
                Ok(sig.to_bytes().to_vec())
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
            LocalKey::RsaPss2048(key) => {
                use rsa::pkcs8::EncodePublicKey as RsaEncodePublicKey;
                let pub_key = rsa::RsaPublicKey::from(key);
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

    fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }
}

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
        format!("secretx://local-signing/{ED25519_KEY}?algorithm=ed25519")
    }
    fn p256_uri() -> String {
        format!("secretx://local-signing/{P256_KEY}?algorithm=p256")
    }
    fn rsa_uri() -> String {
        format!("secretx://local-signing/{RSA_KEY}?algorithm=rsa-pss-2048")
    }

    // ── from_uri parsing ──────────────────────────────────────────────────────

    #[test]
    fn from_uri_wrong_backend() {
        assert!(matches!(
            LocalSigningBackend::from_uri("secretx://file//tmp/key.der?algorithm=ed25519"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_missing_path() {
        assert!(matches!(
            LocalSigningBackend::from_uri("secretx://local-signing?algorithm=ed25519"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_missing_algorithm_param() {
        assert!(matches!(
            LocalSigningBackend::from_uri("secretx://local-signing//tmp/key.der"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_unknown_algorithm() {
        // Key file doesn't need to exist for algorithm rejection.
        assert!(matches!(
            LocalSigningBackend::from_uri("secretx://local-signing//tmp/key.der?algorithm=elgamal"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    // ── Ed25519 ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn ed25519_loads_and_signs() {
        let backend =
            LocalSigningBackend::from_uri(&ed25519_uri()).expect("ed25519 from_uri failed");
        assert_eq!(backend.algorithm(), SigningAlgorithm::Ed25519);

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
        let backend = LocalSigningBackend::from_uri(&ed25519_uri()).unwrap();
        let s1 = backend.sign(b"message one").await.unwrap();
        let s2 = backend.sign(b"message two").await.unwrap();
        assert_ne!(s1, s2);
    }

    // ── P-256 ────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn p256_loads_and_signs() {
        let backend = LocalSigningBackend::from_uri(&p256_uri()).expect("p256 from_uri failed");
        assert_eq!(backend.algorithm(), SigningAlgorithm::EcdsaP256Sha256);

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
        let backend = LocalSigningBackend::from_uri(&p256_uri()).unwrap();
        let s1 = backend.sign(b"message one").await.unwrap();
        let s2 = backend.sign(b"message two").await.unwrap();
        assert_ne!(s1, s2);
    }

    // ── RSA-PSS-2048 ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn rsa_pss_loads_and_signs() {
        let backend = LocalSigningBackend::from_uri(&rsa_uri()).expect("rsa from_uri failed");
        assert_eq!(backend.algorithm(), SigningAlgorithm::RsaPss2048Sha256);

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
        let backend = LocalSigningBackend::from_uri(&rsa_uri()).unwrap();
        let s1 = backend.sign(b"message one").await.unwrap();
        let s2 = backend.sign(b"message two").await.unwrap();
        assert_ne!(s1, s2);
    }

    // RSA-PSS is randomized so two signatures of the same message differ.
    #[tokio::test]
    async fn rsa_pss_same_message_randomized() {
        let backend = LocalSigningBackend::from_uri(&rsa_uri()).unwrap();
        let s1 = backend.sign(b"same message").await.unwrap();
        let s2 = backend.sign(b"same message").await.unwrap();
        // PSS is probabilistic — signatures should differ with overwhelming probability.
        assert_ne!(s1, s2, "RSA-PSS should produce randomized signatures");
    }

    // ── public_key_der is stable ──────────────────────────────────────────────

    #[tokio::test]
    async fn ed25519_public_key_der_stable() {
        let b = LocalSigningBackend::from_uri(&ed25519_uri()).unwrap();
        let d1 = b.public_key_der().await.unwrap();
        let d2 = b.public_key_der().await.unwrap();
        assert_eq!(d1, d2);
    }
}

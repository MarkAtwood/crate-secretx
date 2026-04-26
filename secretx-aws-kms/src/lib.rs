//! AWS KMS signing backend for secretx.
//!
//! Implements [`SigningBackend`] for AWS KMS asymmetric keys. The private key
//! never leaves AWS — all signing operations are performed inside KMS.
//!
//! # URI format
//!
//! ```text
//! secretx:aws-kms:<key-id>[?algorithm=<algo>]
//! ```
//!
//! Where `<key-id>` is a KMS key UUID, alias ARN (`alias/my-key`), or key ARN,
//! and `<algo>` is one of `ecdsa-p256` (default) or `rsa-pss-2048`.
//!
//! # Example
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), secretx_core::SecretError> {
//! use secretx_aws_kms::AwsKmsBackend;
//! use secretx_core::SigningBackend;
//!
//! let backend = AwsKmsBackend::from_uri(
//!     "secretx:aws-kms:alias/my-signing-key?algorithm=ecdsa-p256",
//! )?;
//! let sig = backend.sign(b"hello world").await?;
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;

use aws_sdk_kms::operation::get_public_key::GetPublicKeyError;
use aws_sdk_kms::operation::sign::SignError;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{MessageType, SigningAlgorithmSpec};
use secretx_core::{
    SecretError, SecretStore, SecretUri, SecretValue, SigningAlgorithm, SigningBackend,
};
use sha2::{Digest as _, Sha256};

// ── Backend ───────────────────────────────────────────────────────────────────

/// AWS KMS signing backend.
///
/// Construct with [`AwsKmsBackend::from_uri`]. The AWS client is built once
/// at construction time using the ambient environment credentials
/// (`AWS_ACCESS_KEY_ID`, `AWS_PROFILE`, instance metadata, etc.).
pub struct AwsKmsBackend {
    client: Arc<aws_sdk_kms::Client>,
    key_id: String,
    algorithm: SigningAlgorithm,
}

impl AwsKmsBackend {
    /// Construct from a `secretx:aws-kms:<key-id>[?algorithm=<algo>]` URI.
    ///
    /// Builds the AWS client synchronously using a scoped thread with its own
    /// tokio runtime so that this constructor can be called from any context.
    /// No network call is made during construction.
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        let parsed = SecretUri::parse(uri)?;
        if parsed.backend() != "aws-kms" {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `aws-kms`, got `{}`",
                parsed.backend()
            )));
        }
        if parsed.path().is_empty() {
            return Err(SecretError::InvalidUri(
                "aws-kms URI requires a key ID: secretx:aws-kms:<key-id>".into(),
            ));
        }

        let algorithm = match parsed.param("algorithm") {
            None | Some("ecdsa-p256") => SigningAlgorithm::EcdsaP256Sha256,
            Some("rsa-pss-2048") => SigningAlgorithm::RsaPss2048Sha256,
            Some(other) => {
                return Err(SecretError::InvalidUri(format!(
                    "unknown algorithm `{other}`; supported: ecdsa-p256, rsa-pss-2048"
                )));
            }
        };

        let key_id = parsed.path().to_owned();

        let client = secretx_core::run_on_new_thread(
            || async {
                let config = aws_config::load_from_env().await;
                Ok(aws_sdk_kms::Client::new(&config))
            },
            "aws-kms",
        )?;

        Ok(Self {
            client: Arc::new(client),
            key_id,
            algorithm,
        })
    }
}

// ── ECDSA DER → raw conversion helpers ───────────────────────────────────────

/// Convert a DER-encoded ECDSA-P256 signature to raw 64-byte (r||s) format.
///
/// AWS KMS Sign() returns DER for ECDSA algorithms.  The `SigningBackend::sign()`
/// contract is raw (r||s) so callers can use consistent verification code across
/// backends (local-signing and pkcs11 also return raw format).
///
/// DER structure: SEQUENCE { INTEGER r, INTEGER s } — each component is
/// zero-padded to 32 bytes for P-256.
fn ecdsa_der_to_raw_p256(der: &[u8]) -> Result<Vec<u8>, SecretError> {
    let parse_err = |msg: &'static str| SecretError::Backend {
        backend: "aws-kms",
        source: format!("ECDSA DER signature parse failed: {msg}").into(),
    };

    // SEQUENCE tag 0x30
    let rest = der
        .strip_prefix(&[0x30])
        .ok_or_else(|| parse_err("expected SEQUENCE tag 0x30"))?;
    let (seq_len, rest) = der_length(rest).ok_or_else(|| parse_err("invalid SEQUENCE length"))?;
    if rest.len() < seq_len {
        return Err(parse_err("SEQUENCE truncated"));
    }
    let rest = &rest[..seq_len];

    let (r, rest) = der_integer(rest).ok_or_else(|| parse_err("invalid INTEGER r"))?;
    let (s, _) = der_integer(rest).ok_or_else(|| parse_err("invalid INTEGER s"))?;

    fn fixed32(n: &[u8]) -> Result<[u8; 32], &'static str> {
        if n.len() > 32 {
            return Err("integer component exceeds 32 bytes for P-256");
        }
        let mut out = [0u8; 32];
        out[32 - n.len()..].copy_from_slice(n);
        Ok(out)
    }

    let r32 = fixed32(r).map_err(parse_err)?;
    let s32 = fixed32(s).map_err(parse_err)?;

    let mut out = vec![0u8; 64];
    out[..32].copy_from_slice(&r32);
    out[32..].copy_from_slice(&s32);
    Ok(out)
}

/// Parse a DER length field. Returns `Some((length, remaining_bytes))`.
fn der_length(bytes: &[u8]) -> Option<(usize, &[u8])> {
    let (&first, rest) = bytes.split_first()?;
    if first < 0x80 {
        Some((first as usize, rest))
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 2 || rest.len() < n {
            return None;
        }
        let mut len = 0usize;
        for &b in &rest[..n] {
            len = (len << 8) | (b as usize);
        }
        Some((len, &rest[n..]))
    }
}

/// Parse a DER INTEGER tag-length-value. Returns `Some((integer_bytes, remaining))`.
/// Strips the leading 0x00 sign-extension byte if present (DER positive integers).
fn der_integer(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&tag, rest) = bytes.split_first()?;
    if tag != 0x02 {
        return None;
    }
    let (len, rest) = der_length(rest)?;
    if rest.len() < len {
        return None;
    }
    let (value, rest) = rest.split_at(len);
    // Strip leading 0x00 sign-extension (DER encodes positive integers with MSB set
    // by prepending 0x00 to distinguish from negative values).
    let value = value.strip_prefix(&[0x00]).unwrap_or(value);
    Some((value, rest))
}

// ── SigningBackend impl ───────────────────────────────────────────────────────

#[async_trait::async_trait]
impl SigningBackend for AwsKmsBackend {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SecretError> {
        let algo_spec = match self.algorithm {
            SigningAlgorithm::EcdsaP256Sha256 => SigningAlgorithmSpec::EcdsaSha256,
            SigningAlgorithm::RsaPss2048Sha256 => SigningAlgorithmSpec::RsassaPssSha256,
            SigningAlgorithm::Ed25519 => {
                // Ed25519 is not a KMS-supported signing algorithm; the URI was
                // syntactically valid, so this is a capability error not a URI error.
                // Backend (not Unavailable): retrying will not add Ed25519 support.
                return Err(SecretError::Backend {
                    backend: "aws-kms",
                    source: "Ed25519 is not supported by AWS KMS; use ecdsa-p256 or rsa-pss-2048"
                        .into(),
                });
            }
            // Non-exhaustive: new variants added in future minor versions will
            // reach this arm.  Backend (not Unavailable): retrying will not help
            // if this backend does not recognize the algorithm.
            _ => {
                return Err(SecretError::Backend {
                    backend: "aws-kms",
                    source: format!("algorithm {:?} is not supported by AWS KMS", self.algorithm)
                        .into(),
                });
            }
        };

        // Pre-hash the message with SHA-256 and send the digest with
        // MessageType::Digest.  MessageType::Raw would hash internally but
        // imposes a 4096-byte message size limit; MessageType::Digest carries
        // no size limit and is semantically identical (both algorithms sign
        // the SHA-256 hash of the message).
        let digest = Sha256::digest(message);

        let response = self
            .client
            .sign()
            .key_id(&self.key_id)
            .message(Blob::new(digest.to_vec()))
            .message_type(MessageType::Digest)
            .signing_algorithm(algo_spec)
            .send()
            .await
            .map_err(|sdk_err| {
                // Use as_service_error() (borrow, not consume) so we can fall
                // back to sdk_err.into() for non-service errors without panic.
                if let Some(svc) = sdk_err.as_service_error() {
                    if matches!(svc, SignError::NotFoundException(_)) {
                        return SecretError::NotFound;
                    }
                    // ThrottlingException and RequestThrottledException are transient;
                    // retry may succeed after backoff.
                    let code = svc.meta().code().unwrap_or("");
                    if code == "ThrottlingException" || code == "RequestThrottledException" {
                        return SecretError::Unavailable {
                            backend: "aws-kms",
                            source: format!("{svc}").into(),
                        };
                    }
                    // Permission denied, invalid key state, etc. — permanent.
                    return SecretError::Backend {
                        backend: "aws-kms",
                        source: format!("{svc}").into(),
                    };
                }
                // Network failure, timeout, credential error — not a service error.
                SecretError::Unavailable {
                    backend: "aws-kms",
                    source: sdk_err.into(),
                }
            })?;

        let sig_bytes = response
            .signature
            .ok_or_else(|| SecretError::Backend {
                backend: "aws-kms",
                source: "KMS sign response contained no signature".into(),
            })?
            .into_inner();

        // AWS KMS returns DER-encoded ECDSA signatures.  Convert to raw (r||s) so
        // callers receive consistent 64-byte output regardless of which SigningBackend
        // implementation they use (local-signing and pkcs11 return raw format).
        // RSA-PSS signatures are already raw bytes — no conversion needed.
        match self.algorithm {
            SigningAlgorithm::EcdsaP256Sha256 => ecdsa_der_to_raw_p256(&sig_bytes),
            _ => Ok(sig_bytes),
        }
    }

    async fn public_key_der(&self) -> Result<Vec<u8>, SecretError> {
        let response = self
            .client
            .get_public_key()
            .key_id(&self.key_id)
            .send()
            .await
            .map_err(|sdk_err| {
                if let Some(svc) = sdk_err.as_service_error() {
                    if matches!(svc, GetPublicKeyError::NotFoundException(_)) {
                        return SecretError::NotFound;
                    }
                    // ThrottlingException and RequestThrottledException are transient;
                    // retry may succeed after backoff.
                    let code = svc.meta().code().unwrap_or("");
                    if code == "ThrottlingException" || code == "RequestThrottledException" {
                        return SecretError::Unavailable {
                            backend: "aws-kms",
                            source: format!("{svc}").into(),
                        };
                    }
                    return SecretError::Backend {
                        backend: "aws-kms",
                        source: format!("{svc}").into(),
                    };
                }
                SecretError::Unavailable {
                    backend: "aws-kms",
                    source: sdk_err.into(),
                }
            })?;

        Ok(response
            .public_key
            .ok_or_else(|| SecretError::Backend {
                backend: "aws-kms",
                source: "KMS get_public_key response contained no public key".into(),
            })?
            .into_inner())
    }

    fn algorithm(&self) -> Result<SigningAlgorithm, SecretError> {
        Ok(self.algorithm)
    }
}

// ── SecretStore (stub) ────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl SecretStore for AwsKmsBackend {
    async fn get(&self) -> Result<SecretValue, SecretError> {
        Err(SecretError::Backend {
            backend: "aws-kms",
            source: "aws-kms is a signing-only backend; use SigningBackend".into(),
        })
    }

    async fn refresh(&self) -> Result<SecretValue, SecretError> {
        self.get().await
    }
}

inventory::submit!(secretx_core::SigningBackendRegistration {
    name: "aws-kms",
    factory: |uri: &str| {
        AwsKmsBackend::from_uri(uri)
            .map(|b| std::sync::Arc::new(b) as std::sync::Arc<dyn secretx_core::SigningBackend>)
    },
});

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── URI parsing (no AWS credentials required) ─────────────────────────────

    #[test]
    fn from_uri_wrong_backend() {
        assert!(matches!(
            AwsKmsBackend::from_uri("secretx:aws-sm:some-key"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_missing_key_id() {
        assert!(matches!(
            AwsKmsBackend::from_uri("secretx:aws-kms:"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_invalid_algorithm() {
        assert!(matches!(
            AwsKmsBackend::from_uri("secretx:aws-kms:alias/my-key?algorithm=elgamal"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    // ── Integration tests ─────────────────────────────────────────────────────
    // SECRETX_AWS_KMS_TEST_KEY_ID     — ECC_NIST_P256 key for ECDSA tests
    // SECRETX_AWS_KMS_TEST_RSA_KEY_ID — RSA_2048 key for RSA-PSS tests

    fn integration_key_id() -> Option<String> {
        std::env::var("SECRETX_AWS_KMS_TEST_KEY_ID").ok()
    }

    fn integration_rsa_key_id() -> Option<String> {
        std::env::var("SECRETX_AWS_KMS_TEST_RSA_KEY_ID").ok()
    }

    #[tokio::test]
    async fn integration_sign_and_verify_ecdsa() {
        let Some(key_id) = integration_key_id() else {
            eprintln!("SECRETX_AWS_KMS_TEST_KEY_ID not set; skipping integration test");
            return;
        };

        let uri = format!("secretx:aws-kms:{key_id}?algorithm=ecdsa-p256");
        let backend = AwsKmsBackend::from_uri(&uri).expect("from_uri failed");
        assert_eq!(
            backend.algorithm().expect("algorithm"),
            SigningAlgorithm::EcdsaP256Sha256
        );

        let message = b"hello from secretx-aws-kms integration test";
        let sig_bytes = backend.sign(message).await.expect("sign failed");
        assert_eq!(
            sig_bytes.len(),
            64,
            "ECDSA P-256 raw signature must be 64 bytes"
        );

        let pub_der = backend
            .public_key_der()
            .await
            .expect("public_key_der failed");
        assert!(!pub_der.is_empty(), "public key DER must not be empty");

        // Verify the signature against the public key to confirm ecdsa_der_to_raw_p256
        // is producing a valid (r||s) encoding, not just non-empty bytes.
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
    async fn integration_sign_and_verify_rsa_pss() {
        let Some(key_id) = integration_rsa_key_id() else {
            eprintln!("SECRETX_AWS_KMS_TEST_RSA_KEY_ID not set; skipping integration test");
            return;
        };

        let uri = format!("secretx:aws-kms:{key_id}?algorithm=rsa-pss-2048");
        let backend = AwsKmsBackend::from_uri(&uri).expect("from_uri failed");
        assert_eq!(
            backend.algorithm().expect("algorithm"),
            SigningAlgorithm::RsaPss2048Sha256
        );

        let message = b"hello from secretx-aws-kms rsa-pss integration test";
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
        assert!(!pub_der.is_empty(), "public key DER must not be empty");

        // Verify the signature against the public key to confirm the raw RSA-PSS
        // bytes from KMS are a valid signature over the message.
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
    async fn integration_not_found() {
        let Some(_) = integration_key_id() else {
            eprintln!("SECRETX_AWS_KMS_TEST_KEY_ID not set; skipping integration test");
            return;
        };

        let uri = "secretx:aws-kms:alias/nonexistent-key-that-does-not-exist-secretx-test";
        let backend = AwsKmsBackend::from_uri(uri).expect("from_uri failed");
        let result = backend.sign(b"test").await;
        assert!(
            matches!(result, Err(SecretError::NotFound)),
            "expected NotFound for nonexistent key, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn integration_default_algorithm_is_ecdsa() {
        let Some(key_id) = integration_key_id() else {
            eprintln!("SECRETX_AWS_KMS_TEST_KEY_ID not set; skipping integration test");
            return;
        };

        let uri = format!("secretx:aws-kms:{key_id}");
        let backend = AwsKmsBackend::from_uri(&uri).expect("from_uri failed");
        assert_eq!(
            backend.algorithm().expect("algorithm"),
            SigningAlgorithm::EcdsaP256Sha256,
            "default algorithm must be EcdsaP256Sha256"
        );
    }

    // ── DER → raw ECDSA conversion ────────────────────────────────────────────
    // Oracle: a known P-256 DER signature decoded by hand.
    // This DER byte sequence encodes r=0x01...(32 bytes) s=0x02...(32 bytes)
    // with no leading zero (both r and s have MSB clear).
    //
    // DER: 30 44          # SEQUENCE, 68 bytes
    //       02 20         # INTEGER r, 32 bytes
    //         01 00 ... 00  (0x01 followed by 31 zero bytes)
    //       02 20         # INTEGER s, 32 bytes
    //         02 00 ... 00  (0x02 followed by 31 zero bytes)

    #[test]
    fn ecdsa_der_to_raw_p256_no_padding() {
        // Construct a DER signature where r and s fit in exactly 32 bytes each.
        let mut der = Vec::new();
        let r: Vec<u8> = {
            let mut v = vec![0u8; 32];
            v[0] = 0x01;
            v
        };
        let s: Vec<u8> = {
            let mut v = vec![0u8; 32];
            v[0] = 0x02;
            v
        };
        // INTEGER r
        let mut int_r = vec![0x02u8, 32];
        int_r.extend_from_slice(&r);
        // INTEGER s
        let mut int_s = vec![0x02u8, 32];
        int_s.extend_from_slice(&s);
        // SEQUENCE
        der.push(0x30);
        der.push((int_r.len() + int_s.len()) as u8);
        der.extend_from_slice(&int_r);
        der.extend_from_slice(&int_s);

        let raw = ecdsa_der_to_raw_p256(&der).expect("should parse");
        assert_eq!(raw.len(), 64);
        assert_eq!(&raw[..32], r.as_slice());
        assert_eq!(&raw[32..], s.as_slice());
    }

    #[test]
    fn ecdsa_der_to_raw_p256_with_sign_extension() {
        // r has MSB set, so DER prefixes it with 0x00 (33-byte INTEGER).
        // After stripping 0x00 and left-padding to 32 bytes, result is the same.
        let mut der = Vec::new();
        let r: Vec<u8> = {
            let mut v = vec![0u8; 32];
            v[0] = 0xFF;
            v
        }; // MSB set
        let s: Vec<u8> = {
            let mut v = vec![0u8; 32];
            v[0] = 0x01;
            v
        };
        // INTEGER r with sign extension
        let mut int_r = vec![0x02u8, 33];
        int_r.push(0x00); // sign extension
        int_r.extend_from_slice(&r);
        // INTEGER s (no extension needed)
        let mut int_s = vec![0x02u8, 32];
        int_s.extend_from_slice(&s);
        // SEQUENCE
        der.push(0x30);
        der.push((int_r.len() + int_s.len()) as u8);
        der.extend_from_slice(&int_r);
        der.extend_from_slice(&int_s);

        let raw = ecdsa_der_to_raw_p256(&der).expect("should parse");
        assert_eq!(raw.len(), 64);
        assert_eq!(&raw[..32], r.as_slice()); // 0xFF... recovered
        assert_eq!(&raw[32..], s.as_slice());
    }

    #[test]
    fn ecdsa_der_to_raw_p256_bad_tag_rejected() {
        // Not a SEQUENCE (0x30), must fail.
        let garbage = [0x31u8, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        assert!(matches!(
            ecdsa_der_to_raw_p256(&garbage),
            Err(SecretError::Backend { .. })
        ));
    }
}

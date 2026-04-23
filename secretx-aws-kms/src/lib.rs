//! AWS KMS signing backend for secretx.
//!
//! Implements [`SigningBackend`] for AWS KMS asymmetric keys. The private key
//! never leaves AWS — all signing operations are performed inside KMS.
//!
//! # URI format
//!
//! ```text
//! secretx://aws-kms/<key-id>[?algorithm=<algo>]
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
//!     "secretx://aws-kms/alias/my-signing-key?algorithm=ecdsa-p256",
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
use secretx_core::{SecretError, SecretStore, SecretUri, SecretValue, SigningAlgorithm, SigningBackend};

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
    /// Construct from a `secretx://aws-kms/<key-id>[?algorithm=<algo>]` URI.
    ///
    /// Builds the AWS client synchronously using a scoped thread with its own
    /// tokio runtime so that this constructor can be called from any context.
    /// No network call is made during construction.
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        let parsed = SecretUri::parse(uri)?;
        if parsed.backend != "aws-kms" {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `aws-kms`, got `{}`",
                parsed.backend
            )));
        }
        if parsed.path.is_empty() {
            return Err(SecretError::InvalidUri(
                "aws-kms URI requires a key ID: secretx://aws-kms/<key-id>".into(),
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

        let key_id = parsed.path.clone();

        // Build the AWS client using a scoped thread with its own tokio runtime.
        // This allows from_uri to be called from any context (inside or outside
        // an existing runtime) without panicking on nested block_on calls.
        let mut client_result: Option<Result<aws_sdk_kms::Client, SecretError>> = None;
        std::thread::scope(|s| {
            let join = s.spawn(|| -> Result<aws_sdk_kms::Client, SecretError> {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| SecretError::Backend {
                        backend: "aws-kms",
                        source: Box::new(e) as Box<dyn std::error::Error + Send + Sync>,
                    })?;
                Ok(rt.block_on(async {
                    let config = aws_config::load_from_env().await;
                    aws_sdk_kms::Client::new(&config)
                }))
            });
            client_result = Some(join.join().unwrap_or_else(|_| {
                Err(SecretError::Backend {
                    backend: "aws-kms",
                    source: "AWS client construction thread panicked".into(),
                })
            }));
        });

        let client = client_result
            .expect("scope always sets client_result before exiting")?;

        Ok(Self {
            client: Arc::new(client),
            key_id,
            algorithm,
        })
    }
}

// ── SigningBackend impl ───────────────────────────────────────────────────────

#[async_trait::async_trait]
impl SigningBackend for AwsKmsBackend {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SecretError> {
        let algo_spec = match self.algorithm {
            SigningAlgorithm::EcdsaP256Sha256 => SigningAlgorithmSpec::EcdsaSha256,
            SigningAlgorithm::RsaPss2048Sha256 => SigningAlgorithmSpec::RsassaPssSha256,
            SigningAlgorithm::Ed25519 => {
                return Err(SecretError::InvalidUri(
                    "Ed25519 is not supported by aws-kms backend".into(),
                ));
            }
        };

        let response = self
            .client
            .sign()
            .key_id(&self.key_id)
            .message(Blob::new(message))
            .message_type(MessageType::Raw)
            .signing_algorithm(algo_spec)
            .send()
            .await
            .map_err(|e| {
                let svc = e.into_service_error();
                if matches!(svc, SignError::NotFoundException(_)) {
                    SecretError::NotFound
                } else {
                    SecretError::Backend {
                        backend: "aws-kms",
                        source: svc.into(),
                    }
                }
            })?;

        Ok(response
            .signature
            .ok_or_else(|| SecretError::Backend {
                backend: "aws-kms",
                source: "KMS sign response contained no signature".into(),
            })?
            .into_inner())
    }

    async fn public_key_der(&self) -> Result<Vec<u8>, SecretError> {
        let response = self
            .client
            .get_public_key()
            .key_id(&self.key_id)
            .send()
            .await
            .map_err(|e| {
                let svc = e.into_service_error();
                if matches!(svc, GetPublicKeyError::NotFoundException(_)) {
                    SecretError::NotFound
                } else {
                    SecretError::Backend {
                        backend: "aws-kms",
                        source: svc.into(),
                    }
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

    fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }
}

// ── SecretStore (stub) ────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl SecretStore for AwsKmsBackend {
    async fn get(&self, _name: &str) -> Result<SecretValue, SecretError> {
        Err(SecretError::Unavailable {
            backend: "aws-kms",
            source: "aws-kms is a signing-only backend; use SigningBackend".into(),
        })
    }

    async fn put(&self, _name: &str, _value: SecretValue) -> Result<(), SecretError> {
        Err(SecretError::Unavailable {
            backend: "aws-kms",
            source: "aws-kms is a signing-only backend; use SigningBackend".into(),
        })
    }

    async fn refresh(&self, name: &str) -> Result<SecretValue, SecretError> {
        self.get(name).await
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── URI parsing (no AWS credentials required) ─────────────────────────────

    #[test]
    fn from_uri_wrong_backend() {
        assert!(matches!(
            AwsKmsBackend::from_uri("secretx://aws-sm/some-key"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_missing_key_id() {
        assert!(matches!(
            AwsKmsBackend::from_uri("secretx://aws-kms/"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_invalid_algorithm() {
        assert!(matches!(
            AwsKmsBackend::from_uri("secretx://aws-kms/alias/my-key?algorithm=elgamal"),
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

        let uri = format!("secretx://aws-kms/{key_id}?algorithm=ecdsa-p256");
        let backend = AwsKmsBackend::from_uri(&uri).expect("from_uri failed");
        assert_eq!(backend.algorithm(), SigningAlgorithm::EcdsaP256Sha256);

        let message = b"hello from secretx-aws-kms integration test";
        let sig_bytes = backend.sign(message).await.expect("sign failed");
        assert!(!sig_bytes.is_empty(), "signature must not be empty");

        let pub_der = backend.public_key_der().await.expect("public_key_der failed");
        assert!(!pub_der.is_empty(), "public key DER must not be empty");
    }

    #[tokio::test]
    async fn integration_sign_and_verify_rsa_pss() {
        let Some(key_id) = integration_rsa_key_id() else {
            eprintln!("SECRETX_AWS_KMS_TEST_RSA_KEY_ID not set; skipping integration test");
            return;
        };

        let uri = format!("secretx://aws-kms/{key_id}?algorithm=rsa-pss-2048");
        let backend = AwsKmsBackend::from_uri(&uri).expect("from_uri failed");
        assert_eq!(backend.algorithm(), SigningAlgorithm::RsaPss2048Sha256);

        let message = b"hello from secretx-aws-kms rsa-pss integration test";
        let sig_bytes = backend.sign(message).await.expect("sign failed");
        assert!(!sig_bytes.is_empty(), "signature must not be empty");

        let pub_der = backend.public_key_der().await.expect("public_key_der failed");
        assert!(!pub_der.is_empty(), "public key DER must not be empty");
    }

    #[tokio::test]
    async fn integration_not_found() {
        let Some(_) = integration_key_id() else {
            eprintln!("SECRETX_AWS_KMS_TEST_KEY_ID not set; skipping integration test");
            return;
        };

        let uri = "secretx://aws-kms/alias/nonexistent-key-that-does-not-exist-secretx-test";
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

        let uri = format!("secretx://aws-kms/{key_id}");
        let backend = AwsKmsBackend::from_uri(&uri).expect("from_uri failed");
        assert_eq!(
            backend.algorithm(),
            SigningAlgorithm::EcdsaP256Sha256,
            "default algorithm must be EcdsaP256Sha256"
        );
    }
}

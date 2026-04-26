# secretx-aws-kms

AWS KMS signing backend for [secretx](https://crates.io/crates/secretx).

Implements `SigningBackend` for AWS KMS asymmetric keys. The private key never leaves AWS — all signing operations are performed inside KMS.

## URI

```text
secretx:aws-kms:<key-id>[?algorithm=<algo>]
```

- `key-id` — KMS key UUID, alias (`alias/my-key`), or key ARN
- `algorithm` — `ecdsa-p256` (default) or `rsa-pss-2048`

## Usage

```toml
[dependencies]
secretx-aws-kms = "0.2"
secretx-core = "0.2"
```

```rust
use secretx_aws_kms::AwsKmsBackend;
use secretx_core::SigningBackend;

let backend = AwsKmsBackend::from_uri(
    "secretx:aws-kms:alias/my-signing-key?algorithm=ecdsa-p256",
)?;
let sig = backend.sign(b"hello world").await?;
let pubkey_der = backend.public_key_der().await?;
```

## Credentials

AWS credentials are loaded from the standard credential chain at construction time.

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace. Enable the `aws-kms` feature on the `secretx` umbrella crate to use it via URI dispatch.

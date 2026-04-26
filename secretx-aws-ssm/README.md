# secretx-aws-ssm

AWS Systems Manager Parameter Store backend for [secretx](https://crates.io/crates/secretx).

Fetches `SecureString` parameters with decryption enabled. `put` writes a `SecureString` parameter, creating a new version.

## URI

```text
secretx:aws-ssm:<parameter_name>

secretx:aws-ssm:/prod/db/password   →  SSM path "/prod/db/password"
secretx:aws-ssm:my-param            →  SSM path "my-param"
```

SSM paths that start with `/` use a leading `/` in the path component of the URI.

## Usage

```toml
[dependencies]
secretx-aws-ssm = "0.2"
secretx-core = "0.2"
```

```rust
use secretx_aws_ssm::AwsSsmBackend;
use secretx_core::SecretStore;

let store = AwsSsmBackend::from_uri("secretx:aws-ssm:/prod/db/password")?;
let value = store.get().await?;
```

## Credentials

AWS credentials are loaded from the standard credential chain at construction time.

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace. Enable the `aws-ssm` feature on the `secretx` umbrella crate to use it via URI dispatch.

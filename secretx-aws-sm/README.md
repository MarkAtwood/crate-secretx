# secretx-aws-sm

AWS Secrets Manager backend for [secretx](https://crates.io/crates/secretx).

## URI

```text
secretx:aws-sm:<name>[?field=<json_field>]
```

- `name` — secret name or ARN in Secrets Manager
- `field` — optional: extract a single field from a JSON string secret
  (e.g. `?field=password` applied to `{"username":"foo","password":"bar"}`)

## Usage

```toml
[dependencies]
secretx-aws-sm = "0.2"
secretx-core = "0.2"
```

```rust
use secretx_aws_sm::AwsSmBackend;
use secretx_core::SecretStore;

let store = AwsSmBackend::from_uri("secretx:aws-sm:prod/my-secret")?;
let value = store.get().await?;
```

## Credentials

AWS credentials are loaded from the standard credential chain at construction time: `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` env vars, `~/.aws/credentials`, instance metadata (EC2/ECS/Lambda), and so on.

## Part of secretx

This crate is part of the [secretx](https://crates.io/crates/secretx) workspace. Enable the `aws-sm` feature on the `secretx` umbrella crate to use it via URI dispatch.

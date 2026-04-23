//! Bitwarden Secrets Manager backend for secretx.
//!
//! # Integration test status
//!
//! Unit tests (URI parsing, error mapping) pass without credentials.
//! Live integration tests require a Bitwarden Secrets Manager account
//! (available on Teams/Enterprise plans) and a machine account access token.
//! Set `SECRETX_BWS_TEST=1` and `BWS_ACCESS_TOKEN` to enable them.
//! **Not yet integration-tested.**
//!
//! URI: `secretx://bitwarden/<project-name>/<secret-name>`
//!
//! Authentication is via the `BWS_ACCESS_TOKEN` environment variable, which
//! must hold a Bitwarden Secrets Manager machine account access token.
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), secretx_core::SecretError> {
//! use secretx_bitwarden::BitwardenBackend;
//! use secretx_core::SecretStore;
//!
//! // BWS_ACCESS_TOKEN must be set in the environment.
//! let store = BitwardenBackend::from_uri("secretx://bitwarden/my-project/my-secret")?;
//! let value = store.get("secretx://bitwarden/my-project/my-secret").await?;
//! # Ok(())
//! # }
//! ```

use bitwarden::{
    Client,
    auth::login::AccessTokenLoginRequest,
    secrets_manager::{
        ClientProjectsExt, ClientSecretsExt,
        projects::ProjectsListRequest,
        secrets::{SecretGetRequest, SecretIdentifiersByProjectRequest},
    },
};
use secretx_core::{SecretError, SecretStore, SecretUri, SecretValue};
use zeroize::Zeroizing;

const BACKEND: &str = "bitwarden";

/// Backend that reads secrets from Bitwarden Secrets Manager.
///
/// Construct with [`from_uri`](BitwardenBackend::from_uri). Authenticates
/// lazily on the first [`get`](SecretStore::get) call using the
/// `BWS_ACCESS_TOKEN` environment variable.
pub struct BitwardenBackend {
    access_token: Zeroizing<String>,
    project_name: String,
    secret_name: String,
}

impl BitwardenBackend {
    /// Construct from a `secretx://bitwarden/<project-name>/<secret-name>` URI.
    ///
    /// Reads the `BWS_ACCESS_TOKEN` environment variable at construction time.
    /// No network call is made until [`get`](SecretStore::get) is called.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::InvalidUri`] if the URI does not match the
    /// expected format or does not name the `bitwarden` backend.
    ///
    /// Returns [`SecretError::Unavailable`] if `BWS_ACCESS_TOKEN` is not set.
    pub fn from_uri(uri: &str) -> Result<Self, SecretError> {
        let parsed = SecretUri::parse(uri)?;
        if parsed.backend != BACKEND {
            return Err(SecretError::InvalidUri(format!(
                "expected backend `{BACKEND}`, got `{}`",
                parsed.backend
            )));
        }

        // path is "<project-name>/<secret-name>"
        let (project_name, secret_name) = parsed.path.split_once('/').ok_or_else(|| {
            SecretError::InvalidUri(format!(
                "bitwarden URI requires `<project-name>/<secret-name>`, got path: `{}`",
                parsed.path
            ))
        })?;

        if project_name.is_empty() || secret_name.is_empty() {
            return Err(SecretError::InvalidUri(
                "bitwarden URI: project-name and secret-name must not be empty".into(),
            ));
        }

        let access_token = std::env::var("BWS_ACCESS_TOKEN").map_err(|_| {
            SecretError::Unavailable {
                backend: BACKEND,
                source: "BWS_ACCESS_TOKEN environment variable is not set".into(),
            }
        })?;

        Ok(Self {
            access_token: Zeroizing::new(access_token),
            project_name: project_name.to_owned(),
            secret_name: secret_name.to_owned(),
        })
    }
}

/// Create an authenticated Bitwarden client using the given access token.
///
/// Returns the client and the organization UUID extracted from the JWT token
/// embedded in the access token.
async fn build_authed_client(
    access_token: &str,
) -> Result<(Client, uuid::Uuid), SecretError> {
    let client = Client::new(None);

    let auth_resp = client
        .auth()
        .login_access_token(&AccessTokenLoginRequest {
            access_token: access_token.to_string(),
            state_file: None,
        })
        .await
        .map_err(|e| SecretError::Unavailable {
            backend: BACKEND,
            source: e.into(),
        })?;

    if !auth_resp.authenticated {
        return Err(SecretError::Unavailable {
            backend: BACKEND,
            source: "access token login did not authenticate".into(),
        });
    }

    let org_id: uuid::Uuid = client
        .internal
        .get_access_token_organization()
        .ok_or_else(|| SecretError::Unavailable {
            backend: BACKEND,
            source: "could not determine organization ID from access token".into(),
        })?
        .into();

    Ok((client, org_id))
}

/// Resolve `project_name` to its UUID by listing all projects in the org.
async fn resolve_project_id(
    client: &Client,
    org_id: uuid::Uuid,
    project_name: &str,
) -> Result<uuid::Uuid, SecretError> {
    let resp = client
        .projects()
        .list(&ProjectsListRequest {
            organization_id: org_id,
        })
        .await
        .map_err(|e| SecretError::Backend {
            backend: BACKEND,
            source: e.into(),
        })?;

    resp.data
        .into_iter()
        .find(|p| p.name == project_name)
        .map(|p| p.id)
        .ok_or(SecretError::NotFound)
}

/// Find the secret UUID within a project by secret name.
async fn resolve_secret_id(
    client: &Client,
    project_id: uuid::Uuid,
    secret_name: &str,
) -> Result<uuid::Uuid, SecretError> {
    let resp = client
        .secrets()
        .list_by_project(&SecretIdentifiersByProjectRequest {
            project_id,
        })
        .await
        .map_err(|e| SecretError::Backend {
            backend: BACKEND,
            source: e.into(),
        })?;

    resp.data
        .into_iter()
        .find(|s| s.key == secret_name)
        .map(|s| s.id)
        .ok_or(SecretError::NotFound)
}

/// Fetch the secret value: resolve names to UUIDs, then get the secret.
async fn fetch(
    access_token: &str,
    project_name: &str,
    secret_name: &str,
) -> Result<SecretValue, SecretError> {
    let (client, org_id) = build_authed_client(access_token).await?;

    let project_id = resolve_project_id(&client, org_id, project_name).await?;
    let secret_id = resolve_secret_id(&client, project_id, secret_name).await?;

    let secret_resp = client
        .secrets()
        .get(&SecretGetRequest { id: secret_id })
        .await
        .map_err(|e| SecretError::Backend {
            backend: BACKEND,
            source: e.into(),
        })?;

    Ok(SecretValue::new(secret_resp.value.into_bytes()))
}

#[async_trait::async_trait]
impl SecretStore for BitwardenBackend {
    async fn get(&self, _name: &str) -> Result<SecretValue, SecretError> {
        fetch(&self.access_token, &self.project_name, &self.secret_name).await
    }

    async fn put(&self, _name: &str, _value: SecretValue) -> Result<(), SecretError> {
        Err(SecretError::Unavailable {
            backend: BACKEND,
            source: "put is not supported by the Bitwarden Secrets Manager backend".into(),
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
    use std::sync::Mutex;

    // Serialize all tests that read or write BWS_ACCESS_TOKEN to prevent races.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn from_uri_wrong_backend() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("BWS_ACCESS_TOKEN", "dummy") };
        assert!(matches!(
            BitwardenBackend::from_uri("secretx://env/FOO"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_wrong_scheme() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("BWS_ACCESS_TOKEN", "dummy") };
        assert!(matches!(
            BitwardenBackend::from_uri("https://bitwarden/proj/sec"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_missing_secret_name() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("BWS_ACCESS_TOKEN", "dummy") };
        assert!(matches!(
            BitwardenBackend::from_uri("secretx://bitwarden/only-project"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_empty_project() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("BWS_ACCESS_TOKEN", "dummy") };
        assert!(matches!(
            BitwardenBackend::from_uri("secretx://bitwarden//secret-name"),
            Err(SecretError::InvalidUri(_))
        ));
    }

    #[test]
    fn from_uri_missing_token() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::remove_var("BWS_ACCESS_TOKEN") };
        assert!(matches!(
            BitwardenBackend::from_uri("secretx://bitwarden/proj/sec"),
            Err(SecretError::Unavailable { .. })
        ));
    }

    #[test]
    fn from_uri_valid() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe { std::env::set_var("BWS_ACCESS_TOKEN", "dummy-token") };
        let backend = BitwardenBackend::from_uri("secretx://bitwarden/my-project/my-secret");
        assert!(backend.is_ok());
        let b = backend.unwrap();
        assert_eq!(b.project_name, "my-project");
        assert_eq!(b.secret_name, "my-secret");
    }

    // Integration tests — skipped unless BWS_ACCESS_TOKEN is set AND
    // SECRETX_BWS_TEST=1.

    #[tokio::test]
    async fn integration_get() {
        if std::env::var("SECRETX_BWS_TEST").as_deref() != Ok("1") {
            return;
        }
        let project = match std::env::var("SECRETX_BWS_TEST_PROJECT") {
            Ok(p) => p,
            Err(_) => return,
        };
        let secret = match std::env::var("SECRETX_BWS_TEST_SECRET") {
            Ok(s) => s,
            Err(_) => return,
        };
        let uri = format!("secretx://bitwarden/{project}/{secret}");
        let store = BitwardenBackend::from_uri(&uri).unwrap();
        let value = store.get(&uri).await.unwrap();
        assert!(!value.as_bytes().is_empty());
    }
}

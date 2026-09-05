use crate::oauth::{ClientRegistry, FirstPartyClient, RedirectKind, RegisteredRedirect};
use serde::Deserialize;
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
use thiserror::Error;
use url::Url;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Development,
    Production,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub mode: Mode,
    pub issuer: Url,
    pub bind: std::net::SocketAddr,
    pub database: DatabaseConfig,
    pub signing: SigningConfig,
    #[serde(default)]
    pub authorization: Option<AuthorizationConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationConfig {
    pub google: Option<GoogleClientConfig>,
    pub clients: Vec<ClientDeclaration>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoogleClientConfig {
    pub client_id: String,
    pub client_secret_env: String,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientDeclaration {
    pub id: String,
    pub display_name: String,
    pub redirects: Vec<RedirectDeclaration>,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub resources: Vec<String>,
    pub default_resource: Option<String>,
    #[serde(default)]
    pub browser_origins: Vec<String>,
    #[serde(default)]
    pub post_logout_redirects: Vec<String>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedirectDeclaration {
    pub uri: String,
    pub kind: ConfiguredRedirectKind,
}
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfiguredRedirectKind {
    Exact,
    NativeLoopback,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    pub url: Option<String>,
    #[serde(default = "default_database_env")]
    pub url_env: String,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    #[serde(default = "default_min_connections")]
    pub min_connections: u32,
    #[serde(default = "default_timeout")]
    pub connect_timeout_seconds: u64,
    #[serde(default = "default_timeout")]
    pub acquire_timeout_seconds: u64,
    #[serde(default = "default_ready_timeout")]
    pub readiness_timeout_milliseconds: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningConfig {
    pub manifest: PathBuf,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("cannot read configuration: {0}")]
    Read(#[from] std::io::Error),
    #[error("invalid TOML configuration")]
    Parse,
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = fs::read_to_string(path)?;
        let mut config: Self = toml::from_str(&text).map_err(|_| ConfigError::Parse)?;
        if config.signing.manifest.is_relative() {
            let parent = path.parent().unwrap_or_else(|| Path::new("."));
            config.signing.manifest = parent.join(&config.signing.manifest);
        }
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.issuer.cannot_be_a_base() || self.issuer.host_str().is_none() {
            return Err(invalid("issuer must be an absolute URL"));
        }
        if !self.issuer.username().is_empty()
            || self.issuer.password().is_some()
            || self.issuer.query().is_some()
            || self.issuer.fragment().is_some()
        {
            return Err(invalid(
                "issuer cannot contain credentials, query, or fragment",
            ));
        }
        if self.issuer.path() != "/" {
            return Err(invalid("issuer path is not supported"));
        }
        match self.mode {
            Mode::Production if self.issuer.scheme() != "https" => {
                return Err(invalid("production issuer must use HTTPS"));
            }
            Mode::Development
                if self.issuer.scheme() == "http" && !is_loopback_url(&self.issuer) =>
            {
                return Err(invalid("development HTTP issuer must use a loopback IP"));
            }
            Mode::Development if !matches!(self.issuer.scheme(), "http" | "https") => {
                return Err(invalid("issuer must use HTTP or HTTPS"));
            }
            _ => {}
        }
        if !self.bind.ip().is_loopback() {
            return Err(invalid("bind address must be an explicit loopback IP"));
        }
        if self.bind.port() == 0 {
            return Err(invalid("bind port must be non-zero"));
        }
        if self.database.max_connections == 0
            || self.database.min_connections > self.database.max_connections
        {
            return Err(invalid("database pool bounds are invalid"));
        }
        if self.database.url_env.trim().is_empty() {
            return Err(invalid("database url_env cannot be empty"));
        }
        if let Some(auth) = &self.authorization
            && (auth.clients.is_empty()
                || auth.google.as_ref().is_some_and(|g| {
                    g.client_id.trim().is_empty() || g.client_secret_env.trim().is_empty()
                })
                || self.authorization_registry().is_err())
        {
            return Err(invalid("authorization configuration is invalid"));
        }
        Ok(())
    }
    pub fn authorization_registry(&self) -> Result<Option<ClientRegistry>, ConfigError> {
        self.authorization
            .as_ref()
            .map(|auth| {
                let clients = auth
                    .clients
                    .iter()
                    .map(|c| {
                        let redirects = c
                            .redirects
                            .iter()
                            .map(|r| {
                                RegisteredRedirect::new(
                                    r.uri.clone(),
                                    match r.kind {
                                        ConfiguredRedirectKind::Exact => RedirectKind::Exact,
                                        ConfiguredRedirectKind::NativeLoopback => {
                                            RedirectKind::NativeLoopback
                                        }
                                    },
                                )
                            })
                            .collect::<Result<Vec<_>, _>>()
                            .map_err(|_| invalid("authorization client redirect is invalid"))?;
                        FirstPartyClient::new(
                            c.id.clone(),
                            c.display_name.clone(),
                            redirects,
                            c.scopes.clone(),
                            c.resources.clone(),
                            c.default_resource.clone(),
                            c.browser_origins.clone(),
                            c.post_logout_redirects.clone(),
                        )
                        .map_err(|_| invalid("authorization client is invalid"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                ClientRegistry::with_issuer(clients, &self.issuer)
                    .map_err(|_| invalid("authorization registry is invalid"))
            })
            .transpose()
    }
}

impl DatabaseConfig {
    pub fn resolved_url(&self) -> Result<String, ConfigError> {
        match std::env::var(&self.url_env) {
            Ok(value) if !value.is_empty() => Ok(value),
            _ => self
                .url
                .clone()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| invalid("database URL is not configured")),
        }
    }
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_secs(self.connect_timeout_seconds)
    }
    pub fn acquire_timeout(&self) -> Duration {
        Duration::from_secs(self.acquire_timeout_seconds)
    }
    pub fn readiness_timeout(&self) -> Duration {
        Duration::from_millis(self.readiness_timeout_milliseconds)
    }
}

fn is_loopback_url(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        _ => false,
    }
}
fn invalid(message: &str) -> ConfigError {
    ConfigError::Invalid(message.into())
}
fn default_database_env() -> String {
    "ERI_DATABASE_URL".into()
}
fn default_max_connections() -> u32 {
    10
}
fn default_min_connections() -> u32 {
    1
}
fn default_timeout() -> u64 {
    5
}
fn default_ready_timeout() -> u64 {
    500
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config(mode: Mode, issuer: &str, bind: &str) -> Config {
        Config {
            mode,
            issuer: Url::parse(issuer).unwrap(),
            bind: bind.parse().unwrap(),
            database: DatabaseConfig {
                url: Some("postgres://invalid".into()),
                url_env: "UNSET_ERI_TEST_URL".into(),
                max_connections: 2,
                min_connections: 0,
                connect_timeout_seconds: 1,
                acquire_timeout_seconds: 1,
                readiness_timeout_milliseconds: 10,
            },
            signing: SigningConfig {
                manifest: "keys.json".into(),
            },
            authorization: None,
        }
    }
    #[test]
    fn production_requires_https() {
        assert!(
            config(
                Mode::Production,
                "http://auth.example:8080",
                "127.0.0.1:8080"
            )
            .validate()
            .is_err()
        );
    }
    #[test]
    fn development_http_requires_ip_loopback() {
        assert!(
            config(Mode::Development, "http://localhost:8080", "127.0.0.1:8080")
                .validate()
                .is_err()
        );
    }
    #[test]
    fn issuer_rejects_ambiguous_parts() {
        assert!(
            config(
                Mode::Production,
                "https://u:p@auth.example/path?q=1",
                "127.0.0.1:8080"
            )
            .validate()
            .is_err()
        );
    }
    #[test]
    fn bind_requires_loopback_and_port() {
        assert!(
            config(Mode::Production, "https://auth.example", "0.0.0.0:8080")
                .validate()
                .is_err()
        );
    }
    #[test]
    fn explicit_development_is_valid() {
        assert!(
            config(Mode::Development, "http://127.0.0.1:8082", "127.0.0.1:8082")
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn development_accepts_ipv6_loopback_and_rejects_issuer_paths() {
        assert!(
            config(Mode::Development, "http://[::1]:8082", "[::1]:8082")
                .validate()
                .is_ok()
        );
        assert!(
            config(
                Mode::Development,
                "http://127.0.0.1:8082/path",
                "127.0.0.1:8082"
            )
            .validate()
            .is_err()
        );
    }

    #[test]
    fn typed_authorization_builds_reviewed_client_policy() {
        let mut value = config(Mode::Production, "https://auth.example", "127.0.0.1:8080");
        value.authorization = Some(AuthorizationConfig {
            google: Some(GoogleClientConfig {
                client_id: "google-client".into(),
                client_secret_env: "ERI_GOOGLE_CLIENT_SECRET".into(),
            }),
            clients: vec![ClientDeclaration {
                id: "web".into(),
                display_name: "Web application".into(),
                redirects: vec![RedirectDeclaration {
                    uri: "https://app.example/callback".into(),
                    kind: ConfiguredRedirectKind::Exact,
                }],
                scopes: vec!["openid".into()],
                resources: vec![],
                default_resource: None,
                browser_origins: vec!["https://app.example".into()],
                post_logout_redirects: vec!["https://app.example/signed-out".into()],
            }],
        });
        value.validate().unwrap();
        let registry = value.authorization_registry().unwrap().unwrap();
        assert!(registry.trusted_redirect("web", "https://app.example/callback"));
        assert!(!registry.trusted_redirect("web", "https://app.example/signed-out"));
        assert!(registry.valid_post_logout_redirect("web", "https://app.example/signed-out"));
    }

    #[test]
    fn typed_authorization_rejects_unreviewed_or_ambiguous_values() {
        let mut value = config(Mode::Production, "https://auth.example", "127.0.0.1:8080");
        value.authorization = Some(AuthorizationConfig {
            google: Some(GoogleClientConfig {
                client_id: " ".into(),
                client_secret_env: "ERI_GOOGLE_CLIENT_SECRET".into(),
            }),
            clients: vec![],
        });
        assert!(value.validate().is_err());
    }

    #[test]
    fn malformed_toml_error_does_not_disclose_source_values() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("eri.toml");
        let sentinel = "SENTINEL_DATABASE_SECRET";
        fs::write(&path, format!("mode = [\"{sentinel}\"\n")).unwrap();
        let error = Config::load(&path).unwrap_err();
        assert!(!format!("{error}").contains(sentinel));
        assert!(!format!("{error:?}").contains(sentinel));
        let wrapped = anyhow::Error::new(error);
        assert!(!format!("{wrapped:#}").contains(sentinel));
        assert!(!format!("{wrapped:?}").contains(sentinel));
    }
}

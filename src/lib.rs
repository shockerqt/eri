pub mod config;
pub mod credentials;
pub mod database;
pub mod identity;
pub mod keys;
pub mod oauth;
mod web;

pub use config::Config;
pub use credentials::{
    AuthorizationCode, CredentialError, CredentialStore, ExchangeResult, ProviderSession,
    RefreshToken,
};
pub use database::Database;
pub use identity::{AuthenticatedUser, ExternalIdentity};
pub use keys::SigningKeys;
pub use oauth::{
    AuthorizationRequest, ClientRegistry, FirstPartyClient, OAuthError, RedirectKind,
    RegisteredRedirect, ValidatedAuthorizationGrant, s256_challenge, verify_s256,
};
pub use web::{AppState, router};

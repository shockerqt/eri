pub mod browser;
pub mod config;
pub mod credentials;
pub mod database;
pub mod google;
pub mod identity;
pub mod keys;
pub mod oauth;
mod web;

pub use browser::{
    BrowserError, BrowserStart, BrowserStore, CallbackClaim, ConsentHandle, ConsentOutcome,
    DenialOutcome, LoginCompletion,
};
pub use config::Config;
pub use credentials::{
    AuthorizationCode, CredentialError, CredentialStore, ExchangeResult, ProviderSession,
    RefreshToken,
};
pub use database::{Database, UserProfile};
pub use google::{GoogleAdapter, GoogleError, VerifiedGoogleIdentity};
pub use identity::{AuthenticatedUser, ExternalIdentity};
pub use keys::SigningKeys;
pub use oauth::{
    AuthorizationRequest, ClientRegistry, FirstPartyClient, OAuthError, PendingAuthorizationGrant,
    RedirectKind, RegisteredRedirect, ValidatedAuthorizationGrant, s256_challenge, verify_s256,
};
pub use web::{AppState, router};

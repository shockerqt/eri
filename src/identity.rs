use thiserror::Error;
use uuid::Uuid;

pub const GOOGLE_ISSUER: &str = "https://accounts.google.com";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalIdentity {
    issuer: &'static str,
    subject: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthenticatedUser(Uuid);

impl AuthenticatedUser {
    pub(crate) fn new(id: Uuid) -> Self {
        Self(id)
    }
    pub(crate) fn id(self) -> Uuid {
        self.0
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IdentityError {
    #[error("unsupported external identity issuer")]
    UnsupportedIssuer,
    #[error("external identity subject is empty")]
    EmptySubject,
}

impl ExternalIdentity {
    pub fn google(issuer: &str, subject: impl Into<String>) -> Result<Self, IdentityError> {
        if !matches!(issuer, "accounts.google.com" | GOOGLE_ISSUER) {
            return Err(IdentityError::UnsupportedIssuer);
        }
        let subject = subject.into();
        if subject.is_empty() {
            return Err(IdentityError::EmptySubject);
        }
        Ok(Self {
            issuer: GOOGLE_ISSUER,
            subject,
        })
    }

    pub fn issuer(&self) -> &'static str {
        self.issuer
    }
    pub fn subject(&self) -> &str {
        &self.subject
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_only_documented_google_issuer_forms() {
        let bare = ExternalIdentity::google("accounts.google.com", "subject").unwrap();
        let https = ExternalIdentity::google("https://accounts.google.com", "subject").unwrap();
        assert_eq!(bare, https);
        assert_eq!(bare.issuer(), GOOGLE_ISSUER);
        assert!(ExternalIdentity::google("HTTPS://ACCOUNTS.GOOGLE.COM", "subject").is_err());
        assert!(ExternalIdentity::google("https://accounts.google.com/", "subject").is_err());
        assert!(ExternalIdentity::google("https://other.example", "subject").is_err());
        assert!(ExternalIdentity::google(GOOGLE_ISSUER, "").is_err());
    }
}

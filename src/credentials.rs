use crate::{
    AuthenticatedUser,
    oauth::{ValidatedAuthorizationGrant, verify_s256},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use std::{fmt, time::Duration};
use thiserror::Error;
use uuid::Uuid;

pub struct AuthorizationCode {
    raw: String,
}
pub struct RefreshToken {
    raw: String,
}
pub struct ProviderSession {
    raw: String,
    pub(crate) id: Uuid,
    expires_at: DateTime<Utc>,
}

macro_rules! redacted_debug {
    ($type:ty, $name:literal) => {
        impl fmt::Debug for $type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!($name, "([REDACTED])"))
            }
        }
    };
}
redacted_debug!(AuthorizationCode, "AuthorizationCode");
redacted_debug!(RefreshToken, "RefreshToken");
redacted_debug!(ProviderSession, "ProviderSession");

impl AuthorizationCode {
    pub fn expose(&self) -> &str {
        &self.raw
    }
}
impl RefreshToken {
    pub fn expose(&self) -> &str {
        &self.raw
    }
}
impl ProviderSession {
    pub fn expose(&self) -> &str {
        &self.raw
    }
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

#[derive(Clone)]
pub struct CredentialStore {
    pool: PgPool,
}

#[derive(Debug)]
pub struct ExchangeResult {
    pub user_id: Uuid,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub resource: String,
    pub refresh_token: Option<RefreshToken>,
    pub oidc_nonce: Option<String>,
    pub upstream_auth_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("invalid grant")]
    InvalidGrant,
    #[error("credential lifetime is invalid")]
    InvalidLifetime,
    #[error("credential persistence failed")]
    Database(#[from] sqlx::Error),
}

impl CredentialStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create_provider_session(
        &self,
        user: AuthenticatedUser,
        lifetime: Duration,
    ) -> Result<ProviderSession, CredentialError> {
        let seconds = bounded_seconds(lifetime, 30 * 24 * 60 * 60)?;
        let raw = random_credential();
        let id = Uuid::new_v4();
        let expires_at: DateTime<Utc> = sqlx::query_scalar("INSERT INTO provider_sessions (id,token_hash,user_id,auth_time,expires_at,upstream_auth_time) SELECT $1,$2,$3,t,t + make_interval(secs => $4::double precision),$5 FROM (SELECT clock_timestamp() AS t) now RETURNING expires_at")
            .bind(id).bind(hash(&raw)).bind(user.id()).bind(seconds).bind(user.upstream_auth_time()).fetch_one(&self.pool).await?;
        Ok(ProviderSession {
            raw,
            id,
            expires_at,
        })
    }

    pub async fn find_provider_session(
        &self,
        raw: &str,
    ) -> Result<ProviderSession, CredentialError> {
        let row: Option<(Uuid, DateTime<Utc>)> = sqlx::query_as("SELECT id,expires_at FROM provider_sessions WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at > clock_timestamp()")
            .bind(hash(raw)).fetch_optional(&self.pool).await?;
        row.map(|(id, expires_at)| ProviderSession {
            raw: raw.to_owned(),
            id,
            expires_at,
        })
        .ok_or(CredentialError::InvalidGrant)
    }

    pub async fn issue_authorization_code(
        &self,
        session: &ProviderSession,
        grant: &ValidatedAuthorizationGrant,
        lifetime: Duration,
    ) -> Result<AuthorizationCode, CredentialError> {
        let seconds = bounded_seconds(lifetime, 60)?;
        let mut tx = self.pool.begin().await?;
        let locked: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM provider_sessions WHERE id=$1 FOR UPDATE")
                .bind(session.id)
                .fetch_optional(&mut *tx)
                .await?;
        if locked.is_none() {
            return Err(CredentialError::InvalidGrant);
        }
        let active: bool = sqlx::query_scalar(
            "SELECT revoked_at IS NULL AND expires_at > clock_timestamp() FROM provider_sessions WHERE id=$1",
        )
        .bind(session.id)
        .fetch_one(&mut *tx)
        .await?;
        if !active {
            return Err(CredentialError::InvalidGrant);
        }
        let upstream_auth_time: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT upstream_auth_time FROM provider_sessions WHERE id=$1")
                .bind(session.id)
                .fetch_one(&mut *tx)
                .await?;
        let code = insert_authorization_code_tx(
            &mut tx,
            session.id,
            grant,
            None,
            upstream_auth_time,
            seconds,
        )
        .await?;
        tx.commit().await?;
        Ok(code)
    }

    pub async fn exchange_code(
        &self,
        raw: &str,
        client_id: &str,
        redirect_uri: &str,
        resource: &str,
        verifier: &str,
    ) -> Result<ExchangeResult, CredentialError> {
        let mut tx = self.pool.begin().await?;
        let code: Option<CodeRow> = sqlx::query_as("SELECT id,session_id,client_id,redirect_uri,scopes,resource,code_challenge,issue_refresh_token,oidc_nonce,upstream_auth_time FROM authorization_codes WHERE code_hash=$1").bind(hash(raw)).fetch_optional(&mut *tx).await?;
        let Some(code) = code else {
            return Err(CredentialError::InvalidGrant);
        };
        // Bindings are validated before replay can mutate the grant.
        if code.client_id != client_id
            || code.redirect_uri.as_bytes() != redirect_uri.as_bytes()
            || code.resource.as_bytes() != resource.as_bytes()
            || !verify_s256(verifier, &code.code_challenge)
        {
            return Err(CredentialError::InvalidGrant);
        }
        let session: Option<SessionRow> = sqlx::query_as(
            "SELECT user_id,expires_at,revoked_at FROM provider_sessions WHERE id=$1 FOR UPDATE",
        )
        .bind(code.session_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(session) = session else {
            return Err(CredentialError::InvalidGrant);
        };
        let locked: CodeState = sqlx::query_as(
            "SELECT expires_at,consumed_at FROM authorization_codes WHERE id=$1 FOR UPDATE",
        )
        .bind(code.id)
        .fetch_one(&mut *tx)
        .await?;
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        if locked.consumed_at.is_some() {
            sqlx::query("UPDATE refresh_families SET revoked_at=COALESCE(revoked_at,$2) WHERE source_code_id=$1").bind(code.id).bind(now).execute(&mut *tx).await?;
            tx.commit().await?;
            return Err(CredentialError::InvalidGrant);
        }
        if locked.expires_at <= now || session.expires_at <= now || session.revoked_at.is_some() {
            return Err(CredentialError::InvalidGrant);
        }
        sqlx::query("UPDATE authorization_codes SET consumed_at=$2 WHERE id=$1")
            .bind(code.id)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        let refresh_token = if code.issue_refresh_token {
            let family_id = Uuid::new_v4();
            sqlx::query("INSERT INTO refresh_families (id,source_code_id,session_id,user_id,client_id,scopes,resource,issued_at,expires_at,upstream_auth_time) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,LEAST($8 + interval '30 days',$9),$10)")
                .bind(family_id).bind(code.id).bind(code.session_id).bind(session.user_id).bind(&code.client_id).bind(&code.scopes).bind(&code.resource).bind(now).bind(session.expires_at).bind(code.upstream_auth_time).execute(&mut *tx).await?;
            Some(insert_refresh(&mut tx, family_id, now).await?)
        } else {
            None
        };
        tx.commit().await?;
        Ok(ExchangeResult {
            user_id: session.user_id,
            client_id: code.client_id,
            scopes: code.scopes,
            resource: code.resource,
            refresh_token,
            oidc_nonce: code.oidc_nonce,
            upstream_auth_time: code.upstream_auth_time,
        })
    }

    pub async fn rotate_refresh(
        &self,
        raw: &str,
        client_id: &str,
        resource: &str,
    ) -> Result<ExchangeResult, CredentialError> {
        let mut tx = self.pool.begin().await?;
        let lookup: Option<TokenLookup> = sqlx::query_as("SELECT m.id,m.family_id,f.session_id FROM refresh_token_members m JOIN refresh_families f ON f.id=m.family_id WHERE m.token_hash=$1").bind(hash(raw)).fetch_optional(&mut *tx).await?;
        let Some(lookup) = lookup else {
            return Err(CredentialError::InvalidGrant);
        };
        let session: SessionRow = sqlx::query_as(
            "SELECT user_id,expires_at,revoked_at FROM provider_sessions WHERE id=$1 FOR UPDATE",
        )
        .bind(lookup.session_id)
        .fetch_one(&mut *tx)
        .await?;
        let family: FamilyRow = sqlx::query_as("SELECT client_id,scopes,resource,expires_at,revoked_at,upstream_auth_time FROM refresh_families WHERE id=$1 FOR UPDATE").bind(lookup.family_id).fetch_one(&mut *tx).await?;
        let member: MemberRow =
            sqlx::query_as("SELECT consumed_at FROM refresh_token_members WHERE id=$1 FOR UPDATE")
                .bind(lookup.id)
                .fetch_one(&mut *tx)
                .await?;
        // A wrong binding is not replay evidence and cannot revoke another grant.
        if family.client_id != client_id || family.resource.as_bytes() != resource.as_bytes() {
            return Err(CredentialError::InvalidGrant);
        }
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        if member.consumed_at.is_some() {
            sqlx::query(
                "UPDATE refresh_families SET revoked_at=COALESCE(revoked_at,$2) WHERE id=$1",
            )
            .bind(lookup.family_id)
            .bind(now)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Err(CredentialError::InvalidGrant);
        }
        if family.revoked_at.is_some()
            || session.revoked_at.is_some()
            || family.expires_at <= now
            || session.expires_at <= now
        {
            return Err(CredentialError::InvalidGrant);
        }
        let successor = insert_refresh(&mut tx, lookup.family_id, now).await?;
        let successor_id: Uuid =
            sqlx::query_scalar("SELECT id FROM refresh_token_members WHERE token_hash=$1")
                .bind(hash(successor.expose()))
                .fetch_one(&mut *tx)
                .await?;
        sqlx::query("UPDATE refresh_token_members SET consumed_at=$2,successor_id=$3 WHERE id=$1")
            .bind(lookup.id)
            .bind(now)
            .bind(successor_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(ExchangeResult {
            user_id: session.user_id,
            client_id: family.client_id,
            scopes: family.scopes,
            resource: family.resource,
            refresh_token: Some(successor),
            oidc_nonce: None,
            upstream_auth_time: family.upstream_auth_time,
        })
    }

    pub async fn revoke_refresh(&self, raw: &str, client_id: &str) -> Result<(), CredentialError> {
        let mut tx = self.pool.begin().await?;
        let lookup: Option<RevocationLookup> = sqlx::query_as("SELECT m.family_id,f.session_id,f.client_id FROM refresh_token_members m JOIN refresh_families f ON f.id=m.family_id WHERE m.token_hash=$1").bind(hash(raw)).fetch_optional(&mut *tx).await?;
        if let Some(lookup) = lookup.filter(|lookup| lookup.client_id == client_id) {
            sqlx::query("SELECT id FROM provider_sessions WHERE id=$1 FOR UPDATE")
                .bind(lookup.session_id)
                .fetch_one(&mut *tx)
                .await?;
            sqlx::query("SELECT id FROM refresh_families WHERE id=$1 FOR UPDATE")
                .bind(lookup.family_id)
                .fetch_one(&mut *tx)
                .await?;
            sqlx::query("UPDATE refresh_families SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE id=$1").bind(lookup.family_id).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn logout(&self, session: &ProviderSession) -> Result<(), CredentialError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT id FROM provider_sessions WHERE id=$1 FOR UPDATE")
            .bind(session.id)
            .fetch_one(&mut *tx)
            .await?;
        sqlx::query("UPDATE provider_sessions SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE id=$1").bind(session.id).execute(&mut *tx).await?;
        sqlx::query("UPDATE refresh_families SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE session_id=$1").bind(session.id).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
}

async fn insert_refresh(
    tx: &mut Transaction<'_, Postgres>,
    family_id: Uuid,
    now: DateTime<Utc>,
) -> Result<RefreshToken, sqlx::Error> {
    let token = RefreshToken {
        raw: random_credential(),
    };
    sqlx::query("INSERT INTO refresh_token_members (id,family_id,token_hash,issued_at) VALUES ($1,$2,$3,$4)").bind(Uuid::new_v4()).bind(family_id).bind(hash(&token.raw)).bind(now).execute(&mut **tx).await?;
    Ok(token)
}

pub(crate) async fn insert_authorization_code_tx(
    tx: &mut Transaction<'_, Postgres>,
    session_id: Uuid,
    grant: &ValidatedAuthorizationGrant,
    oidc_nonce: Option<&str>,
    upstream_auth_time: Option<DateTime<Utc>>,
    lifetime_seconds: f64,
) -> Result<AuthorizationCode, sqlx::Error> {
    let code = AuthorizationCode {
        raw: random_credential(),
    };
    sqlx::query("INSERT INTO authorization_codes (id,code_hash,session_id,client_id,redirect_uri,scopes,resource,code_challenge,issue_refresh_token,issued_at,expires_at,oidc_nonce,upstream_auth_time) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,t,LEAST(t + make_interval(secs => $10::double precision),(SELECT expires_at FROM provider_sessions WHERE id=$3)),$11,$12 FROM (SELECT clock_timestamp() AS t) now")
        .bind(Uuid::new_v4()).bind(hash(&code.raw)).bind(session_id).bind(grant.client_id()).bind(grant.redirect_uri()).bind(grant.scopes()).bind(grant.resource()).bind(grant.code_challenge()).bind(grant.issue_refresh_token()).bind(lifetime_seconds).bind(oidc_nonce).bind(upstream_auth_time).execute(&mut **tx).await?;
    Ok(code)
}

pub(crate) fn new_provider_session(
    raw: String,
    id: Uuid,
    expires_at: DateTime<Utc>,
) -> ProviderSession {
    ProviderSession {
        raw,
        id,
        expires_at,
    }
}
pub(crate) fn random_secret() -> String {
    random_credential()
}
pub(crate) fn secret_hash(raw: &str) -> Vec<u8> {
    hash(raw)
}

fn bounded_seconds(duration: Duration, maximum: u64) -> Result<f64, CredentialError> {
    if duration.is_zero() || duration.as_secs() > maximum || duration.subsec_nanos() != 0 {
        Err(CredentialError::InvalidLifetime)
    } else {
        Ok(duration.as_secs() as f64)
    }
}
fn random_credential() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
fn hash(raw: &str) -> Vec<u8> {
    Sha256::digest(raw.as_bytes()).to_vec()
}

#[derive(sqlx::FromRow)]
struct CodeRow {
    id: Uuid,
    session_id: Uuid,
    client_id: String,
    redirect_uri: String,
    scopes: Vec<String>,
    resource: String,
    code_challenge: String,
    issue_refresh_token: bool,
    oidc_nonce: Option<String>,
    upstream_auth_time: Option<DateTime<Utc>>,
}
#[derive(sqlx::FromRow)]
struct CodeState {
    expires_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
}
#[derive(sqlx::FromRow)]
struct SessionRow {
    user_id: Uuid,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}
#[derive(sqlx::FromRow)]
struct TokenLookup {
    id: Uuid,
    family_id: Uuid,
    session_id: Uuid,
}
#[derive(sqlx::FromRow)]
struct RevocationLookup {
    family_id: Uuid,
    session_id: Uuid,
    client_id: String,
}
#[derive(sqlx::FromRow)]
struct FamilyRow {
    client_id: String,
    scopes: Vec<String>,
    resource: String,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
    upstream_auth_time: Option<DateTime<Utc>>,
}
#[derive(sqlx::FromRow)]
struct MemberRow {
    consumed_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::{
        AuthorizationRequest, ClientRegistry, FirstPartyClient, RedirectKind, RegisteredRedirect,
        s256_challenge,
    };
    use sqlx::postgres::PgPoolOptions;

    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const REDIRECT: &str = "com.example:/oauth/callback?raw=%2F";
    const RESOURCE: &str = "https://api.example/resource";

    fn assert_isolated() {
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL required");
        assert!(
            url == std::env::var("ERI_TEST_DATABASE_URL").unwrap(),
            "database tests require the isolated test URL"
        );
        assert_eq!(url::Url::parse(&url).unwrap().path(), "/eri_inf008_test");
    }
    fn grant(offline: bool) -> ValidatedAuthorizationGrant {
        let client = FirstPartyClient::new(
            "mobile",
            "Mobile",
            vec![RegisteredRedirect::new(REDIRECT, RedirectKind::Exact).unwrap()],
            ["openid", "offline_access"],
            [RESOURCE],
            None,
            std::iter::empty::<String>(),
            std::iter::empty::<String>(),
        )
        .unwrap();
        let registry = ClientRegistry::new(vec![client]).unwrap();
        let scopes: &[&str] = if offline {
            &["openid", "offline_access"]
        } else {
            &["openid"]
        };
        registry
            .validate_pending(AuthorizationRequest {
                client_id: "mobile",
                redirect_uri: REDIRECT,
                response_type: "code",
                code_challenge_method: "S256",
                code_challenge: &s256_challenge(VERIFIER).unwrap(),
                scopes,
                resource: Some(RESOURCE),
            })
            .and_then(|pending| pending.approve(offline))
            .unwrap()
    }
    async fn setup(pool: &PgPool) -> (CredentialStore, ProviderSession) {
        assert_isolated();
        let user_id: Uuid = sqlx::query_scalar("INSERT INTO users DEFAULT VALUES RETURNING id")
            .fetch_one(pool)
            .await
            .unwrap();
        let store = CredentialStore::new(pool.clone());
        let session = store
            .create_provider_session(
                AuthenticatedUser::new(user_id, None),
                Duration::from_secs(20 * 24 * 60 * 60),
            )
            .await
            .unwrap();
        assert_eq!(session.expose().len(), 43);
        assert!(!format!("{session:?}").contains(session.expose()));
        (store, session)
    }
    async fn renewable(
        store: &CredentialStore,
        session: &ProviderSession,
    ) -> (AuthorizationCode, RefreshToken) {
        let code = store
            .issue_authorization_code(session, &grant(true), Duration::from_secs(45))
            .await
            .unwrap();
        let refresh = store
            .exchange_code(code.expose(), "mobile", REDIRECT, RESOURCE, VERIFIER)
            .await
            .unwrap()
            .refresh_token
            .unwrap();
        (code, refresh)
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn bindings_replay_and_restart_state(pool: PgPool) {
        let (store, session) = setup(&pool).await;
        let code = store
            .issue_authorization_code(&session, &grant(true), Duration::from_secs(45))
            .await
            .unwrap();
        for denied in [
            store
                .exchange_code(code.expose(), "other", REDIRECT, RESOURCE, VERIFIER)
                .await,
            store
                .exchange_code(
                    code.expose(),
                    "mobile",
                    "com.example:/wrong",
                    RESOURCE,
                    VERIFIER,
                )
                .await,
            store
                .exchange_code(
                    code.expose(),
                    "mobile",
                    REDIRECT,
                    "https://api.example/other",
                    VERIFIER,
                )
                .await,
            store
                .exchange_code(
                    code.expose(),
                    "mobile",
                    REDIRECT,
                    RESOURCE,
                    "wrong-verifier-value-that-is-long-enough-123456789",
                )
                .await,
        ] {
            assert!(matches!(denied, Err(CredentialError::InvalidGrant)));
        }
        let result = store
            .exchange_code(code.expose(), "mobile", REDIRECT, RESOURCE, VERIFIER)
            .await
            .unwrap();
        let refresh = result.refresh_token.unwrap();
        // Wrong-binding replay cannot revoke the legitimate family.
        assert!(
            store
                .exchange_code(code.expose(), "other", REDIRECT, RESOURCE, VERIFIER)
                .await
                .is_err()
        );
        let successor = store
            .rotate_refresh(refresh.expose(), "mobile", RESOURCE)
            .await
            .unwrap()
            .refresh_token
            .unwrap();
        assert!(
            store
                .exchange_code(code.expose(), "mobile", REDIRECT, RESOURCE, VERIFIER)
                .await
                .is_err()
        );
        let fresh_pool = PgPoolOptions::new()
            .max_connections(3)
            .connect_with((*pool.connect_options()).clone())
            .await
            .unwrap();
        let fresh = CredentialStore::new(fresh_pool);
        assert!(
            fresh
                .rotate_refresh(successor.expose(), "mobile", RESOURCE)
                .await
                .is_err()
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn session_recovers_by_hash_and_rejects_unknown_expired_revoked(pool: PgPool) {
        let (_store, session) = setup(&pool).await;
        let fresh_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_with((*pool.connect_options()).clone())
            .await
            .unwrap();
        let fresh = CredentialStore::new(fresh_pool);
        assert_eq!(
            fresh
                .find_provider_session(session.expose())
                .await
                .unwrap()
                .expires_at(),
            session.expires_at()
        );
        assert!(fresh.find_provider_session("unknown").await.is_err());
        sqlx::query("UPDATE provider_sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1").bind(session.id).execute(&pool).await.unwrap();
        assert!(fresh.find_provider_session(session.expose()).await.is_err());
        assert!(
            fresh
                .issue_authorization_code(&session, &grant(false), Duration::from_secs(30))
                .await
                .is_err()
        );
        sqlx::query("UPDATE provider_sessions SET expires_at=clock_timestamp()+interval '1 day',revoked_at=clock_timestamp() WHERE id=$1").bind(session.id).execute(&pool).await.unwrap();
        assert!(fresh.find_provider_session(session.expose()).await.is_err());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn database_time_rejects_expired_code_family_and_session(pool: PgPool) {
        let (store, session) = setup(&pool).await;
        let code = store
            .issue_authorization_code(&session, &grant(true), Duration::from_secs(30))
            .await
            .unwrap();
        sqlx::query(
            "UPDATE authorization_codes SET expires_at=clock_timestamp()-interval '1 second'",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            store
                .exchange_code(code.expose(), "mobile", REDIRECT, RESOURCE, VERIFIER)
                .await
                .is_err()
        );
        let code = store
            .issue_authorization_code(&session, &grant(true), Duration::from_secs(30))
            .await
            .unwrap();
        let refresh = store
            .exchange_code(code.expose(), "mobile", REDIRECT, RESOURCE, VERIFIER)
            .await
            .unwrap()
            .refresh_token
            .unwrap();
        sqlx::query("UPDATE refresh_families SET expires_at=clock_timestamp()-interval '1 second'")
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            store
                .rotate_refresh(refresh.expose(), "mobile", RESOURCE)
                .await
                .is_err()
        );
        sqlx::query("UPDATE refresh_families SET expires_at=clock_timestamp()+interval '1 day'")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE provider_sessions SET expires_at=clock_timestamp()-interval '1 second'",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            store
                .rotate_refresh(refresh.expose(), "mobile", RESOURCE)
                .await
                .is_err()
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn wrong_refresh_bindings_and_revocation_client_do_not_revoke(pool: PgPool) {
        let (store, session) = setup(&pool).await;
        let (_, refresh) = renewable(&store, &session).await;
        assert!(
            store
                .rotate_refresh(refresh.expose(), "other", RESOURCE)
                .await
                .is_err()
        );
        assert!(
            store
                .rotate_refresh(refresh.expose(), "mobile", "https://api.example/other")
                .await
                .is_err()
        );
        store
            .revoke_refresh(refresh.expose(), "other")
            .await
            .unwrap();
        let successor = store
            .rotate_refresh(refresh.expose(), "mobile", RESOURCE)
            .await
            .unwrap()
            .refresh_token
            .unwrap();
        store
            .revoke_refresh(successor.expose(), "mobile")
            .await
            .unwrap();
        assert!(
            store
                .rotate_refresh(successor.expose(), "mobile", RESOURCE)
                .await
                .is_err()
        );
        store.revoke_refresh("unknown", "mobile").await.unwrap();
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn concurrent_refresh_replay_invalidates_winner(pool: PgPool) {
        let (store, session) = setup(&pool).await;
        let (_, refresh) = renewable(&store, &session).await;
        let (a, b) = tokio::join!(
            store.rotate_refresh(refresh.expose(), "mobile", RESOURCE),
            store.rotate_refresh(refresh.expose(), "mobile", RESOURCE)
        );
        let (winner, loser) = if a.is_ok() {
            (a.unwrap(), b)
        } else {
            (b.unwrap(), a)
        };
        assert!(loser.is_err());
        assert!(
            store
                .rotate_refresh(winner.refresh_token.unwrap().expose(), "mobile", RESOURCE)
                .await
                .is_err()
        );
        let revoked: bool =
            sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM refresh_families")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(revoked);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn concurrent_code_exchange_has_one_success_and_revokes_family(pool: PgPool) {
        let (store, session) = setup(&pool).await;
        let code = store
            .issue_authorization_code(&session, &grant(true), Duration::from_secs(30))
            .await
            .unwrap();
        let (a, b) = tokio::join!(
            store.exchange_code(code.expose(), "mobile", REDIRECT, RESOURCE, VERIFIER),
            store.exchange_code(code.expose(), "mobile", REDIRECT, RESOURCE, VERIFIER),
        );
        let (winner, loser) = if a.is_ok() {
            (a.unwrap(), b)
        } else {
            (b.unwrap(), a)
        };
        assert!(loser.is_err());
        assert!(
            store
                .rotate_refresh(winner.refresh_token.unwrap().expose(), "mobile", RESOURCE)
                .await
                .is_err()
        );
        let revoked: bool =
            sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM refresh_families")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(revoked);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn logout_races_cannot_leave_code_or_refresh_renewable(pool: PgPool) {
        let (store, session) = setup(&pool).await;
        let code = store
            .issue_authorization_code(&session, &grant(true), Duration::from_secs(30))
            .await
            .unwrap();
        let (exchange, logout) = tokio::join!(
            store.exchange_code(code.expose(), "mobile", REDIRECT, RESOURCE, VERIFIER),
            store.logout(&session)
        );
        logout.unwrap();
        if let Ok(result) = exchange {
            assert!(
                store
                    .rotate_refresh(result.refresh_token.unwrap().expose(), "mobile", RESOURCE)
                    .await
                    .is_err()
            );
        }
        let active: i64 =
            sqlx::query_scalar("SELECT count(*) FROM refresh_families WHERE revoked_at IS NULL")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(active, 0);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn logout_racing_refresh_cannot_leave_successor_renewable(pool: PgPool) {
        let (store, session) = setup(&pool).await;
        let (_, refresh) = renewable(&store, &session).await;
        let (rotation, logout) = tokio::join!(
            store.rotate_refresh(refresh.expose(), "mobile", RESOURCE),
            store.logout(&session),
        );
        logout.unwrap();
        if let Ok(result) = rotation {
            assert!(
                store
                    .rotate_refresh(result.refresh_token.unwrap().expose(), "mobile", RESOURCE)
                    .await
                    .is_err()
            );
        }
        let active: i64 =
            sqlx::query_scalar("SELECT count(*) FROM refresh_families WHERE revoked_at IS NULL")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(active, 0);
    }
}

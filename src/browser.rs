use crate::{
    ClientRegistry, PendingAuthorizationGrant, ProviderSession, VerifiedGoogleIdentity,
    credentials::{insert_authorization_code_tx, new_provider_session, random_secret, secret_hash},
    database::{lock_verified_google_identity_tx, upsert_verified_google_identity_tx},
    oauth::s256_challenge,
};
use chrono::{DateTime, Utc};
use sqlx::{Acquire, PgPool, Postgres, Transaction};
use std::{fmt, time::Duration};
use thiserror::Error;
use uuid::Uuid;

#[derive(Clone)]
pub struct BrowserStore {
    pool: PgPool,
}
pub struct BrowserStart {
    transaction_id: Uuid,
    upstream_state: String,
    browser_binding: String,
    upstream_nonce: String,
    upstream_verifier: String,
}
pub struct CallbackClaim {
    raw: String,
}
pub struct ConsentHandle {
    transaction_id: Uuid,
    csrf: String,
}
pub struct LoginCompletion {
    pub session: ProviderSession,
    pub consent: ConsentHandle,
}
pub struct ConsentOutcome {
    pub code: crate::AuthorizationCode,
    pub redirect_uri: String,
    pub downstream_state: Option<String>,
}
pub struct DenialOutcome {
    pub redirect_uri: String,
    pub downstream_state: Option<String>,
}

macro_rules! redacted {
    ($t:ty,$n:literal) => {
        impl fmt::Debug for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!($n, "([REDACTED])"))
            }
        }
    };
}
redacted!(BrowserStart, "BrowserStart");
redacted!(CallbackClaim, "CallbackClaim");
redacted!(ConsentHandle, "ConsentHandle");

impl BrowserStart {
    pub fn transaction_id(&self) -> Uuid {
        self.transaction_id
    }
    pub fn upstream_state(&self) -> &str {
        &self.upstream_state
    }
    pub fn browser_binding(&self) -> &str {
        &self.browser_binding
    }
    pub fn upstream_nonce(&self) -> &str {
        &self.upstream_nonce
    }
    pub fn upstream_verifier(&self) -> &str {
        &self.upstream_verifier
    }
    pub fn upstream_challenge(&self) -> String {
        s256_challenge(&self.upstream_verifier).expect("generated verifier is valid")
    }
}
impl CallbackClaim {
    pub fn expose(&self) -> &str {
        &self.raw
    }
}
impl ConsentHandle {
    pub fn transaction_id(&self) -> Uuid {
        self.transaction_id
    }
    pub fn csrf(&self) -> &str {
        &self.csrf
    }
}

#[derive(Debug, Error)]
pub enum BrowserError {
    #[error("browser authorization is invalid or expired")]
    Invalid,
    #[error("authorization policy changed")]
    PolicyChanged,
    #[error("browser authorization persistence failed")]
    Database(#[from] sqlx::Error),
}

impl BrowserStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
    pub async fn begin_google(
        &self,
        pending: &PendingAuthorizationGrant,
        downstream_state: Option<&str>,
        oidc_nonce: Option<&str>,
    ) -> Result<BrowserStart, BrowserError> {
        let start = BrowserStart {
            transaction_id: Uuid::new_v4(),
            upstream_state: random_secret(),
            browser_binding: random_secret(),
            upstream_nonce: random_secret(),
            upstream_verifier: random_secret(),
        };
        sqlx::query("INSERT INTO browser_authorizations(id,stage,upstream_state_hash,browser_binding_hash,upstream_nonce,upstream_verifier,client_id,redirect_uri,scopes,resource,code_challenge,downstream_state,oidc_nonce,created_at,expires_at) SELECT $1,'awaiting_google',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,t,t+interval '10 minutes' FROM(SELECT clock_timestamp()t)n")
   .bind(start.transaction_id).bind(secret_hash(&start.upstream_state)).bind(secret_hash(&start.browser_binding)).bind(&start.upstream_nonce).bind(&start.upstream_verifier).bind(pending.client_id()).bind(pending.redirect_uri()).bind(pending.scopes()).bind(pending.resource()).bind(pending.code_challenge()).bind(downstream_state).bind(oidc_nonce).execute(&self.pool).await?;
        Ok(start)
    }
    pub async fn begin_authenticated(
        &self,
        session: &ProviderSession,
        pending: &PendingAuthorizationGrant,
        downstream_state: Option<&str>,
        oidc_nonce: Option<&str>,
    ) -> Result<ConsentHandle, BrowserError> {
        let id = Uuid::new_v4();
        let csrf = random_secret();
        let mut tx = self.pool.begin().await?;
        let session_row = lock_session(&mut tx, session.id).await?;
        ensure_fresh(&mut tx, &session_row, None).await?;
        sqlx::query("INSERT INTO browser_authorizations(id,stage,csrf_hash,session_id,client_id,redirect_uri,scopes,resource,code_challenge,downstream_state,oidc_nonce,created_at,expires_at)SELECT $1,'awaiting_consent',$2,$3,$4,$5,$6,$7,$8,$9,$10,t,t+interval '10 minutes'FROM(SELECT clock_timestamp()t)n")
   .bind(id).bind(secret_hash(&csrf)).bind(session.id).bind(pending.client_id()).bind(pending.redirect_uri()).bind(pending.scopes()).bind(pending.resource()).bind(pending.code_challenge()).bind(downstream_state).bind(oidc_nonce).execute(&mut*tx).await?;
        tx.commit().await?;
        Ok(ConsentHandle {
            transaction_id: id,
            csrf,
        })
    }
    pub async fn claim_callback(
        &self,
        state: &str,
        binding: &str,
    ) -> Result<(CallbackClaim, String, String), BrowserError> {
        let claim = random_secret();
        let mut tx = self.pool.begin().await?;
        let row: Option<(Uuid, String, String, DateTime<Utc>)> = sqlx::query_as(
            "SELECT id,upstream_verifier,upstream_nonce,expires_at FROM browser_authorizations WHERE upstream_state_hash=$1 AND browser_binding_hash=$2 AND stage='awaiting_google' FOR UPDATE",
        )
        .bind(secret_hash(state))
        .bind(secret_hash(binding))
        .fetch_optional(&mut *tx)
        .await?;
        let Some((id, verifier, nonce, expires_at)) = row else {
            return Err(BrowserError::Invalid);
        };
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        if expires_at <= now {
            sqlx::query("UPDATE browser_authorizations SET stage='expired',upstream_verifier=NULL WHERE id=$1")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            return Err(BrowserError::Invalid);
        }
        sqlx::query("UPDATE browser_authorizations SET stage='callback_claimed',claim_hash=$2,upstream_verifier=NULL WHERE id=$1")
            .bind(id)
            .bind(secret_hash(&claim))
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok((CallbackClaim { raw: claim }, verifier, nonce))
    }
    pub async fn fail_callback(&self, claim: &CallbackClaim) -> Result<(), BrowserError> {
        let changed=sqlx::query("UPDATE browser_authorizations SET stage='failed' WHERE claim_hash=$1 AND stage='callback_claimed'").bind(secret_hash(&claim.raw)).execute(&self.pool).await?.rows_affected();
        if changed == 1 {
            Ok(())
        } else {
            Err(BrowserError::Invalid)
        }
    }
    pub async fn complete_callback(
        &self,
        claim: &CallbackClaim,
        identity: &VerifiedGoogleIdentity,
        session_lifetime: Duration,
    ) -> Result<LoginCompletion, BrowserError> {
        let seconds = bounded_seconds(session_lifetime, 30 * 24 * 60 * 60)?;
        let mut tx = self.pool.begin().await?;
        let row:Option<(Uuid,DateTime<Utc>)>=sqlx::query_as("SELECT id,expires_at FROM browser_authorizations WHERE claim_hash=$1 AND stage='callback_claimed' FOR UPDATE").bind(secret_hash(&claim.raw)).fetch_optional(&mut*tx).await?;
        let Some((transaction_id, expires)) = row else {
            return Err(BrowserError::Invalid);
        };
        let session_raw = random_secret();
        let session_id = Uuid::new_v4();
        let upstream_auth_time = identity
            .auth_time()
            .and_then(|v| DateTime::<Utc>::from_timestamp(v, 0));
        let mut staged = tx.begin().await?;
        lock_verified_google_identity_tx(&mut staged, identity).await?;
        let profile_time: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *staged)
            .await?;
        let user_id =
            upsert_verified_google_identity_tx(&mut staged, identity, profile_time).await?;
        let session_expiry:DateTime<Utc>=sqlx::query_scalar("INSERT INTO provider_sessions(id,token_hash,user_id,auth_time,expires_at,upstream_auth_time)VALUES($1,$2,$3,$4,$4+make_interval(secs=>$5::double precision),$6)RETURNING expires_at").bind(session_id).bind(secret_hash(&session_raw)).bind(user_id).bind(profile_time).bind(seconds).bind(upstream_auth_time).fetch_one(&mut*staged).await?;
        let final_now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *staged)
            .await?;
        if expires <= final_now {
            staged.rollback().await?;
            sqlx::query("UPDATE browser_authorizations SET stage='expired' WHERE id=$1")
                .bind(transaction_id)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            return Err(BrowserError::Invalid);
        }
        staged.commit().await?;
        let csrf = random_secret();
        let changed=sqlx::query("UPDATE browser_authorizations SET stage='awaiting_consent',session_id=$2,csrf_hash=$3,claim_hash=NULL WHERE id=$1 AND stage='callback_claimed'").bind(transaction_id).bind(session_id).bind(secret_hash(&csrf)).execute(&mut*tx).await?.rows_affected();
        if changed != 1 {
            return Err(BrowserError::Invalid);
        }
        tx.commit().await?;
        Ok(LoginCompletion {
            session: new_provider_session(session_raw, session_id, session_expiry),
            consent: ConsentHandle {
                transaction_id,
                csrf,
            },
        })
    }
    pub async fn approve(
        &self,
        session: &ProviderSession,
        handle: &ConsentHandle,
        registry: &ClientRegistry,
    ) -> Result<ConsentOutcome, BrowserError> {
        let mut tx = self.pool.begin().await?;
        let session_row = lock_session(&mut tx, session.id).await?;
        let row = lock_consent(&mut tx, handle.transaction_id, session.id, &handle.csrf).await?;
        ensure_fresh(&mut tx, &session_row, Some(row.expires_at)).await?;
        let pending = revalidate(registry, &row)?;
        let grant = pending
            .approve(true)
            .map_err(|_| BrowserError::PolicyChanged)?;
        let code = insert_authorization_code_tx(
            &mut tx,
            session.id,
            &grant,
            row.oidc_nonce.as_deref(),
            session_row.upstream_auth_time,
            60.0,
        )
        .await?;
        sqlx::query(
            "UPDATE browser_authorizations SET stage='approved',csrf_hash=NULL WHERE id=$1",
        )
        .bind(handle.transaction_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(ConsentOutcome {
            code,
            redirect_uri: row.redirect_uri,
            downstream_state: row.downstream_state,
        })
    }
    pub async fn deny(
        &self,
        session: &ProviderSession,
        handle: &ConsentHandle,
    ) -> Result<DenialOutcome, BrowserError> {
        let mut tx = self.pool.begin().await?;
        let session_row = lock_session(&mut tx, session.id).await?;
        let row = lock_consent(&mut tx, handle.transaction_id, session.id, &handle.csrf).await?;
        ensure_fresh(&mut tx, &session_row, Some(row.expires_at)).await?;
        sqlx::query("UPDATE browser_authorizations SET stage='denied',csrf_hash=NULL WHERE id=$1")
            .bind(handle.transaction_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(DenialOutcome {
            redirect_uri: row.redirect_uri,
            downstream_state: row.downstream_state,
        })
    }
}

#[derive(sqlx::FromRow)]
struct SessionRow {
    upstream_auth_time: Option<DateTime<Utc>>,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}
async fn lock_session(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<SessionRow, BrowserError> {
    sqlx::query_as("SELECT upstream_auth_time,expires_at,revoked_at FROM provider_sessions WHERE id=$1 FOR UPDATE")
        .bind(id).fetch_optional(&mut**tx).await?.ok_or(BrowserError::Invalid)
}
#[derive(sqlx::FromRow)]
struct ConsentRow {
    client_id: String,
    redirect_uri: String,
    scopes: Vec<String>,
    resource: String,
    code_challenge: String,
    downstream_state: Option<String>,
    oidc_nonce: Option<String>,
    expires_at: DateTime<Utc>,
}
async fn lock_consent(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    session: Uuid,
    csrf: &str,
) -> Result<ConsentRow, BrowserError> {
    sqlx::query_as("SELECT client_id,redirect_uri,scopes,resource,code_challenge,downstream_state,oidc_nonce,expires_at FROM browser_authorizations WHERE id=$1 AND session_id=$2 AND csrf_hash=$3 AND stage='awaiting_consent' FOR UPDATE").bind(id).bind(session).bind(secret_hash(csrf)).fetch_optional(&mut**tx).await?.ok_or(BrowserError::Invalid)
}
async fn ensure_fresh(
    tx: &mut Transaction<'_, Postgres>,
    session: &SessionRow,
    browser_expiry: Option<DateTime<Utc>>,
) -> Result<(), BrowserError> {
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await?;
    if session.revoked_at.is_some()
        || session.expires_at <= now
        || browser_expiry.is_some_and(|expiry| expiry <= now)
    {
        Err(BrowserError::Invalid)
    } else {
        Ok(())
    }
}
fn revalidate(
    reg: &ClientRegistry,
    row: &ConsentRow,
) -> Result<PendingAuthorizationGrant, BrowserError> {
    let scopes = row.scopes.iter().map(String::as_str).collect::<Vec<_>>();
    reg.validate_pending_parts(
        &row.client_id,
        &row.redirect_uri,
        "code",
        "S256",
        &row.code_challenge,
        &scopes,
        Some(&row.resource),
    )
    .map_err(|_| BrowserError::PolicyChanged)
}
fn bounded_seconds(d: Duration, max: u64) -> Result<f64, BrowserError> {
    if d.is_zero() || d.as_secs() > max || d.subsec_nanos() != 0 {
        Err(BrowserError::Invalid)
    } else {
        Ok(d.as_secs() as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuthenticatedUser, AuthorizationRequest, CredentialStore, FirstPartyClient, RedirectKind,
        RegisteredRedirect,
    };
    use sqlx::{PgPool, postgres::PgPoolOptions};
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const REDIRECT: &str = "com.example:/cb";
    const RESOURCE: &str = "https://api.example/resource";
    fn isolated() {
        let value = std::env::var("DATABASE_URL").unwrap();
        assert!(
            value == std::env::var("ERI_TEST_DATABASE_URL").unwrap(),
            "database tests require isolated URL"
        );
    }
    fn registry(include_resource: bool) -> ClientRegistry {
        let resources = if include_resource {
            vec![RESOURCE]
        } else {
            vec![]
        };
        ClientRegistry::with_issuer(
            vec![
                FirstPartyClient::new(
                    "mobile",
                    "Mobile",
                    vec![RegisteredRedirect::new(REDIRECT, RedirectKind::Exact).unwrap()],
                    ["openid", "offline_access"],
                    resources,
                    include_resource.then(|| RESOURCE.into()),
                    ["https://app.example"],
                    ["https://app.example/logout"],
                )
                .unwrap(),
            ],
            &url::Url::parse("https://auth.example/").unwrap(),
        )
        .unwrap()
    }
    fn pending(
        reg: &ClientRegistry,
        offline: bool,
        resource: Option<&str>,
    ) -> PendingAuthorizationGrant {
        let scopes: &[&str] = if offline {
            &["openid", "offline_access"]
        } else {
            &["openid"]
        };
        reg.validate_pending(AuthorizationRequest {
            client_id: "mobile",
            redirect_uri: REDIRECT,
            response_type: "code",
            code_challenge_method: "S256",
            code_challenge: &s256_challenge(VERIFIER).unwrap(),
            scopes,
            resource,
        })
        .unwrap()
    }
    async fn session(pool: &PgPool) -> ProviderSession {
        let id: Uuid = sqlx::query_scalar("INSERT INTO users DEFAULT VALUES RETURNING id")
            .fetch_one(pool)
            .await
            .unwrap();
        CredentialStore::new(pool.clone())
            .create_provider_session(AuthenticatedUser::new(id, None), Duration::from_secs(3600))
            .await
            .unwrap()
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn callback_binding_replay_concurrency_and_restart(pool: PgPool) {
        isolated();
        let store = BrowserStore::new(pool.clone());
        let start = store
            .begin_google(
                &pending(&registry(true), false, Some(RESOURCE)),
                Some("downstream-state"),
                Some("oidc-nonce"),
            )
            .await
            .unwrap();
        assert!(
            store
                .claim_callback(start.upstream_state(), "wrong")
                .await
                .is_err()
        );
        let stage: String =
            sqlx::query_scalar("SELECT stage FROM browser_authorizations WHERE id=$1")
                .bind(start.transaction_id())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stage, "awaiting_google");
        let fresh = PgPoolOptions::new()
            .max_connections(3)
            .connect_with((*pool.connect_options()).clone())
            .await
            .unwrap();
        let reopened = BrowserStore::new(fresh);
        let (a, b) = tokio::join!(
            reopened.claim_callback(start.upstream_state(), start.browser_binding()),
            store.claim_callback(start.upstream_state(), start.browser_binding())
        );
        assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
        assert!(
            store
                .claim_callback(start.upstream_state(), start.browser_binding())
                .await
                .is_err()
        );
        let erased: bool = sqlx::query_scalar(
            "SELECT upstream_verifier IS NULL FROM browser_authorizations WHERE id=$1",
        )
        .bind(start.transaction_id())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(erased);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn callback_expiry_failure_profile_replacement_and_provenance(pool: PgPool) {
        isolated();
        let reg = registry(true);
        let store = BrowserStore::new(pool.clone());
        let expired = store
            .begin_google(&pending(&reg, false, Some(RESOURCE)), None, None)
            .await
            .unwrap();
        sqlx::query("UPDATE browser_authorizations SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1").bind(expired.transaction_id()).execute(&pool).await.unwrap();
        assert!(
            store
                .claim_callback(expired.upstream_state(), expired.browser_binding())
                .await
                .is_err()
        );
        let start = store
            .begin_google(
                &pending(&reg, true, Some(RESOURCE)),
                Some("state"),
                Some("nonce"),
            )
            .await
            .unwrap();
        let (claim, verifier, nonce) = store
            .claim_callback(start.upstream_state(), start.browser_binding())
            .await
            .unwrap();
        assert_eq!(verifier, start.upstream_verifier());
        assert_eq!(nonce, start.upstream_nonce());
        let fresh = PgPoolOptions::new()
            .max_connections(2)
            .connect_with((*pool.connect_options()).clone())
            .await
            .unwrap();
        let reopened = BrowserStore::new(fresh);
        let auth = Utc::now().timestamp() - 60;
        let complete = reopened
            .complete_callback(
                &claim,
                &VerifiedGoogleIdentity::for_test(
                    "subject",
                    Some("Name"),
                    Some("same@example.test"),
                    Some(auth),
                ),
                Duration::from_secs(3600),
            )
            .await
            .unwrap();
        assert!(
            store
                .complete_callback(
                    &claim,
                    &VerifiedGoogleIdentity::for_test("subject", None, None, None),
                    Duration::from_secs(60)
                )
                .await
                .is_err()
        );
        let approved = store
            .approve(&complete.session, &complete.consent, &reg)
            .await
            .unwrap();
        assert_eq!(approved.downstream_state.as_deref(), Some("state"));
        let exchanged = CredentialStore::new(pool.clone())
            .exchange_code(
                approved.code.expose(),
                "mobile",
                REDIRECT,
                RESOURCE,
                VERIFIER,
            )
            .await
            .unwrap();
        assert_eq!(exchanged.oidc_nonce.as_deref(), Some("nonce"));
        assert_eq!(exchanged.upstream_auth_time.unwrap().timestamp(), auth);
        let db = crate::Database::from_pool(pool.clone(), Duration::from_secs(1));
        let profile = db.user_profile(exchanged.user_id).await.unwrap().unwrap();
        assert_eq!(profile.name.as_deref(), Some("Name"));
        let next = store
            .begin_google(&pending(&reg, false, Some(RESOURCE)), None, None)
            .await
            .unwrap();
        let (claim, _, _) = store
            .claim_callback(next.upstream_state(), next.browser_binding())
            .await
            .unwrap();
        store
            .complete_callback(
                &claim,
                &VerifiedGoogleIdentity::for_test("subject", None, None, None),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        let cleared = db.user_profile(exchanged.user_id).await.unwrap().unwrap();
        assert_eq!(cleared.name, None);
        assert_eq!(cleared.verified_email, None);
        let same_email = store
            .begin_google(&pending(&reg, false, Some(RESOURCE)), None, None)
            .await
            .unwrap();
        let (claim, _, _) = store
            .claim_callback(same_email.upstream_state(), same_email.browser_binding())
            .await
            .unwrap();
        let other = store
            .complete_callback(
                &claim,
                &VerifiedGoogleIdentity::for_test(
                    "different-subject",
                    None,
                    Some("same@example.test"),
                    None,
                ),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        assert_ne!(other.session.id, complete.session.id);
        let user_count: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(user_count, 2, "matching email must not link identities");
        let after_claim = store
            .begin_google(&pending(&reg, false, Some(RESOURCE)), None, None)
            .await
            .unwrap();
        let (claim, _, _) = store
            .claim_callback(after_claim.upstream_state(), after_claim.browser_binding())
            .await
            .unwrap();
        sqlx::query("UPDATE browser_authorizations SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1")
            .bind(after_claim.transaction_id())
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            store
                .complete_callback(
                    &claim,
                    &VerifiedGoogleIdentity::for_test("expired-subject", None, None, None),
                    Duration::from_secs(60),
                )
                .await
                .is_err()
        );
        let expired_user: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM external_identities WHERE subject='expired-subject')",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(!expired_user);
        let failed = store
            .begin_google(&pending(&reg, false, Some(RESOURCE)), None, None)
            .await
            .unwrap();
        let (claim, _, _) = store
            .claim_callback(failed.upstream_state(), failed.browser_binding())
            .await
            .unwrap();
        store.fail_callback(&claim).await.unwrap();
        assert!(
            store
                .complete_callback(
                    &claim,
                    &VerifiedGoogleIdentity::for_test("other", None, None, None),
                    Duration::from_secs(60)
                )
                .await
                .is_err()
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn consent_is_session_csrf_policy_and_one_use_bound(pool: PgPool) {
        isolated();
        let reg = registry(true);
        let store = BrowserStore::new(pool.clone());
        let one = session(&pool).await;
        let two = session(&pool).await;
        let handle = store
            .begin_authenticated(
                &one,
                &pending(&reg, true, Some(RESOURCE)),
                Some("state"),
                None,
            )
            .await
            .unwrap();
        let wrong = ConsentHandle {
            transaction_id: handle.transaction_id,
            csrf: "wrong".into(),
        };
        assert!(store.approve(&one, &wrong, &reg).await.is_err());
        assert!(store.approve(&two, &handle, &reg).await.is_err());
        let stage: String =
            sqlx::query_scalar("SELECT stage FROM browser_authorizations WHERE id=$1")
                .bind(handle.transaction_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stage, "awaiting_consent");
        assert!(
            store
                .approve(&one, &handle, &registry(false))
                .await
                .is_err()
        );
        let out = store.approve(&one, &handle, &reg).await.unwrap();
        assert!(store.approve(&one, &handle, &reg).await.is_err());
        assert!(
            CredentialStore::new(pool.clone())
                .exchange_code(out.code.expose(), "mobile", REDIRECT, RESOURCE, VERIFIER)
                .await
                .is_ok()
        );
        let denial = store
            .begin_authenticated(
                &one,
                &pending(&reg, false, Some(RESOURCE)),
                Some("denied"),
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            store
                .deny(&one, &denial)
                .await
                .unwrap()
                .downstream_state
                .as_deref(),
            Some("denied")
        );
        assert!(store.deny(&one, &denial).await.is_err());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn independent_tabs_and_logout_race_leave_no_usable_code(pool: PgPool) {
        isolated();
        let reg = registry(true);
        let store = BrowserStore::new(pool.clone());
        let session = session(&pool).await;
        let a = store
            .begin_authenticated(
                &session,
                &pending(&reg, false, Some(RESOURCE)),
                Some("a"),
                None,
            )
            .await
            .unwrap();
        let b = store
            .begin_authenticated(
                &session,
                &pending(&reg, false, Some(RESOURCE)),
                Some("b"),
                None,
            )
            .await
            .unwrap();
        assert_ne!(a.transaction_id, b.transaction_id);
        let creds = CredentialStore::new(pool.clone());
        let (approval, logout) =
            tokio::join!(store.approve(&session, &a, &reg), creds.logout(&session));
        logout.unwrap();
        if let Ok(out) = approval {
            assert!(
                creds
                    .exchange_code(out.code.expose(), "mobile", REDIRECT, RESOURCE, VERIFIER)
                    .await
                    .is_err()
            )
        }
        assert!(store.deny(&session, &b).await.is_err());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn approval_rechecks_browser_and_session_expiry_after_lock_wait(pool: PgPool) {
        isolated();
        let reg = registry(true);
        let store = BrowserStore::new(pool.clone());
        let provider = session(&pool).await;

        let browser_expiring = store
            .begin_authenticated(&provider, &pending(&reg, false, Some(RESOURCE)), None, None)
            .await
            .unwrap();
        sqlx::query("UPDATE browser_authorizations SET expires_at=clock_timestamp()+interval '1 second' WHERE id=$1")
            .bind(browser_expiring.transaction_id)
            .execute(&pool)
            .await
            .unwrap();
        let mut blocker = pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM browser_authorizations WHERE id=$1 FOR UPDATE")
            .bind(browser_expiring.transaction_id)
            .execute(&mut *blocker)
            .await
            .unwrap();
        let (result, ()) = tokio::join!(store.approve(&provider, &browser_expiring, &reg), async {
            tokio::time::sleep(Duration::from_millis(1500)).await;
            blocker.commit().await.unwrap();
        });
        assert!(result.is_err());

        let session_expiring = store
            .begin_authenticated(&provider, &pending(&reg, false, Some(RESOURCE)), None, None)
            .await
            .unwrap();
        sqlx::query("UPDATE provider_sessions SET expires_at=clock_timestamp()+interval '1 second' WHERE id=$1")
            .bind(provider.id)
            .execute(&pool)
            .await
            .unwrap();
        let mut blocker = pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM browser_authorizations WHERE id=$1 FOR UPDATE")
            .bind(session_expiring.transaction_id)
            .execute(&mut *blocker)
            .await
            .unwrap();
        let (result, ()) = tokio::join!(store.approve(&provider, &session_expiring, &reg), async {
            tokio::time::sleep(Duration::from_millis(1500)).await;
            blocker.commit().await.unwrap();
        });
        assert!(result.is_err());
        let codes: i64 = sqlx::query_scalar("SELECT count(*) FROM authorization_codes")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(codes, 0);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn callback_rechecks_expiry_after_identity_lock_wait(pool: PgPool) {
        isolated();
        let reg = registry(true);
        let store = BrowserStore::new(pool.clone());
        let start = store
            .begin_google(&pending(&reg, false, Some(RESOURCE)), None, None)
            .await
            .unwrap();
        let (claim, _, _) = store
            .claim_callback(start.upstream_state(), start.browser_binding())
            .await
            .unwrap();
        sqlx::query("UPDATE browser_authorizations SET expires_at=clock_timestamp()+interval '1 second' WHERE id=$1")
            .bind(start.transaction_id)
            .execute(&pool)
            .await
            .unwrap();
        let identity = VerifiedGoogleIdentity::for_test("blocked-subject", None, None, None);
        let mut blocker = pool.begin().await.unwrap();
        lock_verified_google_identity_tx(&mut blocker, &identity)
            .await
            .unwrap();
        let (result, ()) = tokio::join!(
            store.complete_callback(&claim, &identity, Duration::from_secs(60)),
            async {
                tokio::time::sleep(Duration::from_millis(1500)).await;
                blocker.commit().await.unwrap();
            }
        );
        assert!(result.is_err());
        let counts: (i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM provider_sessions),(SELECT count(*) FROM external_identities),(SELECT count(*) FROM user_profiles)",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(counts, (0, 0, 0));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn callback_rolls_back_profile_and_session_after_profile_lock_wait(pool: PgPool) {
        isolated();
        let original = VerifiedGoogleIdentity::for_test(
            "profile-blocked-subject",
            Some("Original"),
            Some("original@example.test"),
            None,
        );
        let database = crate::Database::from_pool(pool.clone(), Duration::from_secs(1));
        let user = database
            .find_or_create_verified_google_identity(&original)
            .await
            .unwrap();
        let mut blocker = pool.begin().await.unwrap();
        sqlx::query("SELECT user_id FROM user_profiles WHERE user_id=$1 FOR UPDATE")
            .bind(user.subject())
            .execute(&mut *blocker)
            .await
            .unwrap();

        let completion_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_with((*pool.connect_options()).clone())
            .await
            .unwrap();
        let backend_pid: i32 = {
            let mut connection = completion_pool.acquire().await.unwrap();
            sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *connection)
                .await
                .unwrap()
        };
        let store = BrowserStore::new(completion_pool);
        let reg = registry(true);
        let start = store
            .begin_google(&pending(&reg, false, Some(RESOURCE)), None, None)
            .await
            .unwrap();
        let (claim, _, _) = store
            .claim_callback(start.upstream_state(), start.browser_binding())
            .await
            .unwrap();
        sqlx::query("UPDATE browser_authorizations SET expires_at=clock_timestamp()+interval '1 second' WHERE id=$1")
            .bind(start.transaction_id)
            .execute(&pool)
            .await
            .unwrap();
        let replacement = VerifiedGoogleIdentity::for_test(
            "profile-blocked-subject",
            Some("Replacement"),
            Some("replacement@example.test"),
            None,
        );
        let completion = tokio::spawn(async move {
            store
                .complete_callback(&claim, &replacement, Duration::from_secs(60))
                .await
        });
        let mut observed_wait = false;
        for _ in 0..100 {
            observed_wait = sqlx::query_scalar::<_, bool>(
                "SELECT COALESCE(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1",
            )
            .bind(backend_pid)
            .fetch_optional(&pool)
            .await
            .unwrap()
            .unwrap_or(false);
            if observed_wait {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            observed_wait,
            "completion must reach the held profile row lock"
        );
        tokio::time::sleep(Duration::from_millis(1200)).await;
        blocker.commit().await.unwrap();
        assert!(completion.await.unwrap().is_err());

        let profile = database
            .user_profile(user.subject())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(profile.name.as_deref(), Some("Original"));
        assert_eq!(
            profile.verified_email.as_deref(),
            Some("original@example.test")
        );
        let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM provider_sessions")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(sessions, 0);
        let stage: String =
            sqlx::query_scalar("SELECT stage FROM browser_authorizations WHERE id=$1")
                .bind(start.transaction_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stage, "expired");
    }
}

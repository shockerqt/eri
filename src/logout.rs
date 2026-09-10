use crate::{
    ClientRegistry, CredentialError, ProviderSession,
    credentials::{random_secret, secret_hash},
};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

pub struct LogoutChallenge {
    id: Uuid,
    csrf: String,
    redirect_uri: String,
}
pub struct LogoutOutcome {
    pub redirect_uri: String,
    pub state: Option<String>,
}
#[derive(sqlx::FromRow)]
struct LogoutRow {
    client_id: String,
    post_logout_redirect_uri: String,
    downstream_state: Option<String>,
    expires_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
}
impl LogoutChallenge {
    pub fn id(&self) -> Uuid {
        self.id
    }
    pub fn csrf(&self) -> &str {
        &self.csrf
    }
    pub fn submitted(id: Uuid, csrf: String) -> Self {
        Self {
            id,
            csrf,
            redirect_uri: String::new(),
        }
    }
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }
}

#[derive(Clone)]
pub struct LogoutStore {
    pool: PgPool,
}
impl LogoutStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
    pub async fn begin(
        &self,
        session: &ProviderSession,
        client_id: &str,
        redirect: &str,
        state: Option<&str>,
        registry: &ClientRegistry,
    ) -> Result<LogoutChallenge, CredentialError> {
        if !registry.valid_post_logout_redirect(client_id, redirect) {
            return Err(CredentialError::InvalidGrant);
        }
        self.insert(session, client_id, redirect, state).await
    }
    pub async fn begin_local(
        &self,
        session: &ProviderSession,
        local_uri: &str,
    ) -> Result<LogoutChallenge, CredentialError> {
        self.insert(session, "", local_uri, None).await
    }
    async fn insert(
        &self,
        session: &ProviderSession,
        client_id: &str,
        redirect: &str,
        state: Option<&str>,
    ) -> Result<LogoutChallenge, CredentialError> {
        let id = Uuid::new_v4();
        let csrf = random_secret();
        let mut tx = self.pool.begin().await?;
        let active: Option<(DateTime<Utc>, Option<DateTime<Utc>>)> = sqlx::query_as(
            "SELECT expires_at,revoked_at FROM provider_sessions WHERE id=$1 FOR UPDATE",
        )
        .bind(session.id)
        .fetch_optional(&mut *tx)
        .await?;
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        if active.is_none_or(|(expires, revoked)| revoked.is_some() || expires <= now) {
            return Err(CredentialError::InvalidGrant);
        }
        sqlx::query("INSERT INTO logout_challenges(id,csrf_hash,session_id,client_id,post_logout_redirect_uri,downstream_state,created_at,expires_at)SELECT $1,$2,$3,$4,$5,$6,t,t+interval '10 minutes'FROM(SELECT clock_timestamp()t)n").bind(id).bind(secret_hash(&csrf)).bind(session.id).bind(client_id).bind(redirect).bind(state).execute(&mut*tx).await?;
        tx.commit().await?;
        Ok(LogoutChallenge {
            id,
            csrf,
            redirect_uri: redirect.to_owned(),
        })
    }
    pub async fn finish(
        &self,
        session: &ProviderSession,
        challenge: &LogoutChallenge,
        registry: &ClientRegistry,
    ) -> Result<LogoutOutcome, CredentialError> {
        let mut tx = self.pool.begin().await?;
        let session_row: Option<(DateTime<Utc>, Option<DateTime<Utc>>)> = sqlx::query_as(
            "SELECT expires_at,revoked_at FROM provider_sessions WHERE id=$1 FOR UPDATE",
        )
        .bind(session.id)
        .fetch_optional(&mut *tx)
        .await?;
        if session_row.is_none() {
            return Err(CredentialError::InvalidGrant);
        }
        let row:Option<LogoutRow>=sqlx::query_as("SELECT client_id,post_logout_redirect_uri,downstream_state,expires_at,consumed_at FROM logout_challenges WHERE id=$1 AND session_id=$2 AND csrf_hash=$3 FOR UPDATE").bind(challenge.id).bind(session.id).bind(secret_hash(&challenge.csrf)).fetch_optional(&mut*tx).await?;
        let Some(row) = row else {
            return Err(CredentialError::InvalidGrant);
        };
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        let (session_expiry, session_revoked) = session_row.unwrap();
        if session_revoked.is_some()
            || session_expiry <= now
            || row.consumed_at.is_some()
            || row.expires_at <= now
            || !row.client_id.is_empty()
                && !registry
                    .valid_post_logout_redirect(&row.client_id, &row.post_logout_redirect_uri)
        {
            return Err(CredentialError::InvalidGrant);
        }
        sqlx::query("UPDATE logout_challenges SET consumed_at=$2 WHERE id=$1")
            .bind(challenge.id)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE provider_sessions SET revoked_at=COALESCE(revoked_at,$2) WHERE id=$1")
            .bind(session.id)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE refresh_families SET revoked_at=COALESCE(revoked_at,$2) WHERE session_id=$1",
        )
        .bind(session.id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(LogoutOutcome {
            redirect_uri: row.post_logout_redirect_uri,
            state: row.downstream_state,
        })
    }
}

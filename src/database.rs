use crate::{
    config::{ConfigError, DatabaseConfig},
    google::VerifiedGoogleIdentity,
    identity::{AuthenticatedUser, ExternalIdentity},
};
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Transaction, postgres::PgPoolOptions};
use tokio::time::timeout;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserProfile {
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub picture: Option<String>,
    pub verified_email: Option<String>,
}

#[derive(Clone)]
pub struct Database {
    pool: PgPool,
    readiness_timeout: std::time::Duration,
}

impl Database {
    pub async fn connect(config: &DatabaseConfig) -> anyhow::Result<Self> {
        let url = config
            .resolved_url()
            .map_err(|e: ConfigError| anyhow::anyhow!(e))?;
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .acquire_timeout(config.acquire_timeout())
            .connect_lazy(&url)?;
        timeout(config.connect_timeout(), pool.acquire())
            .await
            .map_err(|_| anyhow::anyhow!("database connection timed out"))??;
        Ok(Self {
            pool,
            readiness_timeout: config.readiness_timeout(),
        })
    }
    pub fn from_pool(pool: PgPool, readiness_timeout: std::time::Duration) -> Self {
        Self {
            pool,
            readiness_timeout,
        }
    }
    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        sqlx::migrate!().run(&self.pool).await
    }
    pub async fn ready(&self) -> bool {
        timeout(
            self.readiness_timeout,
            sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&self.pool),
        )
        .await
        .is_ok_and(|r| matches!(r, Ok(1)))
    }
    pub async fn find_or_create_external_identity(
        &self,
        identity: &ExternalIdentity,
    ) -> Result<Uuid, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(length($1)::text || ':' || $1 || $2, 0))")
            .bind(identity.issuer())
            .bind(identity.subject())
            .execute(&mut *tx)
            .await?;
        let existing: Option<Uuid> = sqlx::query_scalar(
            "SELECT user_id FROM external_identities WHERE issuer = $1 AND subject = $2",
        )
        .bind(identity.issuer())
        .bind(identity.subject())
        .fetch_optional(&mut *tx)
        .await?;
        let user_id = match existing {
            Some(id) => id,
            None => {
                let id: Uuid = sqlx::query_scalar("INSERT INTO users DEFAULT VALUES RETURNING id")
                    .fetch_one(&mut *tx)
                    .await?;
                sqlx::query("INSERT INTO external_identities (issuer, subject, user_id) VALUES ($1, $2, $3)")
                    .bind(identity.issuer()).bind(identity.subject()).bind(id).execute(&mut *tx).await?;
                id
            }
        };
        tx.commit().await?;
        Ok(user_id)
    }
    pub async fn find_or_create_verified_google_identity(
        &self,
        identity: &VerifiedGoogleIdentity,
    ) -> Result<AuthenticatedUser, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        lock_verified_google_identity_tx(&mut tx, identity).await?;
        let now = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        let id = upsert_verified_google_identity_tx(&mut tx, identity, now).await?;
        tx.commit().await?;
        Ok(AuthenticatedUser::new(
            id,
            identity
                .auth_time()
                .and_then(|value| DateTime::<Utc>::from_timestamp(value, 0)),
        ))
    }
    pub async fn user_profile(&self, user_id: Uuid) -> Result<Option<UserProfile>, sqlx::Error> {
        sqlx::query_as::<_, ProfileRow>("SELECT name,given_name,family_name,picture,verified_email FROM user_profiles WHERE user_id=$1")
            .bind(user_id).fetch_optional(&self.pool).await.map(|row| row.map(Into::into))
    }
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

pub(crate) async fn lock_verified_google_identity_tx(
    tx: &mut Transaction<'_, Postgres>,
    identity: &VerifiedGoogleIdentity,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(length($1)::text||':'||$1||$2,0))")
        .bind("https://accounts.google.com")
        .bind(identity.subject())
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub(crate) async fn upsert_verified_google_identity_tx(
    tx: &mut Transaction<'_, Postgres>,
    identity: &VerifiedGoogleIdentity,
    now: DateTime<Utc>,
) -> Result<Uuid, sqlx::Error> {
    let existing: Option<Uuid> = sqlx::query_scalar(
        "SELECT user_id FROM external_identities WHERE issuer=$1 AND subject=$2",
    )
    .bind("https://accounts.google.com")
    .bind(identity.subject())
    .fetch_optional(&mut **tx)
    .await?;
    let user = if let Some(id) = existing {
        id
    } else {
        let id: Uuid = sqlx::query_scalar("INSERT INTO users DEFAULT VALUES RETURNING id")
            .fetch_one(&mut **tx)
            .await?;
        sqlx::query("INSERT INTO external_identities(issuer,subject,user_id)VALUES($1,$2,$3)")
            .bind("https://accounts.google.com")
            .bind(identity.subject())
            .bind(id)
            .execute(&mut **tx)
            .await?;
        id
    };
    sqlx::query("INSERT INTO user_profiles(user_id,name,given_name,family_name,picture,verified_email,updated_at)VALUES($1,$2,$3,$4,$5,$6,$7)ON CONFLICT(user_id)DO UPDATE SET name=EXCLUDED.name,given_name=EXCLUDED.given_name,family_name=EXCLUDED.family_name,picture=EXCLUDED.picture,verified_email=EXCLUDED.verified_email,updated_at=EXCLUDED.updated_at")
        .bind(user).bind(identity.name()).bind(identity.given_name()).bind(identity.family_name()).bind(identity.picture()).bind(identity.verified_email()).bind(now).execute(&mut**tx).await?;
    Ok(user)
}

#[derive(sqlx::FromRow)]
struct ProfileRow {
    name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    picture: Option<String>,
    verified_email: Option<String>,
}
impl From<ProfileRow> for UserProfile {
    fn from(value: ProfileRow) -> Self {
        Self {
            name: value.name,
            given_name: value.given_name,
            family_name: value.family_name,
            picture: value.picture,
            verified_email: value.verified_email,
        }
    }
}

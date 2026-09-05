use crate::{
    config::{ConfigError, DatabaseConfig},
    google::VerifiedGoogleIdentity,
    identity::{AuthenticatedUser, ExternalIdentity},
};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tokio::time::timeout;
use uuid::Uuid;

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
        let external = ExternalIdentity::google("https://accounts.google.com", identity.subject())
            .expect("verified Google identity has a valid canonical issuer and subject");
        self.find_or_create_external_identity(&external)
            .await
            .map(AuthenticatedUser::new)
    }
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

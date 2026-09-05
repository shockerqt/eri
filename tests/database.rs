use eri::{Database, ExternalIdentity};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::time::Duration;

mod common;

#[sqlx::test(migrations = "./migrations")]
async fn identity_is_unique_and_persists_when_reopened(pool: PgPool) {
    common::assert_isolated_database();
    let database = Database::from_pool(pool.clone(), Duration::from_secs(1));
    assert!(database.ready().await);
    let one = database.clone();
    let two = database.clone();
    let bare = ExternalIdentity::google("accounts.google.com", "subject-1").unwrap();
    let https = ExternalIdentity::google("https://accounts.google.com", "subject-1").unwrap();
    let (first, concurrent) = tokio::join!(
        one.find_or_create_external_identity(&bare),
        two.find_or_create_external_identity(&https)
    );
    let first = first.unwrap();
    assert_eq!(first, concurrent.unwrap());
    let second = database
        .find_or_create_external_identity(&https)
        .await
        .unwrap();
    assert_eq!(first, second);
    drop(database);
    let new_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap();
    let reopened = Database::from_pool(new_pool, Duration::from_secs(1));
    let persisted = reopened
        .find_or_create_external_identity(&https)
        .await
        .unwrap();
    assert_eq!(first, persisted);
    let other = reopened
        .find_or_create_external_identity(
            &ExternalIdentity::google("https://accounts.google.com", "subject-2").unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(first, other);
    reopened.pool().close().await;
    assert!(!reopened.ready().await);
}

#[sqlx::test(migrations = "./migrations")]
async fn database_constraint_rejects_duplicate_external_identity(pool: PgPool) {
    common::assert_isolated_database();
    let first: uuid::Uuid = sqlx::query_scalar("INSERT INTO users DEFAULT VALUES RETURNING id")
        .fetch_one(&pool)
        .await
        .unwrap();
    let second: uuid::Uuid = sqlx::query_scalar("INSERT INTO users DEFAULT VALUES RETURNING id")
        .fetch_one(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO external_identities (issuer, subject, user_id) VALUES ($1, $2, $3)")
        .bind("https://accounts.google.com")
        .bind("subject")
        .bind(first)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        sqlx::query(
            "INSERT INTO external_identities (issuer, subject, user_id) VALUES ($1, $2, $3)"
        )
        .bind("https://accounts.google.com")
        .bind("subject")
        .bind(second)
        .execute(&pool)
        .await
        .is_err()
    );
    assert!(
        sqlx::query(
            "INSERT INTO external_identities (issuer, subject, user_id) VALUES ($1, $2, $3)"
        )
        .bind("https://unsupported.example")
        .bind("subject-2")
        .bind(second)
        .execute(&pool)
        .await
        .is_err()
    );
    assert!(
        sqlx::query(
            "INSERT INTO external_identities (issuer, subject, user_id) VALUES ($1, $2, $3)"
        )
        .bind("https://accounts.google.com")
        .bind("")
        .bind(second)
        .execute(&pool)
        .await
        .is_err()
    );
}

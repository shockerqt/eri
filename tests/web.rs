use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use eri::{
    AppState, Config, Database, SigningKeys,
    config::{DatabaseConfig, Mode, SigningConfig},
    router,
};
use http_body_util::BodyExt;
use sqlx::PgPool;
use std::{fs, path::Path, time::Duration};
use tower::ServiceExt;

mod common;

fn load_keys() -> (tempfile::TempDir, SigningKeys) {
    let dir = tempfile::tempdir().unwrap();
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/keys");
    for name in ["active-private.pem", "active-public.pem"] {
        let target = dir.path().join(name);
        fs::copy(fixtures.join(name), &target).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(target, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    fs::write(dir.path().join("manifest.json"), r#"{"active":{"kid":"active","private_key":"active-private.pem","public_key":"active-public.pem"},"previous":[],"next":[]}"#).unwrap();
    let keys = SigningKeys::load(&dir.path().join("manifest.json")).unwrap();
    (dir, keys)
}

#[sqlx::test(migrations = "./migrations")]
async fn foundation_routes_are_truthful_and_public_only(pool: PgPool) {
    common::assert_isolated_database();
    let (_keys_dir, keys) = load_keys();
    let config = Config {
        mode: Mode::Development,
        issuer: "http://127.0.0.1:18082".parse().unwrap(),
        bind: "127.0.0.1:18082".parse().unwrap(),
        database: DatabaseConfig {
            url: None,
            url_env: "ERI_TEST_DATABASE_URL".into(),
            max_connections: 2,
            min_connections: 0,
            connect_timeout_seconds: 1,
            acquire_timeout_seconds: 1,
            readiness_timeout_milliseconds: 500,
        },
        signing: SigningConfig {
            manifest: "unused".into(),
        },
        authorization: None,
    };
    let app = router(
        AppState::new(
            config,
            Database::from_pool(pool, Duration::from_millis(500)),
            keys,
        )
        .unwrap(),
    );
    let live = app
        .clone()
        .oneshot(Request::get("/health/live").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(live.status(), StatusCode::NO_CONTENT);
    let ready = app
        .clone()
        .oneshot(Request::get("/health/ready").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(ready.status(), StatusCode::NO_CONTENT);
    let unimplemented = app
        .clone()
        .oneshot(Request::get("/authorize").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(unimplemented.status(), StatusCode::NOT_FOUND);

    for path in [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
    ] {
        let metadata = app
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(metadata.status(), StatusCode::NOT_FOUND);
    }

    let jwks = app
        .oneshot(Request::get("/jwks").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(jwks.status(), StatusCode::OK);
    assert_eq!(jwks.headers()[header::CACHE_CONTROL], "public, max-age=300");
    let body: serde_json::Value =
        serde_json::from_slice(&jwks.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["keys"][0]["kty"], "RSA");
    assert!(body["keys"][0].get("d").is_none());
}

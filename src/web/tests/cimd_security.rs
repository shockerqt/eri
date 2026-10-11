//! Synthetic CIMD lifecycle regressions. All accounts, keys, metadata and state
//! belong to the isolated test fixtures; no external provider is contacted.
use super::*;
use crate::cimd::LeasedClientMetadata;
use crate::{AuthenticatedUser, AuthorizationRequest, BrowserError, CredentialError};
const ID: &str = "https://client.example.org/metadata.json";
const REDIRECT: &str = "https://client.example.org/callback";
const RESOURCE: &str = "https://api.example/resource";
const ISSUER: &str = "http://127.0.0.1:18082";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
fn document() -> serde_json::Value {
    json!({"client_id":ID,"client_name":"Declared client","redirect_uris":[REDIRECT,"http://127.0.0.1:34567/callback?fixed=%2F"],"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"]})
}
fn resolved(doc: &serde_json::Value, lease: Duration) -> ClientRegistry {
    registry()
        .project_cimd(
            LeasedClientMetadata::for_test(ID, &serde_json::to_vec(doc).unwrap(), lease),
            &["openid".into(), "offline_access".into()],
            &[RESOURCE.into()],
            true,
        )
        .unwrap()
}
async fn fixture_state(
    pool: &PgPool,
) -> (
    AppState,
    Arc<Mutex<Option<Vec<u8>>>>,
    tempfile::TempDir,
    ProviderSession,
) {
    assert_eq!(
        std::env::var("DATABASE_URL").unwrap(),
        std::env::var("ERI_TEST_DATABASE_URL").unwrap()
    );
    let user: Uuid = sqlx::query_scalar("INSERT INTO users DEFAULT VALUES RETURNING id")
        .fetch_one(pool)
        .await
        .unwrap();
    let session = CredentialStore::new(pool.clone())
        .create_provider_session(
            AuthenticatedUser::new(user, None),
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
    let (dir, keys) = signing_keys();
    let google = GoogleAdapter::for_test_http(
        "http://127.0.0.1:1/authorize".into(),
        "http://127.0.0.1:1/token".into(),
        "http://127.0.0.1:1/certs".into(),
        format!("{ISSUER}/federation/google/callback"),
    );
    let mut state = AppState::for_test_provider(
        Database::from_pool(pool.clone(), Duration::from_secs(1)),
        keys,
        registry(),
        google,
    );
    let source = Arc::new(Mutex::new(Some(serde_json::to_vec(&document()).unwrap())));
    let provider = Arc::get_mut(&mut state.0)
        .unwrap()
        .provider
        .as_mut()
        .unwrap();
    provider.cimd_policy = Some(CimdPolicyConfig {
        scopes: vec!["openid".into(), "offline_access".into()],
        resources: vec![RESOURCE.into()],
        allow_refresh: true,
    });
    provider.cimd_fetcher = CimdFetcher::for_test_document_source(source.clone());
    (state, source, dir, session)
}
fn cookie_for(session: &ProviderSession) -> String {
    format!("{}={}", session_cookie(false), session.expose())
}
fn authorize(redirect: &str) -> String {
    format!(
        "/authorize?{}",
        form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", ID)
            .append_pair("redirect_uri", redirect)
            .append_pair("response_type", "code")
            .append_pair("code_challenge_method", "S256")
            .append_pair("code_challenge", &crate::s256_challenge(VERIFIER).unwrap())
            .append_pair("scope", "openid offline_access")
            .append_pair("resource", RESOURCE)
            .append_pair("state", "bound-state")
            .finish()
    )
}
async fn consent(app: &Router, session: &ProviderSession, redirect: &str) -> (String, String) {
    let response = app
        .clone()
        .oneshot(
            Request::get(authorize(redirect))
                .header(header::COOKIE, cookie_for(session))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let html = body(response).await;
    (
        form_value(&html, "transaction_id"),
        form_value(&html, "csrf"),
    )
}
async fn action(
    app: &Router,
    session: &ProviderSession,
    handle: &(String, String),
    action: &str,
) -> Response {
    let form = form_urlencoded::Serializer::new(String::new())
        .append_pair("transaction_id", &handle.0)
        .append_pair("csrf", &handle.1)
        .append_pair("action", action)
        .finish();
    app.clone()
        .oneshot(
            Request::post("/consent")
                .header(header::COOKIE, cookie_for(session))
                .header(header::ORIGIN, ISSUER)
                .body(Body::from(form))
                .unwrap(),
        )
        .await
        .unwrap()
}
async fn code(app: &Router, session: &ProviderSession, redirect: &str) -> String {
    let handle = consent(app, session, redirect).await;
    let response = action(app, session, &handle, "approve").await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let uri: url::Url = response.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    uri.query_pairs()
        .find(|(key, _)| key == "code")
        .unwrap()
        .1
        .into_owned()
}
fn exchange_form(code: &str, redirect: &str) -> String {
    form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("client_id", ID)
        .append_pair("code", code)
        .append_pair("redirect_uri", redirect)
        .append_pair("code_verifier", VERIFIER)
        .append_pair("resource", RESOURCE)
        .finish()
}
fn refresh_form(token: &str) -> String {
    form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "refresh_token")
        .append_pair("client_id", ID)
        .append_pair("refresh_token", token)
        .append_pair("resource", RESOURCE)
        .finish()
}
async fn token(app: &Router, form: String) -> Response {
    app.clone()
        .oneshot(Request::post("/token").body(Body::from(form)).unwrap())
        .await
        .unwrap()
}
fn change_source(source: &Arc<Mutex<Option<Vec<u8>>>>, doc: Option<serde_json::Value>) {
    *source.lock().unwrap() = doc.map(|doc| serde_json::to_vec(&doc).unwrap());
}
fn changed_document() -> serde_json::Value {
    let mut doc = document();
    doc["redirect_uris"]
        .as_array_mut()
        .unwrap()
        .push("https://client.example.org/added".into());
    doc
}

#[sqlx::test(migrations = "./migrations")]
async fn disabled_policy_static_precedence_and_generic_cors(pool: PgPool) {
    let (mut state, source, _dir, session) = fixture_state(&pool).await;
    Arc::get_mut(&mut state.0)
        .unwrap()
        .provider
        .as_mut()
        .unwrap()
        .cimd_policy = None;
    let app = router(state);
    let response = app
        .oneshot(
            Request::get(authorize(REDIRECT))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.headers().get(header::LOCATION).is_none());
    let (mut state, _, _dir2, _session2) = fixture_state(&pool).await;
    let static_client = FirstPartyClient::new(
        ID,
        "Reviewed static",
        vec![RegisteredRedirect::new(REDIRECT, RedirectKind::Exact).unwrap()],
        ["openid", "offline_access"],
        [RESOURCE],
        None,
        Vec::<String>::new(),
        Vec::<String>::new(),
    )
    .unwrap();
    let provider = Arc::get_mut(&mut state.0)
        .unwrap()
        .provider
        .as_mut()
        .unwrap();
    provider.registry =
        ClientRegistry::with_issuer(vec![static_client], &format!("{ISSUER}/").parse().unwrap())
            .unwrap();
    *source.lock().unwrap() = None;
    provider.cimd_fetcher = CimdFetcher::for_test_document_source(source);
    let app = router(state);
    let handle = consent(&app, &session, REDIRECT).await;
    let binding: Option<String> =
        sqlx::query_scalar("SELECT cimd_binding::text FROM browser_authorizations WHERE id=$1")
            .bind(Uuid::parse_str(&handle.0).unwrap())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(binding.is_none());
    let (state, _, _dir3, _) = fixture_state(&pool).await;
    let app = router(state);
    let generic_code = code(&app, &session, REDIRECT).await;
    let response = app
        .clone()
        .oneshot(
            Request::post("/token")
                .header(header::ORIGIN, "https://client.example.org")
                .body(Body::from(exchange_form(&generic_code, REDIRECT)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none()
    );
    assert_eq!(
        token(&app, exchange_form(&generic_code, REDIRECT))
            .await
            .status(),
        StatusCode::OK
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn metadata_changes_and_outages_fail_without_consuming_grants(pool: PgPool) {
    let (state, source, _dir, session) = fixture_state(&pool).await;
    let app = router(state);
    for decision in ["approve", "deny"] {
        let handle = consent(&app, &session, REDIRECT).await;
        change_source(&source, Some(changed_document()));
        let rejected = action(&app, &session, &handle, decision).await;
        assert!(rejected.headers().get(header::LOCATION).is_none());
        assert!(!body(rejected).await.contains("bound-state"));
        let stage: String =
            sqlx::query_scalar("SELECT stage FROM browser_authorizations WHERE id=$1")
                .bind(Uuid::parse_str(&handle.0).unwrap())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stage, "awaiting_consent");
        change_source(&source, Some(document()));
        assert_eq!(
            action(&app, &session, &handle, "deny").await.status(),
            StatusCode::SEE_OTHER
        );
    }
    let original_code = code(&app, &session, REDIRECT).await;
    for metadata in [Some(changed_document()), None] {
        change_source(&source, metadata);
        assert_eq!(
            token(&app, exchange_form(&original_code, REDIRECT))
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
        let consumed: bool =
            sqlx::query_scalar("SELECT bool_or(consumed_at IS NOT NULL) FROM authorization_codes")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(!consumed);
    }
    change_source(&source, Some(document()));
    let response = token(&app, exchange_form(&original_code, REDIRECT)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let issued: serde_json::Value = serde_json::from_str(&body(response).await).unwrap();
    let refresh = issued["refresh_token"].as_str().unwrap();
    change_source(&source, Some(changed_document()));
    assert_eq!(
        token(&app, refresh_form(refresh)).await.status(),
        StatusCode::BAD_REQUEST
    );
    let state:(bool,bool)=sqlx::query_as("SELECT f.revoked_at IS NOT NULL,m.consumed_at IS NOT NULL FROM refresh_families f JOIN refresh_token_members m ON m.family_id=f.id").fetch_one(&pool).await.unwrap();
    assert_eq!(state, (false, false));
    change_source(&source, Some(document()));
    let response = token(&app, refresh_form(refresh)).await;
    assert_eq!(response.status(), StatusCode::OK);
    change_source(&source, None);
    assert_eq!(
        token(&app, refresh_form(refresh)).await.status(),
        StatusCode::BAD_REQUEST
    );
    let revoked: bool = sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM refresh_families")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!revoked);
    change_source(&source, Some(document()));
    assert_eq!(
        token(&app, refresh_form(refresh)).await.status(),
        StatusCode::BAD_REQUEST
    );
    let revoked: bool = sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM refresh_families")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(revoked);
}

#[sqlx::test(migrations = "./migrations")]
async fn native_loopback_actual_exchange_and_nonexpanding_policy(pool: PgPool) {
    let (state, _, _dir, session) = fixture_state(&pool).await;
    let app = router(state);
    let actual = "http://127.0.0.1:45678/callback?fixed=%2F";
    let original_code = code(&app, &session, actual).await;
    assert_eq!(
        token(
            &app,
            exchange_form(&original_code, "http://127.0.0.1:34567/callback?fixed=%2F")
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        token(&app, exchange_form(&original_code, actual))
            .await
            .status(),
        StatusCode::OK
    );
    let reg = resolved(&document(), Duration::from_secs(60));
    assert!(!reg.valid_browser_origin(ID, "https://client.example.org"));
    assert!(!reg.valid_post_logout_redirect(ID, REDIRECT));
    assert!(
        reg.validate_pending(AuthorizationRequest {
            client_id: ID,
            redirect_uri: REDIRECT,
            response_type: "code",
            code_challenge_method: "S256",
            code_challenge: &crate::s256_challenge(VERIFIER).unwrap(),
            scopes: &["openid"],
            resource: None
        })
        .is_err()
    );
    for (scopes, resource) in [
        (&["openid", "admin"][..], RESOURCE),
        (&["openid"][..], "https://unreviewed.example.org/mcp"),
        (&["openid"][..], "http://127.0.0.1:18082/userinfo"),
    ] {
        assert!(
            reg.validate_pending(AuthorizationRequest {
                client_id: ID,
                redirect_uri: REDIRECT,
                response_type: "code",
                code_challenge_method: "S256",
                code_challenge: &crate::s256_challenge(VERIFIER).unwrap(),
                scopes,
                resource: Some(resource)
            })
            .is_err()
        );
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn callback_and_cancel_revalidate_full_binding_before_identity_or_redirect(pool: PgPool) {
    let (_state, _source, _dir, _session) = fixture_state(&pool).await;
    let reg = resolved(&document(), Duration::from_secs(60));
    let pending = reg
        .validate_pending(AuthorizationRequest {
            client_id: ID,
            redirect_uri: REDIRECT,
            response_type: "code",
            code_challenge_method: "S256",
            code_challenge: &crate::s256_challenge(VERIFIER).unwrap(),
            scopes: &["openid"],
            resource: Some(RESOURCE),
        })
        .unwrap();
    let store = BrowserStore::new(pool.clone());
    let start = store
        .begin_google(&pending, Some("bound-state"), None)
        .await
        .unwrap();
    let changed = resolved(&changed_document(), Duration::from_secs(60));
    assert!(matches!(
        store
            .cancel_google_with_registry(
                start.transaction_id(),
                start.upstream_state(),
                start.browser_binding(),
                &changed
            )
            .await,
        Err(BrowserError::PolicyChanged)
    ));
    store
        .start_google(
            start.transaction_id(),
            start.upstream_state(),
            start.browser_binding(),
        )
        .await
        .unwrap();
    let (claim, _, _) = store
        .claim_callback(start.upstream_state(), start.browser_binding())
        .await
        .unwrap();
    assert!(matches!(
        store.deny_callback(&claim, &changed).await,
        Err(BrowserError::PolicyChanged)
    ));
    let identity = crate::VerifiedGoogleIdentity::for_test("generic-subject", None, None, None);
    assert!(matches!(
        store
            .complete_callback_with_registry(&claim, &identity, Duration::from_secs(60), &changed)
            .await,
        Err(BrowserError::PolicyChanged)
    ));
    let profiles: i64 = sqlx::query_scalar("SELECT count(*) FROM external_identities")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(profiles, 0);
    assert!(
        store
            .complete_callback(&claim, &identity, Duration::from_secs(60))
            .await
            .is_err()
    );
    assert!(
        store
            .complete_callback_with_registry(&claim, &identity, Duration::from_secs(60), &reg)
            .await
            .is_ok()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn expired_lease_after_lock_wait_rolls_back_and_fresh_resolution_recovers(pool: PgPool) {
    let (state, _, _dir, session) = fixture_state(&pool).await;
    let app = router(state);
    let handle = consent(&app, &session, REDIRECT).await;
    let handle = ConsentHandle::submitted(Uuid::parse_str(&handle.0).unwrap(), handle.1);
    let short = resolved(&document(), Duration::from_millis(50));
    let mut lock = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM provider_sessions WHERE id=$1 FOR UPDATE")
        .bind(session.id)
        .execute(&mut *lock)
        .await
        .unwrap();
    let store = BrowserStore::new(pool.clone());
    let approval = store.approve(&session, &handle, &short);
    let release = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        lock.rollback().await.unwrap();
    };
    let (result, _) = tokio::join!(approval, release);
    assert!(matches!(result, Err(BrowserError::MetadataExpired)));
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM authorization_codes")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    let fresh = resolved(&document(), Duration::from_secs(60));
    let issued = store.approve(&session, &handle, &fresh).await.unwrap();
    let single = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap();
    let blocker = single.acquire().await.unwrap();
    let lookup_store = CredentialStore::new(single.clone());
    let lookup_lease = resolved(&document(), Duration::from_millis(50));
    let lookup = lookup_store.exchange_code_request(
        issued.code.expose(),
        ID,
        REDIRECT,
        Some(RESOURCE),
        VERIFIER,
        None,
        &lookup_lease,
    );
    let release = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(blocker);
    };
    let (result, _) = tokio::join!(lookup, release);
    assert!(matches!(result, Err(CredentialError::MetadataExpired)));
    single.close().await;
    let short = resolved(&document(), Duration::from_millis(50));
    let mut lock = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM provider_sessions WHERE id=$1 FOR UPDATE")
        .bind(session.id)
        .execute(&mut *lock)
        .await
        .unwrap();
    let credentials = CredentialStore::new(pool.clone());
    let exchange = credentials.exchange_code_request(
        issued.code.expose(),
        ID,
        REDIRECT,
        Some(RESOURCE),
        VERIFIER,
        None,
        &short,
    );
    let release = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        lock.rollback().await.unwrap();
    };
    let (result, _) = tokio::join!(exchange, release);
    assert!(matches!(result, Err(CredentialError::MetadataExpired)));
    let consumed: bool =
        sqlx::query_scalar("SELECT consumed_at IS NOT NULL FROM authorization_codes")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!consumed);
    let fresh = resolved(&document(), Duration::from_secs(60));
    let issued = CredentialStore::new(pool.clone())
        .exchange_code_request(
            issued.code.expose(),
            ID,
            REDIRECT,
            Some(RESOURCE),
            VERIFIER,
            None,
            &fresh,
        )
        .await
        .unwrap();
    let refresh = issued.refresh_token.unwrap();
    let (one, two) = tokio::join!(
        credentials.rotate_refresh_request(refresh.expose(), ID, Some(RESOURCE), None, &fresh),
        credentials.rotate_refresh_request(refresh.expose(), ID, Some(RESOURCE), None, &fresh)
    );
    assert_ne!(one.is_ok(), two.is_ok());
    let winner = one.or(two).unwrap().refresh_token.unwrap();
    assert!(
        credentials
            .rotate_refresh_request(winner.expose(), ID, Some(RESOURCE), None, &fresh)
            .await
            .is_err()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn durable_binding_classification_refresh_permission_and_schema_constraints(pool: PgPool) {
    let (state, _, _dir, session) = fixture_state(&pool).await;
    let app = router(state);
    let dynamic_code = code(&app, &session, REDIRECT).await;
    let client = FirstPartyClient::new(
        ID,
        "Reviewed static",
        vec![RegisteredRedirect::new(REDIRECT, RedirectKind::Exact).unwrap()],
        ["openid", "offline_access"],
        [RESOURCE],
        None,
        Vec::<String>::new(),
        Vec::<String>::new(),
    )
    .unwrap();
    let static_registry =
        ClientRegistry::with_issuer(vec![client], &format!("{ISSUER}/").parse().unwrap()).unwrap();
    let static_grant = static_registry
        .validate_pending(AuthorizationRequest {
            client_id: ID,
            redirect_uri: REDIRECT,
            response_type: "code",
            code_challenge_method: "S256",
            code_challenge: &crate::s256_challenge(VERIFIER).unwrap(),
            scopes: &["openid", "offline_access"],
            resource: Some(RESOURCE),
        })
        .unwrap()
        .approve(true)
        .unwrap();
    let credentials = CredentialStore::new(pool.clone());
    let static_code = credentials
        .issue_authorization_code(&session, &static_grant, Duration::from_secs(60))
        .await
        .unwrap();
    let dynamic_registry = resolved(&document(), Duration::from_secs(60));
    assert!(matches!(
        credentials
            .exchange_code_request(
                &dynamic_code,
                ID,
                REDIRECT,
                Some(RESOURCE),
                VERIFIER,
                None,
                &static_registry
            )
            .await,
        Err(CredentialError::InvalidGrant)
    ));
    assert!(matches!(
        credentials
            .exchange_code_request(
                static_code.expose(),
                ID,
                REDIRECT,
                Some(RESOURCE),
                VERIFIER,
                None,
                &dynamic_registry
            )
            .await,
        Err(CredentialError::InvalidGrant)
    ));
    assert!(
        credentials
            .exchange_code(&dynamic_code, ID, REDIRECT, RESOURCE, VERIFIER)
            .await
            .is_err()
    );
    let none = ClientRegistry::new(vec![]).unwrap();
    assert!(
        credentials
            .exchange_code_request(
                static_code.expose(),
                ID,
                REDIRECT,
                Some(RESOURCE),
                VERIFIER,
                None,
                &none
            )
            .await
            .is_err()
    );
    let consumed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM authorization_codes WHERE consumed_at IS NOT NULL",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(consumed, 0);
    for invalid in [
        json!({}),
        json!({"version":2,"client_id":ID,"redirects":[],"refresh_allowed":true}),
        json!({"version":1,"client_id":"different","redirects":[],"refresh_allowed":true}),
        json!({"version":1,"client_id":ID,"redirects":[],"refresh_allowed":true,"extra":"x".repeat(50000)}),
    ] {
        let error = sqlx::query(
            "UPDATE authorization_codes SET cimd_binding=$1::jsonb WHERE cimd_binding IS NOT NULL",
        )
        .bind(serde_json::to_string(&invalid).unwrap())
        .execute(&pool)
        .await
        .unwrap_err();
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("23514")
        );
    }
    // A reconstructed registry/store uses only persisted binding and fresh metadata.
    let result = CredentialStore::new(pool.clone())
        .exchange_code_request(
            &dynamic_code,
            ID,
            REDIRECT,
            Some(RESOURCE),
            VERIFIER,
            None,
            &resolved(&document(), Duration::from_secs(60)),
        )
        .await
        .unwrap();
    let refresh = result.refresh_token.unwrap();
    let mut removed = document();
    removed["grant_types"] = json!(["authorization_code"]);
    assert!(
        credentials
            .rotate_refresh_request(
                refresh.expose(),
                ID,
                Some(RESOURCE),
                None,
                &resolved(&removed, Duration::from_secs(60))
            )
            .await
            .is_err()
    );
    let without_offline = registry()
        .project_cimd(
            LeasedClientMetadata::for_test(
                ID,
                &serde_json::to_vec(&document()).unwrap(),
                Duration::from_secs(60),
            ),
            &["openid".into()],
            &[RESOURCE.into()],
            true,
        )
        .unwrap();
    assert!(
        credentials
            .rotate_refresh_request(refresh.expose(), ID, Some(RESOURCE), None, &without_offline)
            .await
            .is_err()
    );
    let wrong_resource = registry()
        .project_cimd(
            LeasedClientMetadata::for_test(
                ID,
                &serde_json::to_vec(&document()).unwrap(),
                Duration::from_secs(60),
            ),
            &["openid".into(), "offline_access".into()],
            &["https://other.example.org/resource".into()],
            true,
        )
        .unwrap();
    assert!(
        credentials
            .rotate_refresh_request(refresh.expose(), ID, Some(RESOURCE), None, &wrong_resource)
            .await
            .is_err()
    );
    let mut cosmetics = document();
    cosmetics["client_name"] = "New display name".into();
    cosmetics["redirect_uris"].as_array_mut().unwrap().reverse();
    assert!(
        CredentialStore::new(pool.clone())
            .rotate_refresh_request(
                refresh.expose(),
                ID,
                Some(RESOURCE),
                None,
                &resolved(&cosmetics, Duration::from_secs(60))
            )
            .await
            .is_ok()
    );
}

//! Headless MCP authorization contract using a synthetic protected resource.
//! Its HTTP router is a fixture, not Balance; no Balance or Google service is contacted.

use super::*;
use jsonwebtoken::{DecodingKey, Validation, decode};

const RESOURCE: &str = "https://balance-staging.shocker.cl/api/mcp";
const RESOURCE_METADATA: &str =
    "https://balance-staging.shocker.cl/.well-known/oauth-protected-resource/api/mcp";
const REDIRECT: &str = "https://mcp-client.example.test/oauth/callback";
const ISSUER: &str = "http://127.0.0.1:18082";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

#[sqlx::test(migrations = "./migrations")]
async fn protected_resource_to_jwks_and_refresh_contract(pool: PgPool) {
    run_resource_contract(pool, false).await;
}
#[sqlx::test(migrations = "./migrations")]
async fn generic_cimd_resource_to_google_consent_jwks_refresh_and_logout(pool: PgPool) {
    run_resource_contract(pool, true).await;
}
async fn run_resource_contract(pool: PgPool, generic: bool) {
    let client_id = if generic {
        "https://mcp-client.example.org/metadata.json"
    } else {
        "synthetic-mcp"
    };
    let redirect = if generic {
        "https://mcp-client.example.org/oauth/callback"
    } else {
        REDIRECT
    };
    let database_url = std::env::var("DATABASE_URL").unwrap();
    assert_eq!(
        database_url,
        std::env::var("ERI_TEST_DATABASE_URL").unwrap()
    );

    // Model only the RFC 9728 HTTP discovery contract. This fixture does not
    // assert that Balance currently serves either response in staging.
    let resource_server = Router::new()
        .route(
            "/api/mcp",
            post(|| async {
                Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header(
                        header::WWW_AUTHENTICATE,
                        format!("Bearer resource_metadata=\"{RESOURCE_METADATA}\""),
                    )
                    .body(Body::empty())
                    .unwrap()
            }),
        )
        .route(
            "/.well-known/oauth-protected-resource/api/mcp",
            get(|| async {
                axum::Json(json!({
                    "resource": RESOURCE,
                    "authorization_servers": [ISSUER],
                    "scopes_supported": ["openid", "profile", "email"]
                }))
            }),
        );
    let resource_url = url::Url::parse(RESOURCE).unwrap();
    let challenge = resource_server
        .clone()
        .oneshot(
            Request::post(resource_url.path())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(challenge.status(), StatusCode::UNAUTHORIZED);
    let authenticate = challenge.headers()[header::WWW_AUTHENTICATE]
        .to_str()
        .unwrap();
    let metadata_uri = authenticate
        .strip_prefix("Bearer resource_metadata=\"")
        .unwrap()
        .strip_suffix('"')
        .unwrap();
    assert_eq!(metadata_uri, RESOURCE_METADATA);
    let metadata_url = url::Url::parse(metadata_uri).unwrap();
    assert_eq!(metadata_url.origin(), resource_url.origin());
    let resource_metadata = resource_server
        .oneshot(
            Request::get(metadata_url.path())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resource_metadata.status(), StatusCode::OK);
    let protected_resource: serde_json::Value =
        serde_json::from_str(&body(resource_metadata).await).unwrap();
    assert_eq!(protected_resource["resource"], RESOURCE);
    assert_eq!(
        protected_resource["scopes_supported"],
        json!(["openid", "profile", "email"])
    );
    let resource = protected_resource["resource"].as_str().unwrap();
    let issuer = protected_resource["authorization_servers"][0]
        .as_str()
        .unwrap();
    let registry = ClientRegistry::with_issuer(
        vec![
            FirstPartyClient::new(
                "synthetic-mcp",
                "Synthetic MCP client",
                vec![RegisteredRedirect::new(redirect, RedirectKind::Exact).unwrap()],
                ["openid", "profile", "email", "offline_access"],
                [resource],
                None,
                ["https://mcp-client.example.test"],
                Vec::<String>::new(),
            )
            .unwrap(),
        ],
        &format!("{issuer}/").parse().unwrap(),
    )
    .unwrap();

    let nonce = Arc::new(Mutex::new(String::new()));
    let public = RsaPublicKey::from_public_key_pem(
        std::str::from_utf8(&fixture("active-public.pem")).unwrap(),
    )
    .unwrap();
    let upstream_jwks = json!({"keys":[{"kty":"RSA","kid":"google","use":"sig","alg":"RS256","n":URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),"e":URL_SAFE_NO_PAD.encode(public.e().to_bytes_be())}]});
    let token_nonce = nonce.clone();
    let upstream = Router::new()
        .route("/token", post(move || {
            let nonce = token_nonce.lock().unwrap().clone();
            async move {
                let now = Utc::now().timestamp();
                let claims = json!({"iss":"https://accounts.google.com","sub":"mcp-fixture-user","aud":"client-1","exp":now+300,"iat":now,"nonce":nonce});
                let mut header = Header::new(Algorithm::RS256);
                header.kid = Some("google".into());
                axum::Json(json!({"id_token":jsonwebtoken::encode(&header, &claims, &EncodingKey::from_rsa_pem(&fixture("active-private.pem")).unwrap()).unwrap()}))
            }
        }))
        .route("/certs", get(move || {
            let jwks = upstream_jwks.clone();
            async move { axum::Json(jwks) }
        }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_origin = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });

    let (_keys_dir, keys) = signing_keys();
    let google = GoogleAdapter::for_test_http(
        format!("{upstream_origin}/authorize"),
        format!("{upstream_origin}/token"),
        format!("{upstream_origin}/certs"),
        format!("{issuer}/federation/google/callback"),
    );
    let mut state = AppState::for_test_provider(
        Database::from_pool(pool.clone(), Duration::from_secs(1)),
        keys,
        registry,
        google,
    );
    if generic {
        let provider = Arc::get_mut(&mut state.0)
            .unwrap()
            .provider
            .as_mut()
            .unwrap();
        provider.cimd_policy = Some(CimdPolicyConfig {
            scopes: vec![
                "openid".into(),
                "profile".into(),
                "email".into(),
                "offline_access".into(),
            ],
            resources: vec![resource.into()],
            allow_refresh: true,
        });
        let document = json!({"client_id":client_id,"client_name":"Synthetic public client","redirect_uris":[redirect],"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"]});
        provider.cimd_fetcher = CimdFetcher::for_test_document_source(Arc::new(Mutex::new(Some(
            serde_json::to_vec(&document).unwrap(),
        ))));
    }
    let app = router(state);
    let as_path = format!(
        "{}/.well-known/oauth-authorization-server",
        url::Url::parse(issuer)
            .unwrap()
            .path()
            .trim_end_matches('/')
    );
    let metadata_response = app
        .clone()
        .oneshot(Request::get(as_path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(metadata_response.status(), StatusCode::OK);
    let metadata: serde_json::Value = serde_json::from_str(&body(metadata_response).await).unwrap();
    assert_eq!(metadata["issuer"], issuer);
    assert_eq!(metadata["client_id_metadata_document_supported"], generic);
    assert!(metadata.get("registration_endpoint").is_none());
    assert_eq!(
        metadata["code_challenge_methods_supported"],
        json!(["S256"])
    );
    assert_eq!(
        metadata["authorization_response_iss_parameter_supported"],
        true
    );
    assert_eq!(
        metadata["token_endpoint_auth_methods_supported"],
        json!(["none"])
    );

    let authorize_path =
        url::Url::parse(metadata["authorization_endpoint"].as_str().unwrap()).unwrap();
    let challenge = crate::oauth::s256_challenge(VERIFIER).unwrap();
    let authorize = format!(
        "{}?{}",
        authorize_path.path(),
        form_urlencoded::Serializer::new(String::new())
            .append_pair("response_type", "code")
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", redirect)
            // offline_access is an extra AS scope for the synthetic refresh
            // check; the protected resource advertises the three scopes above.
            .append_pair("scope", "openid profile email offline_access")
            .append_pair("resource", resource)
            .append_pair("code_challenge_method", "S256")
            .append_pair("code_challenge", &challenge)
            .append_pair("state", "mcp-state")
            .append_pair("nonce", "mcp-nonce")
            .finish()
    );
    let start = begin_test_google(&app, &authorize).await;
    let transaction_cookie = cookie_value(&start);
    let upstream_url: url::Url = start.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let query = upstream_url
        .query_pairs()
        .collect::<std::collections::HashMap<_, _>>();
    *nonce.lock().unwrap() = query["nonce"].to_string();
    let callback = format!(
        "/federation/google/callback?state={}&code=synthetic",
        query["state"]
    );
    let completed = app
        .clone()
        .oneshot(
            Request::get(callback)
                .header(header::COOKIE, transaction_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(completed.status(), StatusCode::OK);
    let session_cookie = cookie_value(&completed);
    let html = body(completed).await;
    if generic {
        assert!(html.contains(client_id));
        assert!(html.contains("nombre declarado"));
    }
    let silent = app
        .clone()
        .oneshot(
            Request::get(format!("{authorize}&prompt=none"))
                .header(header::COOKIE, &session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(silent.status(), StatusCode::SEE_OTHER);
    assert!(
        silent.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .contains("error=consent_required")
    );
    let approval = form_urlencoded::Serializer::new(String::new())
        .append_pair("transaction_id", &form_value(&html, "transaction_id"))
        .append_pair("csrf", &form_value(&html, "csrf"))
        .append_pair("action", "approve")
        .finish();
    let approved = app
        .clone()
        .oneshot(
            Request::post("/consent")
                .header(header::COOKIE, &session_cookie)
                .header(header::ORIGIN, issuer)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(approval))
                .unwrap(),
        )
        .await
        .unwrap();
    let returned = consent_http_target(approved).await;
    assert_eq!(returned.as_str().split('?').next().unwrap(), redirect);
    let callback_values = returned
        .query_pairs()
        .collect::<std::collections::HashMap<_, _>>();
    assert_eq!(callback_values["state"], "mcp-state");
    assert_eq!(callback_values["iss"], issuer);

    let token_path = url::Url::parse(metadata["token_endpoint"].as_str().unwrap()).unwrap();
    let exchange = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("client_id", client_id)
        .append_pair("code", &callback_values["code"])
        .append_pair("redirect_uri", redirect)
        .append_pair("code_verifier", VERIFIER)
        .append_pair("resource", resource)
        .finish();
    let response = app
        .clone()
        .oneshot(
            Request::post(token_path.path())
                .body(Body::from(exchange))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let issued: serde_json::Value = serde_json::from_str(&body(response).await).unwrap();
    assert_eq!(issued["token_type"], "Bearer");
    let access = issued["access_token"].as_str().unwrap();
    let jwt_header = jsonwebtoken::decode_header(access).unwrap();
    assert_eq!(jwt_header.alg, Algorithm::RS256);
    assert_eq!(jwt_header.typ.as_deref(), Some("at+jwt"));

    // Verify solely against the advertised public JWKS, as an MCP resource
    // server would. Explicitly reject an unrelated audience.
    let jwks_path = url::Url::parse(metadata["jwks_uri"].as_str().unwrap()).unwrap();
    let jwks_response = app
        .clone()
        .oneshot(Request::get(jwks_path.path()).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let jwks: serde_json::Value = serde_json::from_str(&body(jwks_response).await).unwrap();
    let key = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["kid"] == jwt_header.kid.as_deref().unwrap())
        .unwrap();
    assert!(key.get("d").is_none());
    let decoding_key =
        DecodingKey::from_rsa_components(key["n"].as_str().unwrap(), key["e"].as_str().unwrap())
            .unwrap();
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[resource]);
    let claims = decode::<serde_json::Value>(access, &decoding_key, &validation)
        .unwrap()
        .claims;
    assert_eq!(claims["client_id"], client_id);
    assert!(
        claims["aud"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == resource)
    );
    validation.set_audience(&["https://other.example.test/mcp"]);
    assert!(decode::<serde_json::Value>(access, &decoding_key, &validation).is_err());

    let refresh = issued["refresh_token"].as_str().unwrap();
    let refresh_form = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "refresh_token")
        .append_pair("client_id", client_id)
        .append_pair("refresh_token", refresh)
        .append_pair("resource", resource)
        .finish();
    let refreshed = app
        .clone()
        .oneshot(
            Request::post(token_path.path())
                .body(Body::from(refresh_form.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refreshed.status(), StatusCode::OK);
    let refreshed: serde_json::Value = serde_json::from_str(&body(refreshed).await).unwrap();
    assert!(
        decode::<serde_json::Value>(
            refreshed["access_token"].as_str().unwrap(),
            &decoding_key,
            &{
                let mut expected = Validation::new(Algorithm::RS256);
                expected.set_issuer(&[issuer]);
                expected.set_audience(&[resource]);
                expected
            }
        )
        .is_ok()
    );
    let replay = app
        .clone()
        .oneshot(
            Request::post(token_path.path())
                .body(Body::from(refresh_form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body(replay).await).unwrap(),
        json!({"error":"invalid_grant"})
    );
    let successor_form = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "refresh_token")
        .append_pair("client_id", client_id)
        .append_pair(
            "refresh_token",
            refreshed["refresh_token"].as_str().unwrap(),
        )
        .append_pair("resource", resource)
        .finish();
    let revoked = app
        .clone()
        .oneshot(
            Request::post(token_path.path())
                .body(Body::from(successor_form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoked.status(), StatusCode::BAD_REQUEST);
    let consent = app
        .clone()
        .oneshot(
            Request::get(&authorize)
                .header(header::COOKIE, &session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(consent.status(), StatusCode::OK);
    let html = body(consent).await;
    let approval = form_urlencoded::Serializer::new(String::new())
        .append_pair("transaction_id", &form_value(&html, "transaction_id"))
        .append_pair("csrf", &form_value(&html, "csrf"))
        .append_pair("action", "approve")
        .finish();
    let approved = app
        .clone()
        .oneshot(
            Request::post("/consent")
                .header(header::COOKIE, &session_cookie)
                .header(header::ORIGIN, issuer)
                .body(Body::from(approval))
                .unwrap(),
        )
        .await
        .unwrap();
    let location = consent_http_target(approved).await;
    let code = location
        .query_pairs()
        .find(|(key, _)| key == "code")
        .unwrap()
        .1
        .into_owned();
    let exchange = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("client_id", client_id)
        .append_pair("code", &code)
        .append_pair("redirect_uri", redirect)
        .append_pair("code_verifier", VERIFIER)
        .append_pair("resource", resource)
        .finish();
    let live = app
        .clone()
        .oneshot(Request::post("/token").body(Body::from(exchange)).unwrap())
        .await
        .unwrap();
    assert_eq!(live.status(), StatusCode::OK);
    let live: serde_json::Value = serde_json::from_str(&body(live).await).unwrap();
    let logout = app
        .clone()
        .oneshot(
            Request::get("/logout")
                .header(header::COOKIE, &session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(logout.status(), StatusCode::OK);
    let html = body(logout).await;
    let logout_form = form_urlencoded::Serializer::new(String::new())
        .append_pair("challenge", &form_value(&html, "challenge"))
        .append_pair("csrf", &form_value(&html, "csrf"))
        .finish();
    let ended = app
        .clone()
        .oneshot(
            Request::post("/logout")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &session_cookie)
                .header(header::ORIGIN, issuer)
                .body(Body::from(logout_form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ended.status(), StatusCode::SEE_OTHER);
    let refresh_form = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "refresh_token")
        .append_pair("client_id", client_id)
        .append_pair("refresh_token", live["refresh_token"].as_str().unwrap())
        .append_pair("resource", resource)
        .finish();
    let ended_refresh = app
        .oneshot(
            Request::post("/token")
                .body(Body::from(refresh_form))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ended_refresh.status(), StatusCode::BAD_REQUEST);
}

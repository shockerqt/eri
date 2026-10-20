//! All identities, cookies and signing material here are isolated fixtures.
use super::*;
use crate::{AuthenticatedUser, oauth::LogoutFlow, tokens::IdClaims};
const ISSUER: &str = "http://127.0.0.1:18082";
const RESOURCE: &str = "https://api.example/resource";
const RETURN: &str = "https://app.example/signed-out";
const CALLBACK: &str = "https://app.example/callback?fixed=%2F";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
fn policy(opt_in: bool) -> ClientRegistry {
    ClientRegistry::with_issuer(
        vec![
            FirstPartyClient::new(
                "web",
                "Balance",
                vec![RegisteredRedirect::new(CALLBACK, RedirectKind::Exact).unwrap()],
                ["openid", "offline_access"],
                [RESOURCE],
                None,
                ["https://app.example"],
                [RETURN],
            )
            .unwrap()
            .with_logout_flow(if opt_in {
                LogoutFlow::IdTokenHint
            } else {
                LogoutFlow::Interactive
            }),
        ],
        &ISSUER.parse().unwrap(),
    )
    .unwrap()
}
async fn fixture_state(
    pool: &PgPool,
    opt_in: bool,
) -> (tempfile::TempDir, AppState, ProviderSession, Uuid) {
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
    // An older active provider session allows proof that an expired hint remains usable.
    sqlx::query("UPDATE provider_sessions SET auth_time=clock_timestamp()-interval '10 minutes' WHERE id=$1").bind(session.id).execute(pool).await.unwrap();
    let (dir, keys) = signing_keys();
    let google = GoogleAdapter::for_test_http(
        "http://127.0.0.1:1/authorize".into(),
        "http://127.0.0.1:1/token".into(),
        "http://127.0.0.1:1/certs".into(),
        format!("{ISSUER}/federation/google/callback"),
    );
    let state = AppState::for_test_provider(
        Database::from_pool(pool.clone(), Duration::from_secs(1)),
        keys,
        policy(opt_in),
        google,
    );
    (dir, state, session, user)
}
fn claims(session: &ProviderSession, user: Uuid) -> IdClaims {
    let now = Utc::now().timestamp();
    IdClaims {
        iss: ISSUER.into(),
        sub: user,
        aud: "web".into(),
        sid: Some(session.id),
        exp: now + 300,
        iat: now,
        nonce: None,
        auth_time: None,
    }
}
fn request(session: &ProviderSession, hint: Option<&str>, post: bool) -> Request<Body> {
    let mut params = form_urlencoded::Serializer::new(String::new());
    params
        .append_pair("client_id", "web")
        .append_pair("post_logout_redirect_uri", RETURN)
        .append_pair("state", "bye & safe");
    if let Some(hint) = hint {
        params.append_pair("id_token_hint", hint);
    }
    let params = params.finish();
    let request = if post {
        Request::post("/logout")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(params))
    } else {
        Request::get(format!("/logout?{params}")).body(Body::empty())
    };
    let mut request = request.unwrap();
    request.headers_mut().insert(
        header::COOKIE,
        format!("{}={}", session_cookie(false), session.expose())
            .parse()
            .unwrap(),
    );
    request
}
async fn renewable(
    store: &CredentialStore,
    session: &ProviderSession,
    registry: &ClientRegistry,
) -> crate::ExchangeResult {
    let grant = registry
        .validate_pending(AuthorizationRequest {
            client_id: "web",
            redirect_uri: CALLBACK,
            response_type: "code",
            code_challenge_method: "S256",
            code_challenge: &crate::s256_challenge(VERIFIER).unwrap(),
            scopes: &["openid", "offline_access"],
            resource: Some(RESOURCE),
        })
        .unwrap()
        .approve(true)
        .unwrap();
    let code = store
        .issue_authorization_code(session, &grant, Duration::from_secs(45))
        .await
        .unwrap();
    store
        .exchange_code(code.expose(), "web", CALLBACK, RESOURCE, VERIFIER)
        .await
        .unwrap()
}
#[sqlx::test(migrations = "./migrations")]
async fn automatic_get_and_form_post_revoke_independent_families_and_clear_cookie(pool: PgPool) {
    for post in [false, true] {
        let (_dir, state, session, _user) = fixture_state(&pool, true).await;
        let store = CredentialStore::new(pool.clone());
        let a = renewable(&store, &session, &policy(true)).await;
        let tokens = tokens::issue(
            &state.0.keys,
            ISSUER,
            &format!("{ISSUER}/userinfo"),
            a,
            true,
        )
        .unwrap();
        let hint = tokens.id_token.as_deref().unwrap();
        assert_eq!(
            state.0.keys.verify_id_logout(hint, ISSUER).unwrap().sid,
            Some(session.id)
        );
        let b = renewable(&store, &session, &policy(true))
            .await
            .refresh_token
            .unwrap();
        store
            .revoke_refresh(tokens.refresh_token.as_deref().unwrap(), "web")
            .await
            .unwrap();
        let b_successor = store
            .rotate_refresh(b.expose(), "web", RESOURCE)
            .await
            .unwrap()
            .refresh_token
            .unwrap();
        let app = router(state);
        let response = app
            .clone()
            .oneshot(request(&session, Some(hint), post))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers()[header::LOCATION],
            "https://app.example/signed-out?state=bye+%26+safe"
        );
        assert!(
            response.headers()[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
        );
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(
            store
                .rotate_refresh(b_successor.expose(), "web", RESOURCE)
                .await
                .is_err()
        );
        let active: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM refresh_families WHERE session_id=$1 AND revoked_at IS NULL",
        )
        .bind(session.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(active, 0);
        assert_eq!(
            app.oneshot(request(&session, Some(hint), post))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
}
#[sqlx::test(migrations = "./migrations")]
async fn expired_hint_only_qualifies_for_current_active_session(pool: PgPool) {
    let (_dir, state, session, user) = fixture_state(&pool, true).await;
    let mut c = claims(&session, user);
    c.iat -= 500;
    c.exp -= 400;
    let hint = state.0.keys.sign_id(&c).unwrap();
    assert_eq!(
        router(state)
            .oneshot(request(&session, Some(&hint), false))
            .await
            .unwrap()
            .status(),
        StatusCode::SEE_OTHER
    );
}
#[sqlx::test(migrations = "./migrations")]
async fn valid_but_unbound_or_default_hints_require_confirmation(pool: PgPool) {
    for case in ["missing", "old", "subject", "sid", "old_iat", "default"] {
        let (_dir, state, session, user) = fixture_state(&pool, case != "default").await;
        let mut c = claims(&session, user);
        match case {
            "old" => c.sid = None,
            "subject" => c.sub = Uuid::new_v4(),
            "sid" => c.sid = Some(Uuid::new_v4()),
            "old_iat" => {
                c.iat -= 1000;
                c.exp -= 900;
            }
            _ => {}
        }
        let hint = state.0.keys.sign_id(&c).unwrap();
        let response = router(state)
            .oneshot(request(
                &session,
                if case == "missing" { None } else { Some(&hint) },
                false,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{case}");
        assert!(body(response).await.contains("name=csrf"));
        let active: bool =
            sqlx::query_scalar("SELECT revoked_at IS NULL FROM provider_sessions WHERE id=$1")
                .bind(session.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(active, "{case}");
    }
}
#[sqlx::test(migrations = "./migrations")]
async fn invalid_hints_and_ambiguous_requests_have_no_logout_effect(pool: PgPool) {
    for case in [
        "aud",
        "issuer",
        "future",
        "interval",
        "signature",
        "key",
        "algorithm",
        "type",
        "crit",
        "duplicate",
        "mixed",
        "bad_return",
    ] {
        let (_dir, state, session, user) = fixture_state(&pool, true).await;
        let mut c = claims(&session, user);
        match case {
            "aud" => c.aud = "other".into(),
            "issuer" => c.iss = "https://evil.example".into(),
            "future" => {
                c.iat += 300;
                c.exp += 600;
            }
            "interval" => c.exp = c.iat,
            _ => {}
        }
        let mut h = Header::new(Algorithm::RS256);
        h.typ = Some(if case == "type" { "at+jwt" } else { "JWT" }.into());
        h.kid = Some(if case == "key" { "unknown" } else { "active" }.into());
        let mut hint = if case == "algorithm" {
            jsonwebtoken::encode(
                &Header::new(Algorithm::HS256),
                &c,
                &EncodingKey::from_secret(b"test-only"),
            )
            .unwrap()
        } else {
            jsonwebtoken::encode(
                &h,
                &c,
                &EncodingKey::from_rsa_pem(&fixture("active-private.pem")).unwrap(),
            )
            .unwrap()
        };
        if case == "signature" {
            let mut parts: Vec<_> = hint.split('.').map(str::to_owned).collect();
            let replacement = if parts[2].starts_with('A') { "B" } else { "A" };
            parts[2].replace_range(..1, replacement);
            hint = parts.join(".");
        }
        if case == "crit" {
            let mut parts: Vec<_> = hint.split('.').map(str::to_owned).collect();
            let header = json!({"alg":"RS256","typ":"JWT","kid":"active","crit":["unknown"]});
            parts[0] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
            hint = parts.join(".");
        }
        let mut req = request(&session, Some(&hint), false);
        if ["duplicate", "mixed", "bad_return"].contains(&case) {
            let uri = format!(
                "{}{}",
                req.uri(),
                match case {
                    "duplicate" => "&id_token_hint=",
                    "mixed" => "&challenge=bad",
                    _ => "&post_logout_redirect_uri=https://evil.example",
                }
            );
            *req.uri_mut() = uri.parse().unwrap();
        }
        assert_eq!(
            router(state).oneshot(req).await.unwrap().status(),
            StatusCode::BAD_REQUEST,
            "{case}"
        );
        let active: bool =
            sqlx::query_scalar("SELECT revoked_at IS NULL FROM provider_sessions WHERE id=$1")
                .bind(session.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(active, "{case}");
    }
}
#[sqlx::test(migrations = "./migrations")]
async fn confirmation_requires_same_origin_and_unique_csrf_and_is_one_use(pool: PgPool) {
    let (_dir, state, session, _) = fixture_state(&pool, true).await;
    let app = router(state.clone());
    let html = body(
        app.clone()
            .oneshot(request(&session, None, false))
            .await
            .unwrap(),
    )
    .await;
    let id = form_value(&html, "challenge");
    let csrf = form_value(&html, "csrf");
    let form = format!("challenge={id}&csrf={csrf}");
    let cookie = format!("{}={}", session_cookie(false), session.expose());
    for (origin, suffix) in [
        ("https://evil.example", ""),
        (ISSUER, "&csrf=duplicate"),
        (ISSUER, "&client_id=web"),
        (ISSUER, "&id_token_hint=foo"),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::post("/logout")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(header::ORIGIN, origin)
                    .header(header::COOKIE, &cookie)
                    .body(Body::from(format!("{form}{suffix}")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let make_request = || {
        Request::post("/logout")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ORIGIN, ISSUER)
            .header(header::COOKIE, &cookie)
            .body(Body::from(form.clone()))
            .unwrap()
    };
    let (a, b) = tokio::join!(
        app.clone().oneshot(make_request()),
        app.clone().oneshot(make_request())
    );
    let statuses = [a.unwrap().status(), b.unwrap().status()];
    assert_eq!(
        statuses
            .iter()
            .filter(|&&s| s == StatusCode::SEE_OTHER)
            .count(),
        1
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|&&s| s == StatusCode::BAD_REQUEST)
            .count(),
        1
    );
    assert_eq!(
        app.oneshot(make_request()).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn finish_rechecks_policy_and_active_session_and_serializes_hint_races(pool: PgPool) {
    let (_dir, state, session, user) = fixture_state(&pool, true).await;
    let store = LogoutStore::new(pool.clone());
    let challenge = store
        .begin(&session, "web", RETURN, Some("race"), &policy(true))
        .await
        .unwrap();
    let c = claims(&session, user);
    assert!(
        store
            .finish_hint(&session, &challenge, &policy(false), &c)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .finish_hint(&session, &challenge, &ClientRegistry::default(), &c)
            .await
            .is_err()
    );
    let hint = state.0.keys.sign_id(&c).unwrap();
    let app = router(state);
    let (a, b) = tokio::join!(
        app.clone().oneshot(request(&session, Some(&hint), false)),
        app.oneshot(request(&session, Some(&hint), true))
    );
    let statuses = [a.unwrap().status(), b.unwrap().status()];
    assert_eq!(
        statuses
            .iter()
            .filter(|&&s| s == StatusCode::SEE_OTHER)
            .count(),
        1
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|&&s| s == StatusCode::BAD_REQUEST)
            .count(),
        1
    );
    assert!(
        store
            .finish_hint(&session, &challenge, &policy(true), &c)
            .await
            .is_err()
    );
}

#[test]
fn hint_verification_requires_identity_and_time_claims_and_rejects_signed_crit() {
    let (_dir, keys) = signing_keys();
    let now = Utc::now().timestamp();
    let valid = json!({"iss":ISSUER,"sub":Uuid::new_v4(),"aud":"web","iat":now,"exp":now+300});
    for key in ["iss", "sub", "aud", "iat", "exp"] {
        let mut c = valid.clone();
        c.as_object_mut().unwrap().remove(key);
        assert!(
            keys.verify_id_logout(&keys.sign_id(&c).unwrap(), ISSUER)
                .is_err(),
            "{key}"
        );
    }
    // A correctly signed critical extension is still unsupported.
    let header =
        URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT","kid":"active","crit":["unknown"]}"#);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&valid).unwrap());
    let signing_input = format!("{header}.{payload}");
    let signature = jsonwebtoken::crypto::sign(
        signing_input.as_bytes(),
        &EncodingKey::from_rsa_pem(&fixture("active-private.pem")).unwrap(),
        Algorithm::RS256,
    )
    .unwrap();
    let token = format!("{signing_input}.{signature}");
    assert!(keys.verify_id_logout(&token, ISSUER).is_err());
}

#[sqlx::test(migrations = "./migrations")]
async fn signed_audience_can_identify_rp_but_cookie_return_and_post_encoding_are_required(
    pool: PgPool,
) {
    let (_dir, state, session, user) = fixture_state(&pool, true).await;
    let hint = state.0.keys.sign_id(&claims(&session, user)).unwrap();
    let app = router(state);
    let mut missing_cookie = request(&session, Some(&hint), false);
    missing_cookie.headers_mut().remove(header::COOKIE);
    assert_eq!(
        app.clone().oneshot(missing_cookie).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    let mut wrong_return = request(&session, Some(&hint), false);
    let uri = wrong_return.uri().to_string().replace(
        "https%3A%2F%2Fapp.example%2Fsigned-out",
        "https%3A%2F%2Fevil.example%2F",
    );
    *wrong_return.uri_mut() = uri.parse().unwrap();
    assert_eq!(
        app.clone().oneshot(wrong_return).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    let mut wrong_encoding = request(&session, Some(&hint), true);
    wrong_encoding
        .headers_mut()
        .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    assert_eq!(
        app.clone().oneshot(wrong_encoding).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    let mut mixed_query = request(&session, Some(&hint), true);
    *mixed_query.uri_mut() = "/logout?client_id=web".parse().unwrap();
    assert_eq!(
        app.clone().oneshot(mixed_query).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    let mut hint_only = request(&session, Some(&hint), false);
    let uri = hint_only.uri().to_string().replace("client_id=web&", "");
    *hint_only.uri_mut() = uri.parse().unwrap();
    assert_eq!(
        app.oneshot(hint_only).await.unwrap().status(),
        StatusCode::SEE_OTHER
    );
}

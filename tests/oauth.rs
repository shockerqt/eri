use eri::{
    AuthorizationFlow, AuthorizationRequest, ClientRegistry, FirstPartyClient, RedirectKind,
    RegisteredRedirect, s256_challenge, verify_s256,
};

fn registry() -> ClientRegistry {
    ClientRegistry::new(vec![
        FirstPartyClient::new(
            "mobile",
            "Mobile",
            vec![
                RegisteredRedirect::new(
                    "com.example.app:/oauth/callback?x=%2F",
                    RedirectKind::Exact,
                )
                .unwrap(),
                RegisteredRedirect::new("http://127.0.0.1/cb?x=%2F", RedirectKind::NativeLoopback)
                    .unwrap(),
                RegisteredRedirect::new("http://[::1]/cb?x=%2F", RedirectKind::NativeLoopback)
                    .unwrap(),
                RegisteredRedirect::new("http://127.0.0.1:80", RedirectKind::NativeLoopback)
                    .unwrap(),
                RegisteredRedirect::new("http://[::1]?raw=%2F", RedirectKind::NativeLoopback)
                    .unwrap(),
                RegisteredRedirect::new(
                    "http://127.0.0.1/cb%2Fpart?x=%2F",
                    RedirectKind::NativeLoopback,
                )
                .unwrap(),
                RegisteredRedirect::new("https://app.example/OAuth?x=%2F", RedirectKind::Exact)
                    .unwrap(),
            ],
            ["openid", "profile", "offline_access"],
            ["https://api.example/resource"],
            Some("https://api.example/resource".into()),
            ["https://app.example"],
            ["https://app.example/logout"],
        )
        .unwrap(),
    ])
    .unwrap()
}

#[test]
fn pre_authorization_requires_explicit_static_policy_and_resource() {
    let trusted = FirstPartyClient::with_authorization_flow(
        "web",
        "Balance",
        vec![
            RegisteredRedirect::new(
                "https://app.example/callback",
                RedirectKind::AppClaimedHttps,
            )
            .unwrap(),
        ],
        ["openid", "offline_access"],
        ["https://api.example/resource"],
        None,
        ["https://app.example"],
        Vec::<String>::new(),
        AuthorizationFlow::GooglePreauthorized,
    )
    .unwrap();
    let trusted_registry =
        ClientRegistry::with_issuer(vec![trusted], &"https://auth.example/".parse().unwrap())
            .unwrap();
    let request = AuthorizationRequest {
        client_id: "web",
        redirect_uri: "https://app.example/callback",
        response_type: "code",
        code_challenge_method: "S256",
        code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        scopes: &["openid", "offline_access"],
        resource: Some("https://api.example/resource"),
    };
    let approved = trusted_registry.validate_pending(request.clone()).unwrap();
    assert!(trusted_registry.pre_authorizes(&approved));
    let userinfo = trusted_registry
        .validate_pending(AuthorizationRequest {
            resource: Some("https://auth.example/userinfo"),
            ..request
        })
        .unwrap();
    assert!(!trusted_registry.pre_authorizes(&userinfo));
    assert!(!registry().pre_authorizes(&approved));
}

#[test]
fn preauthorization_needs_the_selected_verified_https_redirect_not_just_a_client_id() {
    let claimed = "https://app.example/auth-callback";
    let legacy = "balance-dev://auth-callback";
    let exact_https = "https://app.example/ordinary-callback";
    let client = FirstPartyClient::with_authorization_flow(
        "native",
        "Balance",
        vec![
            RegisteredRedirect::new(claimed, RedirectKind::AppClaimedHttps).unwrap(),
            RegisteredRedirect::new(legacy, RedirectKind::Exact).unwrap(),
            RegisteredRedirect::new(exact_https, RedirectKind::Exact).unwrap(),
        ],
        ["openid", "offline_access"],
        ["https://api.example/resource"],
        None,
        Vec::<String>::new(),
        Vec::<String>::new(),
        AuthorizationFlow::GooglePreauthorized,
    )
    .unwrap();
    let registry = ClientRegistry::new(vec![client]).unwrap();
    for (redirect_uri, expected) in [(claimed, true), (legacy, false), (exact_https, false)] {
        let pending = registry
            .validate_pending(AuthorizationRequest {
                client_id: "native",
                redirect_uri,
                response_type: "code",
                code_challenge_method: "S256",
                code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                scopes: &["openid", "offline_access"],
                resource: Some("https://api.example/resource"),
            })
            .unwrap();
        assert_eq!(registry.pre_authorizes(&pending), expected);
    }
    for uri in [
        "balance-dev://auth-callback",
        "http://app.example/callback",
        "https://127.0.0.1/callback",
        "https://localhost/callback",
    ] {
        assert!(RegisteredRedirect::new(uri, RedirectKind::AppClaimedHttps).is_err());
    }
    assert!(!registry.trusted_redirect("native", "https://app.example/auth-callback/"));
    assert!(!registry.trusted_redirect("native", "https://app.example:8443/auth-callback"));
}

fn validate<'a>(
    redirect: &'a str,
    scopes: &'a [&'a str],
) -> Result<eri::PendingAuthorizationGrant, eri::OAuthError> {
    registry().validate_pending(AuthorizationRequest {
        client_id: "mobile",
        redirect_uri: redirect,
        response_type: "code",
        code_challenge_method: "S256",
        code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        scopes,
        resource: Some("https://api.example/resource"),
    })
}

#[test]
fn rfc7636_s256_vector_is_independent() {
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    assert_eq!(s256_challenge(verifier).unwrap(), expected);
    assert!(verify_s256(verifier, expected));
    assert!(!verify_s256(
        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXa",
        expected
    ));
    assert!(s256_challenge("short").is_err());
}

#[test]
fn redirects_are_byte_exact_except_native_literal_loopback_port() {
    for accepted in [
        "com.example.app:/oauth/callback?x=%2F",
        "https://app.example/OAuth?x=%2F",
        "http://127.0.0.1:49152/cb?x=%2F",
        "http://[::1]:49153/cb?x=%2F",
        "http://127.0.0.1:80",
        "http://127.0.0.1:49154",
        "http://[::1]:49155?raw=%2F",
        "http://127.0.0.1:49156/cb%2Fpart?x=%2F",
    ] {
        assert!(validate(accepted, &["openid"]).is_ok(), "{accepted}");
    }
    for rejected in [
        "https://app.example/oauth?x=%2F",
        "https://APP.example/OAuth?x=%2F",
        "https://app.example/OAuth?x=/",
        "https://app.example:443/OAuth?x=%2F",
        "http://localhost:49152/cb?x=%2F",
        "http://127.0.0.2:49152/cb?x=%2F",
        "http://127.0.0.1:49152/cb?x=/",
        "http://127.0.0.1:49156/cb/part?x=%2F",
        "http://127.0.0.1:49152/cb?x=%2F#fragment",
        "http://user@127.0.0.1:49152/cb?x=%2F",
        "http://127.0.0.1evil:49152/cb?x=%2F",
        "http://127.0.0.1::49152/cb?x=%2F",
    ] {
        assert!(validate(rejected, &["openid"]).is_err(), "{rejected}");
    }
}

#[test]
fn policy_restricts_method_scopes_and_resources() {
    let grant = validate(
        "https://app.example/OAuth?x=%2F",
        &["offline_access", "openid"],
    )
    .unwrap();
    assert_eq!(grant.resource(), "https://api.example/resource");
    assert!(validate("https://app.example/OAuth?x=%2F", &["openid", "openid"],).is_err());
    let mut request = AuthorizationRequest {
        client_id: "mobile",
        redirect_uri: "https://app.example/OAuth?x=%2F",
        response_type: "token",
        code_challenge_method: "S256",
        code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        scopes: &["openid"],
        resource: Some("https://api.example/other"),
    };
    assert!(registry().validate_pending(request.clone()).is_err());
    request.response_type = "code";
    assert!(registry().validate_pending(request.clone()).is_err());
    request.resource = Some("https://api.example/resource");
    request.code_challenge_method = "plain";
    assert!(registry().validate_pending(request).is_err());

    for invalid in ["", "two words", "line\nbreak", "tab\tscope"] {
        assert!(
            FirstPartyClient::new(
                "bad",
                "Bad",
                vec![RegisteredRedirect::new("com.example:/cb", RedirectKind::Exact).unwrap()],
                [invalid],
                ["https://api.example/resource"],
                None,
                std::iter::empty::<String>(),
                std::iter::empty::<String>(),
            )
            .is_err()
        );
    }
}

#[test]
fn challenge_is_exact_canonical_s256_output() {
    let registry = registry();
    for invalid in [
        "...........................................",
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c",
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM=",
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw.cM",
    ] {
        let request = AuthorizationRequest {
            client_id: "mobile",
            redirect_uri: "https://app.example/OAuth?x=%2F",
            response_type: "code",
            code_challenge_method: "S256",
            code_challenge: invalid,
            scopes: &["openid"],
            resource: Some("https://api.example/resource"),
        };
        assert!(registry.validate_pending(request).is_err(), "{invalid}");
    }
}

#[test]
fn pending_consent_userinfo_and_redirect_trust_are_distinct() {
    let client = FirstPartyClient::new(
        "browser",
        "Browser client",
        vec![RegisteredRedirect::new("https://app.example/callback", RedirectKind::Exact).unwrap()],
        ["openid", "offline_access"],
        std::iter::empty::<String>(),
        None,
        ["https://app.example"],
        ["https://app.example/signed-out"],
    )
    .unwrap();
    let registry = ClientRegistry::with_issuer(
        vec![client],
        &url::Url::parse("https://auth.example/").unwrap(),
    )
    .unwrap();
    assert!(registry.trusted_redirect("browser", "https://app.example/callback"));
    assert!(!registry.trusted_redirect("browser", "https://app.example/signed-out"));
    assert!(registry.valid_post_logout_redirect("browser", "https://app.example/signed-out"));
    assert!(!registry.valid_post_logout_redirect("browser", "https://app.example/callback"));

    let pending = registry
        .validate_pending(AuthorizationRequest {
            client_id: "browser",
            redirect_uri: "https://app.example/callback",
            response_type: "code",
            code_challenge_method: "S256",
            code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            scopes: &["openid", "offline_access"],
            resource: None,
        })
        .unwrap();
    assert_eq!(pending.resource(), "https://auth.example/userinfo");

    let no_openid = registry.validate_pending(AuthorizationRequest {
        client_id: "browser",
        redirect_uri: "https://app.example/callback",
        response_type: "code",
        code_challenge_method: "S256",
        code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        scopes: &["offline_access"],
        resource: Some("https://auth.example/userinfo"),
    });
    assert!(no_openid.is_err());
}

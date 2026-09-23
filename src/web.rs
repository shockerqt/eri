use crate::{
    AuthorizationRequest, BrowserStore, ClientRegistry, Config, ConsentHandle, CredentialStore,
    Database, GoogleAdapter, LogoutChallenge, LogoutStore, ProviderSession, SigningKeys,
    config::Mode,
    tokens::{self, AccessClaims},
};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::DefaultBodyLimit,
    extract::{RawQuery, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use chrono::Utc;
use serde::Serialize;
use std::{sync::Arc, time::Duration};
use url::form_urlencoded;
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState(Arc<Inner>);
struct Provider {
    registry: ClientRegistry,
    google: GoogleAdapter,
    issuer: String,
    userinfo: String,
    secure: bool,
}
struct Inner {
    database: Database,
    keys: SigningKeys,
    provider: Option<Provider>,
}
impl AppState {
    pub fn new(config: Config, database: Database, keys: SigningKeys) -> anyhow::Result<Self> {
        let provider = if let Some(auth) = &config.authorization {
            let google = auth.google.as_ref().ok_or_else(|| {
                anyhow::anyhow!("authorization provider configuration is incomplete")
            })?;
            if std::env::var(&google.client_secret_env)
                .ok()
                .is_none_or(|v| v.is_empty())
            {
                anyhow::bail!("authorization provider secret is unavailable")
            };
            let registry = config
                .authorization_registry()?
                .ok_or_else(|| anyhow::anyhow!("authorization configuration is invalid"))?;
            let issuer = config.issuer.as_str().trim_end_matches('/').to_owned();
            Some(Provider {
                registry,
                google: GoogleAdapter::new(
                    &google.client_id,
                    &google.client_secret_env,
                    &config.issuer,
                )?,
                userinfo: format!("{issuer}/userinfo"),
                issuer,
                secure: config.mode == Mode::Production,
            })
        } else {
            None
        };
        Ok(Self(Arc::new(Inner {
            database,
            keys,
            provider,
        })))
    }
}

#[cfg(test)]
impl AppState {
    fn for_test_provider(
        database: Database,
        keys: SigningKeys,
        registry: ClientRegistry,
        google: GoogleAdapter,
    ) -> Self {
        Self::for_test_provider_mode(database, keys, registry, google, false)
    }
    fn for_test_provider_mode(
        database: Database,
        keys: SigningKeys,
        registry: ClientRegistry,
        google: GoogleAdapter,
        secure: bool,
    ) -> Self {
        Self::for_test_provider_at(
            database,
            keys,
            registry,
            google,
            secure,
            "http://127.0.0.1:18082".to_owned(),
        )
    }
    fn for_test_provider_at(
        database: Database,
        keys: SigningKeys,
        registry: ClientRegistry,
        google: GoogleAdapter,
        secure: bool,
        issuer: String,
    ) -> Self {
        Self(Arc::new(Inner {
            database,
            keys,
            provider: Some(Provider {
                registry,
                google,
                userinfo: format!("{issuer}/userinfo"),
                issuer,
                secure,
            }),
        }))
    }
}

pub fn router(state: AppState) -> Router {
    let mut app = Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/jwks", get(jwks))
        .route("/auth.css", get(css));
    if state.0.provider.is_some() {
        app = app
            .route("/", get(signed_out))
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/.well-known/oauth-authorization-server", get(discovery))
            .route("/authorize", get(authorize_get).post(authorize_post))
            .route("/federation/google/start", post(google_start))
            .route("/federation/google/callback", get(callback))
            .route("/consent", get(consent_get).post(consent_post))
            .route("/token", post(token).options(api_options))
            .route(
                "/userinfo",
                get(userinfo).post(userinfo).options(api_options),
            )
            .route("/revoke", post(revoke).options(api_options))
            .route("/logout", get(logout_get).post(logout_post));
    }
    app.layer(DefaultBodyLimit::max(8192))
        .with_state(state)
        .fallback(not_found)
        .method_not_allowed_fallback(not_found)
        .layer(middleware::from_fn(security_middleware))
}
async fn security_middleware(request: axum::http::Request<Body>, next: Next) -> Response {
    let public = matches!(
        request.uri().path(),
        "/jwks"
            | "/.well-known/openid-configuration"
            | "/.well-known/oauth-authorization-server"
            | "/auth.css"
    );
    let mut response = next.run(request).await;
    if public {
        public_security(response.headers_mut())
    } else {
        sensitive_headers(response.headers_mut())
    }
    response
}
async fn live() -> Response {
    sensitive(StatusCode::NO_CONTENT.into_response())
}
async fn ready(State(s): State<AppState>) -> Response {
    sensitive(
        if s.0.database.ready().await {
            StatusCode::NO_CONTENT
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        }
        .into_response(),
    )
}
async fn jwks(State(s): State<AppState>) -> Response {
    public_json(s.0.keys.jwks_json().to_owned())
}
async fn css() -> Response {
    let mut r = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        CSS,
    )
        .into_response();
    public_security(r.headers_mut());
    r
}
async fn signed_out() -> Response {
    sensitive(
        Html(page(
            "Sesión cerrada",
            "<p>Tu sesión de Eri se cerró correctamente.</p>",
        ))
        .into_response(),
    )
}

#[derive(Serialize)]
struct Metadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    revocation_endpoint: String,
    jwks_uri: String,
    response_types_supported: [&'static str; 1],
    subject_types_supported: [&'static str; 1],
    id_token_signing_alg_values_supported: [&'static str; 1],
    token_endpoint_auth_methods_supported: [&'static str; 1],
    grant_types_supported: [&'static str; 2],
    code_challenge_methods_supported: [&'static str; 1],
    authorization_response_iss_parameter_supported: bool,
    request_uri_parameter_supported: bool,
    request_parameter_supported: bool,
    claims_parameter_supported: bool,
    scopes_supported: Vec<String>,
}
async fn discovery(State(s): State<AppState>) -> Response {
    let p = s.0.provider.as_ref().unwrap();
    let b = &p.issuer;
    json_public(&Metadata {
        issuer: b.clone(),
        authorization_endpoint: format!("{b}/authorize"),
        token_endpoint: format!("{b}/token"),
        userinfo_endpoint: format!("{b}/userinfo"),
        revocation_endpoint: format!("{b}/revoke"),
        jwks_uri: format!("{b}/jwks"),
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
        token_endpoint_auth_methods_supported: ["none"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        code_challenge_methods_supported: ["S256"],
        authorization_response_iss_parameter_supported: true,
        request_uri_parameter_supported: false,
        request_parameter_supported: false,
        claims_parameter_supported: false,
        scopes_supported: p.registry.advertised_scopes().into_iter().collect(),
    })
}

async fn authorize_get(
    State(s): State<AppState>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
) -> Response {
    authorize(s, raw.unwrap_or_default(), headers).await
}
async fn authorize_post(State(s): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    authorize(
        s,
        String::from_utf8(body.to_vec()).unwrap_or_default(),
        headers,
    )
    .await
}
async fn authorize(s: AppState, raw: String, headers: HeaderMap) -> Response {
    let Ok(q) = pairs(&raw, 8192) else {
        return local_error("Solicitud inválida");
    };
    let (Some(client), Some(redirect)) = (one(&q, "client_id"), one(&q, "redirect_uri")) else {
        return local_error("Solicitud inválida");
    };
    let p = s.0.provider.as_ref().unwrap();
    if !p.registry.trusted_redirect(client, redirect) {
        return local_error("Cliente o retorno inválido");
    }
    let state = match optional(&q, "state") {
        Ok(v) => v,
        Err(_) => return local_error("Solicitud inválida"),
    };
    match authorize_valid(&s, &q, &headers).await {
        Ok(r) => r,
        Err(code) => oauth_redirect(redirect, state, &p.issuer, &code),
    }
}
async fn authorize_valid(
    s: &AppState,
    q: &[(String, String)],
    headers: &HeaderMap,
) -> Result<Response, String> {
    let p = s.0.provider.as_ref().unwrap();
    for unsupported in ["request_uri", "request", "claims", "response_mode"] {
        if optional(q, unsupported)?.is_some() {
            return Err("request_not_supported".into());
        }
    }
    let client = required(q, "client_id")?;
    let redirect = required(q, "redirect_uri")?;
    let response_type = required(q, "response_type")?;
    let method = required(q, "code_challenge_method")?;
    let challenge = required(q, "code_challenge")?;
    let scope = required(q, "scope")?;
    let scopes = scope
        .split(' ')
        .filter(|v| !v.is_empty())
        .collect::<Vec<_>>();
    let resource = optional(q, "resource")?;
    let nonce = optional(q, "nonce")?;
    let downstream = optional(q, "state")?;
    let prompt = optional(q, "prompt")?;
    if prompt.is_some_and(|v| !matches!(v, "none" | "consent" | "login")) {
        return Err("invalid_request".into());
    }
    let max_age = optional(q, "max_age")?
        .map(|v| {
            v.parse::<u64>()
                .ok()
                .filter(|n| *n <= 31_536_000)
                .ok_or("invalid_request")
        })
        .transpose()?;
    let pending = p
        .registry
        .validate_pending(AuthorizationRequest {
            client_id: client,
            redirect_uri: redirect,
            response_type,
            code_challenge_method: method,
            code_challenge: challenge,
            scopes: &scopes,
            resource,
        })
        .map_err(|_| "invalid_request".to_owned())?;
    let session = session_from(headers, &s.0.database, p.secure).await;
    if prompt == Some("login") {
        return Err("login_required".into());
    }
    if let Some(session) = session {
        if let Some(max_age) = max_age {
            let auth_time = BrowserStore::new(s.0.database.pool().clone())
                .session_upstream_auth_time(&session)
                .await
                .map_err(|_| "login_required".to_owned())?;
            let Some(auth_time) = auth_time else {
                return Err("login_required".into());
            };
            if Utc::now().signed_duration_since(auth_time).num_seconds() > max_age as i64 {
                return Err("login_required".into());
            }
        }
        if prompt == Some("none") {
            return Err("consent_required".into());
        }
        let store = BrowserStore::new(s.0.database.pool().clone());
        let handle = store
            .begin_authenticated(&session, &pending, downstream, nonce)
            .await
            .map_err(|_| "server_error".to_owned())?;
        return Ok(consent_page(&store, &session, &handle, &p.registry).await);
    }
    if prompt == Some("none") || max_age.is_some() {
        return Err("login_required".into());
    }
    if transaction_cookie_count(headers, p.secure) >= 4 {
        return Err("temporarily_unavailable".into());
    }
    let start = BrowserStore::new(s.0.database.pool().clone())
        .begin_google(&pending, downstream, nonce)
        .await
        .map_err(|_| "server_error".to_owned())?;
    let upstream = p
        .google
        .authorization_url(
            start.upstream_state(),
            start.upstream_nonce(),
            &start.upstream_challenge(),
            false,
        )
        .map_err(|_| "server_error".to_owned())?;
    let cookie = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600{}",
        tx_cookie(start.transaction_id(), p.secure),
        start.browser_binding(),
        if p.secure { "; Secure" } else { "" }
    );
    let client_name = p.registry.display_name(client).ok_or("server_error")?;
    let mut r = login_page(
        render_login(
            client_name,
            pending.scopes(),
            pending.resource(),
            start.transaction_id(),
            start.upstream_state(),
        ),
        upstream.as_str(),
        pending.redirect_uri(),
    );
    r.headers_mut()
        .insert(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
    Ok(sensitive(r))
}

async fn google_start(State(s): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let p = s.0.provider.as_ref().unwrap();
    if !same_origin(&headers, &p.issuer) {
        return local_error("Origen inválido");
    }
    let Ok(q) = pairs_bytes(&body, 1024) else {
        return local_error("Solicitud inválida");
    };
    let (Ok(id), Ok(state), Ok(action)) = (
        required(&q, "transaction_id")
            .and_then(|v| Uuid::parse_str(v).map_err(|_| "invalid_request".into())),
        required(&q, "state"),
        required(&q, "action"),
    ) else {
        return local_error("Solicitud inválida");
    };
    if !matches!(action, "continue" | "cancel") {
        return local_error("Solicitud inválida");
    }
    let name = tx_cookie(id, p.secure);
    let Some(binding) = cookie(&headers, &name) else {
        return local_error("La solicitud expiró");
    };
    let store = BrowserStore::new(s.0.database.pool().clone());
    if action == "cancel" {
        let outcome = store.cancel_google(id, state, binding).await;
        let Ok(outcome) = outcome else {
            return local_error("La solicitud expiró");
        };
        let mut response = oauth_redirect(
            &outcome.redirect_uri,
            outcome.downstream_state.as_deref(),
            &p.issuer,
            "access_denied",
        );
        clear_transaction_cookie(&mut response, Some(&name), p.secure);
        return response;
    }
    let Ok((nonce, verifier)) = store.start_google(id, state, binding).await else {
        return local_error("La solicitud expiró");
    };
    let Ok(challenge) = crate::oauth::s256_challenge(&verifier) else {
        return local_error("Solicitud inválida");
    };
    let Ok(url) = p.google.authorization_url(state, &nonce, &challenge, false) else {
        return local_error("No se pudo iniciar el acceso");
    };
    sensitive(Redirect::to(url.as_str()).into_response())
}

async fn callback(
    State(s): State<AppState>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
) -> Response {
    let Ok(q) = pairs(&raw.unwrap_or_default(), 4096) else {
        return local_error("Respuesta de acceso inválida");
    };
    let Some(state) = one(&q, "state") else {
        return local_error("Respuesta de acceso inválida");
    };
    let code = match optional(&q, "code") {
        Ok(v) => v,
        Err(_) => return local_error("Respuesta de acceso inválida"),
    };
    let upstream_error = match optional(&q, "error") {
        Ok(v) => v,
        Err(_) => return local_error("Respuesta de acceso inválida"),
    };
    if code.is_some() == upstream_error.is_some() {
        return local_error("Respuesta de acceso inválida");
    }
    let p = s.0.provider.as_ref().unwrap();
    let store = BrowserStore::new(s.0.database.pool().clone());
    let mut winner = None;
    let mut consumed_cookie = None;
    for (name, binding) in transaction_cookies(&headers, p.secure) {
        if let Ok(v) = store.claim_callback(state, &binding).await {
            winner = Some(v);
            consumed_cookie = Some(name);
            break;
        }
    }
    let Some((claim, verifier, nonce)) = winner else {
        return local_error("Respuesta de acceso inválida");
    };
    if upstream_error.is_some() {
        if upstream_error != Some("access_denied") {
            let _ = store.fail_callback(&claim).await;
            let mut response = local_error("Respuesta de acceso inválida");
            clear_transaction_cookie(&mut response, consumed_cookie.as_deref(), p.secure);
            return response;
        }
        let mut response = match store.deny_callback(&claim, &p.registry).await {
            Ok(v) => oauth_redirect(
                &v.redirect_uri,
                v.downstream_state.as_deref(),
                &p.issuer,
                "access_denied",
            ),
            Err(_) => local_error("Respuesta de acceso inválida"),
        };
        clear_transaction_cookie(&mut response, consumed_cookie.as_deref(), p.secure);
        return response;
    }
    let identity = match p
        .google
        .exchange_code(code.unwrap(), &verifier, &nonce)
        .await
    {
        Ok(v) => v,
        Err(_) => {
            let _ = store.fail_callback(&claim).await;
            let mut response = local_error("No se pudo verificar el acceso");
            clear_transaction_cookie(&mut response, consumed_cookie.as_deref(), p.secure);
            return response;
        }
    };
    let completion = match store
        .complete_callback(&claim, &identity, Duration::from_secs(30 * 24 * 3600))
        .await
    {
        Ok(v) => v,
        Err(_) => {
            let mut response = local_error("La solicitud expiró");
            clear_transaction_cookie(&mut response, consumed_cookie.as_deref(), p.secure);
            return response;
        }
    };
    let mut r = consent_page(
        &store,
        &completion.session,
        &completion.consent,
        &p.registry,
    )
    .await;
    let cookie = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Lax{}",
        session_cookie(p.secure),
        completion.session.expose(),
        if p.secure { "; Secure" } else { "" }
    );
    r.headers_mut()
        .insert(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
    clear_transaction_cookie(&mut r, consumed_cookie.as_deref(), p.secure);
    sensitive(r)
}
async fn consent_get(
    State(s): State<AppState>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
) -> Response {
    let Ok(q) = pairs(&raw.unwrap_or_default(), 2048) else {
        return local_error("Solicitud inválida");
    };
    let (Some(id), Some(csrf)) = (one(&q, "transaction_id"), one(&q, "csrf")) else {
        return local_error("Solicitud inválida");
    };
    let Ok(id) = Uuid::parse_str(id) else {
        return local_error("Solicitud inválida");
    };
    let p = s.0.provider.as_ref().unwrap();
    let Some(session) = session_from(&headers, &s.0.database, p.secure).await else {
        return local_error("Sesión inválida");
    };
    consent_page(
        &BrowserStore::new(s.0.database.pool().clone()),
        &session,
        &ConsentHandle::submitted(id, csrf.into()),
        &p.registry,
    )
    .await
}
async fn consent_page(
    store: &BrowserStore,
    session: &ProviderSession,
    handle: &ConsentHandle,
    registry: &ClientRegistry,
) -> Response {
    match store.consent_view(session, handle, registry).await {
        Ok(v) => form_page(render_consent(&v), &v.redirect_uri),
        Err(_) => local_error("La solicitud expiró"),
    }
}
async fn consent_post(State(s): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let Ok(q) = pairs_bytes(&body, 4096) else {
        return local_error("Solicitud inválida");
    };
    let (Some(id), Some(csrf), Some(action)) = (
        one(&q, "transaction_id"),
        one(&q, "csrf"),
        one(&q, "action"),
    ) else {
        return local_error("Solicitud inválida");
    };
    let Ok(id) = Uuid::parse_str(id) else {
        return local_error("Solicitud inválida");
    };
    let p = s.0.provider.as_ref().unwrap();
    if !same_origin(&headers, &p.issuer) {
        return local_error("Origen inválido");
    }
    let Some(session) = session_from(&headers, &s.0.database, p.secure).await else {
        return local_error("Sesión inválida");
    };
    let h = ConsentHandle::submitted(id, csrf.into());
    let store = BrowserStore::new(s.0.database.pool().clone());
    match action {
        "approve" => match store.approve(&session, &h, &p.registry).await {
            Ok(v) => code_redirect(
                &v.redirect_uri,
                v.downstream_state.as_deref(),
                &p.issuer,
                v.code.expose(),
            ),
            Err(_) => local_error("La solicitud expiró"),
        },
        "deny" => match store.deny(&session, &h).await {
            Ok(v) => oauth_redirect(
                &v.redirect_uri,
                v.downstream_state.as_deref(),
                &p.issuer,
                "access_denied",
            ),
            Err(_) => local_error("La solicitud expiró"),
        },
        _ => local_error("Solicitud inválida"),
    }
}

async fn token(State(s): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let Ok(q) = pairs_bytes(&body, 8192) else {
        return token_error("invalid_request");
    };
    let Some(client) = one(&q, "client_id") else {
        return token_error("invalid_request");
    };
    if ["client_secret", "client_assertion", "client_assertion_type"]
        .iter()
        .any(|name| q.iter().any(|(key, _)| key == name))
    {
        return token_error("invalid_client");
    }
    let p = s.0.provider.as_ref().unwrap();
    if origin(&headers).is_some_and(|o| !p.registry.valid_browser_origin(client, o)) {
        return token_error("invalid_client");
    }
    let resource = match optional(&q, "resource") {
        Ok(v) => v,
        Err(_) => return token_error("invalid_request"),
    };
    let scope = match optional(&q, "scope") {
        Ok(v) => v.map(|v| v.split(' ').map(str::to_owned).collect::<Vec<_>>()),
        Err(_) => return token_error("invalid_request"),
    };
    let store = CredentialStore::new(s.0.database.pool().clone());
    let result = match one(&q, "grant_type") {
        Some("authorization_code") => {
            let (Some(code), Some(redirect), Some(verifier)) = (
                one(&q, "code"),
                one(&q, "redirect_uri"),
                one(&q, "code_verifier"),
            ) else {
                return token_error("invalid_request");
            };
            store
                .exchange_code_request(
                    code,
                    client,
                    redirect,
                    resource,
                    verifier,
                    scope.as_deref(),
                    &p.registry,
                )
                .await
                .map(|v| (v, true))
        }
        Some("refresh_token") => {
            let Some(refresh) = one(&q, "refresh_token") else {
                return token_error("invalid_request");
            };
            store
                .rotate_refresh_request(refresh, client, resource, scope.as_deref(), &p.registry)
                .await
                .map(|v| (v, false))
        }
        _ => return token_error("unsupported_grant_type"),
    };
    let mut response = match result {
        Ok((v, initial)) => match tokens::issue(&s.0.keys, &p.issuer, &p.userinfo, v, initial) {
            Ok(v) => json_sensitive(&v),
            Err(_) => token_error("server_error"),
        },
        Err(_) => token_error("invalid_grant"),
    };
    if let Some(value) = origin(&headers) {
        cors(response.headers_mut(), value)
    }
    response
}
async fn userinfo(State(s): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let p = s.0.provider.as_ref().unwrap();
    let form = if body.is_empty() {
        vec![]
    } else {
        match pairs_bytes(&body, 4096) {
            Ok(v) => v,
            Err(_) => return bearer_error(),
        }
    };
    let Some(token) = bearer(&headers, &form) else {
        return bearer_error();
    };
    let claims: AccessClaims = match s.0.keys.verify(token, &p.issuer, &p.userinfo) {
        Ok(v) => v,
        Err(_) => return bearer_error(),
    };
    let now = Utc::now().timestamp();
    if claims.exp <= now - 30
        || claims.iat > now + 30
        || claims.jti.is_empty()
        || claims.client_id.is_empty()
    {
        return bearer_error();
    }
    let scopes = claims.scope.split(' ').collect::<Vec<_>>();
    if !scopes.contains(&"openid")
        || scopes.is_empty()
        || scopes.iter().any(|scope| !valid_scope(scope))
    {
        return bearer_error();
    }
    if origin(&headers).is_some_and(|o| !p.registry.valid_browser_origin(&claims.client_id, o)) {
        return bearer_error();
    }
    let Some(profile) = s.0.database.user_profile(claims.sub).await.ok().flatten() else {
        return bearer_error();
    };
    let mut value = serde_json::json!({"sub":claims.sub});
    if scopes.contains(&"profile") {
        if let Some(v) = profile.name {
            value["name"] = v.into()
        }
        if let Some(v) = profile.given_name {
            value["given_name"] = v.into()
        }
        if let Some(v) = profile.family_name {
            value["family_name"] = v.into()
        }
        if let Some(v) = profile.picture {
            value["picture"] = v.into()
        }
    }
    if scopes.contains(&"email")
        && let Some(v) = profile.verified_email
    {
        value["email"] = v.into();
        value["email_verified"] = true.into()
    }
    let mut response = json_sensitive(&value);
    if let Some(origin) = origin(&headers) {
        cors(response.headers_mut(), origin)
    }
    response
}
async fn revoke(State(s): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let Ok(q) = pairs_bytes(&body, 4096) else {
        return token_error("invalid_request");
    };
    let (Some(client), Some(value)) = (one(&q, "client_id"), one(&q, "token")) else {
        return token_error("invalid_request");
    };
    let p = s.0.provider.as_ref().unwrap();
    if origin(&headers).is_some_and(|o| !p.registry.valid_browser_origin(client, o)) {
        return token_error("invalid_client");
    }
    if CredentialStore::new(s.0.database.pool().clone())
        .revoke_refresh(value, client)
        .await
        .is_err()
    {
        let mut response = json_sensitive_status(
            StatusCode::SERVICE_UNAVAILABLE,
            &serde_json::json!({"error":"server_error"}),
        );
        if let Some(origin) = origin(&headers) {
            cors(response.headers_mut(), origin)
        }
        return response;
    }
    let mut response = sensitive(StatusCode::OK.into_response());
    if let Some(origin) = origin(&headers) {
        cors(response.headers_mut(), origin)
    }
    response
}
async fn api_options(State(s): State<AppState>, headers: HeaderMap) -> Response {
    let p = s.0.provider.as_ref().unwrap();
    let Some(o) = origin(&headers) else {
        return sensitive(StatusCode::BAD_REQUEST.into_response());
    };
    let requested_method = headers
        .get(header::ACCESS_CONTROL_REQUEST_METHOD)
        .and_then(|v| v.to_str().ok());
    let requested_headers = headers
        .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let headers_valid = requested_headers
        .split(',')
        .map(|v| v.trim().to_ascii_lowercase())
        .all(|v| v.is_empty() || matches!(v.as_str(), "authorization" | "content-type"));
    if !p.registry.reviewed_browser_origin(o)
        || !matches!(requested_method, Some("GET" | "POST"))
        || !headers_valid
    {
        return sensitive(StatusCode::FORBIDDEN.into_response());
    }
    let mut r = StatusCode::NO_CONTENT.into_response();
    cors(r.headers_mut(), o);
    r
}

async fn logout_get(
    State(s): State<AppState>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
) -> Response {
    let Ok(q) = pairs(&raw.unwrap_or_default(), 4096) else {
        return local_error("Solicitud inválida");
    };
    if one(&q, "id_token_hint").is_some() {
        return local_error("Solicitud inválida");
    }
    let client = match optional(&q, "client_id") {
        Ok(v) => v,
        Err(_) => return local_error("Solicitud inválida"),
    };
    let redirect = match optional(&q, "post_logout_redirect_uri") {
        Ok(v) => v,
        Err(_) => return local_error("Solicitud inválida"),
    };
    if client.is_some() != redirect.is_some() {
        return local_error("Solicitud inválida");
    }
    let state = match optional(&q, "state") {
        Ok(v) => v,
        Err(_) => return local_error("Solicitud inválida"),
    };
    let p = s.0.provider.as_ref().unwrap();
    let Some(session) = session_from(&headers, &s.0.database, p.secure).await else {
        return local_error("Sesión inválida");
    };
    let store = LogoutStore::new(s.0.database.pool().clone());
    let challenge = match (client, redirect) {
        (Some(client), Some(redirect)) => {
            store
                .begin(&session, client, redirect, state, &p.registry)
                .await
        }
        (None, None) => store.begin_local(&session, &p.issuer).await,
        _ => unreachable!(),
    };
    match challenge {
        Ok(c) => form_page(render_logout(&c), c.redirect_uri()),
        Err(_) => local_error("Solicitud inválida"),
    }
}
async fn logout_post(State(s): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let Ok(q) = pairs_bytes(&body, 4096) else {
        return local_error("Solicitud inválida");
    };
    let (Some(id), Some(csrf)) = (one(&q, "challenge"), one(&q, "csrf")) else {
        return local_error("Solicitud inválida");
    };
    let Ok(id) = Uuid::parse_str(id) else {
        return local_error("Solicitud inválida");
    };
    let p = s.0.provider.as_ref().unwrap();
    if !same_origin(&headers, &p.issuer) {
        return local_error("Origen inválido");
    }
    let Some(session) = session_from(&headers, &s.0.database, p.secure).await else {
        return local_error("Sesión inválida");
    };
    match LogoutStore::new(s.0.database.pool().clone())
        .finish(
            &session,
            &LogoutChallenge::submitted(id, csrf.into()),
            &p.registry,
        )
        .await
    {
        Ok(v) => {
            let mut r = redirect_params(&v.redirect_uri, &[("state", v.state.as_deref())]);
            r.headers_mut().append(
                header::SET_COOKIE,
                HeaderValue::from_str(&format!(
                    "{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{}",
                    session_cookie(p.secure),
                    if p.secure { "; Secure" } else { "" }
                ))
                .unwrap(),
            );
            sensitive(r)
        }
        Err(_) => local_error("Solicitud inválida"),
    }
}

fn pairs_bytes(body: &Bytes, max: usize) -> Result<Vec<(String, String)>, ()> {
    pairs(std::str::from_utf8(body).map_err(|_| ())?, max)
}
fn pairs(raw: &str, max: usize) -> Result<Vec<(String, String)>, ()> {
    if raw.len() > max || !valid_percent(raw) {
        return Err(());
    }
    let v = form_urlencoded::parse(raw.as_bytes())
        .into_owned()
        .collect::<Vec<_>>();
    if v.len() > 32 || v.iter().any(|(k, v)| k.len() > 128 || v.len() > 2048) {
        Err(())
    } else {
        Ok(v)
    }
}
fn valid_percent(raw: &str) -> bool {
    let b = raw.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && (i + 2 >= b.len() || !b[i + 1].is_ascii_hexdigit() || !b[i + 2].is_ascii_hexdigit())
        {
            return false;
        }
        i += if b[i] == b'%' { 3 } else { 1 }
    }
    true
}
fn valid_scope(scope: &str) -> bool {
    !scope.is_empty()
        && scope
            .bytes()
            .all(|b| b == b'!' || (b'#'..=b'[').contains(&b) || (b']'..=b'~').contains(&b))
}
fn one<'a>(q: &'a [(String, String)], name: &str) -> Option<&'a str> {
    let mut v = q.iter().filter(|(k, _)| k == name).map(|(_, v)| v.as_str());
    let f = v.next()?;
    if v.next().is_some() { None } else { Some(f) }
}
fn required<'a>(q: &'a [(String, String)], name: &str) -> Result<&'a str, String> {
    one(q, name)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| "invalid_request".into())
}
fn optional<'a>(q: &'a [(String, String)], name: &str) -> Result<Option<&'a str>, String> {
    if q.iter().filter(|(k, _)| k == name).count() > 1 {
        Err("invalid_request".into())
    } else {
        Ok(one(q, name))
    }
}
async fn session_from(h: &HeaderMap, d: &Database, secure: bool) -> Option<ProviderSession> {
    let raw = cookie(h, session_cookie(secure))?;
    CredentialStore::new(d.pool().clone())
        .find_provider_session(raw)
        .await
        .ok()
}
fn cookie<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut found = None;
    for value in h.get_all(header::COOKIE) {
        let text = value.to_str().ok()?;
        if text.len() > 4096 {
            return None;
        }
        for part in text.split(';').take(32) {
            let (k, v) = part.trim().split_once('=')?;
            if k == name {
                if found.is_some() || v.len() > 512 {
                    return None;
                }
                found = Some(v)
            }
        }
    }
    found
}
fn transaction_cookies(h: &HeaderMap, secure: bool) -> Vec<(String, String)> {
    let prefix = if secure { "__Host-eri_tx_" } else { "eri_tx_" };
    let values = h
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|p| p.trim().split_once('='))
        .filter(|(k, v)| {
            k.strip_prefix(prefix)
                .is_some_and(|id| Uuid::parse_str(id).is_ok())
                && v.len() <= 512
        })
        .map(|(k, v)| (k.into(), v.into()))
        .collect::<Vec<_>>();
    let unique = values
        .iter()
        .map(|(name, _)| name)
        .collect::<std::collections::BTreeSet<_>>();
    if values.len() > 4 || unique.len() != values.len() {
        Vec::new()
    } else {
        values
    }
}
fn transaction_cookie_count(h: &HeaderMap, secure: bool) -> usize {
    let prefix = if secure { "__Host-eri_tx_" } else { "eri_tx_" };
    h.get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|p| p.trim().split_once('='))
        .filter(|(k, _)| {
            k.strip_prefix(prefix)
                .is_some_and(|id| Uuid::parse_str(id).is_ok())
        })
        .count()
}
fn tx_cookie(id: Uuid, secure: bool) -> String {
    if secure {
        format!("__Host-eri_tx_{id}")
    } else {
        format!("eri_tx_{id}")
    }
}
fn session_cookie(secure: bool) -> &'static str {
    if secure {
        "__Host-eri_session"
    } else {
        "eri_dev_session"
    }
}
fn clear_transaction_cookie(response: &mut Response, name: Option<&str>, secure: bool) {
    if let Some(name) = name {
        let clear = format!(
            "{name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{}",
            if secure { "; Secure" } else { "" }
        );
        response
            .headers_mut()
            .append(header::SET_COOKIE, HeaderValue::from_str(&clear).unwrap());
    }
}
fn origin(h: &HeaderMap) -> Option<&str> {
    let mut values = h.get_all(header::ORIGIN).iter();
    let first = values.next()?;
    if values.next().is_some() {
        return Some("\0");
    }
    first.to_str().ok().or(Some("\0"))
}
fn same_origin(h: &HeaderMap, issuer: &str) -> bool {
    origin(h).is_none_or(|v| v == issuer)
}
fn bearer<'a>(h: &'a HeaderMap, f: &'a [(String, String)]) -> Option<&'a str> {
    let a = h
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let b = one(f, "access_token");
    match (a, b) {
        (Some(v), None) | (None, Some(v)) => Some(v),
        _ => None,
    }
}
fn redirect_params(base: &str, items: &[(&str, Option<&str>)]) -> Response {
    let mut url = base.to_owned();
    let mut e = form_urlencoded::Serializer::new(String::new());
    for (k, v) in items {
        if let Some(v) = v {
            e.append_pair(k, v);
        }
    }
    let q = e.finish();
    if !q.is_empty() {
        url.push(if base.contains('?') { '&' } else { '?' });
        url.push_str(&q)
    }
    Redirect::to(&url).into_response()
}
fn oauth_redirect(base: &str, state: Option<&str>, issuer: &str, error: &str) -> Response {
    sensitive(redirect_params(
        base,
        &[
            ("error", Some(error)),
            ("state", state),
            ("iss", Some(issuer)),
        ],
    ))
}
fn code_redirect(base: &str, state: Option<&str>, issuer: &str, code: &str) -> Response {
    sensitive(redirect_params(
        base,
        &[
            ("code", Some(code)),
            ("state", state),
            ("iss", Some(issuer)),
        ],
    ))
}
fn render_consent(v: &crate::ConsentView) -> String {
    page(
        "Autorizar acceso",
        &format!(
            "<p><strong>{}</strong> solicita acceso a tu cuenta.</p><p class=account>Cuenta: <strong>{}</strong></p><p>Permisos: {}</p><p>Recurso: {}</p><form method=post action=/consent><input type=hidden name=transaction_id value=\"{}\"><input type=hidden name=csrf value=\"{}\"><button name=action value=approve>Autorizar</button><button class=secondary name=action value=deny>Denegar</button></form>",
            escape(&v.client_name),
            escape(&v.account),
            escape(&v.scopes.join(" · ")),
            escape(&v.resource),
            v.transaction_id,
            escape(&v.csrf)
        ),
    )
}
fn render_login(
    client_name: &str,
    scopes: &[String],
    resource: &str,
    id: Uuid,
    state: &str,
) -> String {
    page(
        &escape(client_name),
        &format!(
            "<p>Esta aplicación solicita acceso a tu cuenta.</p><p>Permisos: {}</p><p>Recurso: {}</p><form method=post action=/federation/google/start><input type=hidden name=transaction_id value=\"{}\"><input type=hidden name=state value=\"{}\"><button name=action value=continue>Continuar con Google</button><button class=secondary name=action value=cancel>Cancelar</button></form>",
            escape(&scopes.join(" · ")),
            escape(resource),
            id,
            escape(state),
        ),
    )
}
fn render_logout(v: &LogoutChallenge) -> String {
    page(
        "Cerrar sesión",
        &format!(
            "<p>Se cerrará tu sesión en Eri.</p><form method=post action=/logout><input type=hidden name=challenge value=\"{}\"><input type=hidden name=csrf value=\"{}\"><button>Cerrar sesión</button></form>",
            v.id(),
            escape(v.csrf())
        ),
    )
}
fn page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=es><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><link rel=stylesheet href=/auth.css><title>{title} · Eri</title></head><body><main><div class=mark>E</div><p class=eyebrow>IDENTIDAD SHOCKER</p><h1>{title}</h1>{body}</main></body></html>"
    )
}
fn escape(v: &str) -> String {
    v.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn local_error(m: &str) -> Response {
    sensitive(
        (
            StatusCode::BAD_REQUEST,
            Html(page(
                "No pudimos continuar",
                &format!("<p>{}</p>", escape(m)),
            )),
        )
            .into_response(),
    )
}
fn form_page(html: String, redirect_uri: &str) -> Response {
    let mut response = sensitive(Html(html).into_response());
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin"),
    );
    if let Some(source) = form_action_source(redirect_uri) {
        let policy = format!(
            "default-src 'none'; style-src 'self'; form-action 'self' {source}; frame-ancestors 'none'; base-uri 'none'"
        );
        if let Ok(value) = HeaderValue::from_str(&policy) {
            response
                .headers_mut()
                .insert(header::CONTENT_SECURITY_POLICY, value);
        }
    }
    response
}
fn login_page(html: String, google_uri: &str, redirect_uri: &str) -> Response {
    let mut response = sensitive(Html(html).into_response());
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin"),
    );
    if let (Some(google), Some(client)) = (
        form_action_source(google_uri),
        form_action_source(redirect_uri),
    ) {
        let policy = format!(
            "default-src 'none'; style-src 'self'; form-action 'self' {google} {client}; frame-ancestors 'none'; base-uri 'none'"
        );
        if let Ok(value) = HeaderValue::from_str(&policy) {
            response
                .headers_mut()
                .insert(header::CONTENT_SECURITY_POLICY, value);
        }
    }
    response
}
fn form_action_source(redirect_uri: &str) -> Option<String> {
    let url = url::Url::parse(redirect_uri).ok()?;
    match url.scheme() {
        "http" | "https" => Some(url.origin().ascii_serialization()),
        scheme
            if !scheme.is_empty()
                && scheme.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
                }) =>
        {
            Some(format!("{scheme}:"))
        }
        _ => None,
    }
}
fn token_error(c: &str) -> Response {
    json_sensitive_status(StatusCode::BAD_REQUEST, &serde_json::json!({"error":c}))
}
fn bearer_error() -> Response {
    let mut r = json_sensitive_status(
        StatusCode::UNAUTHORIZED,
        &serde_json::json!({"error":"invalid_token"}),
    );
    r.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer error=\"invalid_token\""),
    );
    r
}
fn json_sensitive<T: Serialize>(v: &T) -> Response {
    json_sensitive_status(StatusCode::OK, v)
}
fn json_sensitive_status<T: Serialize>(s: StatusCode, v: &T) -> Response {
    let mut r = (
        s,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string(v).unwrap(),
    )
        .into_response();
    sensitive_headers(r.headers_mut());
    r
}
fn json_public<T: Serialize>(v: &T) -> Response {
    public_json(serde_json::to_string(v).unwrap())
}
fn public_json(body: String) -> Response {
    let mut r = (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "public, max-age=300"),
        ],
        body,
    )
        .into_response();
    public_security(r.headers_mut());
    r
}
fn sensitive(mut r: Response) -> Response {
    sensitive_headers(r.headers_mut());
    r
}
fn sensitive_headers(h: &mut HeaderMap) {
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    if !h.contains_key(header::REFERRER_POLICY) {
        h.insert(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        );
    }
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    if !h.contains_key(header::CONTENT_SECURITY_POLICY) {
        h.insert(header::CONTENT_SECURITY_POLICY,HeaderValue::from_static("default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"));
    }
}
fn public_security(h: &mut HeaderMap) {
    h.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
}
fn cors(h: &mut HeaderMap, o: &str) {
    if let Ok(v) = HeaderValue::from_str(o) {
        h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
        h.insert(header::VARY, HeaderValue::from_static("Origin"));
        h.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, OPTIONS"),
        );
        h.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("authorization, content-type"),
        );
    }
}
async fn not_found() -> Response {
    sensitive(StatusCode::NOT_FOUND.into_response())
}
const CSS: &str = "*{box-sizing:border-box}html{background:#111918;color:#f1f2e9;font-family:system-ui,sans-serif}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:1.5rem}main{width:min(30rem,100%);background:#1b2926;border-top:5px solid #bde6cc;padding:2.5rem;box-shadow:0 18px 50px #0006;overflow-wrap:anywhere}.mark{display:grid;place-items:center;width:2.5rem;height:2.5rem;border-radius:50%;background:#bde6cc;color:#111918;font-weight:800}.eyebrow{font:700 .7rem ui-monospace,monospace;letter-spacing:.14em;color:#aebdb5}h1{font-size:clamp(2rem,8vw,3.4rem);line-height:.95;letter-spacing:-.05em}p{line-height:1.6}button{border:0;background:#bde6cc;color:#111918;padding:.85rem 1.2rem;font-weight:700;margin:.5rem .5rem 0 0}button.secondary{background:#aebdb5;color:#111918}button:focus-visible{outline:3px solid #f0aaa0;outline-offset:3px}@media(max-width:35rem){main{padding:1.5rem}}";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FirstPartyClient, RedirectKind, RegisteredRedirect, config::DatabaseConfig};
    use axum::{body::Body, extract::Query, http::Request};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use http_body_util::BodyExt;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use rsa::{RsaPublicKey, pkcs8::DecodePublicKey, traits::PublicKeyParts};
    use serde_json::json;
    use sqlx::PgPool;
    use std::{
        fs,
        path::Path,
        sync::{
            Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };
    use tokio::net::TcpListener;
    use tower::ServiceExt;

    fn fixture(name: &str) -> Vec<u8> {
        fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/keys")
                .join(name),
        )
        .unwrap()
    }
    fn signing_keys() -> (tempfile::TempDir, SigningKeys) {
        let dir = tempfile::tempdir().unwrap();
        for name in ["active-private.pem", "active-public.pem"] {
            let target = dir.path().join(name);
            fs::copy(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/keys")
                    .join(name),
                &target,
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(target, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        fs::write(dir.path().join("manifest.json"),r#"{"active":{"kid":"active","private_key":"active-private.pem","public_key":"active-public.pem"},"previous":[],"next":[]}"#).unwrap();
        let keys = SigningKeys::load(&dir.path().join("manifest.json")).unwrap();
        (dir, keys)
    }
    fn registry() -> ClientRegistry {
        ClientRegistry::with_issuer(
            vec![
                FirstPartyClient::new(
                    "web",
                    "Balance",
                    vec![
                        RegisteredRedirect::new(
                            "https://app.example/callback?fixed=%2F",
                            RedirectKind::Exact,
                        )
                        .unwrap(),
                    ],
                    ["openid", "profile", "email", "offline_access"],
                    ["https://api.example/resource"],
                    None,
                    ["https://app.example"],
                    ["https://app.example/signed-out"],
                )
                .unwrap(),
            ],
            &"http://127.0.0.1:18082/".parse().unwrap(),
        )
        .unwrap()
    }
    fn browser_registry(client_origin: &str, issuer: &str) -> ClientRegistry {
        ClientRegistry::with_issuer(
            vec![
                FirstPartyClient::new(
                    "web",
                    "Balance",
                    vec![
                        RegisteredRedirect::new(
                            format!("{client_origin}/callback"),
                            RedirectKind::Exact,
                        )
                        .unwrap(),
                    ],
                    ["openid", "profile", "email", "offline_access"],
                    ["https://api.example/resource"],
                    None,
                    [client_origin],
                    [format!("{client_origin}/signed-out")],
                )
                .unwrap(),
            ],
            &issuer.parse().unwrap(),
        )
        .unwrap()
    }
    fn form_value(html: &str, name: &str) -> String {
        let marker = format!("name={name} value=\"");
        let rest = html.split_once(&marker).unwrap().1;
        rest.split_once('"').unwrap().0.into()
    }
    fn cookie_value(response: &Response) -> String {
        response
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .into()
    }
    async fn begin_test_google(app: &Router, authorize: &str) -> Response {
        let landing = app
            .clone()
            .oneshot(Request::get(authorize).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(landing.status(), StatusCode::OK);
        let set_cookie = landing.headers()[header::SET_COOKIE].clone();
        let cookie = cookie_value(&landing);
        let html = body(landing).await;
        assert!(html.contains("Continuar con Google"));
        let form = form_urlencoded::Serializer::new(String::new())
            .append_pair("transaction_id", &form_value(&html, "transaction_id"))
            .append_pair("state", &form_value(&html, "state"))
            .append_pair("action", "continue")
            .finish();
        let mut response = app
            .clone()
            .oneshot(
                Request::post("/federation/google/start")
                    .header(header::COOKIE, cookie.clone())
                    .header(header::ORIGIN, "http://127.0.0.1:18082")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        response
            .headers_mut()
            .insert(header::SET_COOKIE, set_cookie);
        response
    }
    async fn body(response: Response) -> String {
        String::from_utf8(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap()
    }

    #[sqlx::test(migrations = "./migrations")]
    #[ignore = "requires the explicitly provisioned local Playwright Chromium runtime"]
    async fn chromium_follows_bound_consent_and_logout_redirects(pool: PgPool) {
        let nonce = Arc::new(Mutex::new(String::new()));
        let public = RsaPublicKey::from_public_key_pem(
            std::str::from_utf8(&fixture("active-public.pem")).unwrap(),
        )
        .unwrap();
        let jwks = json!({"keys":[{"kty":"RSA","kid":"google","use":"sig","alg":"RS256","key_ops":["verify"],"n":URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),"e":URL_SAFE_NO_PAD.encode(public.e().to_bytes_be())}]});

        let eri_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let eri_origin = format!("http://{}", eri_listener.local_addr().unwrap());
        let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_origin = format!("http://{}", client_listener.local_addr().unwrap());
        let client_hits = Arc::new(AtomicUsize::new(0));
        let callback_hits = client_hits.clone();
        let signed_out_hits = client_hits.clone();
        let client = Router::new()
            .route(
                "/callback",
                get(move || {
                    callback_hits.fetch_add(1, Ordering::SeqCst);
                    async { "authorization callback reached" }
                }),
            )
            .route(
                "/signed-out",
                get(move || {
                    signed_out_hits.fetch_add(10, Ordering::SeqCst);
                    async { "logout callback reached" }
                }),
            );
        tokio::spawn(async move { axum::serve(client_listener, client).await.unwrap() });

        let callback = format!("{eri_origin}/federation/google/callback");
        let authorize_callback = callback.clone();
        let authorize_nonce = nonce.clone();
        let token_nonce = nonce.clone();
        let upstream = Router::new()
            .route(
                "/authorize",
                get(move |Query(query): Query<std::collections::HashMap<String, String>>| {
                    let callback = authorize_callback.clone();
                    let nonce = authorize_nonce.clone();
                    async move {
                        *nonce.lock().unwrap() = query["nonce"].clone();
                        Redirect::to(&format!(
                            "{callback}?state={}&code=browser",
                            query["state"]
                        ))
                    }
                }),
            )
            .route(
                "/token",
                post(move || {
                    let nonce = token_nonce.lock().unwrap().clone();
                    async move {
                        let now = Utc::now().timestamp();
                        let claims=json!({"iss":"https://accounts.google.com","sub":"browser-subject","aud":"client-1","exp":now+300,"iat":now,"nonce":nonce,"name":"Browser Persona","email":"browser@example.test","email_verified":true});
                        let mut header = Header::new(Algorithm::RS256);
                        header.kid = Some("google".into());
                        let token = jsonwebtoken::encode(
                            &header,
                            &claims,
                            &EncodingKey::from_rsa_pem(&fixture("active-private.pem")).unwrap(),
                        )
                        .unwrap();
                        axum::Json(json!({"id_token":token}))
                    }
                }),
            )
            .route(
                "/certs",
                get(move || {
                    let jwks = jwks.clone();
                    async move { axum::Json(jwks) }
                }),
            );
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_origin = format!("http://{}", upstream_listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(upstream_listener, upstream).await.unwrap() });

        let (_dir, keys) = signing_keys();
        let google = GoogleAdapter::for_test_http(
            format!("{upstream_origin}/authorize"),
            format!("{upstream_origin}/token"),
            format!("{upstream_origin}/certs"),
            callback,
        );
        let eri = router(AppState::for_test_provider_at(
            Database::from_pool(pool, Duration::from_secs(1)),
            keys,
            browser_registry(&client_origin, &eri_origin),
            google,
            false,
            eri_origin.clone(),
        ));
        tokio::spawn(async move { axum::serve(eri_listener, eri).await.unwrap() });

        let status = tokio::task::spawn_blocking({
            let eri_origin = eri_origin.clone();
            let client_origin = client_origin.clone();
            move || {
                std::process::Command::new("timeout")
                    .arg("60s")
                    .arg("node")
                    .arg("tests/browser-flow.cjs")
                    .arg(eri_origin)
                    .arg(client_origin)
                    .status()
                    .unwrap()
            }
        })
        .await
        .unwrap();
        assert!(status.success());
        assert_eq!(client_hits.load(Ordering::SeqCst), 12);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn synthetic_signed_upstream_http_flow(pool: PgPool) {
        let database_url = std::env::var("DATABASE_URL").unwrap();
        assert!(
            database_url == std::env::var("ERI_TEST_DATABASE_URL").unwrap(),
            "database tests require isolated URL"
        );
        let nonce = Arc::new(Mutex::new(String::new()));
        let public = RsaPublicKey::from_public_key_pem(
            std::str::from_utf8(&fixture("active-public.pem")).unwrap(),
        )
        .unwrap();
        let jwks = json!({"keys":[{"kty":"RSA","kid":"google","use":"sig","alg":"RS256","key_ops":["verify"],"n":URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),"e":URL_SAFE_NO_PAD.encode(public.e().to_bytes_be())}]});
        let token_nonce = nonce.clone();
        let fail_exchange = Arc::new(AtomicBool::new(false));
        let token_failure = fail_exchange.clone();
        let upstream=Router::new().route("/token",post(move||{let nonce=token_nonce.lock().unwrap().clone();let fail=token_failure.swap(false,Ordering::SeqCst);async move{if fail{return StatusCode::BAD_GATEWAY.into_response()}let now=Utc::now().timestamp();let claims=json!({"iss":"https://accounts.google.com","sub":"signed-subject","aud":"client-1","exp":now+300,"iat":now,"nonce":nonce,"name":"Persona","email":"person@example.test","email_verified":true,"auth_time":now-10});let mut h=Header::new(Algorithm::RS256);h.kid=Some("google".into());h.typ=Some("JWT".into());let token=jsonwebtoken::encode(&h,&claims,&EncodingKey::from_rsa_pem(&fixture("active-private.pem")).unwrap()).unwrap();axum::Json(json!({"id_token":token})).into_response()}})).route("/certs",get(move||{let jwks=jwks.clone();async move{axum::Json(jwks)}}));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
        let (_dir, keys) = signing_keys();
        let google = GoogleAdapter::for_test_http(
            format!("http://{address}/authorize"),
            format!("http://{address}/token"),
            format!("http://{address}/certs"),
            "http://127.0.0.1:18082/federation/google/callback".into(),
        );
        let secure_database = Database::from_pool(pool.clone(), Duration::from_secs(1));
        let (_secure_dir, secure_keys) = signing_keys();
        let secure_app = router(AppState::for_test_provider_mode(
            secure_database,
            secure_keys,
            registry(),
            google.clone(),
            true,
        ));
        let state = AppState::for_test_provider(
            Database::from_pool(pool, Duration::from_secs(1)),
            keys,
            registry(),
            google,
        );
        let app = router(state);
        let metadata = app
            .clone()
            .oneshot(
                Request::get("/.well-known/openid-configuration")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let metadata: serde_json::Value = serde_json::from_str(&body(metadata).await).unwrap();
        assert_eq!(metadata["issuer"], "http://127.0.0.1:18082");
        assert_eq!(
            metadata["authorization_endpoint"],
            "http://127.0.0.1:18082/authorize"
        );
        assert_eq!(metadata["token_endpoint"], "http://127.0.0.1:18082/token");
        assert_eq!(
            metadata["userinfo_endpoint"],
            "http://127.0.0.1:18082/userinfo"
        );
        assert_eq!(
            metadata["revocation_endpoint"],
            "http://127.0.0.1:18082/revoke"
        );
        assert_eq!(metadata["jwks_uri"], "http://127.0.0.1:18082/jwks");
        assert_eq!(
            metadata["grant_types_supported"],
            json!(["authorization_code", "refresh_token"])
        );
        assert_eq!(
            metadata["code_challenge_methods_supported"],
            json!(["S256"])
        );
        assert_eq!(
            metadata["authorization_response_iss_parameter_supported"],
            true
        );
        assert_eq!(metadata["request_uri_parameter_supported"], false);
        assert_eq!(metadata["request_parameter_supported"], false);
        assert_eq!(metadata["claims_parameter_supported"], false);
        assert!(metadata.get("end_session_endpoint").is_none());
        let signed_out_page = app
            .clone()
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(signed_out_page.status(), StatusCode::OK);
        assert!(body(signed_out_page).await.contains("Sesión cerrada"));
        let authorize = "/authorize?client_id=web&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback%3Ffixed%3D%252F&response_type=code&code_challenge_method=S256&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&scope=openid%20profile%20email%20offline_access&resource=https%3A%2F%2Fapi.example%2Fresource&state=downstream&nonce=downstream-nonce";
        let landing = app
            .clone()
            .oneshot(Request::get(authorize).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(landing.status(), StatusCode::OK);
        assert_eq!(landing.headers()[header::REFERRER_POLICY], "strict-origin");
        assert_eq!(landing.headers()[header::CACHE_CONTROL], "no-store");
        let landing_cookie = cookie_value(&landing);
        let html = body(landing).await;
        assert!(html.contains("Balance"));
        for scope in ["openid", "profile", "email", "offline_access"] {
            assert!(html.contains(scope));
        }
        assert!(html.contains("https://api.example/resource"));
        assert!(html.contains("Continuar con Google"));
        assert!(html.contains("Cancelar"));
        let cancel_body = form_urlencoded::Serializer::new(String::new())
            .append_pair("transaction_id", &form_value(&html, "transaction_id"))
            .append_pair("state", &form_value(&html, "state"))
            .append_pair("action", "cancel")
            .finish();
        let cancelled = app
            .clone()
            .oneshot(
                Request::post("/federation/google/start")
                    .header(header::COOKIE, &landing_cookie)
                    .header(header::ORIGIN, "http://127.0.0.1:18082")
                    .body(Body::from(cancel_body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cancelled.status(), StatusCode::SEE_OTHER);
        assert!(
            cancelled.headers()[header::LOCATION]
                .to_str()
                .unwrap()
                .contains("error=access_denied")
        );
        assert!(
            cancelled
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .any(|v| v.to_str().unwrap().contains("Max-Age=0"))
        );
        let replay = app
            .clone()
            .oneshot(
                Request::post("/federation/google/start")
                    .header(header::COOKIE, &landing_cookie)
                    .header(header::ORIGIN, "http://127.0.0.1:18082")
                    .body(Body::from(cancel_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
        let duplicate = app
            .clone()
            .oneshot(
                Request::get(format!("{authorize}&client_id=web"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(duplicate.status(), StatusCode::BAD_REQUEST);
        assert!(duplicate.headers().get(header::LOCATION).is_none());
        let unsupported = app
            .clone()
            .oneshot(
                Request::get(format!(
                    "{authorize}&request_uri=https%3A%2F%2Fevil.example%2Frequest"
                ))
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unsupported.status(), StatusCode::SEE_OTHER);
        assert!(
            unsupported.headers()[header::LOCATION]
                .to_str()
                .unwrap()
                .contains("error=request_not_supported")
        );
        let silent = app
            .clone()
            .oneshot(
                Request::get(format!("{authorize}&prompt=none"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            silent.headers()[header::LOCATION]
                .to_str()
                .unwrap()
                .contains("error=login_required")
        );
        let preflight = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/token")
                    .header(header::ORIGIN, "https://app.example")
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                    .header(
                        header::ACCESS_CONTROL_REQUEST_HEADERS,
                        "content-type, authorization",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(preflight.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            preflight.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
            "https://app.example"
        );
        for (origin, requested_headers) in [
            ("https://evil.example", "content-type"),
            ("https://app.example", "content-type, x-unreviewed"),
        ] {
            let rejected = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("OPTIONS")
                        .uri("/token")
                        .header(header::ORIGIN, origin)
                        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                        .header(header::ACCESS_CONTROL_REQUEST_HEADERS, requested_headers)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
            assert!(
                rejected
                    .headers()
                    .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .is_none()
            );
        }
        for _ in 0..4 {
            let failed_start = begin_test_google(&app, authorize).await;
            assert_eq!(failed_start.status(), StatusCode::SEE_OTHER);
            assert!(
                failed_start.headers()[header::SET_COOKIE]
                    .to_str()
                    .unwrap()
                    .contains("Max-Age=600")
            );
            let failed_cookie = cookie_value(&failed_start);
            let failed_url: url::Url = failed_start.headers()[header::LOCATION]
                .to_str()
                .unwrap()
                .parse()
                .unwrap();
            let failed_state = failed_url
                .query_pairs()
                .find(|(key, _)| key == "state")
                .unwrap()
                .1
                .into_owned();
            fail_exchange.store(true, Ordering::SeqCst);
            let failed = app
                .clone()
                .oneshot(
                    Request::get(format!(
                        "/federation/google/callback?state={failed_state}&code=synthetic"
                    ))
                    .header(header::COOKIE, &failed_cookie)
                    .body(Body::empty())
                    .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(failed.status(), StatusCode::BAD_REQUEST);
            assert!(
                failed
                    .headers()
                    .get_all(header::SET_COOKIE)
                    .iter()
                    .any(|value| {
                        value
                            .to_str()
                            .unwrap()
                            .starts_with(failed_cookie.split('=').next().unwrap())
                            && value.to_str().unwrap().contains("Max-Age=0")
                    })
            );
        }
        let upstream_error_start = begin_test_google(&app, authorize).await;
        let upstream_error_cookie = cookie_value(&upstream_error_start);
        let upstream_error_url: url::Url = upstream_error_start.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let upstream_error_state = upstream_error_url
            .query_pairs()
            .find(|(key, _)| key == "state")
            .unwrap()
            .1
            .into_owned();
        let upstream_error = app
            .clone()
            .oneshot(
                Request::get(format!(
                    "/federation/google/callback?state={upstream_error_state}&error=server_error"
                ))
                .header(header::COOKIE, &upstream_error_cookie)
                .body(Body::empty())
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(upstream_error.status(), StatusCode::BAD_REQUEST);
        assert!(
            upstream_error
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .any(|value| value.to_str().unwrap().contains("Max-Age=0"))
        );
        let secure_start = begin_test_google(&secure_app, authorize).await;
        let secure_cookie = cookie_value(&secure_start);
        assert!(secure_cookie.starts_with("__Host-eri_tx_"));
        let secure_url: url::Url = secure_start.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let secure_state = secure_url
            .query_pairs()
            .find(|(key, _)| key == "state")
            .unwrap()
            .1
            .into_owned();
        let secure_callback =
            format!("/federation/google/callback?state={secure_state}&error=access_denied");
        let (_, secure_binding) = secure_cookie.split_once('=').unwrap();
        for attacker_cookie in [
            format!(
                "eri_tx_{}={secure_binding}",
                secure_cookie["__Host-eri_tx_".len()..]
                    .split('=')
                    .next()
                    .unwrap()
            ),
            format!("attacker{}", secure_cookie),
        ] {
            let rejected = secure_app
                .clone()
                .oneshot(
                    Request::get(&secure_callback)
                        .header(header::COOKIE, attacker_cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                rejected
                    .headers()
                    .get_all(header::SET_COOKIE)
                    .iter()
                    .count(),
                0
            );
        }
        let secure_denied = secure_app
            .clone()
            .oneshot(
                Request::get(&secure_callback)
                    .header(header::COOKIE, secure_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(secure_denied.status(), StatusCode::SEE_OTHER);
        let start = begin_test_google(&app, authorize).await;
        assert_eq!(start.status(), StatusCode::SEE_OTHER);
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
        assert!(
            completed.headers()[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .unwrap()
                .contains("form-action 'self' https://app.example")
        );
        let session_cookie = cookie_value(&completed);
        let html = body(completed).await;
        assert!(html.contains("Cuenta: <strong>person@example.test</strong>"));
        let id = form_value(&html, "transaction_id");
        let csrf = form_value(&html, "csrf");
        let consent = form_urlencoded::Serializer::new(String::new())
            .append_pair("transaction_id", &id)
            .append_pair("csrf", &csrf)
            .append_pair("action", "approve")
            .finish();
        for attacker_session in [session_cookie.clone(), format!("attacker_{session_cookie}")] {
            let rejected_session = secure_app
                .clone()
                .oneshot(
                    Request::post("/consent")
                        .header(header::COOKIE, attacker_session)
                        .header(header::ORIGIN, "http://127.0.0.1:18082")
                        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                        .body(Body::from(consent.clone()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(rejected_session.status(), StatusCode::BAD_REQUEST);
        }
        let rejected_origin = app
            .clone()
            .oneshot(
                Request::post("/consent")
                    .header(header::COOKIE, &session_cookie)
                    .header(header::ORIGIN, "https://evil.example")
                    .body(Body::from(consent.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rejected_origin.status(), StatusCode::BAD_REQUEST);
        let approved = app
            .clone()
            .oneshot(
                Request::post("/consent")
                    .header(header::COOKIE, &session_cookie)
                    .header(header::ORIGIN, "http://127.0.0.1:18082")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(consent))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(approved.status(), StatusCode::SEE_OTHER);
        let returned: url::Url = approved.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(
            returned.as_str().split('?').next().unwrap(),
            "https://app.example/callback"
        );
        assert!(returned.as_str().contains("fixed=%2F&"));
        let code = returned
            .query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .into_owned();
        let exchange = form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("client_id", "web")
            .append_pair("code", &code)
            .append_pair("redirect_uri", "https://app.example/callback?fixed=%2F")
            .append_pair(
                "code_verifier",
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            )
            .finish();
        let response = app
            .clone()
            .oneshot(Request::post("/token").body(Body::from(exchange)).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let tokens: serde_json::Value = serde_json::from_str(&body(response).await).unwrap();
        let access = tokens["access_token"].as_str().unwrap();
        let id_token = tokens["id_token"].as_str().unwrap();
        assert_eq!(
            jsonwebtoken::decode_header(access).unwrap().typ.as_deref(),
            Some("at+jwt")
        );
        assert_eq!(
            jsonwebtoken::decode_header(id_token)
                .unwrap()
                .typ
                .as_deref(),
            Some("JWT")
        );
        let info = app
            .clone()
            .oneshot(
                Request::get("/userinfo")
                    .header(header::AUTHORIZATION, format!("Bearer {access}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(info.status(), StatusCode::OK);
        let profile: serde_json::Value = serde_json::from_str(&body(info).await).unwrap();
        assert_eq!(profile["email"], "person@example.test");
        let id_as_access = app
            .clone()
            .oneshot(
                Request::get("/userinfo")
                    .header(header::AUTHORIZATION, format!("Bearer {id_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(id_as_access.status(), StatusCode::UNAUTHORIZED);
        let conflicting = app
            .clone()
            .oneshot(
                Request::post("/userinfo")
                    .header(header::AUTHORIZATION, format!("Bearer {access}"))
                    .body(Body::from(format!("access_token={access}")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(conflicting.status(), StatusCode::UNAUTHORIZED);
        let wrong_origin = app
            .clone()
            .oneshot(
                Request::get("/userinfo")
                    .header(header::AUTHORIZATION, format!("Bearer {access}"))
                    .header(header::ORIGIN, "https://evil.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(wrong_origin.status(), StatusCode::UNAUTHORIZED);
        let refresh = tokens["refresh_token"].as_str().unwrap();
        let refresh_body = form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "refresh_token")
            .append_pair("client_id", "web")
            .append_pair("refresh_token", refresh)
            .finish();
        let refreshed = app
            .clone()
            .oneshot(
                Request::post("/token")
                    .body(Body::from(refresh_body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let refreshed: serde_json::Value = serde_json::from_str(&body(refreshed).await).unwrap();
        assert!(refreshed.get("id_token").is_none());
        let successor = refreshed["refresh_token"].as_str().unwrap();
        let replay = app
            .clone()
            .oneshot(
                Request::post("/token")
                    .body(Body::from(refresh_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
        let replay_json: serde_json::Value = serde_json::from_str(&body(replay).await).unwrap();
        assert_eq!(replay_json, json!({"error":"invalid_grant"}));
        let successor_body = form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "refresh_token")
            .append_pair("client_id", "web")
            .append_pair("refresh_token", successor)
            .finish();
        let successor_after_replay = app
            .clone()
            .oneshot(
                Request::post("/token")
                    .body(Body::from(successor_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(successor_after_replay.status(), StatusCode::BAD_REQUEST);
        let unknown_revocation = app
            .clone()
            .oneshot(
                Request::post("/revoke")
                    .body(Body::from("client_id=web&token=unknown"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unknown_revocation.status(), StatusCode::OK);
        let silent_sso = app
            .clone()
            .oneshot(
                Request::get(format!("{authorize}&prompt=none"))
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            silent_sso.headers()[header::LOCATION]
                .to_str()
                .unwrap()
                .contains("error=consent_required")
        );
        let forced = app
            .clone()
            .oneshot(
                Request::get(format!("{authorize}&prompt=login"))
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            forced.headers()[header::LOCATION]
                .to_str()
                .unwrap()
                .contains("error=login_required")
        );
        let stale = app
            .clone()
            .oneshot(
                Request::get(format!("{authorize}&max_age=0"))
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            stale.headers()[header::LOCATION]
                .to_str()
                .unwrap()
                .contains("error=login_required")
        );
        let second_consent = app
            .clone()
            .oneshot(
                Request::get(authorize)
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second_consent.status(), StatusCode::OK);
        let second_html = body(second_consent).await;
        let second_form = form_urlencoded::Serializer::new(String::new())
            .append_pair(
                "transaction_id",
                &form_value(&second_html, "transaction_id"),
            )
            .append_pair("csrf", &form_value(&second_html, "csrf"))
            .append_pair("action", "approve")
            .finish();
        let second_approved = app
            .clone()
            .oneshot(
                Request::post("/consent")
                    .header(header::COOKIE, &session_cookie)
                    .header(header::ORIGIN, "http://127.0.0.1:18082")
                    .body(Body::from(second_form))
                    .unwrap(),
            )
            .await
            .unwrap();
        let second_returned: url::Url = second_approved.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let second_code = second_returned
            .query_pairs()
            .find(|(key, _)| key == "code")
            .unwrap()
            .1
            .into_owned();
        let second_exchange = form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("client_id", "web")
            .append_pair("code", &second_code)
            .append_pair("redirect_uri", "https://app.example/callback?fixed=%2F")
            .append_pair(
                "code_verifier",
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            )
            .finish();
        let second_tokens = app
            .clone()
            .oneshot(
                Request::post("/token")
                    .body(Body::from(second_exchange))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second_tokens.status(), StatusCode::OK);
        let second_tokens: serde_json::Value =
            serde_json::from_str(&body(second_tokens).await).unwrap();
        let live_logout_refresh = second_tokens["refresh_token"].as_str().unwrap().to_owned();
        let logout=app.clone().oneshot(Request::get("/logout?client_id=web&post_logout_redirect_uri=https%3A%2F%2Fapp.example%2Fsigned-out&state=bye").header(header::COOKIE,&session_cookie).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(logout.status(), StatusCode::OK);
        assert!(
            logout.headers()[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .unwrap()
                .contains("form-action 'self' https://app.example")
        );
        let logout_html = body(logout).await;
        let challenge = form_value(&logout_html, "challenge");
        let logout_csrf = form_value(&logout_html, "csrf");
        let logout_form = form_urlencoded::Serializer::new(String::new())
            .append_pair("challenge", &challenge)
            .append_pair("csrf", &logout_csrf)
            .finish();
        let ended = app
            .clone()
            .oneshot(
                Request::post("/logout")
                    .header(header::COOKIE, &session_cookie)
                    .header(header::ORIGIN, "http://127.0.0.1:18082")
                    .body(Body::from(logout_form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ended.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            ended.headers()[header::LOCATION],
            "https://app.example/signed-out?state=bye"
        );
        let logout_refresh_use = app
            .clone()
            .oneshot(
                Request::post("/token")
                    .body(Body::from(
                        form_urlencoded::Serializer::new(String::new())
                            .append_pair("grant_type", "refresh_token")
                            .append_pair("client_id", "web")
                            .append_pair("refresh_token", &live_logout_refresh)
                            .finish(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(logout_refresh_use.status(), StatusCode::BAD_REQUEST);
        let sso = begin_test_google(&app, authorize).await;
        assert_eq!(sso.status(), StatusCode::SEE_OTHER);
        assert!(
            sso.headers()[header::LOCATION]
                .to_str()
                .unwrap()
                .starts_with(&format!("http://{address}/authorize"))
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn revocation_reports_persistence_failure(pool: PgPool) {
        let (_dir, keys) = signing_keys();
        let google = GoogleAdapter::for_test_http(
            "http://127.0.0.1:1/authorize".into(),
            "http://127.0.0.1:1/token".into(),
            "http://127.0.0.1:1/certs".into(),
            "http://127.0.0.1:18082/federation/google/callback".into(),
        );
        let app = router(AppState::for_test_provider(
            Database::from_pool(pool.clone(), Duration::from_secs(1)),
            keys,
            registry(),
            google,
        ));
        pool.close().await;
        let response = app
            .oneshot(
                Request::post("/revoke")
                    .body(Body::from("client_id=web&token=unknown"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body(response).await).unwrap(),
            json!({"error":"server_error"})
        );
    }

    #[test]
    fn form_action_csp_uses_only_origin_or_registered_native_scheme() {
        assert_eq!(
            form_action_source("https://app.example/callback?secret=value").as_deref(),
            Some("https://app.example")
        );
        assert_eq!(
            form_action_source("com.example.app:/oauth/callback").as_deref(),
            Some("com.example.app:")
        );
        assert_eq!(form_action_source("not a redirect"), None);
    }

    #[test]
    fn foundation_config_type_remains_available() {
        let _ = DatabaseConfig {
            url: None,
            url_env: "X".into(),
            max_connections: 1,
            min_connections: 0,
            connect_timeout_seconds: 1,
            acquire_timeout_seconds: 1,
            readiness_timeout_milliseconds: 1,
        };
    }
}

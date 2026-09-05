use crate::{Config, Database, SigningKeys};
use axum::{
    Router,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState(Arc<Inner>);
struct Inner {
    database: Database,
    keys: SigningKeys,
}

impl AppState {
    pub fn new(_config: Config, database: Database, keys: SigningKeys) -> anyhow::Result<Self> {
        Ok(Self(Arc::new(Inner { database, keys })))
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/jwks", get(jwks))
        .with_state(state)
}

async fn live() -> StatusCode {
    StatusCode::NO_CONTENT
}
async fn ready(State(state): State<AppState>) -> StatusCode {
    if state.0.database.ready().await {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}
async fn jwks(State(state): State<AppState>) -> Response {
    let mut headers = public_headers();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    (headers, state.0.keys.jwks_json().to_owned()).into_response()
}
fn public_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers
}

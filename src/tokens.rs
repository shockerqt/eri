use crate::{ExchangeResult, KeyError, SigningKeys};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessClaims {
    pub iss: String,
    pub sub: Uuid,
    pub aud: Vec<String>,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,
    pub client_id: String,
    pub scope: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdClaims {
    pub iss: String,
    pub sub: Uuid,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub nonce: Option<String>,
    pub auth_time: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}

pub fn issue(
    keys: &SigningKeys,
    issuer: &str,
    userinfo: &str,
    exchange: ExchangeResult,
    initial: bool,
) -> Result<TokenResponse, KeyError> {
    let now = Utc::now().timestamp();
    let scope = exchange.scopes.join(" ");
    let mut audiences = vec![exchange.resource.clone()];
    if exchange.scopes.iter().any(|scope| scope == "openid")
        && !audiences.iter().any(|audience| audience == userinfo)
    {
        audiences.push(userinfo.to_owned());
    }
    let access_token = keys.sign(&AccessClaims {
        iss: issuer.into(),
        sub: exchange.user_id,
        aud: audiences,
        exp: now + 300,
        iat: now,
        jti: Uuid::new_v4().to_string(),
        client_id: exchange.client_id.clone(),
        scope: scope.clone(),
    })?;
    let id_token = if initial && exchange.scopes.iter().any(|scope| scope == "openid") {
        Some(keys.sign_id(&IdClaims {
            iss: issuer.into(),
            sub: exchange.user_id,
            aud: exchange.client_id,
            exp: now + 300,
            iat: now,
            nonce: exchange.oidc_nonce,
            auth_time: exchange.upstream_auth_time.map(|time| time.timestamp()),
        })?)
    } else {
        None
    };
    Ok(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: 300,
        scope,
        refresh_token: exchange
            .refresh_token
            .map(|token| token.expose().to_owned()),
        id_token,
    })
}

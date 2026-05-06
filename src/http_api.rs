use crate::guan_yuan_sso;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tracing::warn;

const DEFAULT_EXPIRATION: u64 = 28_800;

#[derive(Clone)]
pub struct AppState {
    private_key: Arc<RsaPrivateKey>,
    base_url: String,
    provider: String,
}

impl AppState {
    pub fn new(private_key: RsaPrivateKey, base_url: String, provider: String) -> Self {
        Self {
            private_key: Arc::new(private_key),
            base_url,
            provider,
        }
    }

    fn provider(&self) -> &'_ str {
        self.provider.as_str()
    }

    fn base_url(&self) -> &'_ str {
        self.base_url.as_str()
    }

    fn private_key(&self) -> &'_ RsaPrivateKey {
        &*self.private_key
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/token", post(issue_token))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenRequest {
    pub domain_id: String,
    pub external_user_id: String,
    #[serde(default = "default_expiration")]
    pub expired_time_seconds: u64,
    #[serde(default)]
    pub provider: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenResponse {
    pub token_hex: String,
    pub token_base64: String,
    pub timestamp: i64,
    pub sso_url: String,
}

#[derive(Debug)]
pub enum ApiError {
    Validation(String),
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            ApiError::Validation(msg) => {
                let body = Json(json!({ "error": msg }));
                (StatusCode::BAD_REQUEST, body).into_response()
            }
            ApiError::Internal(msg) => {
                let body = Json(json!({ "error": msg }));
                (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
            }
        }
    }
}

#[tracing::instrument(name = "healthcheck")]
async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

#[tracing::instrument(
    name = "issue_token",
    skip(state, request),
    fields(domain = %request.domain_id, user = %request.external_user_id)
)]
async fn issue_token(
    State(state): State<AppState>,
    Json(request): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, ApiError> {
    if request.domain_id.as_str().trim().is_empty() {
        return Err(ApiError::Validation("domainId is required".to_owned()));
    }
    if request.external_user_id.as_str().trim().is_empty() {
        return Err(ApiError::Validation(
            "externalUserId is required".to_owned(),
        ));
    }

    let timestamp = Utc::now().timestamp();
    let expires = request.expired_time_seconds;
    let payload = TokenPayload {
        domain_id: request.domain_id.as_str(),
        external_user_id: request.external_user_id.as_str(),
        timestamp,
        expired_time_seconds: expires,
    };
    let payload_json =
        serde_json::to_string(&payload).map_err(|err| ApiError::Internal(err.to_string()))?;

    let encoded = guan_yuan_sso::private_encrypt(&payload_json, state.private_key())
        .map_err(|err| ApiError::Internal(err.to_string()))?;
    let token_hex = guan_yuan_sso::to_hex_string(&encoded);

    let provider = request
        .provider
        .as_deref()
        .unwrap_or_else(|| state.provider());
    let sso_url = format!(
        "{}pref.HostNavOnly=true&pageRenderType=phoneView&provider={provider}&ssoToken={token_hex}",
        state.base_url()
    );

    tracing::info!(
        target: "http_api",
        domain = %request.domain_id,
        user = %request.external_user_id,
        provider = provider,
        "issued SSO token"
    );

    let response = Json(TokenResponse {
        token_hex,
        token_base64: encoded,
        timestamp,
        sso_url,
    });

    if state.provider().is_empty() {
        warn!("provider value resolved to empty string; check configuration");
    }

    Ok(response)
}

fn default_expiration() -> u64 {
    DEFAULT_EXPIRATION
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TokenPayload<'a> {
    #[serde(rename = "domainId")]
    domain_id: &'a str,
    #[serde(rename = "externalUserId")]
    external_user_id: &'a str,
    timestamp: i64,
    #[serde(rename = "expiredTimeSeconds")]
    expired_time_seconds: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, Bytes},
        http::{Request, StatusCode},
    };
    use http_body_util::{BodyExt, Full};
    use serde_json::Value;
    use tower::ServiceExt;
    use tracing::instrument::WithSubscriber;

    fn token_request(payload: Value) -> Request<Body> {
        let payload_json = payload.to_string();
        let bytes = Bytes::copy_from_slice(payload_json.as_bytes());
        let body = Body::new(Full::new(bytes));
        Request::builder()
            .method("POST")
            .uri("/api/token")
            .header("content-type", "application/json")
            .body(body)
            .unwrap()
    }

    #[tokio::test]
    async fn issue_token_endpoint_returns_payload() {
        let (_public, private) = guan_yuan_sso::create_keys().unwrap();
        let private_key = guan_yuan_sso::get_private_key(private.as_str()).unwrap();
        let app = router(AppState::new(
            private_key,
            "https://example.com/?".to_string(),
            "guanbi".to_string(),
        ));

        let body = json!({
            "domainId": "guanbi",
            "externalUserId": "tester",
            "expiredTimeSeconds": 60
        });

        let response = app.oneshot(token_request(body)).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn issue_token_rejects_empty_domain() {
        let (_public, private) = guan_yuan_sso::create_keys().unwrap();
        let private_key = guan_yuan_sso::get_private_key(private.as_str()).unwrap();
        let app = router(AppState::new(
            private_key,
            "https://example.com/?".to_string(),
            "guanbi".to_string(),
        ));

        let body = json!({
            "domainId": " ",
            "externalUserId": "tester"
        });

        let response = app.oneshot(token_request(body)).await.unwrap();

        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let payload: Value = serde_json::from_slice(&bytes.to_vec()).unwrap();

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(payload["error"], "domainId is required");
    }

    #[tokio::test]
    async fn issue_token_applies_provider_override() {
        let (_public, private) = guan_yuan_sso::create_keys().unwrap();
        let private_key = guan_yuan_sso::get_private_key(private.as_str()).unwrap();
        let app = router(AppState::new(
            private_key,
            "https://example.com/?".to_string(),
            "guanbi".to_string(),
        ));

        let body = json!({
            "domainId": "guanbi",
            "externalUserId": "tester",
            "provider": "custom"
        });

        let response = app
            .oneshot(token_request(body))
            .await
            .unwrap();

        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let payload: Value = serde_json::from_slice(bytes.into()).unwrap();

        assert_eq!(status, StatusCode::OK);
        let url = payload["ssoUrl"].as_str().unwrap();
        assert!(
            url.contains("provider=custom"),
            "expected provider override to propagate in ssoUrl: {url}"
        );
    }
}

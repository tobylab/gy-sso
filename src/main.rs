use hello::{
    guan_yuan_sso::{self, PRIVATE_KEY_ENV},
    http_api::{self, AppState},
};
use rsa::RsaPrivateKey;
use std::{env, io};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

const DEFAULT_BASE_URL: &str = "https://ds.cdlsym.com/m/page/ma81657b8a6404bc39b936c5?";
const DEFAULT_PROVIDER: &str = "guanbi";
const DEFAULT_BIND_ADDR: &str = "0.0.0.0:8080";
const BASE_URL_ENV: &str = "SSO_BASE_URL";
const PROVIDER_ENV: &str = "SSO_PROVIDER";
const BIND_ADDR_ENV: &str = "SSO_BIND_ADDR";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    init_tracing()?;
    let config = ServerConfig::from_env()?;
    let state = AppState::new(config.private_key, config.base_url, config.provider);
    let app = http_api::router(state);

    let listener = TcpListener::bind(config.bind_addr.as_str()).await?;
    let addr = listener.local_addr()?;
    tracing::info!("Listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

struct ServerConfig {
    bind_addr: String,
    base_url: String,
    provider: String,
    private_key: RsaPrivateKey,
}

impl ServerConfig {
    fn from_env() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let bind_addr = env::var(BIND_ADDR_ENV).unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string());

        let base_url = env::var(BASE_URL_ENV).unwrap_or_else(|_| DEFAULT_BASE_URL.to_string());
        let provider = env::var(PROVIDER_ENV).unwrap_or_else(|_| DEFAULT_PROVIDER.to_string());

        let private_key_raw = env::var(PRIVATE_KEY_ENV)
            .map_err(|_| config_error(format!("environment variable {PRIVATE_KEY_ENV} 未设置")))?;
        let private_key = guan_yuan_sso::get_private_key(private_key_raw.as_str())?;

        Ok(Self {
            bind_addr,
            base_url: normalize_base_url(base_url),
            provider,
            private_key,
        })
    }
}

fn normalize_base_url(url: String) -> String {
    let url_ref = url.as_str();
    if url_ref.ends_with('?') || url_ref.ends_with('&') {
        return url;
    }
    if url_ref.contains('?') {
        format!("{url}&")
    } else {
        format!("{url}?")
    }
}

fn config_error(message: String) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(io::Error::other(message))
}

fn init_tracing() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info,tower_http=debug,axum=info"))?;
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init()
        .map_err(|err| {
            eprintln!("failed to initialize tracing: {err}");
            config_error(format!("failed to initialize tracing: {err}"))
        })
}

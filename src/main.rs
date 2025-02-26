use std::{convert::Infallible, sync::Arc};

use autopush::{App, Backend, SessionHandle};
use axum::{
    Router,
    extract::{Path, Request},
    response::IntoResponse,
};
use clap::Parser;
use http::StatusCode;
use tokio::net::TcpListener;
use tracing::{level_filters::LevelFilter, warn};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Timestamp;

struct WebPushInterceptor {
    public_url: Arc<url::Url>,
}

#[derive(Debug, clap::Parser)]
struct Args {
    #[clap(short, long)]
    public_url: url::Url,

    #[clap(short, long, default_value = "0.0.0.0:6060")]
    listen: String,
}

struct WebPushInterceptorSession {
    public_url: Arc<url::Url>,
    client_id: String,
}

impl SessionHandle for WebPushInterceptorSession {
    fn register(
        &self,
        channel_id: uuid::Uuid,
        key: Option<String>,
    ) -> impl Future<Output = Option<url::Url>> + Send {
        async move {
            Some(
                url::Url::parse(format!("{}/ingest/{}", self.public_url, self.client_id).as_str())
                    .unwrap(),
            )
        }
    }

    fn unregister(
        &self,
        channel_id: uuid::Uuid,
        code: Option<u32>,
    ) -> impl Future<Output = ()> + Send {
        async move { () }
    }
}

impl Backend for WebPushInterceptor {
    type Error = Infallible;
    type SessionHandle = WebPushInterceptorSession;

    async fn sign_in(
        &self,
        client_id: Option<String>,
    ) -> Result<(String, Self::SessionHandle), Self::Error> {
        let client_id = client_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        Ok((
            client_id.clone(),
            WebPushInterceptorSession {
                public_url: self.public_url.clone(),
                client_id,
            },
        ))
    }
}

async fn fallback(req: Request) -> impl IntoResponse {
    warn!("Not found: {}", req.uri());
    (StatusCode::NOT_FOUND, req.uri().to_string()).into_response()
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let fmt_layer = tracing_subscriber::fmt::layer().with_target(false);
    let filter_layer = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();

    let router = Router::new()
        .route(
            "/",
            axum::routing::get(App::handle_ws::<Arc<WebPushInterceptor>>),
        )
        .route("/ingest/{id}", axum::routing::post(App::handle_ingest))
        .with_state(Arc::new(WebPushInterceptor {
            public_url: args.public_url.into(),
        }))
        .fallback(fallback);
    axum::serve(
        TcpListener::bind("0.0.0.0:6060").await.unwrap(),
        router.into_make_service(),
    )
    .await
    .expect("Failed to serve");
}

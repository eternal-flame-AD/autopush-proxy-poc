use std::{collections::HashMap, convert::Infallible, sync::Arc, time::Duration};

use axum::{
    body::Body,
    extract::{
        Path, State, WebSocketUpgrade,
        ws::{self, Utf8Bytes, WebSocket},
    },
    http::header,
    response::IntoResponse,
};

use axum_extra::{
    TypedHeader,
    headers::{
        Authorization, ContentEncoding, ContentLength, Header,
        authorization::{Bearer, Credentials},
    },
};
use crypto_header::{CryptoKey, EncryptionSalt, Vapid};
use futures::{FutureExt, SinkExt, TryFutureExt};
use http::StatusCode;
use machine::{AxumWebsocket, Machine};
use protocol::{ClientMessage, ServerMessage};
use serde::Deserialize;
use tracing::{debug, error, info, trace, warn};
use uuid::Uuid;

pub(crate) mod protocol;

pub mod machine;

pub mod e2e;

pub(crate) mod crypto_header;

#[derive(Debug, thiserror::Error)]
pub enum TryDecodeWsMessageError {
    #[error("WebSocket error: {0}")]
    Websocket(#[from] axum::Error),

    #[error("Failed to decode message")]
    Decode(#[from] serde_json::Error),
}

impl TryFrom<Utf8Bytes> for ClientMessage {
    type Error = TryDecodeWsMessageError;

    fn try_from(value: Utf8Bytes) -> Result<Self, Self::Error> {
        debug!("Received message: {}", value);
        let msg: ClientMessage = serde_json::from_str(&value)?;
        Ok(msg)
    }
}

pub const DEFAULT_WEBSOCKET_PATH: &str = "/";

pub trait SessionHandle: Send + Sync + 'static {
    fn register(
        &self,
        channel_id: Uuid,
        key: Option<String>,
    ) -> impl Future<Output = Option<url::Url>> + Send;
    fn unregister(&self, channel_id: Uuid, code: Option<u32>) -> impl Future<Output = ()> + Send;
}

pub trait WebSocketError: std::error::Error {
    fn code(&self) -> u32;
}

impl WebSocketError for Infallible {
    fn code(&self) -> u32 {
        unreachable!()
    }
}

pub trait Backend: Send + Sync + 'static {
    type Error: WebSocketError + Send + 'static;
    type SessionHandle: SessionHandle;

    /// Identity the client and return the assigned uaid + session handle, if None is returned the connection is rejected
    ///
    /// We highly recommend keeping it a valid UUID for maximum compatibility with official clients.
    fn sign_in(
        &self,
        claimed_uaid: Option<String>,
    ) -> impl Future<Output = Result<(String, Self::SessionHandle), Self::Error>> + Send;
}

impl<B: Backend> Backend for Arc<B> {
    type Error = B::Error;
    type SessionHandle = B::SessionHandle;

    async fn sign_in(
        &self,
        claimed_uaid: Option<String>,
    ) -> Result<(String, Self::SessionHandle), Self::Error> {
        self.as_ref().sign_in(claimed_uaid).await
    }
}

pub enum AppError<B: Backend> {
    Backend(B::Error),
}

pub struct App {}

#[derive(derive_more::Debug, thiserror::Error)]
pub enum HandleWsError<B: Backend> {
    #[error("Backend error: {0}")]
    Backend(B::Error),

    #[error("Failed to receive message")]
    Receive(#[from] axum::Error),

    #[error("Failed to decode message")]
    Decode(#[from] TryDecodeWsMessageError),

    #[error("Did not handshake")]
    DidNotHandshake,

    #[error("Abrupt close")]
    AbruptClose,

    #[error("Payload too large ({0})")]
    PayloadTooLarge(&'static str),

    #[error("Unexpected message")]
    UnexpectedMessage,

    #[error("Timeout")]
    Timeout,
}

async fn initialize_ws_connection<B: Backend + Clone>(
    state: B,
    mut ws: WebSocket,
) -> Result<(AxumWebsocket, B::SessionHandle), HandleWsError<B>> {
    // wait for a client hello
    let session_handle = match tokio::time::timeout(Duration::from_secs(10), ws.recv()).await {
        Ok(Some(Ok(ws::Message::Text(msg)))) => match msg.try_into()? {
            ClientMessage::Hello {
                uaid,
                broadcasts,
                _channel_ids,
            } => match state.sign_in(uaid).await {
                Ok((uaid, session_handle)) => {
                    ws.send(
                        ServerMessage::Hello {
                            uaid: uaid.clone(),
                            status: 200,
                            use_webpush: true,
                            broadcasts: HashMap::new(),
                        }
                        .to_json()
                        .unwrap()
                        .into(),
                    )
                    .await?;
                    info!("Signed in: {}", uaid);
                    session_handle
                }
                Err(e) => {
                    ws.send(
                        ServerMessage::Hello {
                            uaid: String::new(),
                            status: e.code(),
                            use_webpush: true,
                            broadcasts: HashMap::new(),
                        }
                        .to_json()
                        .unwrap()
                        .into(),
                    )
                    .await?;
                    return Err(HandleWsError::Backend(e));
                }
            },
            _ => {
                return Err(HandleWsError::UnexpectedMessage);
            }
        },
        Ok(None) | Ok(Some(Ok(ws::Message::Close(_)))) => {
            warn!("Client closed connection without sending a hello");
            return Err(HandleWsError::DidNotHandshake);
        }
        Ok(Some(Ok(u))) => {
            debug!("Received unexpected message: {:?}", u);
            return Err(HandleWsError::UnexpectedMessage);
        }
        Ok(Some(Err(e))) => {
            error!("Client hello error: {:?}", e);
            return Err(HandleWsError::DidNotHandshake);
        }
        Err(_) => {
            info!("Client hello timeout");
            return Err(HandleWsError::Timeout);
        }
    };

    Ok((AxumWebsocket::from(ws), session_handle))
}

#[derive(Debug, Deserialize)]
pub struct IngestPathParam {
    id: String,
}

impl App {
    pub async fn handle_ingest(
        TypedHeader(content_encoding): TypedHeader<ContentEncoding>,
        TypedHeader(Authorization(vapid)): TypedHeader<Authorization<Vapid>>,
        crypto_key: Option<TypedHeader<CryptoKey>>,
        encryption_salt: Option<TypedHeader<EncryptionSalt>>,
        Path(ingest_path): Path<IngestPathParam>,
        body: Body,
    ) -> impl IntoResponse {
        info!(
            "ingest id={} vapid: {:?} crypto_key: {:?} encryption_salt: {:?}",
            ingest_path.id, vapid, crypto_key, encryption_salt
        );

        if content_encoding.contains("aesgcm") || content_encoding.contains("aes128gcm") {
            info!("Content encoding: aesgcm");
        }

        StatusCode::NOT_IMPLEMENTED
    }

    pub async fn handle_ws<B: Backend + Clone>(
        State(state): State<B>,
        upgrader: WebSocketUpgrade,
    ) -> impl IntoResponse {
        info!("got connection");
        upgrader
            .max_frame_size(1 << 20)
            .max_message_size(1 << 20)
            .on_failed_upgrade(|e| {
                error!("Failed to upgrade: {:?}", e);
            })
            .on_upgrade(move |mut ws| {
                if let Some(protocol) = ws.protocol() {
                    info!("WebSocket protocol: {:?}", protocol);
                } else {
                    info!("No protocol (normal)");
                }

                initialize_ws_connection(state, ws)
                    .map_ok(move |(ws, session_handle)| async move {
                        let mut machine = Machine::new(session_handle, ws);
                        loop {
                            match match tokio::time::timeout(
                                Duration::from_secs(600),
                                machine.handle_message(),
                            )
                            .await
                            {
                                Ok(res) => res,
                                Err(timeout) => {
                                    error!("Timeout handling message, elapsed: {:?}", timeout);
                                    break;
                                }
                            } {
                                Ok(Some(_)) => (),
                                Ok(None) => {
                                    info!("Client disconnected");
                                    break;
                                }
                                Err(e) => {
                                    error!("Error handling message: {:?}", e);
                                    break;
                                }
                            }
                        }
                        if let Err(e) = Machine::shutdown(machine).await {
                            error!("Error shutting down machine: {:?}", e);
                        }
                    })
                    .inspect_err(|e| error!("Error initializing ws connection: {:?}", e))
                    .map(|_| ())
            })
    }
}

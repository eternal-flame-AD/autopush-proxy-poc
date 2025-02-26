use std::{
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use axum::extract::ws;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use futures::{Sink, SinkExt, Stream, TryStreamExt};
use p256::PublicKey;
use tokio::time::Instant;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    Backend, SessionHandle, TryDecodeWsMessageError,
    protocol::{ClientMessage, ServerMessage},
};

const PONG_PAYLOAD: &str = "{}";

pub trait WebsocketIO: Stream<Item = Result<ClientMessage, Self::Error>> + Send + Unpin {
    type Error: std::error::Error + Send;

    fn send(&mut self, msg: ServerMessage) -> impl Future<Output = Result<(), Self::Error>> + Send;
    fn shutdown(self) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

#[derive(Debug, thiserror::Error)]
pub enum AxumWebsocketError {
    #[error("WebSocket error: {0}")]
    Websocket(#[from] axum::Error),

    #[error("Failed to decode message")]
    Decode(#[from] TryDecodeWsMessageError),

    #[error("Failed to encode message")]
    Encode(#[from] serde_json::Error),

    #[error("Unexpected message type: {0}")]
    UnexpectedType(&'static str),

    #[error("Abrupt close")]
    AbruptClose,

    #[error("Send buffer full")]
    SendBufferFull,
}

enum AxumWebsocketStage {
    Live,
    TxInProgress,
    Closing,
    Closed,
}

#[pin_project::pin_project]
pub struct AxumWebsocket {
    #[pin]
    inner: axum::extract::ws::WebSocket,

    sending: bool,
    stage: AxumWebsocketStage,
}

impl From<axum::extract::ws::WebSocket> for AxumWebsocket {
    fn from(value: axum::extract::ws::WebSocket) -> Self {
        Self {
            inner: value,
            sending: false,
            stage: AxumWebsocketStage::Live,
        }
    }
}

impl Stream for AxumWebsocket {
    type Item = Result<ClientMessage, AxumWebsocketError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.stage {
            AxumWebsocketStage::TxInProgress => {
                let mut this = self.as_mut().project();
                match this.inner.as_mut().poll_flush(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Ok(_)) => {
                        *this.stage = AxumWebsocketStage::Live;
                        return self.poll_next(cx);
                    }
                    Poll::Ready(Err(e)) => {
                        *this.stage = AxumWebsocketStage::Closed;
                        Poll::Ready(Some(Err(e.into())))
                    }
                }
            }
            AxumWebsocketStage::Live => {
                let mut this = self.as_mut().project();
                match this.inner.as_mut().poll_next(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Some(Ok(ws::Message::Text(msg)))) => {
                        let decoded = msg.try_into()?;
                        Poll::Ready(Some(Ok(decoded)))
                    }
                    Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e.into()))),
                    Poll::Ready(Some(Ok(ws::Message::Ping(msg)))) => {
                        this.inner.start_send(ws::Message::Pong(msg))?;
                        *this.stage = AxumWebsocketStage::TxInProgress;
                        return self.poll_next(cx);
                    }
                    Poll::Ready(Some(Ok(ws::Message::Pong(_)))) => {
                        // this shouldn't happen, we don't send websocket pings
                        Poll::Ready(Some(Err(AxumWebsocketError::UnexpectedType("Pong"))))
                    }
                    Poll::Ready(Some(Ok(ws::Message::Binary(_)))) => {
                        Poll::Ready(Some(Err(AxumWebsocketError::UnexpectedType("Binary"))))
                    }
                    Poll::Ready(Some(Ok(ws::Message::Close(_)))) => {
                        *this.stage = AxumWebsocketStage::Closing;
                        return self.poll_next(cx);
                    }
                    Poll::Ready(None) => {
                        *this.stage = AxumWebsocketStage::Closed;
                        Poll::Ready(Some(Err(AxumWebsocketError::AbruptClose)))
                    }
                }
            }
            AxumWebsocketStage::Closing => {
                let this = self.project();
                match this.inner.poll_close(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Ok(_)) => {
                        *this.stage = AxumWebsocketStage::Closed;
                        Poll::Ready(Some(Err(AxumWebsocketError::AbruptClose)))
                    }
                    Poll::Ready(Err(e)) => {
                        *this.stage = AxumWebsocketStage::Closed;
                        Poll::Ready(Some(Err(e.into())))
                    }
                }
            }
            AxumWebsocketStage::Closed => {
                return Poll::Ready(None);
            }
        }
    }
}

impl WebsocketIO for AxumWebsocket {
    type Error = AxumWebsocketError;

    fn send(&mut self, msg: ServerMessage) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async move {
            self.inner.send(msg.to_json()?.into()).await?;
            Ok(())
        }
    }

    fn shutdown(mut self) -> impl Future<Output = Result<(), Self::Error>> + Send {
        async move {
            self.inner.close().await?;
            Ok(())
        }
    }
}

#[derive(derive_more::Debug, thiserror::Error)]
pub enum MachineError<I: WebsocketIO> {
    #[error("Websocket error: {0}")]
    Websocket(I::Error),

    #[error("Unexpected message type: {0}")]
    UnexpectedType(&'static str),

    #[error("Failed to decode key (not base64): {0}")]
    DecodeKeyBytes(#[from] base64::DecodeError),

    #[error("Failed to decode key: {0}")]
    DecodeKey(#[from] p256::elliptic_curve::Error),

    #[error("Failed to decode channel id: {0}")]
    DecodeChannelId(#[from] uuid::Error),

    #[error("Register declined")]
    RegisterDeclined,
}

pub struct Machine<S: SessionHandle, I: WebsocketIO> {
    session_handle: S,

    io: I,
}

impl<S: SessionHandle, I: WebsocketIO + Unpin> Machine<S, I> {
    pub fn new(session_handle: S, io: I) -> Self {
        Self { session_handle, io }
    }

    pub async fn handle_message(&mut self) -> Result<Option<()>, MachineError<I>> {
        let msg = match self.io.try_next().await {
            Ok(Some(msg)) => Some(msg),
            Ok(None) => {
                return Ok(None);
            }
            Err(e) => {
                return Err(MachineError::Websocket(e));
            }
        };

        match msg {
            Some(msg) => self.process_message(msg).await.map(Some),
            None => Ok(None),
        }
    }

    pub async fn process_message(&mut self, msg: ClientMessage) -> Result<(), MachineError<I>> {
        match msg {
            ClientMessage::Ping => {
                self.io
                    .send(ServerMessage::Ping)
                    .await
                    .map_err(MachineError::Websocket)?;
            }
            ClientMessage::Ack { updates } => {
                for update in updates {
                    info!("Ack: {:?}", update);
                }
            }
            ClientMessage::Nack { code, version } => {
                warn!("Nack: {:?}, {:?}", code, version);
            }
            ClientMessage::Hello { .. } => {
                return Err(MachineError::UnexpectedType("Hello"));
            }
            ClientMessage::Register { channel_id, key } => {
                info!("Register: channel_id: {:?}, key: {:?}", channel_id, key);
                let endpoint = self
                    .session_handle
                    .register(
                        Uuid::parse_str(&channel_id).map_err(MachineError::DecodeChannelId)?,
                        key,
                    )
                    .await;

                let Some(endpoint) = endpoint else {
                    return Err(MachineError::RegisterDeclined);
                };

                self.io
                    .send(ServerMessage::Register {
                        status: 200,
                        push_endpoint: endpoint.to_string(),
                        channel_id: Uuid::parse_str(&channel_id)
                            .map_err(MachineError::DecodeChannelId)?,
                    })
                    .await
                    .map_err(MachineError::Websocket)?;
                return Ok(());
            }
            r @ ClientMessage::Unregister { channel_id, code } => {
                info!("Unregister: {:?}", r);
                self.io
                    .send(ServerMessage::Unregister {
                        status: 200,
                        channel_id: channel_id.clone(),
                    })
                    .await
                    .map_err(MachineError::Websocket)?;
                return Ok(());
            }
            r @ ClientMessage::BroadcastSubscribe { .. } => {
                info!("BroadcastSubscribe: {:?}", r);
                return Err(MachineError::UnexpectedType("BroadcastSubscribe"));
            }
        }

        Ok(())
    }

    pub async fn shutdown(self) -> Result<(), MachineError<I>> {
        self.io.shutdown().await.map_err(MachineError::Websocket)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdh_decode() {
        let key = "BDFOx_sZkEzXgBwe5jLzrfr72-t9IusByQIrl8ognXuvn-HD8z5ym9KEsp476AZlQItwXKgobMtVM-fDFUtECGM";
        let key = BASE64_URL_SAFE_NO_PAD.decode(key).unwrap();
        let key = PublicKey::from_sec1_bytes(key.as_slice()).unwrap();
        println!("{:?}", key);
    }
}

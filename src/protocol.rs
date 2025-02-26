//! Mozilla's Official Autopush protocol payload definitions
//!
//! Mostly copied verbatim from autopush-rs/autoconnect/autoconnect-common/src/protocol.rs
//! to prevent dependency on actix-web.
use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

const fn default_ttl() -> u64 {
    0
}

#[derive(Serialize, Default, Deserialize, Clone, Debug)]
/// A Publishable Notification record. This is a notification that is either
/// received from a third party or is outbound to a UserAgent.
pub struct Notification {
    #[serde(rename = "channelID")]
    pub channel_id: Uuid,
    pub version: String,
    #[serde(default = "default_ttl", skip_serializing)]
    pub ttl: u64,
    #[serde(skip_serializing)]
    pub topic: Option<String>,
    #[serde(skip_serializing)]
    pub timestamp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(skip_serializing)]
    pub sortkey_timestamp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub reliability_id: Option<String>,
    // #[cfg(feature = "reliable_report")]
    // pub reliable_state: Option<crate::reliability::ReliabilityState>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum BroadcastValue {
    Value(String),
    Nested(HashMap<String, BroadcastValue>),
}

#[derive(Debug, Default)]
// Used for the server to flag a webpush client to deliver a Notification or Check storage
pub enum ServerNotification {
    CheckStorage,
    Notification(Notification),
    #[default]
    Disconnect,
}

/// Returned ACKnowledgement of the received message by the User Agent.
/// This is the payload for the `messageType:ack` packet.
///
#[derive(Debug, Deserialize)]
pub struct ClientAck {
    // The channel_id which received messages
    #[serde(rename = "channelID")]
    pub channel_id: Uuid,
    // The corresponding version number for the message.
    pub version: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "messageType", rename_all = "snake_case")]
pub enum ClientMessage {
    Hello {
        uaid: Option<String>,
        #[serde(rename = "channelIDs", skip_serializing_if = "Option::is_none")]
        _channel_ids: Option<Vec<Uuid>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        broadcasts: Option<HashMap<String, String>>,
    },

    Register {
        #[serde(rename = "channelID")]
        channel_id: String,
        key: Option<String>,
    },

    Unregister {
        #[serde(rename = "channelID")]
        channel_id: Uuid,
        code: Option<u32>,
    },

    BroadcastSubscribe {
        broadcasts: HashMap<String, String>,
    },

    Ack {
        updates: Vec<ClientAck>,
    },

    Nack {
        code: Option<i32>,
        version: String,
    },

    Ping,
}

#[derive(Debug, Serialize)]
#[serde(tag = "messageType", rename_all = "snake_case")]
pub enum ServerMessage {
    Hello {
        uaid: String,
        status: u32,
        // This is required for output, but will always be "true"
        use_webpush: bool,
        broadcasts: HashMap<String, BroadcastValue>,
    },

    Register {
        #[serde(rename = "channelID")]
        channel_id: Uuid,
        status: u32,
        #[serde(rename = "pushEndpoint")]
        push_endpoint: String,
    },

    Unregister {
        #[serde(rename = "channelID")]
        channel_id: Uuid,
        status: u32,
    },

    Broadcast {
        broadcasts: HashMap<String, BroadcastValue>,
    },

    Notification(Notification),

    Ping,
}

impl ServerMessage {
    pub fn to_json(&self) -> Result<String, serde_json::error::Error> {
        match self {
            // clients recognize {"messageType": "ping"} but traditionally both
            // client/server send the empty object version
            ServerMessage::Ping => Ok("{}".to_owned()),
            _ => serde_json::to_string(self),
        }
    }
}

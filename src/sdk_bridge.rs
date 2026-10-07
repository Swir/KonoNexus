//! Versioned JSON bridge for native application hosts.
//!
//! This is a local SDK boundary. It does not change the KNP network wire format.

use crate::{KonofixTransport, RelayAppEvent, RelayAppFailureReason, MAX_RELAY_APP_MESSAGE_BYTES};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

pub const KONOFIX_SDK_BRIDGE_DOMAIN: &str = "kononexus/sdk-bridge";
pub const KONOFIX_SDK_BRIDGE_VERSION: u8 = 1;
pub const MAX_SDK_REQUEST_ID_BYTES: usize = 64;
pub const MAX_SDK_CONNECT_ENDPOINTS: usize = 3;
pub const MAX_SDK_JSON_LINE_BYTES: usize = MAX_RELAY_APP_MESSAGE_BYTES * 4 / 3 + 4_096;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KonofixSdkRequest {
    pub domain: String,
    pub version: u8,
    pub request_id: String,
    pub command: KonofixSdkCommand,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KonofixSdkCommand {
    Send {
        peer_node_id: String,
        data_base64: String,
    },
    Connect {
        peer_node_id: String,
        endpoints: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KonofixSdkResponse {
    pub domain: String,
    pub version: u8,
    pub request_id: String,
    pub result: KonofixSdkResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum KonofixSdkResult {
    Sent { message_id: u64 },
    Connected,
    Rejected { code: String, message: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KonofixSdkEventEnvelope {
    pub domain: String,
    pub version: u8,
    pub event: KonofixSdkEvent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KonofixSdkEvent {
    Message {
        peer_node_id: String,
        message_id: u64,
        data_base64: String,
    },
    Delivered {
        peer_node_id: String,
        message_id: u64,
    },
    Failed {
        peer_node_id: String,
        message_id: u64,
        reason: KonofixSdkFailureReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KonofixSdkFailureReason {
    RetriesExhausted,
    Expired,
}

impl KonofixSdkRequest {
    pub fn new_send(
        request_id: impl Into<String>,
        peer_node_id: impl Into<String>,
        data: &[u8],
    ) -> Self {
        Self {
            domain: KONOFIX_SDK_BRIDGE_DOMAIN.to_owned(),
            version: KONOFIX_SDK_BRIDGE_VERSION,
            request_id: request_id.into(),
            command: KonofixSdkCommand::Send {
                peer_node_id: peer_node_id.into(),
                data_base64: STANDARD.encode(data),
            },
        }
    }

    pub fn new_connect(
        request_id: impl Into<String>,
        peer_node_id: impl Into<String>,
        endpoints: impl IntoIterator<Item = SocketAddr>,
    ) -> Self {
        Self {
            domain: KONOFIX_SDK_BRIDGE_DOMAIN.to_owned(),
            version: KONOFIX_SDK_BRIDGE_VERSION,
            request_id: request_id.into(),
            command: KonofixSdkCommand::Connect {
                peer_node_id: peer_node_id.into(),
                endpoints: endpoints
                    .into_iter()
                    .map(|endpoint| endpoint.to_string())
                    .collect(),
            },
        }
    }

    pub fn from_json_verified(json: &str) -> Result<Self> {
        let request: Self = serde_json::from_str(json).context("invalid SDK request JSON")?;
        request.verify()?;
        Ok(request)
    }

    pub fn to_json(&self) -> Result<String> {
        self.verify()?;
        serde_json::to_string(self).context("unable to encode SDK request JSON")
    }

    pub fn verify(&self) -> Result<()> {
        verify_envelope(&self.domain, self.version)?;
        verify_request_id(&self.request_id)?;

        match &self.command {
            KonofixSdkCommand::Send {
                peer_node_id,
                data_base64,
            } => {
                verify_node_id(peer_node_id)?;
                let data = STANDARD
                    .decode(data_base64)
                    .context("data_base64 is not canonical base64")?;
                if data.is_empty() {
                    bail!("send payload must not be empty");
                }
                if data.len() > MAX_RELAY_APP_MESSAGE_BYTES {
                    bail!("send payload exceeds {MAX_RELAY_APP_MESSAGE_BYTES} bytes");
                }
                if STANDARD.encode(&data) != *data_base64 {
                    bail!("data_base64 is not canonical base64");
                }
            }
            KonofixSdkCommand::Connect {
                peer_node_id,
                endpoints,
            } => {
                verify_node_id(peer_node_id)?;
                parse_endpoints(endpoints)?;
            }
        }
        Ok(())
    }

    pub async fn execute(&self, transport: &KonofixTransport) -> Result<KonofixSdkResponse> {
        self.verify()?;
        let result = match &self.command {
            KonofixSdkCommand::Send {
                peer_node_id,
                data_base64,
            } => {
                let data = STANDARD
                    .decode(data_base64)
                    .context("data_base64 is not canonical base64")?;
                match transport.send(peer_node_id.clone(), data).await {
                    Ok(message_id) => KonofixSdkResult::Sent { message_id },
                    Err(error) => rejected("transport_error", error),
                }
            }
            KonofixSdkCommand::Connect {
                peer_node_id,
                endpoints,
            } => match transport
                .connect(peer_node_id.clone(), parse_endpoints(endpoints)?)
                .await
            {
                Ok(()) => KonofixSdkResult::Connected,
                Err(error) => rejected("transport_error", error),
            },
        };

        Ok(KonofixSdkResponse {
            domain: KONOFIX_SDK_BRIDGE_DOMAIN.to_owned(),
            version: KONOFIX_SDK_BRIDGE_VERSION,
            request_id: self.request_id.clone(),
            result,
        })
    }
}

impl KonofixSdkResponse {
    pub fn rejected(
        request_id: impl Into<String>,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            domain: KONOFIX_SDK_BRIDGE_DOMAIN.to_owned(),
            version: KONOFIX_SDK_BRIDGE_VERSION,
            request_id: request_id.into(),
            result: KonofixSdkResult::Rejected {
                code: code.into(),
                message: message.into(),
            },
        }
    }

    pub fn from_json_verified(json: &str) -> Result<Self> {
        let response: Self = serde_json::from_str(json).context("invalid SDK response JSON")?;
        response.verify()?;
        Ok(response)
    }

    pub fn to_json(&self) -> Result<String> {
        self.verify()?;
        serde_json::to_string(self).context("unable to encode SDK response JSON")
    }

    pub fn verify(&self) -> Result<()> {
        verify_envelope(&self.domain, self.version)?;
        verify_request_id(&self.request_id)?;
        match &self.result {
            KonofixSdkResult::Rejected { code, message } => {
                if code.is_empty() || code.chars().any(char::is_control) {
                    bail!("rejection code must not be empty or contain control characters");
                }
                if message.chars().any(char::is_control) {
                    bail!("rejection message must not contain control characters");
                }
            }
            KonofixSdkResult::Sent { .. } | KonofixSdkResult::Connected => {}
        }
        Ok(())
    }
}

impl KonofixSdkEventEnvelope {
    pub fn from_relay_event(event: RelayAppEvent) -> Self {
        let event = match event {
            RelayAppEvent::Message(message) => KonofixSdkEvent::Message {
                peer_node_id: message.peer_node_id,
                message_id: message.message_id,
                data_base64: STANDARD.encode(message.data),
            },
            RelayAppEvent::Delivered(receipt) => KonofixSdkEvent::Delivered {
                peer_node_id: receipt.peer_node_id,
                message_id: receipt.message_id,
            },
            RelayAppEvent::Failed(failure) => KonofixSdkEvent::Failed {
                peer_node_id: failure.peer_node_id,
                message_id: failure.message_id,
                reason: failure.reason.into(),
            },
        };
        Self {
            domain: KONOFIX_SDK_BRIDGE_DOMAIN.to_owned(),
            version: KONOFIX_SDK_BRIDGE_VERSION,
            event,
        }
    }

    pub fn from_json_verified(json: &str) -> Result<Self> {
        let envelope: Self = serde_json::from_str(json).context("invalid SDK event JSON")?;
        envelope.verify()?;
        Ok(envelope)
    }

    pub fn to_json(&self) -> Result<String> {
        self.verify()?;
        serde_json::to_string(self).context("unable to encode SDK event JSON")
    }

    pub fn verify(&self) -> Result<()> {
        verify_envelope(&self.domain, self.version)?;
        match &self.event {
            KonofixSdkEvent::Message {
                peer_node_id,
                data_base64,
                ..
            } => {
                verify_node_id(peer_node_id)?;
                let data = STANDARD
                    .decode(data_base64)
                    .context("data_base64 is not canonical base64")?;
                if data.len() > MAX_RELAY_APP_MESSAGE_BYTES
                    || STANDARD.encode(&data) != *data_base64
                {
                    bail!("invalid SDK message payload");
                }
            }
            KonofixSdkEvent::Delivered { peer_node_id, .. }
            | KonofixSdkEvent::Failed { peer_node_id, .. } => verify_node_id(peer_node_id)?,
        }
        Ok(())
    }
}

impl From<RelayAppFailureReason> for KonofixSdkFailureReason {
    fn from(reason: RelayAppFailureReason) -> Self {
        match reason {
            RelayAppFailureReason::RetriesExhausted => Self::RetriesExhausted,
            RelayAppFailureReason::Expired => Self::Expired,
        }
    }
}

fn rejected(code: &str, error: impl std::fmt::Display) -> KonofixSdkResult {
    KonofixSdkResult::Rejected {
        code: code.to_owned(),
        message: error.to_string(),
    }
}

fn verify_envelope(domain: &str, version: u8) -> Result<()> {
    if domain != KONOFIX_SDK_BRIDGE_DOMAIN {
        bail!("unsupported SDK bridge domain");
    }
    if version != KONOFIX_SDK_BRIDGE_VERSION {
        bail!("unsupported SDK bridge version {version}");
    }
    Ok(())
}

fn verify_request_id(request_id: &str) -> Result<()> {
    if request_id.is_empty() || request_id.len() > MAX_SDK_REQUEST_ID_BYTES {
        bail!("request_id must be 1..={MAX_SDK_REQUEST_ID_BYTES} bytes");
    }
    if request_id.chars().any(char::is_control) {
        bail!("request_id must not contain control characters");
    }
    Ok(())
}

fn verify_node_id(node_id: &str) -> Result<()> {
    let digest = node_id
        .strip_prefix("knp1")
        .context("peer_node_id must start with knp1")?;
    if digest.len() != 40 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("peer_node_id must contain a 20-byte hexadecimal digest");
    }
    Ok(())
}

fn parse_endpoints(endpoints: &[String]) -> Result<Vec<SocketAddr>> {
    if endpoints.is_empty() || endpoints.len() > MAX_SDK_CONNECT_ENDPOINTS {
        bail!("connect requires 1..={MAX_SDK_CONNECT_ENDPOINTS} endpoints");
    }
    let mut parsed = Vec::with_capacity(endpoints.len());
    let mut unique = HashSet::with_capacity(endpoints.len());
    for value in endpoints {
        let endpoint: SocketAddr = value
            .parse()
            .with_context(|| format!("invalid socket endpoint {value}"))?;
        if endpoint.port() == 0 || unusable_ip(endpoint.ip()) {
            bail!("unusable socket endpoint {value}");
        }
        if !unique.insert(endpoint) {
            bail!("duplicate socket endpoint {value}");
        }
        parsed.push(endpoint);
    }
    Ok(parsed)
}

fn unusable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast(),
        IpAddr::V6(ip) => ip.is_unspecified() || ip.is_multicast(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RelayAppDeliveryFailure, RelayAppMessage};

    fn node_id(byte: char) -> String {
        format!("knp1{}", byte.to_string().repeat(40))
    }

    #[test]
    fn send_request_has_stable_json_and_strict_validation() {
        let request = KonofixSdkRequest::new_send("send-1", node_id('a'), b"hello\0world");
        let json = request.to_json().unwrap();
        assert_eq!(
            KonofixSdkRequest::from_json_verified(&json).unwrap(),
            request
        );
        assert!(json.contains("\"type\":\"send\""));
        assert!(json.contains("\"data_base64\":\"aGVsbG8Ad29ybGQ=\""));

        let mut invalid = request.clone();
        invalid.version += 1;
        assert!(invalid.verify().is_err());
        if let KonofixSdkCommand::Send {
            peer_node_id,
            data_base64,
        } = &mut invalid.command
        {
            *peer_node_id = "knp1not-a-node".to_owned();
            *data_base64 = "not base64".to_owned();
        }
        assert!(invalid.verify().is_err());

        let oversized = KonofixSdkRequest::new_send(
            "oversized",
            node_id('b'),
            &vec![0; MAX_RELAY_APP_MESSAGE_BYTES + 1],
        );
        assert!(oversized.verify().is_err());
    }

    #[test]
    fn connect_request_bounds_and_deduplicates_endpoints() {
        let request = KonofixSdkRequest::new_connect(
            "connect-1",
            node_id('c'),
            [
                "192.168.1.8:47000".parse().unwrap(),
                "[2001:db8::8]:47000".parse().unwrap(),
            ],
        );
        request.verify().unwrap();

        let invalid_values = [
            vec![],
            vec!["0.0.0.0:47000".to_owned()],
            vec!["127.0.0.1:0".to_owned()],
            vec!["127.0.0.1:47000".to_owned(), "127.0.0.1:47000".to_owned()],
            vec![
                "127.0.0.1:1".to_owned(),
                "127.0.0.1:2".to_owned(),
                "127.0.0.1:3".to_owned(),
                "127.0.0.1:4".to_owned(),
            ],
        ];
        for endpoints in invalid_values {
            let invalid = KonofixSdkRequest {
                domain: KONOFIX_SDK_BRIDGE_DOMAIN.to_owned(),
                version: KONOFIX_SDK_BRIDGE_VERSION,
                request_id: "invalid-connect".to_owned(),
                command: KonofixSdkCommand::Connect {
                    peer_node_id: node_id('d'),
                    endpoints,
                },
            };
            assert!(invalid.verify().is_err());
        }
    }

    #[test]
    fn event_round_trip_preserves_binary_and_failure_reason() {
        let message =
            KonofixSdkEventEnvelope::from_relay_event(RelayAppEvent::Message(RelayAppMessage {
                peer_node_id: node_id('e'),
                message_id: 42,
                data: vec![0, 1, 254, 255],
            }));
        let json = message.to_json().unwrap();
        assert_eq!(
            KonofixSdkEventEnvelope::from_json_verified(&json).unwrap(),
            message
        );
        assert!(json.contains("\"data_base64\":\"AAH+/w==\""));

        let failure = KonofixSdkEventEnvelope::from_relay_event(RelayAppEvent::Failed(
            RelayAppDeliveryFailure {
                peer_node_id: node_id('f'),
                message_id: 43,
                reason: RelayAppFailureReason::RetriesExhausted,
            },
        ));
        assert!(failure
            .to_json()
            .unwrap()
            .contains("\"reason\":\"retries_exhausted\""));
    }

    #[test]
    fn rejected_response_round_trips_with_correlation_id() {
        let response = KonofixSdkResponse::rejected(
            "bad-request-9",
            "invalid_request",
            "unsupported SDK bridge version 2",
        );
        let json = response.to_json().unwrap();
        assert_eq!(
            KonofixSdkResponse::from_json_verified(&json).unwrap(),
            response
        );
    }
}

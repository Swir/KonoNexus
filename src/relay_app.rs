use anyhow::{bail, Context, Result};
use rand::random;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

pub const RELAY_APP_FRAGMENT_BYTES: usize = 512;
pub const MAX_RELAY_APP_MESSAGE_BYTES: usize = 256 * 1024;
pub const MAX_RELAY_APP_OUTBOUND_MESSAGES: usize = 64;
pub const MAX_RELAY_APP_OUTBOUND_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_RELAY_APP_INBOUND_ASSEMBLIES: usize = 64;
pub const MAX_RELAY_APP_INBOUND_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_RELAY_APP_COMPLETED_MESSAGES: usize = 128;
pub const MAX_RELAY_APP_COMPLETED_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_RELAY_APP_DELIVERED_IDS: usize = 1_024;
pub const MAX_RELAY_APP_RETRANSMISSIONS: u8 = 4;
pub const RELAY_APP_ACK_TIMEOUT: Duration = Duration::from_secs(1);
pub const RELAY_APP_REASSEMBLY_TTL: Duration = Duration::from_secs(30);
pub const RELAY_APP_DELIVERED_TTL: Duration = Duration::from_secs(120);
pub const RELAY_APP_OUTBOUND_TTL: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayAppFragment {
    pub message_id: u64,
    pub fragment_index: u16,
    pub fragment_count: u16,
    pub total_len: u32,
    pub data_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAppMessage {
    pub peer_node_id: String,
    pub message_id: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RelayAppOutboundFragment {
    pub peer_node_id: String,
    pub fragment: RelayAppFragment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayAppReceiveStatus {
    Pending,
    Completed,
    DuplicateCompleted,
}

#[derive(Debug)]
struct OutboundMessage {
    peer_node_id: String,
    message_id: u64,
    data: Vec<u8>,
    fragment_count: u16,
    next_fragment_index: u16,
    awaiting_ack: bool,
    retransmissions: u8,
    retry_at: Option<Instant>,
    created_at: Instant,
}

#[derive(Debug)]
struct InboundAssembly {
    total_len: usize,
    fragments: Vec<Option<Vec<u8>>>,
    received_count: usize,
    expires_at: Instant,
}

#[derive(Debug)]
struct DeliveredRecord {
    total_len: usize,
    fragment_count: u16,
    expires_at: Instant,
}

#[derive(Debug, Default)]
pub struct RelayAppManager {
    outbound: VecDeque<OutboundMessage>,
    outbound_bytes: usize,
    inbound: HashMap<(String, u64), InboundAssembly>,
    inbound_reserved_bytes: usize,
    delivered: HashMap<(String, u64), DeliveredRecord>,
    completed: VecDeque<RelayAppMessage>,
    completed_bytes: usize,
}

impl RelayAppManager {
    pub fn queue(&mut self, peer_node_id: String, data: Vec<u8>, now: Instant) -> Result<u64> {
        if data.is_empty() {
            bail!("relay application message cannot be empty");
        }
        if data.len() > MAX_RELAY_APP_MESSAGE_BYTES {
            bail!("relay application message exceeds maximum size");
        }
        if self.outbound.len() >= MAX_RELAY_APP_OUTBOUND_MESSAGES
            || self.outbound_bytes.saturating_add(data.len()) > MAX_RELAY_APP_OUTBOUND_BYTES
        {
            bail!("relay application outbound queue is full");
        }

        let fragment_count = data.len().div_ceil(RELAY_APP_FRAGMENT_BYTES);
        let fragment_count: u16 = fragment_count
            .try_into()
            .map_err(|_| anyhow::anyhow!("relay application fragment count overflow"))?;

        let mut message_id: u64 = random();
        while self
            .outbound
            .iter()
            .any(|message| message.message_id == message_id)
        {
            message_id = random();
        }

        self.outbound_bytes += data.len();
        self.outbound.push_back(OutboundMessage {
            peer_node_id,
            message_id,
            data,
            fragment_count,
            next_fragment_index: 0,
            awaiting_ack: false,
            retransmissions: 0,
            retry_at: None,
            created_at: now,
        });

        Ok(message_id)
    }

    pub fn peek_next(
        &self,
        ready_peers: &std::collections::HashSet<String>,
    ) -> Option<RelayAppOutboundFragment> {
        let message = self
            .outbound
            .iter()
            .find(|message| !message.awaiting_ack && ready_peers.contains(&message.peer_node_id))?;

        let index = usize::from(message.next_fragment_index);
        let start = index.saturating_mul(RELAY_APP_FRAGMENT_BYTES);
        let end = (start + RELAY_APP_FRAGMENT_BYTES).min(message.data.len());
        if start >= end {
            return None;
        }

        Some(RelayAppOutboundFragment {
            peer_node_id: message.peer_node_id.clone(),
            fragment: RelayAppFragment {
                message_id: message.message_id,
                fragment_index: message.next_fragment_index,
                fragment_count: message.fragment_count,
                total_len: message.data.len() as u32,
                data_hex: hex::encode(&message.data[start..end]),
            },
        })
    }

    pub fn mark_fragment_sent(
        &mut self,
        message_id: u64,
        fragment_index: u16,
        now: Instant,
    ) -> Result<()> {
        let message = self
            .outbound
            .iter_mut()
            .find(|message| message.message_id == message_id)
            .ok_or_else(|| anyhow::anyhow!("relay application outbound message not found"))?;

        if message.awaiting_ack || message.next_fragment_index != fragment_index {
            bail!("relay application fragment send state mismatch");
        }

        message.next_fragment_index = message
            .next_fragment_index
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("relay application fragment index overflow"))?;

        if message.next_fragment_index >= message.fragment_count {
            message.awaiting_ack = true;
            message.retry_at = Some(now + RELAY_APP_ACK_TIMEOUT);
        }

        Ok(())
    }

    pub fn prepare_retransmissions(&mut self, now: Instant) -> (usize, usize) {
        let mut restarted = 0_usize;
        let mut drop_indices = Vec::new();

        for (index, message) in self.outbound.iter_mut().enumerate() {
            if !message.awaiting_ack || !message.retry_at.is_some_and(|retry_at| retry_at <= now) {
                continue;
            }

            if message.retransmissions >= MAX_RELAY_APP_RETRANSMISSIONS {
                drop_indices.push(index);
                continue;
            }

            message.retransmissions += 1;
            message.next_fragment_index = 0;
            message.awaiting_ack = false;
            message.retry_at = None;
            restarted += 1;
        }

        for index in drop_indices.iter().rev().copied() {
            if let Some(message) = self.outbound.remove(index) {
                self.outbound_bytes = self.outbound_bytes.saturating_sub(message.data.len());
            }
        }

        (restarted, drop_indices.len())
    }

    pub fn acknowledge(&mut self, peer_node_id: &str, message_id: u64) -> bool {
        let Some(index) = self.outbound.iter().position(|message| {
            message.message_id == message_id && message.peer_node_id == peer_node_id
        }) else {
            return false;
        };

        if let Some(message) = self.outbound.remove(index) {
            self.outbound_bytes = self.outbound_bytes.saturating_sub(message.data.len());
            return true;
        }

        false
    }

    pub fn accept_fragment(
        &mut self,
        peer_node_id: &str,
        fragment: RelayAppFragment,
        now: Instant,
    ) -> Result<RelayAppReceiveStatus> {
        validate_fragment(&fragment)?;
        self.expire_delivered(now);

        let total_len = fragment.total_len as usize;
        let key = (peer_node_id.to_owned(), fragment.message_id);

        if let Some(delivered) = self.delivered.get(&key) {
            if delivered.total_len != total_len
                || delivered.fragment_count != fragment.fragment_count
            {
                bail!("relay application replay metadata does not match delivered message");
            }
            return Ok(RelayAppReceiveStatus::DuplicateCompleted);
        }

        if !self.inbound.contains_key(&key) {
            if self.inbound.len() >= MAX_RELAY_APP_INBOUND_ASSEMBLIES
                || self.inbound_reserved_bytes.saturating_add(total_len)
                    > MAX_RELAY_APP_INBOUND_BYTES
            {
                bail!("relay application inbound reassembly capacity exceeded");
            }

            self.inbound_reserved_bytes += total_len;
            self.inbound.insert(
                key.clone(),
                InboundAssembly {
                    total_len,
                    fragments: vec![None; usize::from(fragment.fragment_count)],
                    received_count: 0,
                    expires_at: now + RELAY_APP_REASSEMBLY_TTL,
                },
            );
        }

        let assembly = self
            .inbound
            .get_mut(&key)
            .ok_or_else(|| anyhow::anyhow!("relay application reassembly disappeared"))?;

        if assembly.total_len != total_len
            || assembly.fragments.len() != usize::from(fragment.fragment_count)
        {
            bail!("relay application fragment metadata changed mid-message");
        }

        assembly.expires_at = now + RELAY_APP_REASSEMBLY_TTL;
        let index = usize::from(fragment.fragment_index);
        let data =
            hex::decode(&fragment.data_hex).context("relay application fragment is not hex")?;

        match &assembly.fragments[index] {
            Some(existing) if existing == &data => return Ok(RelayAppReceiveStatus::Pending),
            Some(_) => bail!("relay application duplicate fragment content mismatch"),
            None => {
                assembly.fragments[index] = Some(data);
                assembly.received_count += 1;
            }
        }

        if assembly.received_count != assembly.fragments.len() {
            return Ok(RelayAppReceiveStatus::Pending);
        }

        let assembly = self
            .inbound
            .remove(&key)
            .ok_or_else(|| anyhow::anyhow!("relay application reassembly disappeared"))?;
        self.inbound_reserved_bytes = self
            .inbound_reserved_bytes
            .saturating_sub(assembly.total_len);

        let mut data = Vec::with_capacity(assembly.total_len);
        for fragment_data in assembly.fragments {
            let fragment_data = fragment_data
                .ok_or_else(|| anyhow::anyhow!("relay application fragment missing"))?;
            data.extend_from_slice(&fragment_data);
        }

        if data.len() != assembly.total_len {
            bail!("relay application reassembled length mismatch");
        }

        self.insert_delivered(
            key,
            DeliveredRecord {
                total_len: assembly.total_len,
                fragment_count: fragment.fragment_count,
                expires_at: now + RELAY_APP_DELIVERED_TTL,
            },
        );

        self.push_completed(RelayAppMessage {
            peer_node_id: peer_node_id.to_owned(),
            message_id: fragment.message_id,
            data,
        });

        Ok(RelayAppReceiveStatus::Completed)
    }

    pub fn take_completed(&mut self) -> Vec<RelayAppMessage> {
        self.completed_bytes = 0;
        self.completed.drain(..).collect()
    }

    pub fn peek_completed(&self) -> Option<RelayAppMessage> {
        self.completed.front().cloned()
    }

    pub fn pop_completed(&mut self) -> Option<RelayAppMessage> {
        let message = self.completed.pop_front()?;
        self.completed_bytes = self.completed_bytes.saturating_sub(message.data.len());
        Some(message)
    }

    pub fn expire(&mut self, now: Instant) -> (usize, usize) {
        self.expire_delivered(now);

        let expired_inbound: Vec<(String, u64)> = self
            .inbound
            .iter()
            .filter(|(_, assembly)| assembly.expires_at <= now)
            .map(|(key, _)| key.clone())
            .collect();

        for key in &expired_inbound {
            if let Some(assembly) = self.inbound.remove(key) {
                self.inbound_reserved_bytes = self
                    .inbound_reserved_bytes
                    .saturating_sub(assembly.total_len);
            }
        }

        let expired_outbound: Vec<usize> = self
            .outbound
            .iter()
            .enumerate()
            .filter(|(_, message)| now.duration_since(message.created_at) >= RELAY_APP_OUTBOUND_TTL)
            .map(|(index, _)| index)
            .collect();

        for index in expired_outbound.iter().rev().copied() {
            if let Some(message) = self.outbound.remove(index) {
                self.outbound_bytes = self.outbound_bytes.saturating_sub(message.data.len());
            }
        }

        (expired_inbound.len(), expired_outbound.len())
    }

    pub fn outbound_message_count(&self) -> usize {
        self.outbound.len()
    }

    pub fn outbound_bytes(&self) -> usize {
        self.outbound_bytes
    }

    fn insert_delivered(&mut self, key: (String, u64), record: DeliveredRecord) {
        if !self.delivered.contains_key(&key) && self.delivered.len() >= MAX_RELAY_APP_DELIVERED_IDS
        {
            if let Some(oldest) = self
                .delivered
                .iter()
                .min_by_key(|(_, record)| record.expires_at)
                .map(|(key, _)| key.clone())
            {
                self.delivered.remove(&oldest);
            }
        }

        self.delivered.insert(key, record);
    }

    fn expire_delivered(&mut self, now: Instant) {
        self.delivered
            .retain(|_, delivered| delivered.expires_at > now);
    }

    fn push_completed(&mut self, message: RelayAppMessage) {
        while self.completed.len() >= MAX_RELAY_APP_COMPLETED_MESSAGES
            || self.completed_bytes.saturating_add(message.data.len())
                > MAX_RELAY_APP_COMPLETED_BYTES
        {
            let Some(oldest) = self.completed.pop_front() else {
                break;
            };
            self.completed_bytes = self.completed_bytes.saturating_sub(oldest.data.len());
        }

        self.completed_bytes += message.data.len();
        self.completed.push_back(message);
    }
}

fn validate_fragment(fragment: &RelayAppFragment) -> Result<()> {
    if fragment.fragment_count == 0
        || fragment.fragment_index >= fragment.fragment_count
        || fragment.total_len == 0
        || fragment.total_len as usize > MAX_RELAY_APP_MESSAGE_BYTES
    {
        bail!("invalid relay application fragment metadata");
    }

    let expected_count = (fragment.total_len as usize).div_ceil(RELAY_APP_FRAGMENT_BYTES);
    if usize::from(fragment.fragment_count) != expected_count {
        bail!("relay application fragment count does not match total length");
    }

    let decoded =
        hex::decode(&fragment.data_hex).context("relay application fragment is not valid hex")?;
    if decoded.is_empty() || decoded.len() > RELAY_APP_FRAGMENT_BYTES {
        bail!("relay application fragment payload size is invalid");
    }

    let expected_last_len = {
        let remainder = fragment.total_len as usize % RELAY_APP_FRAGMENT_BYTES;
        if remainder == 0 {
            RELAY_APP_FRAGMENT_BYTES
        } else {
            remainder
        }
    };

    if fragment.fragment_index + 1 == fragment.fragment_count {
        if decoded.len() != expected_last_len {
            bail!("relay application final fragment length mismatch");
        }
    } else if decoded.len() != RELAY_APP_FRAGMENT_BYTES {
        bail!("relay application non-final fragment length mismatch");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn drain_one_pass(
        sender: &mut RelayAppManager,
        receiver: &mut RelayAppManager,
        ready: &HashSet<String>,
        now: Instant,
        drop_index: Option<u16>,
    ) -> Option<u64> {
        let mut completed_message = None;

        while let Some(outbound) = sender.peek_next(ready) {
            let fragment_index = outbound.fragment.fragment_index;
            let message_id = outbound.fragment.message_id;

            if drop_index != Some(fragment_index) {
                let status = receiver
                    .accept_fragment("peer-a", outbound.fragment.clone(), now)
                    .unwrap();
                if status == RelayAppReceiveStatus::Completed {
                    completed_message = Some(message_id);
                }
            }

            sender
                .mark_fragment_sent(message_id, fragment_index, now)
                .unwrap();
        }

        completed_message
    }

    #[test]
    fn fragments_reassemble_and_ack_releases_backpressure() {
        let now = Instant::now();
        let data = vec![0x5a; RELAY_APP_FRAGMENT_BYTES * 2 + 17];
        let mut sender = RelayAppManager::default();
        let mut receiver = RelayAppManager::default();
        let message_id = sender.queue("peer-b".into(), data.clone(), now).unwrap();
        let ready = HashSet::from(["peer-b".to_owned()]);

        let completed_id = drain_one_pass(&mut sender, &mut receiver, &ready, now, None);
        assert_eq!(completed_id, Some(message_id));

        let completed = receiver.take_completed();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].data, data);
        assert_eq!(sender.outbound_message_count(), 1);
        assert!(sender.acknowledge("peer-b", message_id));
        assert_eq!(sender.outbound_message_count(), 0);
        assert_eq!(sender.outbound_bytes(), 0);
    }

    #[test]
    fn missing_fragment_is_recovered_by_bounded_retransmission() {
        let now = Instant::now();
        let data = vec![0x33; RELAY_APP_FRAGMENT_BYTES * 2 + 11];
        let mut sender = RelayAppManager::default();
        let mut receiver = RelayAppManager::default();
        let message_id = sender.queue("peer-b".into(), data.clone(), now).unwrap();
        let ready = HashSet::from(["peer-b".to_owned()]);

        assert_eq!(
            drain_one_pass(&mut sender, &mut receiver, &ready, now, Some(1)),
            None
        );
        assert!(receiver.take_completed().is_empty());

        let retry_at = now + RELAY_APP_ACK_TIMEOUT;
        assert_eq!(sender.prepare_retransmissions(retry_at), (1, 0));
        assert_eq!(
            drain_one_pass(&mut sender, &mut receiver, &ready, retry_at, None),
            Some(message_id)
        );

        let completed = receiver.take_completed();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].data, data);
    }

    #[test]
    fn lost_ack_retransmission_does_not_redeliver_message() {
        let now = Instant::now();
        let data = vec![0x44; RELAY_APP_FRAGMENT_BYTES + 7];
        let mut sender = RelayAppManager::default();
        let mut receiver = RelayAppManager::default();
        let message_id = sender.queue("peer-b".into(), data, now).unwrap();
        let ready = HashSet::from(["peer-b".to_owned()]);

        assert_eq!(
            drain_one_pass(&mut sender, &mut receiver, &ready, now, None),
            Some(message_id)
        );
        assert_eq!(receiver.take_completed().len(), 1);

        let retry_at = now + RELAY_APP_ACK_TIMEOUT;
        assert_eq!(sender.prepare_retransmissions(retry_at), (1, 0));

        let outbound = sender.peek_next(&ready).unwrap();
        assert_eq!(
            receiver
                .accept_fragment("peer-a", outbound.fragment.clone(), retry_at)
                .unwrap(),
            RelayAppReceiveStatus::DuplicateCompleted
        );
        sender
            .mark_fragment_sent(message_id, outbound.fragment.fragment_index, retry_at)
            .unwrap();

        assert!(receiver.take_completed().is_empty());
        assert!(sender.acknowledge("peer-b", message_id));
        assert_eq!(sender.outbound_message_count(), 0);
    }

    #[test]
    fn retransmissions_stop_after_bounded_retry_count() {
        let now = Instant::now();
        let mut sender = RelayAppManager::default();
        let ready = HashSet::from(["peer-b".to_owned()]);
        sender.queue("peer-b".into(), vec![1_u8; 32], now).unwrap();

        let mut current = now;
        for retry in 0..=MAX_RELAY_APP_RETRANSMISSIONS {
            while let Some(outbound) = sender.peek_next(&ready) {
                sender
                    .mark_fragment_sent(
                        outbound.fragment.message_id,
                        outbound.fragment.fragment_index,
                        current,
                    )
                    .unwrap();
            }

            current += RELAY_APP_ACK_TIMEOUT;
            let (_, dropped) = sender.prepare_retransmissions(current);

            if retry < MAX_RELAY_APP_RETRANSMISSIONS {
                assert_eq!(dropped, 0);
            } else {
                assert_eq!(dropped, 1);
            }
        }

        assert_eq!(sender.outbound_message_count(), 0);
    }

    #[test]
    fn outbound_limits_apply_backpressure() {
        let now = Instant::now();
        let mut manager = RelayAppManager::default();
        for _ in 0..MAX_RELAY_APP_OUTBOUND_MESSAGES {
            manager.queue("peer".into(), vec![1], now).unwrap();
        }
        assert!(manager.queue("peer".into(), vec![1], now).is_err());
    }

    #[test]
    fn fragment_metadata_tampering_is_rejected() {
        let now = Instant::now();
        let mut receiver = RelayAppManager::default();
        let fragment = RelayAppFragment {
            message_id: 1,
            fragment_index: 0,
            fragment_count: 2,
            total_len: 10,
            data_hex: hex::encode(vec![1_u8; 10]),
        };

        assert!(receiver.accept_fragment("peer", fragment, now).is_err());
    }

    #[test]
    fn stale_reassembly_and_outbound_messages_expire() {
        let now = Instant::now();
        let mut manager = RelayAppManager::default();
        manager.queue("peer".into(), vec![7_u8; 32], now).unwrap();

        let fragment = RelayAppFragment {
            message_id: 2,
            fragment_index: 0,
            fragment_count: 2,
            total_len: (RELAY_APP_FRAGMENT_BYTES + 1) as u32,
            data_hex: hex::encode(vec![3_u8; RELAY_APP_FRAGMENT_BYTES]),
        };
        assert_eq!(
            manager.accept_fragment("peer", fragment, now).unwrap(),
            RelayAppReceiveStatus::Pending
        );

        let (inbound, outbound) =
            manager.expire(now + RELAY_APP_OUTBOUND_TTL + Duration::from_secs(1));
        assert_eq!(inbound, 1);
        assert_eq!(outbound, 1);
    }
}

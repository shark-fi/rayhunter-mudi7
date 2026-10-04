use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::diag::Message;
use crate::diag::diaglog::{LogBody, rrc::LteRrcOtaPacket};

const MAX_STREAMS: usize = 8;
const MAX_BYTES: usize = u16::MAX as usize - 44; // IPv4/UDP/GSMTAP headers in PCAP export.
const MAX_AGE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Stream {
    subscription: Option<u32>,
    bearer: u8,
    channel: u8,
    cell: u16,
    frequency: u32,
    releases: [u8; 4],
    extra: [u8; 2],
    sib_mask: u32,
}

struct Assembly {
    first: Message,
    payload: Vec<u8>,
    next: u8,
    started: Instant,
    timestamp_ms: i64,
}

#[derive(Default)]
pub struct RrcReassembly {
    streams: HashMap<Stream, Assembly>,
    interrupted: usize,
}

impl RrcReassembly {
    pub fn clear(&mut self) -> usize {
        let count = self.streams.len() + self.interrupted;
        self.streams.clear();
        self.interrupted = 0;
        count
    }

    pub fn take_interrupted(&mut self) -> usize {
        std::mem::take(&mut self.interrupted)
    }

    pub fn expire(&mut self, timestamp_ms: Option<i64>, now: Instant) -> usize {
        let before = self.streams.len();
        self.streams.retain(|_, state| {
            now.saturating_duration_since(state.started) < MAX_AGE
                && timestamp_ms.is_none_or(|ts| {
                    ts.saturating_sub(state.timestamp_ms) < MAX_AGE.as_millis() as i64
                })
        });
        before - self.streams.len()
    }

    pub fn process(
        &mut self,
        message: Message,
        now: Instant,
    ) -> Result<Option<Message>, &'static str> {
        let Message::Log {
            subscription,
            timestamp,
            body:
                LogBody::LteRrcOtaMessage {
                    packet:
                        LteRrcOtaPacket::V30 {
                            bearer_id,
                            pdu_num,
                            phy_cell_id,
                            earfcn,
                            rrc_rel_maj,
                            rrc_rel_min,
                            nr_rrc_rel_maj,
                            nr_rrc_rel_min,
                            unknown1,
                            unknown2,
                            sib_mask,
                            segment_id,
                            packet,
                            ..
                        },
                    ..
                },
            ..
        } = &message
        else {
            return Ok(Some(message));
        };
        let key = Stream {
            subscription: *subscription,
            bearer: *bearer_id,
            channel: *pdu_num,
            cell: *phy_cell_id,
            frequency: *earfcn,
            releases: [*rrc_rel_maj, *rrc_rel_min, *nr_rrc_rel_maj, *nr_rrc_rel_min],
            extra: [*unknown1, *unknown2],
            sib_mask: *sib_mask,
        };
        let segment = *segment_id;
        let timestamp_ms = timestamp.to_datetime().timestamp_millis();
        if segment == 0 {
            if self.streams.remove(&key).is_some() {
                self.interrupted += 1;
            }
            return Ok(Some(message));
        }
        if !(1..=7).contains(&segment) || packet.is_empty() || packet.len() > MAX_BYTES {
            self.streams.remove(&key);
            return Err("Invalid or empty RRC segment");
        }
        if segment == 1 {
            if self.streams.remove(&key).is_some() {
                return Err("Overlapping or duplicate first RRC segment");
            }
            if self.streams.len() >= MAX_STREAMS {
                return Err("RRC assembly stream limit exceeded");
            }
            self.streams.insert(
                key,
                Assembly {
                    payload: packet.clone(),
                    first: message,
                    next: 2,
                    started: now,
                    timestamp_ms,
                },
            );
            return Ok(None);
        }
        let Some(mut assembly) = self.streams.remove(&key) else {
            return Err("RRC continuation without a matching first segment");
        };
        if now.saturating_duration_since(assembly.started) >= MAX_AGE
            || timestamp_ms < assembly.timestamp_ms
            || timestamp_ms.saturating_sub(assembly.timestamp_ms) >= MAX_AGE.as_millis() as i64
        {
            return Err("Expired RRC assembly");
        }
        if segment != 7 && segment != assembly.next {
            return Err("Missing, duplicate or out-of-order RRC segment");
        }
        if assembly.payload.len() + packet.len() > MAX_BYTES {
            return Err("RRC assembly byte limit exceeded");
        }
        assembly.payload.extend_from_slice(packet);
        if segment != 7 {
            assembly.next += 1;
            self.streams.insert(key, assembly);
            return Ok(None);
        }
        if let Message::Log {
            body:
                LogBody::LteRrcOtaMessage {
                    packet:
                        LteRrcOtaPacket::V30 {
                            segment_id,
                            len,
                            packet,
                            ..
                        },
                    ..
                },
            ..
        } = &mut assembly.first
        {
            *segment_id = 0;
            *len = assembly.payload.len() as u16;
            *packet = assembly.payload;
        }
        Ok(Some(assembly.first))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diag::diaglog::Timestamp;

    fn segment(subscription: Option<u32>, channel: u8, id: u8, data: &[u8]) -> Message {
        Message::Log {
            subscription,
            pending_msgs: 0,
            outer_length: 0,
            inner_length: 0,
            log_type: 0xb0c0,
            timestamp: Timestamp { ts: 0 },
            body: LogBody::LteRrcOtaMessage {
                ext_header_version: 30,
                packet: LteRrcOtaPacket::V30 {
                    rrc_rel_maj: 17,
                    rrc_rel_min: 0,
                    nr_rrc_rel_maj: 17,
                    nr_rrc_rel_min: 0,
                    bearer_id: 1,
                    phy_cell_id: 1,
                    earfcn: 1,
                    sfn_subfn: 0,
                    pdu_num: channel,
                    sib_mask: 0,
                    len: data.len() as u16,
                    unknown1: 0,
                    unknown2: 0,
                    segment_id: id,
                    packet: data.to_vec(),
                },
            },
        }
    }

    fn payload(message: Message) -> Vec<u8> {
        let Message::Log {
            body: LogBody::LteRrcOtaMessage { packet, .. },
            ..
        } = message
        else {
            panic!("Expected LTE RRC");
        };
        packet.take_payload()
    }

    #[test]
    fn assembles_short_and_full_sequences_and_passes_plain_messages() {
        for fragments in 1..=6 {
            let mut state = RrcReassembly::default();
            let now = Instant::now();
            for id in 1..=fragments {
                assert!(
                    state
                        .process(segment(Some(1), 3, id, &[id]), now)
                        .unwrap()
                        .is_none()
                );
            }
            let result = state
                .process(segment(Some(1), 3, 7, &[7]), now)
                .unwrap()
                .unwrap();
            let mut expected: Vec<u8> = (1..=fragments).collect();
            expected.push(7);
            assert_eq!(payload(result), expected);
            assert_eq!(state.clear(), 0);
            assert_eq!(
                payload(
                    state
                        .process(segment(None, 3, 0, &[9]), now)
                        .unwrap()
                        .unwrap()
                ),
                vec![9]
            );
        }
    }

    #[test]
    fn subscriptions_and_channels_never_share_fragments() {
        let mut state = RrcReassembly::default();
        let now = Instant::now();
        for (subscription, channel, value) in [
            (None, 3, 10),
            (Some(0), 3, 20),
            (Some(1), 3, 30),
            (Some(1), 9, 40),
        ] {
            state
                .process(segment(subscription, channel, 1, &[value]), now)
                .unwrap();
        }
        for (subscription, channel, value) in [
            (None, 3, 10),
            (Some(0), 3, 20),
            (Some(1), 3, 30),
            (Some(1), 9, 40),
        ] {
            let result = state
                .process(segment(subscription, channel, 7, &[99]), now)
                .unwrap()
                .unwrap();
            assert_eq!(payload(result), vec![value, 99]);
        }
    }

    #[test]
    fn invalid_sequences_drop_state_instead_of_decoding_partial_messages() {
        let now = Instant::now();
        for invalid in [1, 3, 6, 8] {
            let mut state = RrcReassembly::default();
            state.process(segment(Some(1), 3, 1, &[1]), now).unwrap();
            assert!(
                state
                    .process(segment(Some(1), 3, invalid, &[2]), now)
                    .is_err()
            );
            assert!(state.process(segment(Some(1), 3, 7, &[3]), now).is_err());
        }
        let mut state = RrcReassembly::default();
        assert!(state.process(segment(Some(1), 3, 7, &[3]), now).is_err());
        state.process(segment(Some(1), 3, 1, &[1]), now).unwrap();
        state.process(segment(Some(1), 3, 2, &[2]), now).unwrap();
        assert!(state.process(segment(Some(1), 3, 2, &[2]), now).is_err());
    }

    #[test]
    fn memory_and_time_limits_are_enforced_and_reset_cannot_complete_old_messages() {
        let now = Instant::now();
        let mut state = RrcReassembly::default();
        for id in 0..MAX_STREAMS {
            state
                .process(segment(Some(id as u32), 3, 1, &[1]), now)
                .unwrap();
        }
        assert!(state.process(segment(Some(99), 3, 1, &[1]), now).is_err());
        assert_eq!(state.expire(None, now + MAX_AGE), MAX_STREAMS);
        state
            .process(segment(Some(1), 3, 1, &vec![1; 40000]), now)
            .unwrap();
        assert!(
            state
                .process(segment(Some(1), 3, 7, &vec![2; 30000]), now)
                .is_err()
        );
        state.process(segment(Some(1), 3, 1, &[1]), now).unwrap();
        assert_eq!(state.clear(), 1);
        assert!(state.process(segment(Some(1), 3, 7, &[2]), now).is_err());
        state.process(segment(Some(1), 3, 1, &[1]), now).unwrap();
        assert!(
            state
                .process(segment(Some(1), 3, 7, &[2]), now + MAX_AGE)
                .is_err()
        );
        state.process(segment(Some(1), 3, 1, &[1]), now).unwrap();
        let timestamp_ms = Timestamp { ts: 0 }.to_datetime().timestamp_millis();
        assert_eq!(state.expire(Some(timestamp_ms - 1), now), 0);
        assert_eq!(state.expire(Some(timestamp_ms + 5000), now), 1);
        state
            .process(segment(Some(1), 3, 1, &vec![1; MAX_BYTES - 1]), now)
            .unwrap();
        let message = state
            .process(segment(Some(1), 3, 7, &[2]), now)
            .unwrap()
            .unwrap();
        assert_eq!(payload(message).len(), MAX_BYTES);
        state
            .process(segment(Some(1), 3, 1, &vec![1; MAX_BYTES]), now)
            .unwrap();
        assert!(state.process(segment(Some(1), 3, 7, &[2]), now).is_err());
    }
}

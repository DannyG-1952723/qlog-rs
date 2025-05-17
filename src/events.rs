use std::collections::HashMap;

use chrono::Utc;
use serde::Serialize;
use serde_with::skip_serializing_none;

use crate::{logfile::TimeFormat, util::{bytes_to_hexstring, is_empty_or_none, GroupId, HexString, PathId, MAX_LOG_DATA_LEN}};

#[cfg(feature = "moq-transfork")]
use crate::moq_transfork::{data::*, events::*};
#[cfg(feature = "moq-transfork")]
use crate::moq_transfork::data::StreamType as MoqStreamType;

#[cfg(feature = "quic-10")]
use crate::quic_10::{data::*, events::*};
#[cfg(feature = "quic-10")]
use crate::quic_10::data::StreamType as QuicStreamType;

#[skip_serializing_none]
#[derive(Serialize)]
pub struct Event {
	time: i64,
	name: String,
	data: ProtocolEventData,
	#[serde(skip_serializing_if = "is_empty_or_none")]
	path: Option<PathId>,
	time_format: Option<TimeFormat>,
	group_id: Option<GroupId>,
	system_info: Option<SystemInformation>,
	#[serde(flatten)]
	custom_fields: HashMap<String, String>
}

impl Event {
    // Assumes default TimeFormat (relative to epoch, epoch = "1970-01-01T00:00:00.000Z")
	// TODO: Base 'time' value upon chosen TimeFormat
    #[allow(dead_code)]
	fn new(event_name: &str, event_data: ProtocolEventData, group_id: Option<String>) -> Self {
		Self {
			time: Utc::now().timestamp_millis(),
			name: event_name.to_string(),
			data: event_data,
			// TODO: Maybe add a path ID
			path: Some("".to_string()),
			time_format: None,
			group_id,
			system_info: None,
			custom_fields: HashMap::new()
		}
	}

    pub fn get_name(&self) -> &String {
		&self.name
	}

	pub fn get_group_id(&self) -> Option<&String> {
		self.group_id.as_ref()
	}

    pub fn set_group_id(&mut self, group_id: Option<&String>) {
		self.group_id = group_id.cloned();
	}
}

#[derive(Serialize)]
#[serde(untagged)]
enum ProtocolEventData {
    #[cfg(feature = "moq-transfork")]
	MoqEventData(MoqEventData),

    #[cfg(feature = "quic-10")]
	Quic10EventData(Quic10EventData)
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct RawInfo {
	/// The full byte length
	length: Option<u64>,
	/// The byte length of the payload
	payload_length: Option<u64>,
	/// The (potentially truncated) contents, including headers and possibly trailers
	data: Option<HexString>
}

impl RawInfo {
	pub fn new(length: Option<u64>, data: Option<&[u8]>) -> Self {
		match data {
			Some(payload) => {
				let payload_length: u64 = payload.len().try_into().unwrap();

				// Only log the first MAX_LOG_DATA_LEN bytes
				if payload_length > MAX_LOG_DATA_LEN.try_into().unwrap() {
					let truncated = &payload[..MAX_LOG_DATA_LEN];
					return Self { length, payload_length: Some(payload_length), data: Some(bytes_to_hexstring(truncated)) };
				}

				Self { length, payload_length: Some(payload_length), data: Some(bytes_to_hexstring(payload)) }
			},
			None => Self { length, payload_length: None, data: None }
		}
	}
}

#[derive(Serialize)]
struct SystemInformation {
	processor_id: Option<u32>,
	process_id: Option<u32>,
	thread_id: Option<u32>
}

#[cfg(feature = "moq-transfork")]
impl Event {
    fn new_moq(event_name: &str, event_data: MoqEventData, group_id: u64) -> Self {
        let group_id = group_id.to_string();
        Self::new(format!("{MOQ_VERSION_STRING}:{event_name}").as_str(), ProtocolEventData::MoqEventData(event_data), Some(group_id))
    }

	pub fn moq_stream_created(stream_type: MoqStreamType, tracing_id: u64) -> Self {
		Self::new_moq("stream_created", MoqEventData::StreamCreated(Stream::new(stream_type)), tracing_id)
	}

	pub fn moq_stream_parsed(stream_type: MoqStreamType, tracing_id: u64) -> Self {
		Self::new_moq("stream_parsed", MoqEventData::StreamParsed(Stream::new(stream_type)), tracing_id)
	}

	pub fn moq_session_started_client_created(supported_versions: Vec<u64>, extension_ids: Option<Vec<u64>>, tracing_id: u64) -> Self {
		Self::new_moq("session_started_created", MoqEventData::SessionStarted(SessionMessage::SessionClient(SessionClient::new(supported_versions, extension_ids, tracing_id))), tracing_id)
	}

	pub fn moq_session_started_client_parsed(supported_versions: Vec<u64>, extension_ids: Option<Vec<u64>>, tracing_id: u64) -> Self {
		Self::new_moq("session_started_parsed", MoqEventData::SessionStarted(SessionMessage::SessionClient(SessionClient::new(supported_versions, extension_ids, tracing_id))), tracing_id)
	}

	pub fn moq_session_started_server_created(selected_version: u64, extension_ids: Option<Vec<u64>>, tracing_id: u64) -> Self {
		Self::new_moq("session_started_created", MoqEventData::SessionStarted(SessionMessage::SessionServer(SessionServer::new(selected_version, extension_ids))), tracing_id)
	}

	pub fn moq_session_started_server_parsed(selected_version: u64, extension_ids: Option<Vec<u64>>, tracing_id: u64) -> Self {
		Self::new_moq("session_started_parsed", MoqEventData::SessionStarted(SessionMessage::SessionServer(SessionServer::new(selected_version, extension_ids))), tracing_id)
	}

	pub fn moq_session_update_created(session_bitrate: u64, tracing_id: u64) -> Self {
		Self::new_moq("session_update_created", MoqEventData::SessionUpdateCreated(SessionUpdate::new(session_bitrate)), tracing_id)
	}

	pub fn moq_session_update_parsed(session_bitrate: u64, tracing_id: u64) -> Self {
		Self::new_moq("session_update_parsed", MoqEventData::SessionUpdateParsed(SessionUpdate::new(session_bitrate)), tracing_id)
	}

	pub fn moq_announce_please_created(track_prefix_parts: Vec<String>, tracing_id: u64) -> Self {
		Self::new_moq("announce_please_created", MoqEventData::AnnouncePleaseCreated(AnnouncePlease::new(track_prefix_parts)), tracing_id)
	}

	pub fn moq_announce_please_parsed(track_prefix_parts: Vec<String>, tracing_id: u64) -> Self {
		Self::new_moq("announce_please_parsed", MoqEventData::AnnouncePleaseParsed(AnnouncePlease::new(track_prefix_parts)), tracing_id)
	}

	pub fn moq_announce_created(announce_status: AnnounceStatus, track_suffix_parts: Vec<Vec<String>>, tracing_id: u64) -> Self {
		Self::new_moq("announce_created", MoqEventData::AnnounceCreated(Announce::new(announce_status, track_suffix_parts)), tracing_id)
	}

	pub fn moq_announce_parsed(announce_status: AnnounceStatus, track_suffix_parts: Vec<Vec<String>>, tracing_id: u64) -> Self {
		Self::new_moq("announce_parsed", MoqEventData::AnnounceParsed(Announce::new(announce_status, track_suffix_parts)), tracing_id)
	}

	pub fn moq_subscription_started_created(subscribe_id: u64, track_path_parts: Vec<String>, track_priority: u64, group_order: u64, group_min: Option<u64>, group_max: Option<u64>, tracing_id: u64) -> Self {
		let group_min = group_min.unwrap_or(0);
		let group_max = group_max.unwrap_or(0);

		Self::new_moq("subscription_started_created", MoqEventData::SubscriptionStarted(Subscribe::new(subscribe_id, track_path_parts, track_priority, group_order, group_min, group_max)), tracing_id)
	}

	pub fn moq_subscription_started_parsed(subscribe_id: u64, track_path_parts: Vec<String>, track_priority: u64, group_order: u64, group_min: Option<u64>, group_max: Option<u64>, tracing_id: u64) -> Self {
		let group_min = group_min.unwrap_or(0);
		let group_max = group_max.unwrap_or(0);

		Self::new_moq("subscription_started_parsed", MoqEventData::SubscriptionStarted(Subscribe::new(subscribe_id, track_path_parts, track_priority, group_order, group_min, group_max)), tracing_id)
	}

	pub fn moq_subscription_update_created(track_priority: u64, group_order: u64, group_min: Option<u64>, group_max: Option<u64>, tracing_id: u64) -> Self {
		let group_min = group_min.unwrap_or(0);
		let group_max = group_max.unwrap_or(0);

		Self::new_moq("subscription_update_created", MoqEventData::SubscriptionUpdateCreated(SubscribeUpdate::new(track_priority, group_order, group_min, group_max)), tracing_id)
	}

	pub fn moq_subscription_update_parsed(track_priority: u64, group_order: u64, group_min: Option<u64>, group_max: Option<u64>, tracing_id: u64) -> Self {
		let group_min = group_min.unwrap_or(0);
		let group_max = group_max.unwrap_or(0);

		Self::new_moq("subscription_update_parsed", MoqEventData::SubscriptionUpdateParsed(SubscribeUpdate::new(track_priority, group_order, group_min, group_max)), tracing_id)
	}

	pub fn moq_subscription_gap_created(group_start: u64, group_count: u64, group_error_code: u64, tracing_id: u64) -> Self {
		Self::new_moq("subscription_gap_created", MoqEventData::SubscriptionGapCreated(SubscribeGap::new(group_start, group_count, group_error_code)), tracing_id)
	}

	pub fn moq_subscription_gap_parsed(group_start: u64, group_count: u64, group_error_code: u64, tracing_id: u64) -> Self {
		Self::new_moq("subscription_gap_parsed", MoqEventData::SubscriptionGapParsed(SubscribeGap::new(group_start, group_count, group_error_code)), tracing_id)
	}

	pub fn moq_info_created(track_priority: u64, group_latest: u64, group_order: u64, tracing_id: u64) -> Self {
		Self::new_moq("info_created", MoqEventData::InfoCreated(Info::new(track_priority, group_latest, group_order)), tracing_id)
	}

	pub fn moq_info_parsed(track_priority: u64, group_latest: u64, group_order: u64, tracing_id: u64) -> Self {
		Self::new_moq("info_parsed", MoqEventData::InfoParsed(Info::new(track_priority, group_latest, group_order)), tracing_id)
	}

	pub fn moq_info_please_created(track_path_parts: Vec<String>, tracing_id: u64) -> Self {
		Self::new_moq("info_please_created", MoqEventData::InfoPleaseCreated(InfoPlease::new(track_path_parts)), tracing_id)
	}

	pub fn moq_info_please_parsed(track_path_parts: Vec<String>, tracing_id: u64) -> Self {
		Self::new_moq("info_please_parsed", MoqEventData::InfoPleaseParsed(InfoPlease::new(track_path_parts)), tracing_id)
	}

	pub fn moq_fetch_created(track_path_parts: Vec<String>, track_priority: u64, group_sequence: u64, frame_sequence: u64, tracing_id: u64) -> Self {
		Self::new_moq("fetch_created", MoqEventData::FetchCreated(Fetch::new(track_path_parts, track_priority, group_sequence, frame_sequence)), tracing_id)
	}

	pub fn moq_fetch_parsed(track_path_parts: Vec<String>, track_priority: u64, group_sequence: u64, frame_sequence: u64, tracing_id: u64) -> Self {
		Self::new_moq("fetch_parsed", MoqEventData::FetchParsed(Fetch::new(track_path_parts, track_priority, group_sequence, frame_sequence)), tracing_id)
	}

	pub fn moq_fetch_update_created(track_priority: u64, tracing_id: u64) -> Self {
		Self::new_moq("fetch_update_created", MoqEventData::FetchUpdateCreated(FetchUpdate::new(track_priority)), tracing_id)
	}

	pub fn moq_fetch_update_parsed(track_priority: u64, tracing_id: u64) -> Self {
		Self::new_moq("fetch_update_parsed", MoqEventData::FetchUpdateParsed(FetchUpdate::new(track_priority)), tracing_id)
	}

	pub fn moq_group_created(subscribe_id: u64, group_sequence: u64, tracing_id: u64) -> Self {
		Self::new_moq("group_created", MoqEventData::GroupCreated(Group::new(subscribe_id, group_sequence)), tracing_id)
	}

	pub fn moq_group_parsed(subscribe_id: u64, group_sequence: u64, tracing_id: u64) -> Self {
		Self::new_moq("group_parsed", MoqEventData::GroupParsed(Group::new(subscribe_id, group_sequence)), tracing_id)
	}

	pub fn moq_frame_created(payload_length: Option<u64>, payload: Option<&[u8]>, tracing_id: u64) -> Self {
		Self::new_moq("frame_created", MoqEventData::FrameCreated(Frame::new(RawInfo::new(payload_length, payload))), tracing_id)
	}

	pub fn moq_frame_parsed(payload_length: Option<u64>, payload: Option<&[u8]>, tracing_id: u64) -> Self {
		Self::new_moq("frame_parsed", MoqEventData::FrameParsed(Frame::new(RawInfo::new(payload_length, payload))), tracing_id)
	}

	pub fn moq_get_stream_type(&self) -> Option<&MoqStreamType> {
		match &self.data {
			ProtocolEventData::MoqEventData(moq_event) => match moq_event {
				MoqEventData::StreamCreated(stream) | MoqEventData::StreamParsed(stream) => {
					Some(stream.get_stream_type())
				}
				_ => None
			},
            _ => None
		}
	}

	pub fn moq_is_session_started_client(&self) -> bool {
		match &self.data {
			ProtocolEventData::MoqEventData(moq_event) => match moq_event {
				MoqEventData::SessionStarted(session_message) => match session_message {
					SessionMessage::SessionClient(_) => {
						true
					}
					_ => false
				}
				_ => false
			},
            _ => false
		}
	}
}

#[cfg(feature = "quic-10")]
impl Event {
    fn new_quic_10(event_name: &str, event_data: Quic10EventData, group_id: Option<String>) -> Self {
        Self::new(
            format!("{QUIC_10_VERSION_STRING}:{event_name}").as_str(), 
            ProtocolEventData::Quic10EventData(event_data),
            group_id
        )
    }

    pub fn quic_10_server_listening(ip_v4: Option<IpAddress>, port_v4: Option<u16>, ip_v6: Option<IpAddress>, port_v6: Option<u16>, retry_required: Option<bool>, cid: Option<String>) -> Self {
        Self::new_quic_10(
            "server_listening",
            Quic10EventData::ServerListening(
                ServerListening::new(ip_v4, port_v4, ip_v6, port_v6, retry_required)
            ),
            cid
        )
    }

    pub fn quic_10_connection_started(local: PathEndpointInfo, remote: PathEndpointInfo, cid: Option<String>) -> Self {
        Self::new_quic_10(
            "connection_started",
            Quic10EventData::ConnectionStarted(
                ConnectionStarted::new(local, remote)
            ),
            cid
        )
    }

    pub fn quic_10_connection_closed(
        owner: Option<Owner>,
        connection_code: Option<ConnectionError>,
        application_code: Option<ApplicationError>,
        code_bytes: Option<u32>,
        internal_code: Option<u32>,
        reason: Option<String>,
        trigger: Option<ConnectionCloseTrigger>,
        cid: Option<String>
    ) -> Self {
        Self::new_quic_10(
            "connection_closed",
            Quic10EventData::ConnectionClosed(
                ConnectionClosed::new(
                    owner,
                    connection_code,
                    application_code,
                    code_bytes,
                    internal_code,
                    reason,
                    trigger
                )
            ),
            cid
        )
    }

    pub fn quic_10_connection_id_updated(owner: Owner, old: Option<ConnectionId>, new: Option<ConnectionId>, cid: Option<String>) -> Self {
        Self::new_quic_10(
            "connection_id_updated", 
            Quic10EventData::ConnectionIdUpdated(
                ConnectionIdUpdated::new(owner, old, new)
            ),
            cid
        )
    }

    pub fn quic_10_spin_bit_updated(state: bool, cid: Option<String>) -> Self {
        Self::new_quic_10(
            "spin_bit_updated",
            Quic10EventData::SpinBitUpdated(
                SpinBitUpdated::new(state)
            ),
            cid
        )
    }

    pub fn quic_10_connection_state_updated(old: Option<ConnectionState>, new: ConnectionState, cid: Option<String>) -> Self {
        Self::new_quic_10(
            "connection_state_updated",
            Quic10EventData::ConnectionStateUpdated(
                ConnectionStateUpdated::new(old, new)
            ),
            cid
        )
    }

    pub fn quic_10_path_assigned(path_id: PathId, path_remote: Option<PathEndpointInfo>, path_local: Option<PathEndpointInfo>, cid: Option<String>) -> Self {
        Self::new_quic_10(
            "path_assigned",
            Quic10EventData::PathAssigned(
                PathAssigned::new(path_id, path_remote, path_local)
            ),
            cid
        )
    }

    pub fn quic_10_mtu_updated(old: Option<u32>, new: u32, done: Option<bool>, cid: Option<String>) -> Self {
        Self::new_quic_10(
            "mtu_updated",
            Quic10EventData::MtuUpdated(
                MtuUpdated::new(old, new, done)
            ),
            cid
        )
    }

    pub fn quic_10_version_information(server_versions: Option<Vec<QuicVersion>>, client_versions: Option<Vec<QuicVersion>>, chosen_version: Option<QuicVersion>, cid: Option<String>) -> Self {
        Self::new_quic_10(
            "version_information",
            Quic10EventData::VersionInformation(
                VersionInformation::new(server_versions, client_versions, chosen_version)
            ),
            cid
        )
    }

    pub fn quic_10_alpn_information(server_alpns: Option<Vec<AlpnIdentifier>>, client_alpns: Option<Vec<AlpnIdentifier>>, chosen_alpn: Option<AlpnIdentifier>, cid: Option<String>) -> Self {
        Self::new_quic_10(
            "alpn_information",
            Quic10EventData::AlpnInformation(
                AlpnInformation::new(server_alpns, client_alpns, chosen_alpn)
            ),
            cid
        )
    }

    pub fn quic_10_parameters_set(
        owner: Option<Owner>,
        resumption_allowed: Option<bool>,
        early_data_enabled: Option<bool>,
        tls_cipher: Option<String>,
        original_destination_connection_id: Option<ConnectionId>,
        initial_source_connection_id: Option<ConnectionId>,
        retry_source_connection_id: Option<ConnectionId>,
        stateless_reset_token: Option<StatelessResetToken>,
        disable_active_migration: Option<bool>,
        max_idle_timeout: Option<u64>,
        max_udp_payload_size: Option<u32>,
        ack_delay_exponent: Option<u16>,
        max_ack_delay: Option<u16>,
        active_connection_id_limit: Option<u32>,
        initial_max_data: Option<u64>,
        initial_max_stream_data_bidi_local: Option<u64>,
        initial_max_stream_data_bidi_remote: Option<u64>,
        initial_max_stream_data_uni: Option<u64>,
        initial_max_streams_bidi: Option<u64>,
        initial_max_streams_uni: Option<u64>,
        preferred_address: Option<PreferredAddress>,
        unknown_parameters: Option<Vec<UnknownParameter>>,
        max_datagram_frame_size: Option<u64>,
        grease_quic_bit: Option<bool>,
        cid: Option<String>
    ) -> Self {
        Self::new_quic_10(
            "parameters_set",
            Quic10EventData::ParametersSet(
                ParametersSet::new(
                    owner,
                    resumption_allowed,
                    early_data_enabled,
                    tls_cipher,
                    original_destination_connection_id,
                    initial_source_connection_id,
                    retry_source_connection_id,
                    stateless_reset_token,
                    disable_active_migration,
                    max_idle_timeout,
                    max_udp_payload_size,
                    ack_delay_exponent,
                    max_ack_delay,
                    active_connection_id_limit,
                    initial_max_data,
                    initial_max_stream_data_bidi_local,
                    initial_max_stream_data_bidi_remote,
                    initial_max_stream_data_uni,
                    initial_max_streams_bidi,
                    initial_max_streams_uni,
                    preferred_address,
                    unknown_parameters,
                    max_datagram_frame_size,
                    grease_quic_bit
                )
            ),
            cid
        )
    }

    pub fn quic_10_parameters_restored(
        disable_active_migration: Option<bool>,
        max_idle_timeout: Option<u64>,
        max_udp_payload_size: Option<u32>,
        active_connection_id_limit: Option<u32>,
        initial_max_data: Option<u64>,
        initial_max_stream_data_bidi_local: Option<u64>,
        initial_max_stream_data_bidi_remote: Option<u64>,
        initial_max_stream_data_uni: Option<u64>,
        initial_max_streams_bidi: Option<u64>,
        initial_max_streams_uni: Option<u64>,
        max_datagram_frame_size: Option<u64>,
        grease_quic_bit: Option<bool>,
        cid: Option<String>
    ) -> Self {
        Self::new_quic_10(
            "parameters_restored",
            Quic10EventData::ParametersRestored(
                ParametersRestored::new(
                    disable_active_migration,
                    max_idle_timeout,
                    max_udp_payload_size,
                    active_connection_id_limit,
                    initial_max_data,
                    initial_max_stream_data_bidi_local,
                    initial_max_stream_data_bidi_remote,
                    initial_max_stream_data_uni,
                    initial_max_streams_bidi,
                    initial_max_streams_uni,
                    max_datagram_frame_size,
                    grease_quic_bit
                )
            ),
            cid
        )
    }

    pub fn quic_10_packet_sent(
        header: PacketHeader,
        frames: Option<Vec<QuicFrame>>,
        stateless_reset_token: Option<StatelessResetToken>,
        supported_versions: Option<Vec<QuicVersion>>,
        raw: Option<RawInfo>,
        datagram_id: Option<u32>,
        is_mtu_probe_packet: Option<bool>,
        trigger: Option<PacketSentTrigger>,
        cid: Option<String>
    ) -> Self {
        Self::new_quic_10(
            "packet_sent",
            Quic10EventData::PacketSent(
                PacketSent::new(header, frames, stateless_reset_token, supported_versions, raw, datagram_id, is_mtu_probe_packet, trigger)
            ),
            cid
        )
    }

    pub fn quic_10_packet_received(
        header: PacketHeader,
        frames: Option<Vec<QuicFrame>>,
        stateless_reset_token: Option<StatelessResetToken>,
        supported_versions: Option<Vec<QuicVersion>>,
        raw: Option<RawInfo>,
        datagram_id: Option<u32>,
        trigger: Option<PacketReceivedTrigger>,
        cid: Option<String>
    ) -> Self {
        Self::new_quic_10(
            "packet_received",
            Quic10EventData::PacketReceived(
                PacketReceived::new(header, frames, stateless_reset_token, supported_versions, raw, datagram_id, trigger)
            ),
            cid
        )
    }

    pub fn quic_10_packet_dropped(
        header: Option<PacketHeader>,
        raw: Option<RawInfo>,
        datagram_id: Option<u32>,
        details: HashMap<String, Vec<u8>>,
        trigger: Option<PacketDroppedTrigger>,
        cid: Option<String>
    ) -> Self {
        Self::new_quic_10(
            "packet_dropped",
            Quic10EventData::PacketDropped(
                PacketDropped::new(header, raw, datagram_id, details, trigger)
            ),
            cid
        )
    }

    pub fn quic_10_packet_buffered(header: Option<PacketHeader>, raw: Option<RawInfo>, datagram_id: Option<u32>, trigger: Option<PacketBufferedTrigger>, cid: Option<String>) -> Self {
        Self::new_quic_10(
            "packet_buffered",
            Quic10EventData::PacketBuffered(
                PacketBuffered::new(header, raw, datagram_id, trigger)
            ),
            cid
        )
    }

    pub fn quic_10_packets_acked(packet_number_space: Option<PacketNumberSpace>, packet_numbers: Option<Vec<u64>>, cid: Option<String>) -> Self {
        Self::new_quic_10(
            "packets_acked",
            Quic10EventData::PacketsAcked(
                PacketsAcked::new(packet_number_space, packet_numbers)
            ),
            cid
        )
    }

    pub fn quic_10_udp_datagrams_sent(count: Option<u16>, raw: Option<Vec<RawInfo>>, ecn: Option<Vec<Ecn>>, datagram_ids: Option<Vec<u32>>, cid: Option<String>) -> Self {
        Self::new_quic_10(
            "udp_datagrams_sent",
            Quic10EventData::UdpDatagramsSent(
                UdpDatagramsSent::new(count, raw, ecn, datagram_ids)
            ),
            cid
        )
    }

    pub fn quic_10_udp_datagrams_received(count: Option<u16>, raw: Option<Vec<RawInfo>>, ecn: Option<Vec<Ecn>>, datagram_ids: Option<Vec<u32>>, cid: Option<String>) -> Self {
        Self::new_quic_10(
            "udp_datagrams_received",
            Quic10EventData::UdpDatagramsReceived(
                UdpDatagramsReceived::new(count, raw, ecn, datagram_ids)
            ),
            cid
        )
    }

    pub fn quic_10_udp_datagram_dropped(raw: Option<RawInfo>, cid: Option<String>) -> Self {
        Self::new_quic_10(
            "udp_datagram_dropped",
            Quic10EventData::UdpDatagramDropped(
                UdpDatagramDropped::new(raw)
            ),
            cid
        )
    }

    pub fn quic_10_stream_state_updated(stream_id: u64, stream_type: Option<QuicStreamType>, old: Option<StreamState>, new: StreamState, stream_side: Option<StreamSide>, cid: Option<String>) -> Self {
        Self::new_quic_10(
            "stream_state_updated",
            Quic10EventData::StreamStateUpdated(
                StreamStateUpdated::new(stream_id, stream_type, old, new, stream_side)
            ),
            cid
        )
    }

    pub fn quic_10_frames_processed(frames: Vec<QuicFrame>, packet_numbers: Option<Vec<u64>>, cid: Option<String>) -> Self {
        Self::new_quic_10(
            "frames_processed",
            Quic10EventData::FramesProcessed(
                FramesProcessed::new(frames, packet_numbers)
            ),
            cid
        )
    }

    pub fn quic_10_stream_data_moved(
        stream_id: Option<u64>,
        offset: Option<u64>,
        length: Option<u64>,
        from: Option<DataLocation>,
        to: Option<DataLocation>,
        additional_info: Option<DataMovedAdditionalInfo>,
        raw: Option<RawInfo>,
        cid: Option<String>
    ) -> Self {
        Self::new_quic_10(
            "stream_data_moved",
            Quic10EventData::StreamDataMoved(
                StreamDataMoved::new(stream_id, offset, length, from, to, additional_info, raw)
            ),
            cid
        )
    }

    pub fn quic_10_datagram_data_moved(length: Option<u64>, from: Option<DataLocation>, to: Option<DataLocation>, raw: Option<RawInfo>, cid: Option<String>) -> Self {
        Self::new_quic_10(
            "datagram_data_moved",
            Quic10EventData::DatagramDataMoved(
                DatagramDataMoved::new(length, from, to, raw)
            ),
            cid
        )
    }

    pub fn quic_10_migration_state_updated(
        old: Option<MigrationState>,
        new: MigrationState,
        path_id: Option<PathId>,
        path_remote: Option<PathEndpointInfo>,
        path_local: Option<PathEndpointInfo>,
        cid: Option<String>
    ) -> Self {
        Self::new_quic_10(
            "migration_state_updated",
            Quic10EventData::MigrationStateUpdated(
                MigrationStateUpdated::new(old, new, path_id, path_remote, path_local)
            ),
            cid
        )
    }

    pub fn quic_10_key_updated(key_type: KeyType, old: Option<HexString>, new: Option<HexString>, key_phase: Option<u64>, trigger: Option<KeyUpdateTrigger>, cid: Option<String>) -> Self {
        Self::new_quic_10(
            "key_updated",
            Quic10EventData::KeyUpdated(
                KeyUpdated::new(key_type, old, new, key_phase, trigger)
            ),
            cid
        )
    }

    pub fn quic_10_key_discarded(key_type: KeyType, key: Option<HexString>, key_phase: Option<u64>, trigger: Option<KeyDiscardTrigger>, cid: Option<String>) -> Self {
        Self::new_quic_10(
            "key_discarded",
            Quic10EventData::KeyDiscarded(
                KeyDiscarded::new(key_type, key, key_phase, trigger)
            ),
            cid
        )
    }

    pub fn quic_10_recovery_parameters_set(
        reordering_threshold: Option<u16>,
        time_threshold: Option<f32>,
        timer_granularity: u16,
        initial_rtt: Option<f32>,
        max_datagram_size: Option<u32>,
        initial_congestion_window: Option<u64>,
        minimum_congestion_window: Option<u64>,
        loss_reduction_factor: Option<f32>,
        persistent_congestion_threshold: Option<u16>,
        cid: Option<String>
    ) -> Self {
        Self::new_quic_10(
            "recovery_parameters_set",
            Quic10EventData::RecoveryParametersSet(
                RecoveryParametersSet::new(
                    reordering_threshold,
                    time_threshold,
                    timer_granularity,
                    initial_rtt,
                    max_datagram_size,
                    initial_congestion_window,
                    minimum_congestion_window,
                    loss_reduction_factor,
                    persistent_congestion_threshold
                )
            ),
            cid
        )
    }

    pub fn quic_10_recovery_metrics_updated(
        min_rtt: Option<f32>,
        smoothed_rtt: Option<f32>,
        latest_rtt: Option<f32>,
        rtt_variance: Option<f32>,
        pto_count: Option<u16>,
        congestion_window: Option<u64>,
        bytes_in_flight: Option<u64>,
        ssthresh: Option<u64>,
        packets_in_flight: Option<u64>,
        pacing_rate: Option<u64>,
        cid: Option<String>
    ) -> Self {
        Self::new_quic_10(
            "recovery_metrics_updated",
            Quic10EventData::RecoveryMetricsUpdated(
                RecoveryMetricsUpdated::new(
                    min_rtt,
                    smoothed_rtt,
                    latest_rtt,
                    rtt_variance,
                    pto_count,
                    congestion_window,
                    bytes_in_flight,
                    ssthresh,
                    packets_in_flight,
                    pacing_rate
                )
            ),
            cid
        )
    }

    pub fn quic_10_congestion_state_updated(old: Option<String>, new: String, trigger: Option<String>, cid: Option<String>) -> Self {
        Self::new_quic_10(
            "congestion_state_updated",
            Quic10EventData::CongestionStateUpdated(
                CongestionStateUpdated::new(old, new, trigger)
            ),
            cid
        )
    }

    pub fn quic_10_loss_timer_updated(timer_type: Option<TimerType>, packet_number_space: Option<PacketNumberSpace>, event_type: EventType, delta: Option<f32>, cid: Option<String>) -> Self {
        Self::new_quic_10(
            "loss_timer_updated",
            Quic10EventData::LossTimerUpdated(
                LossTimerUpdated::new(timer_type, packet_number_space, event_type, delta)
            ),
            cid
        )
    }

    pub fn quic_10_packet_lost(header: Option<PacketHeader>, frames: Option<Vec<QuicFrame>>, is_mtu_probe_packet: Option<bool>, trigger: Option<PacketLostTrigger>, cid: Option<String>) -> Self {
        Self::new_quic_10(
            "packet_lost",
            Quic10EventData::PacketLost(
                PacketLost::new(header, frames, is_mtu_probe_packet, trigger)
            ),
            cid
        )
    }

    pub fn quic_10_marked_for_retransmit(frames: Vec<QuicFrame>, cid: Option<String>) -> Self {
        Self::new_quic_10(
            "marked_for_retransmit",
            Quic10EventData::MarkedForRetransmit(
                MarkedForRetransmit::new(frames)
            ),
            cid
        )
    }

    pub fn quic_10_ecn_state_updated(old: Option<EcnState>, new: EcnState, cid: Option<String>) -> Self {
        Self::new_quic_10(
            "ecn_state_updated",
            Quic10EventData::EcnStateUpdated(
                EcnStateUpdated::new(old, new)
            ),
            cid
        )
    }
}

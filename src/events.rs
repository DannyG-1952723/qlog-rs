use std::collections::HashMap;

use chrono::Utc;
use serde::Serialize;
use serde_with::skip_serializing_none;

use crate::{logfile::TimeFormat, moq::{data::*, events::*}, util::{bytes_to_hexstring, is_empty_or_none, GroupId, HexString, PathId, MAX_LOG_DATA_LEN, VERSION_STRING}};

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
	pub fn stream_created(stream_type: StreamType, tracing_id: u64) -> Self {
		Self::new("stream_created", MoqEventData::StreamCreated(Stream::new(stream_type)), tracing_id)
	}

	pub fn stream_parsed(stream_type: StreamType, tracing_id: u64) -> Self {
		Self::new("stream_parsed", MoqEventData::StreamParsed(Stream::new(stream_type)), tracing_id)
	}

	pub fn session_started_client_created(supported_versions: Vec<u64>, extension_ids: Option<Vec<u64>>, tracing_id: u64) -> Self {
		Self::new("session_started_created", MoqEventData::SessionStarted(SessionMessage::SessionClient(SessionClient::new(supported_versions, extension_ids, tracing_id))), tracing_id)
	}

	pub fn session_started_client_parsed(supported_versions: Vec<u64>, extension_ids: Option<Vec<u64>>, tracing_id: u64) -> Self {
		Self::new("session_started_parsed", MoqEventData::SessionStarted(SessionMessage::SessionClient(SessionClient::new(supported_versions, extension_ids, tracing_id))), tracing_id)
	}

	pub fn session_started_server_created(selected_version: u64, extension_ids: Option<Vec<u64>>, tracing_id: u64) -> Self {
		Self::new("session_started_created", MoqEventData::SessionStarted(SessionMessage::SessionServer(SessionServer::new(selected_version, extension_ids))), tracing_id)
	}

	pub fn session_started_server_parsed(selected_version: u64, extension_ids: Option<Vec<u64>>, tracing_id: u64) -> Self {
		Self::new("session_started_parsed", MoqEventData::SessionStarted(SessionMessage::SessionServer(SessionServer::new(selected_version, extension_ids))), tracing_id)
	}

	pub fn session_update_created(session_bitrate: u64, tracing_id: u64) -> Self {
		Self::new("session_update_created", MoqEventData::SessionUpdateCreated(SessionUpdate::new(session_bitrate)), tracing_id)
	}

	pub fn session_update_parsed(session_bitrate: u64, tracing_id: u64) -> Self {
		Self::new("session_update_parsed", MoqEventData::SessionUpdateParsed(SessionUpdate::new(session_bitrate)), tracing_id)
	}

	pub fn announce_please_created(track_prefix_parts: Vec<String>, tracing_id: u64) -> Self {
		Self::new("announce_please_created", MoqEventData::AnnouncePleaseCreated(AnnouncePlease::new(track_prefix_parts)), tracing_id)
	}

	pub fn announce_please_parsed(track_prefix_parts: Vec<String>, tracing_id: u64) -> Self {
		Self::new("announce_please_parsed", MoqEventData::AnnouncePleaseParsed(AnnouncePlease::new(track_prefix_parts)), tracing_id)
	}

	pub fn announce_created(announce_status: AnnounceStatus, track_suffix_parts: Vec<Vec<String>>, tracing_id: u64) -> Self {
		Self::new("announce_created", MoqEventData::AnnounceCreated(Announce::new(announce_status, track_suffix_parts)), tracing_id)
	}

	pub fn announce_parsed(announce_status: AnnounceStatus, track_suffix_parts: Vec<Vec<String>>, tracing_id: u64) -> Self {
		Self::new("announce_parsed", MoqEventData::AnnounceParsed(Announce::new(announce_status, track_suffix_parts)), tracing_id)
	}

	pub fn subscription_started_created(subscribe_id: u64, track_path_parts: Vec<String>, track_priority: u64, group_order: u64, group_min: Option<u64>, group_max: Option<u64>, tracing_id: u64) -> Self {
		let group_min = group_min.unwrap_or(0);
		let group_max = group_max.unwrap_or(0);

		Self::new("subscription_started_created", MoqEventData::SubscriptionStarted(Subscribe::new(subscribe_id, track_path_parts, track_priority, group_order, group_min, group_max)), tracing_id)
	}

	pub fn subscription_started_parsed(subscribe_id: u64, track_path_parts: Vec<String>, track_priority: u64, group_order: u64, group_min: Option<u64>, group_max: Option<u64>, tracing_id: u64) -> Self {
		let group_min = group_min.unwrap_or(0);
		let group_max = group_max.unwrap_or(0);

		Self::new("subscription_started_parsed", MoqEventData::SubscriptionStarted(Subscribe::new(subscribe_id, track_path_parts, track_priority, group_order, group_min, group_max)), tracing_id)
	}

	pub fn subscription_update_created(track_priority: u64, group_order: u64, group_min: Option<u64>, group_max: Option<u64>, tracing_id: u64) -> Self {
		let group_min = group_min.unwrap_or(0);
		let group_max = group_max.unwrap_or(0);

		Self::new("subscription_update_created", MoqEventData::SubscriptionUpdateCreated(SubscribeUpdate::new(track_priority, group_order, group_min, group_max)), tracing_id)
	}

	pub fn subscription_update_parsed(track_priority: u64, group_order: u64, group_min: Option<u64>, group_max: Option<u64>, tracing_id: u64) -> Self {
		let group_min = group_min.unwrap_or(0);
		let group_max = group_max.unwrap_or(0);

		Self::new("subscription_update_parsed", MoqEventData::SubscriptionUpdateParsed(SubscribeUpdate::new(track_priority, group_order, group_min, group_max)), tracing_id)
	}

	pub fn subscription_gap_created(group_start: u64, group_count: u64, group_error_code: u64, tracing_id: u64) -> Self {
		Self::new("subscription_gap_created", MoqEventData::SubscriptionGapCreated(SubscribeGap::new(group_start, group_count, group_error_code)), tracing_id)
	}

	pub fn subscription_gap_parsed(group_start: u64, group_count: u64, group_error_code: u64, tracing_id: u64) -> Self {
		Self::new("subscription_gap_parsed", MoqEventData::SubscriptionGapParsed(SubscribeGap::new(group_start, group_count, group_error_code)), tracing_id)
	}

	pub fn info_created(track_priority: u64, group_latest: u64, group_order: u64, tracing_id: u64) -> Self {
		Self::new("info_created", MoqEventData::InfoCreated(Info::new(track_priority, group_latest, group_order)), tracing_id)
	}

	pub fn info_parsed(track_priority: u64, group_latest: u64, group_order: u64, tracing_id: u64) -> Self {
		Self::new("info_parsed", MoqEventData::InfoParsed(Info::new(track_priority, group_latest, group_order)), tracing_id)
	}

	pub fn info_please_created(track_path_parts: Vec<String>, tracing_id: u64) -> Self {
		Self::new("info_please_created", MoqEventData::InfoPleaseCreated(InfoPlease::new(track_path_parts)), tracing_id)
	}

	pub fn info_please_parsed(track_path_parts: Vec<String>, tracing_id: u64) -> Self {
		Self::new("info_please_parsed", MoqEventData::InfoPleaseParsed(InfoPlease::new(track_path_parts)), tracing_id)
	}

	pub fn fetch_created(track_path_parts: Vec<String>, track_priority: u64, group_sequence: u64, frame_sequence: u64, tracing_id: u64) -> Self {
		Self::new("fetch_created", MoqEventData::FetchCreated(Fetch::new(track_path_parts, track_priority, group_sequence, frame_sequence)), tracing_id)
	}

	pub fn fetch_parsed(track_path_parts: Vec<String>, track_priority: u64, group_sequence: u64, frame_sequence: u64, tracing_id: u64) -> Self {
		Self::new("fetch_parsed", MoqEventData::FetchParsed(Fetch::new(track_path_parts, track_priority, group_sequence, frame_sequence)), tracing_id)
	}

	pub fn fetch_update_created(track_priority: u64, tracing_id: u64) -> Self {
		Self::new("fetch_update_created", MoqEventData::FetchUpdateCreated(FetchUpdate::new(track_priority)), tracing_id)
	}

	pub fn fetch_update_parsed(track_priority: u64, tracing_id: u64) -> Self {
		Self::new("fetch_update_parsed", MoqEventData::FetchUpdateParsed(FetchUpdate::new(track_priority)), tracing_id)
	}

	pub fn group_created(subscribe_id: u64, group_sequence: u64, tracing_id: u64) -> Self {
		Self::new("group_created", MoqEventData::GroupCreated(Group::new(subscribe_id, group_sequence)), tracing_id)
	}

	pub fn group_parsed(subscribe_id: u64, group_sequence: u64, tracing_id: u64) -> Self {
		Self::new("group_parsed", MoqEventData::GroupParsed(Group::new(subscribe_id, group_sequence)), tracing_id)
	}

	pub fn frame_created(payload_length: Option<u64>, payload: Option<&[u8]>, tracing_id: u64) -> Self {
		Self::new("frame_created", MoqEventData::FrameCreated(Frame::new(RawInfo::new(payload_length, payload))), tracing_id)
	}

	pub fn frame_parsed(payload_length: Option<u64>, payload: Option<&[u8]>, tracing_id: u64) -> Self {
		Self::new("frame_parsed", MoqEventData::FrameParsed(Frame::new(RawInfo::new(payload_length, payload))), tracing_id)
	}

	// Assumes default TimeFormat (relative to epoch, epoch = "1970-01-01T00:00:00.000Z")
	// TODO: Base 'time' value upon chosen TimeFormat
	fn new(event_name: &str, event_data: MoqEventData, group_id: u64) -> Self {
		Self {
			time: Utc::now().timestamp_millis(),
			name: format!("{VERSION_STRING}:{event_name}"),
			data: ProtocolEventData::MoqEventData(event_data),
			// TODO: Maybe add a path ID
			path: Some("".to_string()),
			time_format: None,
			group_id: Some(group_id.to_string()),
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

	pub fn get_stream_type(&self) -> Option<&StreamType> {
		match &self.data {
			ProtocolEventData::MoqEventData(moq_event) => match moq_event {
				MoqEventData::StreamCreated(stream) | MoqEventData::StreamParsed(stream) => {
					Some(stream.get_stream_type())
				}
				_ => None
			}
		}
	}

	pub fn is_session_started_client(&self) -> bool {
		match &self.data {
			ProtocolEventData::MoqEventData(moq_event) => match moq_event {
				MoqEventData::SessionStarted(session_message) => match session_message {
					SessionMessage::SessionClient(_) => {
						true
					}
					_ => false
				}
				_ => false
			}
		}
	}

	pub fn set_group_id(&mut self, group_id: Option<&String>) {
		self.group_id = group_id.cloned();
	}
}

#[derive(Serialize)]
#[serde(untagged)]
enum ProtocolEventData {
	MoqEventData(MoqEventData)
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

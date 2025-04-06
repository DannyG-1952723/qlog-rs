use serde::Serialize;

use crate::events::RawInfo;

use super::data::{AnnounceStatus, StreamType};

#[derive(Serialize)]
pub struct Stream {
	stream_type: StreamType
}

impl Stream {
	pub fn new(stream_type: StreamType) -> Self {
		Self { stream_type }
	}

    pub fn get_stream_type(&self) -> &StreamType {
        &self.stream_type
    }
}

#[derive(Serialize)]
pub struct SessionClient {
	supported_versions: Vec<u64>,
	extension_ids: Vec<u64>,
	tracing_id: u64
}

impl SessionClient {
	pub fn new(supported_versions: Vec<u64>, extension_ids: Option<Vec<u64>>, tracing_id: u64) -> Self {
		let extension_ids = extension_ids.unwrap_or_default();

		Self { supported_versions, extension_ids, tracing_id }
	}
}

#[derive(Serialize)]
pub struct SessionServer {
	selected_version: u64,
	extension_ids: Vec<u64>
}

impl SessionServer {
	pub fn new(selected_version: u64, extension_ids: Option<Vec<u64>>) -> Self {
		let extension_ids = extension_ids.unwrap_or_default();

		Self { selected_version, extension_ids }
	}
}

#[derive(Serialize)]
pub struct SessionUpdate {
	session_bitrate: u64
}

impl SessionUpdate {
	pub fn new(session_bitrate: u64) -> Self {
		Self { session_bitrate }
	}
}

#[derive(Serialize)]
pub struct AnnouncePlease {
	track_prefix_parts: Vec<String>
}

impl AnnouncePlease {
	pub fn new(track_prefix_parts: Vec<String>) -> Self {
		Self { track_prefix_parts }
	}
}

#[derive(Serialize)]
pub struct Announce {
	announce_status: AnnounceStatus,
	track_suffix_parts: Vec<Vec<String>>
}

impl Announce {
	pub fn new(announce_status: AnnounceStatus, track_suffix_parts: Vec<Vec<String>>) -> Self {
		Self { announce_status, track_suffix_parts }
	}
}

#[derive(Serialize)]
pub struct Subscribe {
	subscribe_id: u64,
	track_path_parts: Vec<String>,
	track_priority: u64,
	group_order: u64,
	group_min: u64,
	group_max: u64
}

impl Subscribe {
	pub fn new(subscribe_id: u64, track_path_parts: Vec<String>, track_priority: u64, group_order: u64, group_min: u64, group_max: u64) -> Self {
		Self { subscribe_id, track_path_parts, track_priority, group_order, group_min, group_max }
	}
}

#[derive(Serialize)]
pub struct SubscribeUpdate {
	track_priority: u64,
	group_order: u64,
	group_min: u64,
	group_max: u64
}

impl SubscribeUpdate {
	pub fn new(track_priority: u64, group_order: u64, group_min: u64, group_max: u64) -> Self {
		Self { track_priority, group_order, group_min, group_max }
	}
}

#[derive(Serialize)]
pub struct SubscribeGap {
	group_start: u64,
	group_count: u64,
	group_error_code: u64
}

impl SubscribeGap {
	pub fn new(group_start: u64, group_count: u64, group_error_code: u64) -> Self {
		Self { group_start, group_count, group_error_code }
	}
}

#[derive(Serialize)]
pub struct Info {
	track_priority: u64,
	group_latest: u64,
	group_order: u64
}

impl Info {
	pub fn new(track_priority: u64, group_latest: u64, group_order: u64) -> Self {
		Self { track_priority, group_latest, group_order }
	}
}

#[derive(Serialize)]
pub struct InfoPlease {
	track_path_parts: Vec<String>
}

impl InfoPlease {
	pub fn new(track_path_parts: Vec<String>) -> Self {
		Self { track_path_parts }
	}
}

#[derive(Serialize)]
pub struct Fetch {
	track_path_parts: Vec<String>,
	track_priority: u64,
	group_sequence: u64,
	frame_sequence: u64
}

impl Fetch {
	pub fn new(track_path_parts: Vec<String>, track_priority: u64, group_sequence: u64, frame_sequence: u64) -> Self {
		Self { track_path_parts, track_priority, group_sequence, frame_sequence }
	}
}

#[derive(Serialize)]
pub struct FetchUpdate {
	track_priority: u64
}

impl FetchUpdate {
	pub fn new(track_priority: u64) -> Self {
		Self { track_priority }
	}
}

#[derive(Serialize)]
pub struct Group {
	subscribe_id: u64,
	group_sequence: u64
}

impl Group {
	pub fn new(subscribe_id: u64, group_sequence: u64) -> Self {
		Self { subscribe_id, group_sequence }
	}
}

#[derive(Serialize)]
pub struct Frame {
	payload: RawInfo
}

impl Frame {
	pub fn new(payload: RawInfo) -> Self {
		Self { payload }
	}
}

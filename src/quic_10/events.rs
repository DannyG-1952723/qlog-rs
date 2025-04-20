use std::collections::HashMap;

use serde::Serialize;
use serde_with::skip_serializing_none;

use crate::{events::RawInfo, util::{HexString, PathId}};

use super::data::*;

// Values are optional because some QUIC stacks do not handle sockets directly and are thus unable to log IP and/or port information
/// Emitted when the server starts accepting connections.
#[skip_serializing_none]
#[derive(Serialize)]
pub struct ServerListening {
    ip_v4: Option<IpAddress>,
    port_v4: Option<u16>,
    ip_v6: Option<IpAddress>,
    port_v6: Option<u16>,
    /// The server will always answer client initials with a retry (no 1-RTT connection setups by choice)
    retry_required: Option<bool>
}

impl ServerListening {
    pub fn new(ip_v4: Option<IpAddress>, port_v4: Option<u16>, ip_v6: Option<IpAddress>, port_v6: Option<u16>, retry_required: Option<bool>) -> Self {
        Self { ip_v4, port_v4, ip_v6, port_v6, retry_required }
    }
}

/// Used for both attempting (client-perspective) and accepting (server-perspective) new connections.
#[derive(Serialize)]
pub struct ConnectionStarted {
    local: PathEndpointInfo,
    remote: PathEndpointInfo
}

impl ConnectionStarted {
    pub fn new(local: PathEndpointInfo, remote: PathEndpointInfo) -> Self {
        Self { local, remote }
    }
}

/// Intended to be logged either when the local endpoint silently discards the connection due to an idle timeout, 
/// when a CONNECTION_CLOSE frame is sent (the connection enters the 'closing' state on the sender side), 
/// when a CONNECTION_CLOSE frame is received (the connection enters the 'draining' state on the receiver side) 
/// or when a Stateless Reset packet is received (the connection is discarded at the receiver side). 
/// Connectivity-related updates after this point (e.g., exiting a 'closing' or 'draining' state), should be logged using the ConnectionStateUpdated event instead.
#[skip_serializing_none]
#[derive(Serialize)]
pub struct ConnectionClosed {
    /// Which side closed the connection
    owner: Option<Owner>,
    connection_code: Option<ConnectionError>,
    application_code: Option<ApplicationError>,

    code_bytes: Option<u32>,

    /// To reflect more fine-grained internal error codes
    internal_code: Option<u32>,
    reason: Option<String>,
    trigger: Option<ConnectionCloseTrigger>
}

impl ConnectionClosed {
    pub fn new(
        owner: Option<Owner>,
        connection_code: Option<ConnectionError>,
        application_code: Option<ApplicationError>,
        code_bytes: Option<u32>,
        internal_code: Option<u32>,
        reason: Option<String>,
        trigger: Option<ConnectionCloseTrigger>
    ) -> Self {
        if connection_code == Some(ConnectionError::TransportError(TransportError::Unknown)) && application_code == Some(ApplicationError::Unknown) && code_bytes.is_none() {
            panic!("When the connection_code or application_code is 'unknown', provide a value for code_bytes");
        }

        Self { owner, connection_code, application_code, code_bytes, internal_code, reason, trigger }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct ConnectionIdUpdated {
    /// When the endpoint receives a new connection ID from the peer, this will be Remote.
    /// When the endpoint updates its own connection ID, this will be Local.
    owner: Owner,
    old: Option<ConnectionId>,
    new: Option<ConnectionId>
}

impl ConnectionIdUpdated {
    pub fn new(owner: Owner, old: Option<ConnectionId>, new: Option<ConnectionId>) -> Self {
        Self { owner, old, new }
    }
}

/// Emitted when the spin bit changes value, should not be emitted if the spin bit is set without changing its value.
#[derive(Serialize)]
pub struct SpinBitUpdated {
    state: bool
}

impl SpinBitUpdated {
    pub fn new(state: bool) -> Self {
        Self { state }
    }
}

/// QUIC implementations should mainly log the simplified BaseConnectionStates, adding the more fine-grained GranularConnectionStates when more in-depth debugging is required. Tools should be able to deal with both types equally.
#[skip_serializing_none]
#[derive(Serialize)]
pub struct ConnectionStateUpdated {
    old: Option<ConnectionState>,
    new: ConnectionState
}

impl ConnectionStateUpdated {
    pub fn new(old: Option<ConnectionState>, new: ConnectionState) -> Self {
        Self { old, new }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct PathAssigned {
    path_id: PathId,

    /// Information for traffic going towards the remote receiver.
    path_remote: Option<PathEndpointInfo>,

    /// Information for traffic coming in at the local endpoint.
    path_local: Option<PathEndpointInfo>
}

impl PathAssigned {
    pub fn new(path_id: PathId, path_remote: Option<PathEndpointInfo>, path_local: Option<PathEndpointInfo>) -> Self {
        Self { path_id, path_remote, path_local }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct MtuUpdated {
    old: Option<u32>,
    new: u32,

    /// At some point, MTU discovery stops, as a "good enough" packet size has been found
    done: bool
}

impl MtuUpdated {
    pub fn new(old: Option<u32>, new: u32, done: Option<bool>) -> Self {
        let done = done.unwrap_or_else(|| false);

        Self { old, new, done }
    }
}

/// Intended use:
///   - When sending an initial, the client logs this event with client_versions and chosen_version set
///   - Upon receiving a client initial with a supported version, the server logs this event with server_versions and chosen_version setUpon receiving a client initial with an unsupported version, the server logs this event with server_versions set and client_versions to the single-element array containing the client's attempted version. The absence of chosen_version implies no overlap was found
///   - Upon receiving a version negotiation packet from the server, the client logs this event with client_versions set and server_versions to the versions in the version negotiation packet and chosen_version to the version it will use for the next initial packet. If the client receives a set of server_versions with no viable overlap with its own supported versions, this event should be logged without the chosen_version set
#[skip_serializing_none]
#[derive(Serialize)]
pub struct VersionInformation {
    server_versions: Option<Vec<QuicVersion>>,
    client_versions: Option<Vec<QuicVersion>>,
    chosen_version: Option<QuicVersion>
}

impl VersionInformation {
    pub fn new(server_versions: Option<Vec<QuicVersion>>, client_versions: Option<Vec<QuicVersion>>, chosen_version: Option<QuicVersion>) -> Self {
        Self { server_versions, client_versions, chosen_version }
    }
}

/// Intended use:
///   - When sending an initial, the client logs this event with client_alpns set
///   - When receiving an initial with a supported alpn, the server logs this event with server_alpns set, client_alpns equalling the client-provided list, and chosen_alpn to the value it will send back to the client.
///   - When receiving an initial with an alpn, the client logs this event with chosen_alpn to the received value.
///   - Alternatively, a client can choose to not log the first event, but wait for the receipt of the server initial to log this event with both client_alpns and chosen_alpn set.
#[skip_serializing_none]
#[derive(Serialize)]
pub struct AlpnInformation {
    server_alpns: Option<Vec<AlpnIdentifier>>,
    client_alpns: Option<Vec<AlpnIdentifier>>,
    chosen_alpn: Option<AlpnIdentifier>
}

impl AlpnInformation {
    pub fn new(server_alpns: Option<Vec<AlpnIdentifier>>, client_alpns: Option<Vec<AlpnIdentifier>>, chosen_alpn: Option<AlpnIdentifier>) -> Self {
        Self { server_alpns, client_alpns, chosen_alpn }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct ParametersSet {
    owner: Option<Owner>,

    /// True if valid session ticket was received
    resumption_allowed: Option<bool>,

    /// True if early data extension was enabled on the TLS layer
    early_data_enabled: Option<bool>,

    /// e.g., "AES_128_GCM_SHA256"
    tls_cipher: Option<String>,
    
    // RFC9000
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

    // RFC9221
    max_datagram_frame_size: Option<u64>,

    // RFC9287
    /// True if present, absent or false if extension not negotiated
    grease_quic_bit: Option<bool>
}

impl ParametersSet {
    pub fn new(
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
        grease_quic_bit: Option<bool>
    ) -> Self {
        Self {
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
        }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct ParametersRestored {
    // RFC9000
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

    // RFC9221
    max_datagram_frame_size: Option<u64>,

    // RFC9287
    /// Can only be restored at the client. Servers must not restore this parameter!
    grease_quic_bit: Option<bool>
}

impl ParametersRestored {
    pub fn new(
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
        grease_quic_bit: Option<bool>
    ) -> Self {
        Self {
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
        }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct PacketSent {
    header: PacketHeader,
    frames: Option<Vec<QuicFrame>>,

    /// Only if header.packet_type == StatelessReset.
    /// Always 128 bits in length..
    stateless_reset_token: Option<StatelessResetToken>,

    /// Only if header.packet_type = VersionNegotiation.
    supported_versions: Option<Vec<QuicVersion>>,
    raw: Option<RawInfo>,
    datagram_id: Option<u32>,
    is_mtu_probe_packet: bool,

    trigger: Option<PacketSentTrigger>
}

impl PacketSent {
    pub fn new(
        header: PacketHeader,
        frames: Option<Vec<QuicFrame>>,
        stateless_reset_token: Option<StatelessResetToken>,
        supported_versions: Option<Vec<QuicVersion>>,
        raw: Option<RawInfo>,
        datagram_id: Option<u32>,
        is_mtu_probe_packet: Option<bool>,
        trigger: Option<PacketSentTrigger>
    ) -> Self {
        let is_mtu_probe_packet = is_mtu_probe_packet.unwrap_or_else(|| false);

        Self { header, frames, stateless_reset_token, supported_versions, raw, datagram_id, is_mtu_probe_packet, trigger }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct PacketReceived {
    header: PacketHeader,
    frames: Option<Vec<QuicFrame>>,

    /// Only if header.packet_type == StatelessReset.
    /// Always 128 bits in length.
    stateless_reset_token: Option<StatelessResetToken>,

    /// Only if header.packet_type = VersionNegotiation.
    supported_versions: Option<Vec<QuicVersion>>,
    raw: Option<RawInfo>,
    datagram_id: Option<u32>,

    trigger: Option<PacketReceivedTrigger>
}

impl PacketReceived {
    pub fn new(
        header: PacketHeader,
        frames: Option<Vec<QuicFrame>>,
        stateless_reset_token: Option<StatelessResetToken>,
        supported_versions: Option<Vec<QuicVersion>>,
        raw: Option<RawInfo>,
        datagram_id: Option<u32>,
        trigger: Option<PacketReceivedTrigger>
    ) -> Self {
        Self { header, frames, stateless_reset_token, supported_versions, raw, datagram_id, trigger }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct PacketDropped {
    // Primarily packet_type should be filled here, as other fields might not be decrypteable or parseable
    header: Option<PacketHeader>,
    raw: Option<RawInfo>,
    datagram_id: Option<u32>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    details: HashMap<String, Vec<u8>>,
    trigger: Option<PacketDroppedTrigger>
}

impl PacketDropped {
    pub fn new(
        header: Option<PacketHeader>,
        raw: Option<RawInfo>,
        datagram_id: Option<u32>,
        details: HashMap<String, Vec<u8>>,
        trigger: Option<PacketDroppedTrigger>
    ) -> Self {
        Self { header, raw, datagram_id, details, trigger }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct PacketBuffered {
    // Primarily packet_type and possible packet_number should be filled here as other elements might not be available yet
    header: Option<PacketHeader>,
    raw: Option<RawInfo>,
    datagram_id: Option<u32>,
    trigger: Option<PacketBufferedTrigger>
}

impl PacketBuffered {
    pub fn new(header: Option<PacketHeader>, raw: Option<RawInfo>, datagram_id: Option<u32>, trigger: Option<PacketBufferedTrigger>) -> Self {
        Self { header, raw, datagram_id, trigger }
    }
}

/// Emitted when a (group of) sent packet(s) is acknowledged by the remote peer for the first time.
#[skip_serializing_none]
#[derive(Serialize)]
pub struct PacketsAcked {
    packet_number_space: Option<PacketNumberSpace>,
    packet_numbers: Option<Vec<u64>>
}

impl PacketsAcked {
    pub fn new(packet_number_space: Option<PacketNumberSpace>, packet_numbers: Option<Vec<u64>>) -> Self {
        Self { packet_number_space, packet_numbers }
    }
}

/// Emitted when one or more UDP-level datagrams are passed to the underlying network socket.
/// This is useful for determining how QUIC packet buffers are drained to the OS.
#[skip_serializing_none]
#[derive(Serialize)]
pub struct UdpDatagramsSent {
    // To support passing multiple at once
    count: Option<u16>,

    /// The RawInfo fields do not include the UDP headers, only the UDP payload
    raw: Option<Vec<RawInfo>>,

    // TODO: If not set, defaults to the value used on the last DatagramsSent event
    /// ECN bits in the IP header
    ecn: Option<Vec<Ecn>>,

    datagram_ids: Option<Vec<u32>>
}

impl UdpDatagramsSent {
    pub fn new(count: Option<u16>, raw: Option<Vec<RawInfo>>, ecn: Option<Vec<Ecn>>, datagram_ids: Option<Vec<u32>>) -> Self {
        Self { count, raw, ecn, datagram_ids }
    }
}

/// Emitted when one or more UDP-level datagrams are received from the socket.
/// This is useful for determining how datagrams are passed to the user space stack from the OS.
#[skip_serializing_none]
#[derive(Serialize)]
pub struct UdpDatagramsReceived {
    // To support passing multiple at once
    count: Option<u16>,

    /// The RawInfo fields do not include the UDP headers, only the UDP payload
    raw: Option<Vec<RawInfo>>,

    // TODO: If not set, defaults to the value used on the last DatagramsReceived event
    /// ECN bits in the IP header
    ecn: Option<Vec<Ecn>>,

    datagram_ids: Option<Vec<u32>>
}

impl UdpDatagramsReceived {
    pub fn new(count: Option<u16>, raw: Option<Vec<RawInfo>>, ecn: Option<Vec<Ecn>>, datagram_ids: Option<Vec<u32>>) -> Self {
        Self { count, raw, ecn, datagram_ids }
    }
}

/// Emitted when a UDP-level datagram is dropped.
/// This is typically done if it does not contain a valid QUIC packet.
/// If it does, but the QUIC packet is dropped for other reasons, the PacketDropped event should be used instead.
#[skip_serializing_none]
#[derive(Serialize)]
pub struct UdpDatagramDropped {
    /// The RawInfo fields do not include the UDP headers, only the UDP payload
    raw: Option<RawInfo>,
}

impl UdpDatagramDropped {
    pub fn new(raw: Option<RawInfo>) -> Self {
        Self { raw }
    }
}

/// Emitted whenever the internal state of a QUIC stream is updated.
/// QUIC implementations should mainly log the simplified (HTTP/2-alike) BaseStreamStates instead of the more fine-grained GranularStreamStates.
/// These latter ones are mainly for more in-depth debugging.
#[skip_serializing_none]
#[derive(Serialize)]
pub struct StreamStateUpdated {
    stream_id: u64,

    // Mainly useful when opening the stream
    stream_type: Option<StreamType>,
    old: Option<StreamState>,
    new: StreamState,
    stream_side: Option<StreamSide>,
}

impl StreamStateUpdated {
    pub fn new(stream_id: u64, stream_type: Option<StreamType>, old: Option<StreamState>, new: StreamState, stream_side: Option<StreamSide>) -> Self {
        Self { stream_id, stream_type, old, new, stream_side }
    }
}

/// Intended to prevent a large proliferation of specific purpose events.
#[skip_serializing_none]
#[derive(Serialize)]
pub struct FramesProcessed {
    frames: Vec<QuicFrame>,
    packet_numbers: Option<Vec<u64>>
}

impl FramesProcessed {
    pub fn new(frames: Vec<QuicFrame>, packet_numbers: Option<Vec<u64>>) -> Self {
        Self { frames, packet_numbers }
    }
}

/// Indicates when QUIC stream data moves between the different layers.
/// This helps make clear the flow of data, how long data remains in various buffers, and the overheads introduced by individual layers.
/// This event is only for data in QUIC streams. For data in QUIC Datagram Frames, see the DatagramDataMoved event.
#[skip_serializing_none]
#[derive(Serialize)]
pub struct StreamDataMoved {
    stream_id: Option<u64>,
    offset: Option<u64>,

    /// Byte length of the moved data
    length: Option<u64>,

    from: Option<DataLocation>,
    to: Option<DataLocation>,

    additional_info: Option<DataMovedAdditionalInfo>,

    raw: Option<RawInfo>
}

impl StreamDataMoved {
    pub fn new(
        stream_id: Option<u64>,
        offset: Option<u64>,
        length: Option<u64>,
        from: Option<DataLocation>,
        to: Option<DataLocation>,
        additional_info: Option<DataMovedAdditionalInfo>,
        raw: Option<RawInfo>
    ) -> Self {
        Self { stream_id, offset, length, from, to, additional_info, raw }
    }
}

/// Indicates when QUIC Datagram Frame data moves between the different layers.
/// This helps make clear the flow of data, how long data remains in various buffers, and the overheads introduced by individual layers.
/// This event is only for data in QUIC Datagram Frames. For data in QUIC streams, see the StreamDataMoved event
#[skip_serializing_none]
#[derive(Serialize)]
pub struct DatagramDataMoved {
    /// Byte length of the moved data
    length: Option<u64>,
    from: Option<DataLocation>,
    to: Option<DataLocation>,
    raw: Option<RawInfo>
}

impl DatagramDataMoved {
    pub fn new(length: Option<u64>, from: Option<DataLocation>, to: Option<DataLocation>, raw: Option<RawInfo>) -> Self {
        Self { length, from, to, raw }
    }
}

/// Provides additional information when attempting (client-side) connection migration.
/// Generally speaking, connection migration goes through two phases: a probing phase (which is not always needed/present), and a migration phase (which can be abandoned upon error).
#[skip_serializing_none]
#[derive(Serialize)]
pub struct MigrationStateUpdated {
    old: Option<MigrationState>,
    new: MigrationState,

    path_id: Option<PathId>,

    /// The information for traffic going towards the remote receiver
    path_remote: Option<PathEndpointInfo>,

    /// The information for traffic coming in at the local endpoint
    path_local: Option<PathEndpointInfo>
}

impl MigrationStateUpdated {
    pub fn new(
        old: Option<MigrationState>,
        new: MigrationState,
        path_id: Option<PathId>,
        path_remote: Option<PathEndpointInfo>,
        path_local: Option<PathEndpointInfo>
    ) -> Self {
        Self { old, new, path_id, path_remote, path_local }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct KeyUpdated {
    key_type: KeyType,
    old: Option<HexString>,
    new: Option<HexString>,

    // Needed for 1-RTT key updates
    key_phase: Option<u64>,
    trigger: Option<KeyUpdateTrigger>
}

impl KeyUpdated {
    pub fn new(key_type: KeyType, old: Option<HexString>, new: Option<HexString>, key_phase: Option<u64>, trigger: Option<KeyUpdateTrigger>) -> Self {
        Self { key_type, old, new, key_phase, trigger }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct KeyDiscarded {
    key_type: KeyType,
    key: Option<HexString>,

    // Needed for 1-RTT key updates
    key_phase: Option<u64>,
    trigger: Option<KeyDiscardTrigger>
}

impl KeyDiscarded {
    pub fn new(key_type: KeyType, key: Option<HexString>, key_phase: Option<u64>, trigger: Option<KeyDiscardTrigger>) -> Self {
        Self { key_type, key, key_phase, trigger }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct RecoveryParametersSet {
    // Loss detection, see RFC 9002 Appendix A.2
    /// In amount of packets
    reordering_threshold: Option<u16>,

    /// As RTT multiplier
    time_threshold: Option<f32>,

    /// In ms
    timer_granularity: u16,

    /// In ms
    initial_rtt: Option<f32>,

    // Congestion control, see RFC 9002 Appendix B.2
    /// In bytes. Note that this could be updated after pmtud
    max_datagram_size: Option<u32>,

    /// In bytes
    initial_congestion_window: Option<u64>,

    // Note that this could change when max_datagram_size changes
    /// In bytes
    minimum_congestion_window: Option<u64>,
    loss_reduction_factor: Option<f32>,

    /// As PTO multiplier
    persistent_congestion_threshold: Option<u16>
}

impl RecoveryParametersSet {
    pub fn new(
        reordering_threshold: Option<u16>,
        time_threshold: Option<f32>,
        timer_granularity: u16,
        initial_rtt: Option<f32>,
        max_datagram_size: Option<u32>,
        initial_congestion_window: Option<u64>,
        minimum_congestion_window: Option<u64>,
        loss_reduction_factor: Option<f32>,
        persistent_congestion_threshold: Option<u16>
    ) -> Self {
        Self {
            reordering_threshold,
            time_threshold,
            timer_granularity,
            initial_rtt,
            max_datagram_size,
            initial_congestion_window,
            minimum_congestion_window,
            loss_reduction_factor,
            persistent_congestion_threshold
        }
    }
}

/// Emitted when one or more of the observable recovery metrics changes value.
/// This event should group all possible metric updates that happen at or around the same time in a single event.
/// In order to make logging easier, implementations may log values even if they are the same as previously reported values.
/// However, applications should try to log only actual updates to values.
#[skip_serializing_none]
#[derive(Serialize)]
pub struct RecoveryMetricsUpdated {
    // Loss detection, see RFC 9002 Appendix A.3
    // All following RTT fields are expressed in ms
    min_rtt: Option<f32>,
    smoothed_rtt: Option<f32>,
    latest_rtt: Option<f32>,
    rtt_variance: Option<f32>,
    pto_count: Option<u16>,

    // Congestion control, see RFC 9002 Appendix B.2
    /// In bytes
    congestion_window: Option<u64>,
    bytes_in_flight: Option<u64>,

    /// In bytes
    ssthresh: Option<u64>,

    // qlog defined
    /// Sum of all packet number spaces
    packets_in_flight: Option<u64>,

    // In bits per second
    pacing_rate: Option<u64>
}

impl RecoveryMetricsUpdated {
    pub fn new(
        min_rtt: Option<f32>,
        smoothed_rtt: Option<f32>,
        latest_rtt: Option<f32>,
        rtt_variance: Option<f32>,
        pto_count: Option<u16>,
        congestion_window: Option<u64>,
        bytes_in_flight: Option<u64>,
        ssthresh: Option<u64>,
        packets_in_flight: Option<u64>,
        pacing_rate: Option<u64>
    ) -> Self {
        Self {
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
        }
    }
}

/// Indicates when the congestion controller enters a significant new state and changes its behaviour.
/// The values of the event's fields are intentionally unspecified here in order to support different Congestion Control algorithms, as these typically have different states and even different implementations of these states across stacks.
#[skip_serializing_none]
#[derive(Serialize)]
pub struct CongestionStateUpdated {
    old: Option<String>,
    new: String,
    trigger: Option<String>
}

impl CongestionStateUpdated {
    pub fn new(old: Option<String>, new: String, trigger: Option<String>) -> Self {
        Self { old, new, trigger }
    }
}

/// Emitted when a recovery loss timer changes state.
/// The three main event types are:
///   - Set: the timer is set with a delta timeout for when it will trigger next.
///   - Expired: when the timer effectively expires after the delta timeout.
///   - Cancelled: when a timer is cancelled (e.g., all outstanding packets are acknowledged, start idle period).
/// 
/// In order to indicate an active timer's timeout update, a new set event is used.
#[skip_serializing_none]
#[derive(Serialize)]
pub struct LossTimerUpdated {
    // Called "mode" in RFC 9002 A.9
    timer_type: Option<TimerType>,
    packet_number_space: Option<PacketNumberSpace>,
    event_type: EventType,

    /// If event_type == Set: delta time is in ms from this event's timestamp until when the timer will trigger
    delta: Option<f32>
}

impl LossTimerUpdated {
    pub fn new(timer_type: Option<TimerType>, packet_number_space: Option<PacketNumberSpace>, event_type: EventType, delta: Option<f32>) -> Self {
        Self { timer_type, packet_number_space, event_type, delta }
    }
}

/// Emitted when a packet is deemed lost by loss detection.
#[skip_serializing_none]
#[derive(Serialize)]
pub struct PacketLost {
    // Should include at least the packet_type and packet_number
    header: Option<PacketHeader>,

    // Not all implementations will keep track of full packets, so these are optional
    frames: Option<Vec<QuicFrame>>,
    is_mtu_probe_packet: bool,
    trigger: Option<PacketLostTrigger>
}

impl PacketLost {
    pub fn new(header: Option<PacketHeader>, frames: Option<Vec<QuicFrame>>, is_mtu_probe_packet: Option<bool>, trigger: Option<PacketLostTrigger>) -> Self {
        let is_mtu_probe_packet = is_mtu_probe_packet.unwrap_or_else(|| false);

        Self { header, frames, is_mtu_probe_packet, trigger }
    }
}

/// Indicates which data was marked for retransmission upon detection of packet loss.
#[derive(Serialize)]
pub struct MarkedForRetransmit {
    frames: Vec<QuicFrame>
}

impl MarkedForRetransmit {
    pub fn new(frames: Vec<QuicFrame>) -> Self {
        Self { frames }
    }
}

/// Indicates a progression in the ECN state machine
#[skip_serializing_none]
#[derive(Serialize)]
pub struct EcnStateUpdated {
    old: Option<EcnState>,
    new: EcnState
}

impl EcnStateUpdated {
    pub fn new(old: Option<EcnState>, new: EcnState) -> Self {
        Self { old, new }
    }
}

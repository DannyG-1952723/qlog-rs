use std::{collections::HashMap, fmt::Debug, io::Result, net::{IpAddr, SocketAddr}};

use serde::Serialize;
use serde_with::skip_serializing_none;

use crate::{events::RawInfo, util::HexString};

use super::events::*;

pub const QUIC_10_VERSION_STRING: &str = "quic-10";

#[derive(Serialize)]
#[serde(untagged)]
pub enum Quic10EventData {
    ServerListening(ServerListening),
    ConnectionStarted(ConnectionStarted),
    ConnectionClosed(ConnectionClosed),
    ConnectionIdUpdated(ConnectionIdUpdated),
    SpinBitUpdated(SpinBitUpdated),
    ConnectionStateUpdated(ConnectionStateUpdated),
    PathAssigned(PathAssigned),
    MtuUpdated(MtuUpdated),
    VersionInformation(VersionInformation),
    AlpnInformation(AlpnInformation),
    ParametersSet(ParametersSet),
    ParametersRestored(ParametersRestored),
    PacketSent(PacketSent),
    PacketReceived(PacketReceived),
    PacketDropped(PacketDropped),
    PacketBuffered(PacketBuffered),
    PacketsAcked(PacketsAcked),
    UdpDatagramsSent(UdpDatagramsSent),
    UdpDatagramsReceived(UdpDatagramsReceived),
    UdpDatagramDropped(UdpDatagramDropped),
    StreamStateUpdated(StreamStateUpdated),
    FramesProcessed(FramesProcessed),
    StreamDataMoved(StreamDataMoved),
    DatagramDataMoved(DatagramDataMoved),
    MigrationStateUpdated(MigrationStateUpdated),
    KeyUpdated(KeyUpdated),
    KeyDiscarded(KeyDiscarded),
    RecoveryParametersSet(RecoveryParametersSet),
    RecoveryMetricsUpdated(RecoveryMetricsUpdated),
    CongestionStateUpdated(CongestionStateUpdated),
    LossTimerUpdated(LossTimerUpdated),
    PacketLost(PacketLost),
    MarkedForRetransmit(MarkedForRetransmit),
    EcnStateUpdated(EcnStateUpdated)
}

pub type QuicVersion = HexString;
pub type ConnectionId = HexString;

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Owner {
    Local,
    Remote
}

/// An IpAddress can either be a "human readable" form (e.g., "127.0.0.1" for v4 or "2001:0db8:85a3:0000:0000:8a2e:0370:7334" for v6) or use a raw byte-form (as the string forms can be ambiguous). Additionally, a hash-based or redacted representation can be used if needed for privacy or security reasons.
pub type IpAddress = String;

/// Single half/direction of a path. A full path is comprised of two halves. Firstly: the server sends to the remote client IP + port using a specific destination Connection ID. Secondly: the client sends to the remote server IP + port using a different destination Connection ID.
#[skip_serializing_none]
#[derive(Serialize)]
pub struct PathEndpointInfo {
    ip_v4: Option<IpAddress>,
    port_v4: Option<u16>,
    ip_v6: Option<IpAddress>,
    port_v6: Option<u16>,

    /// Even though usually only a single ConnectionID is associated with a given path at a time, there are situations where there can be an overlap or a need to keep track of previous ConnectionIDs.
    connection_ids: Vec<ConnectionId>
}

impl PathEndpointInfo {
    pub fn new(ip_v4: Option<IpAddress>, port_v4: Option<u16>, ip_v6: Option<IpAddress>, port_v6: Option<u16>, connection_ids: Vec<ConnectionId>) -> Self {
        Self { ip_v4, port_v4, ip_v6, port_v6, connection_ids }
    }
}

// TODO: See what to do with the `connection_ids`
impl From<IpAddr> for PathEndpointInfo {
    fn from(value: IpAddr) -> Self {
        if value.is_ipv4() {
            Self::new(Some(value.to_string()), None, None, None, Vec::default())
        }
        else {
            Self::new(None, None, Some(value.to_string()), None, Vec::default())
        }
    }
}

// TODO: See what to do with the `connection_ids`
impl From<Option<IpAddr>> for PathEndpointInfo {
    fn from(value: Option<IpAddr>) -> Self {
        match value {
            Some(ip) => Self::from(ip),
            None => Self::new(None, None, None, None, Vec::default())
        }
    }
}

// TODO: See what to do with the `connection_ids`
impl From<SocketAddr> for PathEndpointInfo {
    fn from(value: SocketAddr) -> Self {
        if value.is_ipv4() {
            Self::new(Some(value.ip().to_string()), Some(value.port()), None, None, Vec::default())
        }
        else {
            Self::new(None, None, Some(value.ip().to_string()), Some(value.port()), Vec::default())
        }
    }
}

// TODO: See what to do with the `connection_ids`
impl From<Result<SocketAddr>> for PathEndpointInfo {
    fn from(value: Result<SocketAddr>) -> Self {
        match value {
            Ok(socket_addr) => Self::from(socket_addr),
            Err(_) => Self::new(None, None, None, None, Vec::default()),
        }
    }
}

#[derive(PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketType {
    Initial,
    Handshake,
    #[serde(rename = "0RTT")]
    ZeroRtt,
    #[serde(rename = "1RTT")]
    OneRtt,
    Retry,
    VersionNegotiation,
    StatelessReset,
    Unknown
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketNumberSpace {
    Initial,
    Handshake,
    ApplicationData
}

/// If the packet_type numerical value does not map to a known packet_type string, the packet_type value of "unknown" can be used and the raw value captured in the packet_type_bytes field; a numerical value without variable-length integer encoding.
#[skip_serializing_none]
#[derive(Serialize)]
pub struct PacketHeader {
    quic_bit: bool,
    packet_type: PacketType,

    packet_type_bytes: Option<u64>,

    packet_number: Option<u64>,

    /// The bit flags of the packet headers (spin bit, key update bit, etc. up to and including the packet number length bits if present.
    flags: Option<u8>,

    token: Option<Token>,

    /// Signifies length of the packet_number plus the payload.
    length: Option<u16>,

    version: Option<QuicVersion>,
    scil: Option<u8>,
    dcil: Option<u8>,
    scid: Option<ConnectionId>,
    /// Can be skipped for 1RTT packets if correctly using transport:connection_id_updated events.
    dcid: Option<ConnectionId>
}

impl PacketHeader {
    pub fn new(
        quic_bit: Option<bool>,
        packet_type: PacketType,
        packet_type_bytes: Option<u64>,
        packet_number: Option<u64>,
        flags: Option<u8>,
        token: Option<Token>,
        length: Option<u16>,
        version: Option<QuicVersion>,
        scil: Option<u8>,
        dcil: Option<u8>,
        scid: Option<ConnectionId>,
        dcid: Option<ConnectionId>
    ) -> Self {
        let quic_bit = quic_bit.unwrap_or_else(|| true);

        if packet_type == PacketType::Unknown && packet_type_bytes.is_none() {
            panic!("When the packet_type is 'unknown', provide a value for packet_type_bytes");
        }

        if (packet_type == PacketType::Initial || packet_type == PacketType::Handshake || packet_type == PacketType::ZeroRtt || packet_type == PacketType::OneRtt) && packet_number.is_none() {
            panic!("When the packet_type is 'initial', 'handshake', '0RTT', or '1RTT', provide a value for packet_number");
        }

        if (packet_type == PacketType::Initial || packet_type == PacketType::Retry) && token.is_none() {
            panic!("When the packet_type is 'initial', or 'retry', provide a value for token");
        }

        if (packet_type == PacketType::Initial || packet_type == PacketType::Handshake || packet_type == PacketType::ZeroRtt) && length.is_none() {
            panic!("When the packet_type is 'initial', 'handshake', or '0RTT', provide a value for length");
        }

        Self {
            quic_bit,
            packet_type,
            packet_type_bytes,
            packet_number,
            flags,
            token,
            length,
            version,
            scil,
            dcil,
            scid,
            dcid
        }
    }

    pub fn update_packet_length(&mut self, payload_length: u16) {
        let packet_num_length = match self.length {
            Some(length) => length,
            // Don't update when None
            None => return,
        };

        self.length = Some(packet_num_length + payload_length)
    }
}

// The token carried in an Initial packet can either be a retry token from a Retry packet, or one originally provided by the server in a NEW_TOKEN frame used when resuming a connection (e.g., for address validation purposes). Retry and resumption tokens typically contain encoded metadata to check the token's validity when it is used, but this metadata and its format is implementation specific. For that, Token includes a general-purpose details field.
#[skip_serializing_none]
#[derive(Serialize)]
pub struct Token {
    #[serde(rename = "type")]
    token_type: Option<TokenType>,

    /// Decoded fields included in the token (typically: peer's IP address, creation time).
    // TODO: Check if HashMap typing is correct
    #[serde(flatten)]
    details: HashMap<String, String>,

    raw: Option<RawInfo>
}

impl Token {
    pub fn new(token_type: Option<TokenType>, details: Option<HashMap<String, String>>, raw: Option<RawInfo>) -> Self {
        let details = details.unwrap_or_default();

        Self { token_type, details, raw }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    Retry,
    Resumption
}

// Size = 16
// The stateless reset token is carried in stateless reset packets, in transport parameters and in NEW_CONNECTION_ID frames.
pub type StatelessResetToken = HexString;

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    ServerInitialSecret,
    ClientInitialSecret,
    ServerHandshakeSecret,
    ClientHandshakeSecret,
    #[serde(rename = "server_0rtt_secret")]
    ServerZeroRttSecret,
    #[serde(rename = "client_0rtt_secret")]
    ClientZeroRttSecret,
    #[serde(rename = "server_1rtt_secret")]
    ServerOneRttSecret,
    #[serde(rename = "client_1rtt_secret")]
    ClientOneRttSecret,
}

#[derive(Serialize)]
pub enum Ecn {
    #[serde(rename = "Not-ECT")]
    NotEct,
    #[serde(rename = "ECT(1)")]
    EctOne,
    #[serde(rename = "ECT(0)")]
    EctZero,
    #[serde(rename = "CE")]
    Ce
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum QuicFrame {
    QuicBaseFrame(QuicBaseFrame)
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum QuicBaseFrame {
    PaddingFrame(PaddingFrame),
    PingFrame(PingFrame),
    AckFrame(AckFrame),
    ResetStreamFrame(ResetStreamFrame),
    StopSendingFrame(StopSendingFrame),
    CryptoFrame(CryptoFrame),
    NewTokenFrame(NewTokenFrame),
    StreamFrame(StreamFrame),
    MaxDataFrame(MaxDataFrame),
    MaxStreamDataFrame(MaxStreamDataFrame),
    MaxStreamsFrame(MaxStreamsFrame),
    DataBlockedFrame(DataBlockedFrame),
    StreamDataBlockedFrame(StreamDataBlockedFrame),
    StreamsBlockedFrame(StreamsBlockedFrame),
    NewConnectionIdFrame(NewConnectionIdFrame),
    RetireConnectionIdFrame(RetireConnectionIdFrame),
    PathChallengeFrame(PathChallengeFrame),
    PathResponseFrame(PathResponseFrame),
    ConnectionCloseFrame(ConnectionCloseFrame),
    HandshakeDoneFrame(HandshakeDoneFrame),
    UnknownFrame(UnknownFrame),
    DatagramFrame(DatagramFrame)
}

impl Debug for QuicBaseFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PaddingFrame(_) => f.debug_tuple("PaddingFrame").finish(),
            Self::PingFrame(_) => f.debug_tuple("PingFrame").finish(),
            Self::AckFrame(_) => f.debug_tuple("AckFrame").finish(),
            Self::ResetStreamFrame(_) => f.debug_tuple("ResetStreamFrame").finish(),
            Self::StopSendingFrame(_) => f.debug_tuple("StopSendingFrame").finish(),
            Self::CryptoFrame(_) => f.debug_tuple("CryptoFrame").finish(),
            Self::NewTokenFrame(_) => f.debug_tuple("NewTokenFrame").finish(),
            Self::StreamFrame(_) => f.debug_tuple("StreamFrame").finish(),
            Self::MaxDataFrame(_) => f.debug_tuple("MaxDataFrame").finish(),
            Self::MaxStreamDataFrame(_) => f.debug_tuple("MaxStreamDataFrame").finish(),
            Self::MaxStreamsFrame(_) => f.debug_tuple("MaxStreamsFrame").finish(),
            Self::DataBlockedFrame(_) => f.debug_tuple("DataBlockedFrame").finish(),
            Self::StreamDataBlockedFrame(_) => f.debug_tuple("StreamDataBlockedFrame").finish(),
            Self::StreamsBlockedFrame(_) => f.debug_tuple("StreamsBlockedFrame").finish(),
            Self::NewConnectionIdFrame(_) => f.debug_tuple("NewConnectionIdFrame").finish(),
            Self::RetireConnectionIdFrame(_) => f.debug_tuple("RetireConnectionIdFrame").finish(),
            Self::PathChallengeFrame(_) => f.debug_tuple("PathChallengeFrame").finish(),
            Self::PathResponseFrame(_) => f.debug_tuple("PathResponseFrame").finish(),
            Self::ConnectionCloseFrame(_) => f.debug_tuple("ConnectionCloseFrame").finish(),
            Self::HandshakeDoneFrame(_) => f.debug_tuple("HandshakeDoneFrame").finish(),
            Self::UnknownFrame(_) => f.debug_tuple("UnknownFrame").finish(),
            Self::DatagramFrame(_) => f.debug_tuple("DatagramFrame").finish(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameType {
    Padding,
    Ping,
    Ack,
    ResetStream,
    StopSending,
    Crypto,
    NewToken,
    Stream,
    MaxData,
    MaxStreamData,
    MaxStreams,
    DataBlocked,
    StreamDataBlocked,
    StreamsBlocked,
    NewConnectionId,
    RetireConnectionId,
    PathChallenge,
    PathResponse,
    ConnectionClose,
    HandshakeDone,
    Unknown,
    Datagram
}

/// In QUIC, PADDING frames are simply identified as a single byte of value 0. As such, each padding byte could be theoretically interpreted and logged as an individual PaddingFrame.However, as this leads to heavy logging overhead, implementations should instead emit just a single PaddingFrame and set the raw.payload_length property to the amount of PADDING bytes/frames included in the packet.
#[skip_serializing_none]
#[derive(Serialize)]
pub struct PaddingFrame {
    frame_type: FrameType,
    raw: Option<RawInfo>
}

impl PaddingFrame {
    pub fn new(raw: Option<RawInfo>) -> Self {
        Self { frame_type: FrameType::Padding, raw }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct PingFrame {
    frame_type: FrameType,
    raw: Option<RawInfo>
}

impl PingFrame {
    pub fn new(raw: Option<RawInfo>) -> Self {
        Self { frame_type: FrameType::Ping, raw }
    }
}

type AckRange = Vec<u64>;

#[skip_serializing_none]
#[derive(Serialize)]
pub struct AckFrame {
    frame_type: FrameType,

    /// In ms
    ack_delay: Option<f32>,

    // e.g., looks like [[1,2],[4,5], [7], [10,22]] serialized
    acked_ranges: Option<Vec<AckRange>>,

    // ECN (explicit congestion notification) related fields (not always present)
    ect1: Option<u64>,
    ect0: Option<u64>,
    ce: Option<u64>,
    raw: Option<RawInfo>
}

impl AckFrame {
    pub fn new(ack_delay: Option<f32>, acked_ranges: Option<Vec<AckRange>>, ect1: Option<u64>, ect0: Option<u64>, ce: Option<u64>, raw: Option<RawInfo>) -> Self {
        Self { frame_type: FrameType::Ack, ack_delay, acked_ranges, ect1, ect0, ce, raw }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct ResetStreamFrame {
    frame_type: FrameType,
    stream_id: u64,
    error_code: ApplicationError,

    error_code_bytes: Option<u64>,

    /// In bytes
    final_size: u64,
    raw: Option<RawInfo>
}

impl ResetStreamFrame {
    pub fn new(stream_id: u64, error_code: ApplicationError, error_code_bytes: Option<u64>, final_size: u64, raw: Option<RawInfo>) -> Self {
        if error_code == ApplicationError::Unknown && error_code_bytes.is_none() {
            panic!("When the error_code is 'unknown', provide a value for error_code_bytes");
        }

        Self { frame_type: FrameType::ResetStream, stream_id, error_code, error_code_bytes, final_size, raw }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct StopSendingFrame {
    frame_type: FrameType,
    stream_id: u64,
    error_code: ApplicationError,

    error_code_bytes: Option<u64>,

    raw: Option<RawInfo>
}

impl StopSendingFrame {
    pub fn new(stream_id: u64, error_code: ApplicationError, error_code_bytes: Option<u64>, raw: Option<RawInfo>) -> Self {
        if error_code == ApplicationError::Unknown && error_code_bytes.is_none() {
            panic!("When the error_code is 'unknown', give error_code_bytes a value");
        }

        Self { frame_type: FrameType::StopSending, stream_id, error_code, error_code_bytes, raw }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct CryptoFrame {
    frame_type: FrameType,
    offset: u64,
    length: u64,
    raw: Option<RawInfo>
}

impl CryptoFrame {
    pub fn new(offset: u64, length: u64, raw: Option<RawInfo>) -> Self {
        Self { frame_type: FrameType::Crypto, offset, length, raw }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct NewTokenFrame {
    frame_type: FrameType,
    token: Token,
    raw: Option<RawInfo>
}

impl NewTokenFrame {
    pub fn new(token: Token, raw: Option<RawInfo>) -> Self {
        Self { frame_type: FrameType::NewToken, token, raw }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct StreamFrame {
    frame_type: FrameType,
    stream_id: u64,

    // These two MUST always be set
    // If not present in the Frame type, log their default values
    offset: u64,
    length: u64,

    // This MAY be set any time, but MUST only be set if the value is true
    // If absent, the value MUST be assumed to be false
    fin: bool,
    raw: Option<RawInfo>
}

impl StreamFrame {
    pub fn new(stream_id: u64, offset: u64, length: u64, fin: Option<bool>, raw: Option<RawInfo>) -> Self {
        let fin = fin.unwrap_or_else(|| false);

        Self { frame_type: FrameType::Stream, stream_id, offset, length, fin, raw }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct MaxDataFrame {
    frame_type: FrameType,
    maximum: u64,
    raw: Option<RawInfo>
}

impl MaxDataFrame {
    pub fn new(maximum: u64, raw: Option<RawInfo>) -> Self {
        Self { frame_type: FrameType::MaxData, maximum, raw }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct MaxStreamDataFrame {
    frame_type: FrameType,
    stream_id: u64,
    maximum: u64,
    raw: Option<RawInfo>
}

impl MaxStreamDataFrame {
    pub fn new(stream_id: u64, maximum: u64, raw: Option<RawInfo>) -> Self {
        Self { frame_type: FrameType::MaxStreamData, stream_id, maximum, raw }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct MaxStreamsFrame {
    frame_type: FrameType,
    stream_type: StreamType,
    maximum: u64,
    raw: Option<RawInfo>
}

impl MaxStreamsFrame {
    pub fn new(stream_type: StreamType, maximum: u64, raw: Option<RawInfo>) -> Self {
        Self { frame_type: FrameType::MaxStreams, stream_type, maximum, raw }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct DataBlockedFrame {
    frame_type: FrameType,
    limit: u64,
    raw: Option<RawInfo>
}

impl DataBlockedFrame {
    pub fn new(limit: u64, raw: Option<RawInfo>) -> Self {
        Self { frame_type: FrameType::DataBlocked, limit, raw }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct StreamDataBlockedFrame {
    frame_type: FrameType,
    stream_id: u64,
    limit: u64,
    raw: Option<RawInfo>
}

impl StreamDataBlockedFrame {
    pub fn new(stream_id: u64, limit: u64, raw: Option<RawInfo>) -> Self {
        Self { frame_type: FrameType::StreamDataBlocked, stream_id, limit, raw }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct StreamsBlockedFrame {
    frame_type: FrameType,
    stream_type: StreamType,
    limit: u64,
    raw: Option<RawInfo>
}

impl StreamsBlockedFrame {
    pub fn new(stream_type: StreamType, limit: u64, raw: Option<RawInfo>) -> Self {
        Self { frame_type: FrameType::StreamsBlocked, stream_type, limit, raw }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct NewConnectionIdFrame {
    frame_type: FrameType,
    sequence_number: u32,
    retire_prior_to: u32,

    /// Mainly used if e.g., for privacy reasons the full connection_id cannot be logged
    connection_id_length: Option<u8>,
    connection_id: ConnectionId,
    stateless_reset_token: Option<StatelessResetToken>,
    raw: Option<RawInfo>
}

impl NewConnectionIdFrame {
    pub fn new(sequence_number: u32, retire_prior_to: u32, connection_id_length: Option<u8>, connection_id: ConnectionId, stateless_reset_token: Option<StatelessResetToken>, raw: Option<RawInfo>) -> Self {
        Self { frame_type: FrameType::NewConnectionId, sequence_number, retire_prior_to, connection_id_length, connection_id, stateless_reset_token, raw }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct RetireConnectionIdFrame {
    frame_type: FrameType,
    sequence_number: u32,
    raw: Option<RawInfo>
}

impl RetireConnectionIdFrame {
    pub fn new(sequence_number: u32, raw: Option<RawInfo>) -> Self {
        Self { frame_type: FrameType::RetireConnectionId, sequence_number, raw }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct PathChallengeFrame {
    frame_type: FrameType,

    // Always 64 bits
    data: Option<HexString>,
    raw: Option<RawInfo>
}

impl PathChallengeFrame {
    pub fn new(data: Option<HexString>, raw: Option<RawInfo>) -> Self {
        Self { frame_type: FrameType::PathChallenge, data, raw }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct PathResponseFrame {
    frame_type: FrameType,

    // Always 64 bits
    data: Option<HexString>,
    raw: Option<RawInfo>
}

impl PathResponseFrame {
    pub fn new(data: Option<HexString>, raw: Option<RawInfo>) -> Self {
        Self { frame_type: FrameType::PathResponse, data, raw }
    }
}

#[derive(PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorSpace {
    Transport,
    Application
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct ConnectionCloseFrame {
    frame_type: FrameType,
    error_space: Option<ErrorSpace>,
    error_code: Option<Error>,

    error_code_bytes: Option<u64>,

    reason: Option<String>,
    reason_bytes: Option<HexString>,

    trigger_frame_type: Option<TriggerFrameType>,
    raw: Option<RawInfo>
}

impl ConnectionCloseFrame {
    pub fn new(
        error_space: Option<ErrorSpace>,
        error_code: Option<Error>,
        error_code_bytes: Option<u64>,
        reason: Option<String>,
        reason_bytes: Option<HexString>,
        trigger_frame_type: Option<TriggerFrameType>,
        raw: Option<RawInfo>
    ) -> Self {
        if (error_code == Some(Error::ApplicationError(ApplicationError::Unknown)) || error_code == Some(Error::TransportError(TransportError::Unknown))) && error_code_bytes.is_none() {
            panic!("When the error_code is 'unknown', provide a value for error_code_bytes");
        }

        if error_space == Some(ErrorSpace::Transport) && trigger_frame_type.is_none() {
            panic!("When the error_space is 'transport', provide a value for trigger_frame_type");
        }

        Self { frame_type: FrameType::ConnectionClose, error_space, error_code, error_code_bytes, reason, reason_bytes, trigger_frame_type, raw }
    }
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum TriggerFrameType {
    U64(u64),
    Text(String)
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct HandshakeDoneFrame {
    frame_type: FrameType,
    raw: Option<RawInfo>
}

impl HandshakeDoneFrame {
    pub fn new(raw: Option<RawInfo>) -> Self {
        Self { frame_type: FrameType::HandshakeDone, raw }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct UnknownFrame {
    frame_type: FrameType,
    frame_type_bytes: u64,
    raw: Option<RawInfo>
}

impl UnknownFrame {
    pub fn new(frame_type_bytes: u64, raw: Option<RawInfo>) -> Self {
        Self { frame_type: FrameType::Unknown, frame_type_bytes, raw }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct DatagramFrame {
    frame_type: FrameType,
    length: Option<u64>,
    raw: Option<RawInfo>
}

impl DatagramFrame {
    pub fn new(length: Option<u64>, raw: Option<RawInfo>) -> Self {
        Self { frame_type: FrameType::Datagram, length, raw }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamType {
    Unidirectional,
    Bidirectional
}

#[derive(PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportError {
    NoError,
    InternalError,
    ConnectionRefused,
    FlowControlError,
    StreamLimitError,
    StreamStateError,
    FinalSizeError,
    FrameEncodingError,
    TransportParameterError,
    ConnectionIdLimitError,
    ProtocolViolation,
    InvalidToken,
    ApplicationError,
    CryptoBufferExceeded,
    KeyUpdateError,
    AeadLimitReached,
    NoViablePath,
    Unknown
}

#[derive(PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationError {
    Unknown
}

/// All strings from "crypto_error_0x100" to "crypto_error_0x1ff".
pub type CryptoError = String;

#[derive(PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum ConnectionError {
    TransportError(TransportError),
    CryptoError(CryptoError)
}

#[derive(PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Error {
    TransportError(TransportError),
    CryptoError(CryptoError),
    ApplicationError(ApplicationError)
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum ConnectionState {
    BaseConnectionState(BaseConnectionState),
    GranularConnectionState(GranularConnectionState)
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BaseConnectionState {
    /// Initial packet sent/received.
    Attempted,

    /// Handshake packet sent/received.
    HandshakeStarted,

    /// Both sent a TLS Finished message and verified the peer's TLS Finished message.
    /// 1-RTT packets can be sent.
    /// RFC 9001 Section 4.1.1.
    HandshakeComplete,

    /// CONNECTION_CLOSE sent/received, stateless reset received or idle timeout.
    Closed
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GranularConnectionState {
    /// Client sent Handshake packet OR 
    /// client used connection ID chosen by the server OR 
    /// client used valid address validation token.
    /// RFC 9000 Section 8.1
    PeerValidated,

    /// 1-RTT data can be sent by the server, 
    /// but handshake is not done yet 
    /// (server has sent TLS Finished; sometimes called 0.5 RTT data)
    EarlyWrite,

    /// HANDSHAKE_DONE sent/received.
    /// RFC 9001 Section 4.1.2
    HandshakeConfirmed,

    /// CONNECTION_CLOSE sent.
    Closing,

    /// CONNECTION_CLOSE received.
    Draining,

    /// Draining or closing period done, connection state discarded.
    Closed
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum StreamState {
    BaseStreamState(BaseStreamState),
    GranularStreamState(GranularStreamState)
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BaseStreamState {
    Idle,
    Open,
    Closed
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GranularStreamState {
    // Bidirectional stream states, RFC 9000 Section 3.4.
    HalfClosedLocal,
    HalfClosedRemote,

    // Sending-side stream states, RFC 9000 Section 3.1.
    Ready,
    Send,
    DataSent,
    ResetSent,
    ResetReceived,

    // Receive-side stream states, RFC 9000 Section 3.2.
    Receive,
    SizeKnown,
    DataRead,
    ResetRead,

    // Both-side states
    DataReceived,

    // qlog-defined: memory actually freed
    Destroyed
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamSide {
    Sending,
    Receiving
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct AlpnIdentifier {
    byte_value: Option<HexString>,
    string_value: Option<String>
}

impl AlpnIdentifier {
    pub fn new(byte_value: Option<HexString>, string_value: Option<String>) -> Self {
        Self { byte_value, string_value }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct PreferredAddress {
    ip_v4: Option<IpAddress>,
    port_v4: Option<u16>,
    ip_v6: Option<IpAddress>,
    port_v6: Option<u16>,
    connection_id: ConnectionId,
    stateless_reset_token: StatelessResetToken
}

impl PreferredAddress {
    pub fn new(ip_v4: Option<IpAddress>, port_v4: Option<u16>, ip_v6: Option<IpAddress>, port_v6: Option<u16>, connection_id: ConnectionId, stateless_reset_token: StatelessResetToken) -> Self {
        Self { ip_v4, port_v4, ip_v6, port_v6, connection_id, stateless_reset_token }
    }
}

#[skip_serializing_none]
#[derive(Serialize)]
pub struct UnknownParameter {
    id: u64,
    value: Option<HexString>
}

impl UnknownParameter {
    pub fn new(id: u64, value: Option<HexString>) -> Self {
        Self { id, value }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionCloseTrigger {
    IdleTimeout,
    Application,
    Error,
    VersionMismatch,
    // When received from peer
    StatelessReset,
    Aborted,
    // When it is unclear what triggered the CONNECTION_CLOSE
    Unspecified
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketSentTrigger {
    // RFC 9002 Section 6.1.1
    RetransmitReordered,
    // RFC 9002 Section 6.1.2
    RetransmitTimeout,
    // RFC 9002 Section 6.2.4
    PtoProbe,
    // RFC 9002 Section 6.2.3
    RetransmitCrypto,
    // Needed for some CCs to figure out bandwidth allocations when there are no normal sends
    CcBandwidthProbe
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketReceivedTrigger {
    // If packet was buffered because it couldn't be decrypted before
    KeysAvailable
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketDroppedTrigger {
    InternalError,
    Rejected,
    Unsupported,
    Invalid,
    Duplicate,
    ConnectionUnknown,
    DecryptionFailure,
    KeyUnavailable,
    General
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketBufferedTrigger {
    /// Indicates the parser cannot keep up, temporarily buffers packet for later processing
    Backpressure,
    /// If packet cannot be decrypted because the proper keys were not yet available
    KeysUnavailable
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyUpdateTrigger {
    // (e.g., initial, handshake and 0-RTT keys are generated by TLS)
    Tls,
    RemoteUpdate,
    LocalUpdate
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyDiscardTrigger {
    // (e.g., initial, handshake and 0-RTT keys are generated by TLS)
    Tls,
    RemoteUpdate,
    LocalUpdate
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketLostTrigger {
    ReorderingThreshold,
    TimeThreshold,
    // RFC 9002 Section 6.2.4 paragraph 6
    PtoExpired
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataLocation {
    Application,
    Transport,
    Network
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataMovedAdditionalInfo {
    FinSet,
    StreamReset
}

/// Note that MigrationState does not describe a full state machine.
/// These entries are not necessarily chronological, nor will they always all appear during a connection migration attempt.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationState {
    /// Probing packets are sent, migration not initiated yet
    ProbingStarted,
    /// Did not get reply to probing packets, discarding path as an option
    ProbingAbandoned,
    /// Received reply to probing packets, path is migration candidate
    ProbingSuccessful,
    /// Non-probing packets are sent, attempting migration
    MigrationStarted,
    /// Something went wrong during the migration, abandoning attempt
    MigrationAbandoned,
    /// New path is now fully used, old path is discarded
    MigrationComplete
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimerType {
    Ack,
    Pto
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    Set,
    Expired,
    Cancelled
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EcnState {
    /// ECN testing in progress
    Testing,
    /// ECN state unknown, waiting for acknowledgments, for testing packets
    Unknown,
    /// ECN testing failed
    Failed,
    /// Testing was successful, the endpoint now sends packets with ECT(0) marking
    Capable
}

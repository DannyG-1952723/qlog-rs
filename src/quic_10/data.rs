use std::collections::HashMap;

use serde::Serialize;

use crate::{events::RawInfo, util::HexString};

pub const QUIC_10_VERSION_STRING: &str = "quic-10";

#[derive(Serialize)]
#[serde(untagged)]
pub enum Quic10EventData {
    ServerListening,
    ConnectionStarted,
    ConnectionClosed,
    ConnectionIdUpdated,
    SpinBitUpdated,
    ConnectionStateUpdated,
    PathAssigned,
    MtuUpdated,
    KeyUpdated,
    KeyDiscarded,
    VersionInformation,
    AlpnInformation,
    ParametersSet,
    ParametersRestored,
    PacketSent,
    PacketReceived,
    PacketDropped,
    PacketBuffered,
    PacketsAcked,
    UdpDatagramsSent,
    UdpDatagramsReceived,
    UdpDatagramDropped,
    StreamStateUpdated,
    FramesProcessed,
    StreamDataMoved,
    DatagramDataMoved,
    RecoveryParametersSet,
    RecoveryMetricsUpdated,
    CongestionStateUpdated,
    LossTimerUpdated,
    PacketLost
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
pub struct PathEndpointInfo {
    ip_v4: Option<IpAddress>,
    port_v4: Option<u16>,
    ip_v6: Option<IpAddress>,
    port_v6: Option<u16>,

    /// Even though usually only a single ConnectionID is associated with a given path at a time, there are situations where there can be an overlap or a need to keep track of previous ConnectionIDs.
    connection_ids: Vec<ConnectionId>
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
// TODO: Rename 'ZeroRtt' and 'OneRtt' in serialization
pub enum PacketType {
    Initial,
    Handshake,
    ZeroRtt,
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
pub struct PacketHeader {
    // TODO: Default = true
    quic_bit: Option<bool>,
    packet_type: PacketType,

    // TODO: Only if packet_type == Unknown
    packet_type_bytes: Option<u64>,

    // TODO: Only if packet_type == Initial || Handshake || ZeroRtt || OneRtt
    packet_number: Option<u64>,

    /// The bit flags of the packet headers (spin bit, key update bit, etc. up to and including the packet number length bits if present.
    flags: Option<u8>,

    // TODO: Only if packet_type == Initial || Retry
    token: Option<Token>,

    // TODO: Only if packet_type == Initial || Handshake || ZeroRtt
    /// Signifies length of the packet_number plus the payload.
    length: Option<u16>,

    // TODO: Only if present in the header
    version: Option<QuicVersion>,
    scil: Option<u8>,
    dcil: Option<u8>,
    scid: Option<ConnectionId>,
    /// If correctly using transport:connection_id_updated events, dcid can be skipped for 1RTT packets.
    dcid: Option<ConnectionId>
}

// The token carried in an Initial packet can either be a retry token from a Retry packet, or one originally provided by the server in a NEW_TOKEN frame used when resuming a connection (e.g., for address validation purposes). Retry and resumption tokens typically contain encoded metadata to check the token's validity when it is used, but this metadata and its format is implementation specific. For that, Token includes a general-purpose details field.
pub struct Token {
    // TODO: Rename to 'type' in serialization
    token_type: Option<TokenType>,

    /// Decoded fields included in the token (typically: peer's IP address, creation time).
    // TODO: serde flatten
    details: Option<HashMap<String, String>>,

    raw: Option<RawInfo>
}

pub enum TokenType {
    Retry,
    Resumption
}

// Size = 16
// The stateless reset token is carried in stateless reset packets, in transport parameters and in NEW_CONNECTION_ID frames.
pub type StatelessResetToken = HexString;

pub enum KeyType {
    ServerInitialSecret,
    ClientInitialSecret,
    ServerHandshakeSecret,
    ClientHandshakeSecret,
    // TODO: Rename all the following in serde
    ServerZeroRttSecret,
    ClientZeroRttSecret,
    ServerOneRttSecret,
    ClientOneRttSecret,
}

// TODO: Rename all in serde
pub enum Ecn {
    NotEct,
    EctOne,
    EctZero,
    Ce
}

pub enum QuicFrame {
    QuicBaseFrame(QuicBaseFrame)
}

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
pub struct PaddingFrame {
    // TODO: Set to Padding
    frame_type: FrameType,
    raw: Option<RawInfo>
}

pub struct PingFrame {
    // TODO: Set to Ping
    frame_type: FrameType,
    raw: Option<RawInfo>
}

type AckRange = Vec<u64>;

pub struct AckFrame {
    // TODO: Set to Ack
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

pub struct ResetStreamFrame {
    // TODO: Set to ResetStream
    frame_type: FrameType,
    stream_id: u64,
    error_code: ApplicationError,

    // TODO: If error_code == Unknown
    error_code_bytes: Option<u64>,

    /// In bytes
    final_size: u64,
    raw: Option<RawInfo>
}

pub struct StopSendingFrame {
    // TODO: Set to StopSending
    frame_type: FrameType,
    stream_id: u64,
    error_code: ApplicationError,

    // TODO: If error_code == Unknown
    error_code_bytes: Option<u64>,

    raw: Option<RawInfo>
}

pub struct CryptoFrame {
    // TODO: Set to Crypto
    frame_type: FrameType,
    offset: u64,
    length: u64,
    raw: Option<RawInfo>
}

pub struct NewTokenFrame {
    // TODO: Set to NewToken
    frame_type: FrameType,
    token: Token,
    raw: Option<RawInfo>
}

pub struct StreamFrame {
    // TODO: Set to Stream
    frame_type: FrameType,
    stream_id: u64,

    // These two MUST always be set
    // If not present in the Frame type, log their default values
    offset: u64,
    length: u64,

    // This MAY be set any time, but MUST only be set if the value is true
    // If absent, the value MUST be assumed to be false
    // TODO: Set default to false
    fin: Option<bool>,
    raw: Option<RawInfo>
}

pub struct MaxDataFrame {
    // TODO: Set to MaxData
    frame_type: FrameType,
    maximum: u64,
    raw: Option<RawInfo>
}

pub struct MaxStreamDataFrame {
    // TODO: Set to MaxStreamData
    frame_type: FrameType,
    stream_id: u64,
    maximum: u64,
    raw: Option<RawInfo>
}

pub struct MaxStreamsFrame {
    // TODO: Set to MaxStreams
    frame_type: FrameType,
    stream_type: StreamType,
    maximum: u64,
    raw: Option<RawInfo>
}

pub struct DataBlockedFrame {
    // TODO: Set to DataBlocked
    frame_type: FrameType,
    limit: u64,
    raw: Option<RawInfo>
}

pub struct StreamDataBlockedFrame {
    // TODO: Set to StreamDataBlocked
    frame_type: FrameType,
    stream_id: u64,
    limit: u64,
    raw: Option<RawInfo>
}

pub struct StreamsBlockedFrame {
    // TODO: Set to StreamsBlocked
    frame_type: FrameType,
    stream_type: StreamType,
    limit: u64,
    raw: Option<RawInfo>
}

pub struct NewConnectionIdFrame {
    // TODO: Set to NewConnectionId
    frame_type: FrameType,
    sequence_number: u32,
    retire_prior_to: u32,

    /// Mainly used if e.g., for privacy reasons the full connection_id cannot be logged
    connection_id_length: Option<u8>,
    connection_id: ConnectionId,
    stateless_reset_token: Option<StatelessResetToken>,
    raw: Option<RawInfo>
}

pub struct RetireConnectionIdFrame {
    // TODO: Set to RetireConnectionId
    frame_type: FrameType,
    sequence_number: u32,
    raw: Option<RawInfo>
}

pub struct PathChallengeFrame {
    // TODO: Set to PathChallenge
    frame_type: FrameType,

    // Always 64 bits
    data: Option<HexString>,
    raw: Option<RawInfo>
}

pub struct PathResponseFrame {
    // TODO: Set to PathResponse
    frame_type: FrameType,

    // Always 64 bits
    data: Option<HexString>,
    raw: Option<RawInfo>
}

pub enum ErrorSpace {
    Transport,
    Application
}

pub struct ConnectionCloseFrame {
    // TODO: Set to ConnectionClose
    frame_type: FrameType,
    error_space: Option<ErrorSpace>,
    // TODO
    error_code: Option<Error>,

    // TODO: Only if error_code == Unknown
    error_code_bytes: Option<u64>,

    reason: Option<String>,
    reason_bytes: HexString,

    // TODO: When error_space == Transport
    // TODO
    trigger_frame_type: Option<TriggerFrameType>,
    raw: Option<RawInfo>
}

pub enum TriggerFrameType {
    U64(u64),
    Text(String)
}

pub struct HandshakeDoneFrame {
    // TODO: Set to HandshakeDone
    frame_type: FrameType,
    raw: Option<RawInfo>
}

pub struct UnknownFrame {
    // TODO: Set to Unknown
    frame_type: FrameType,
    frame_type_bytes: u64,
    raw: Option<RawInfo>
}

pub struct DatagramFrame {
    // TODO: Set to Datagram
    frame_type: FrameType,
    length: Option<u64>,
    raw: Option<RawInfo>
}

pub enum StreamType {
    Unidirectional,
    Bidirectional
}

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

pub enum ApplicationError {
    Unknown
}

/// All strings from "crypto_error_0x100" to "crypto_error_0x1ff".
pub type CryptoError = String;

pub enum ConnectionError {
    TransportError(TransportError),
    CryptoError(CryptoError)
}

pub enum Error {
    TransportError(TransportError),
    CryptoError(CryptoError),
    ApplicationError(ApplicationError)
}

pub enum ConnectionState {
    BaseConnectionState(BaseConnectionState),
    GranularConnectionState(GranularConnectionState)
}

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

pub enum StreamState {
    BaseStreamState(BaseStreamState),
    GranularStreamState(GranularStreamState)
}

pub enum BaseStreamState {
    Idle,
    Open,
    Closed
}

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

pub enum StreamSide {
    Sending,
    Receiving
}

pub struct AlpnIdentifier {
    byte_value: Option<HexString>,
    string_value: Option<String>
}

pub struct PreferredAddress {
    ip_v4: Option<IpAddress>,
    port_v4: Option<u16>,
    ip_v6: Option<IpAddress>,
    port_v6: Option<u16>,
    connection_id: ConnectionId,
    stateless_reset_token: StatelessResetToken
}

pub struct UnknownParameter {
    id: u64,
    value: Option<HexString>
}

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

pub enum PacketReceivedTrigger {
    // If packet was buffered because it couldn't be decrypted before
    KeysAvailable
}

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

pub enum PacketBufferedTrigger {
    /// Indicates the parser cannot keep up, temporarily buffers packet for later processing
    Backpressure,
    /// If packet cannot be decrypted because the proper keys were not yet available
    KeysUnavailable
}

pub enum KeyUpdateTrigger {
    // (e.g., initial, handshake and 0-RTT keys are generated by TLS)
    Tls,
    RemoteUpdate,
    LocalUpdate
}

pub enum KeyDiscardTrigger {
    // (e.g., initial, handshake and 0-RTT keys are generated by TLS)
    Tls,
    RemoteUpdate,
    LocalUpdate
}

pub enum PacketLostTrigger {
    ReorderingThreshold,
    TimeThreshold,
    // RFC 9002 Section 6.2.4 paragraph 6
    PtoExpired
}

pub enum DataLocation {
    Application,
    Transport,
    Network
}

pub enum DataMovedAdditionalInfo {
    FinSet,
    StreamReset
}

/// Note that MigrationState does not describe a full state machine.
/// These entries are not necessarily chronological, nor will they always all appear during a connection migration attempt.
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

pub enum TimerType {
    Ack,
    Pto
}

pub enum EventType {
    Set,
    Expired,
    Cancelled
}

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

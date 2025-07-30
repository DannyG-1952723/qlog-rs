use std::{collections::VecDeque, env, fs::File, io::{BufWriter, Write}, sync::{mpsc::{self, Sender}, LazyLock, Mutex}, thread};

#[cfg(feature = "quic-10")]
use std::collections::HashMap;

#[cfg(feature = "quic-10")]
use chrono::Utc;

use serde::Serialize;

use crate::{events::Event, logfile::{CommonFields, LogFile, QlogFileSeq, ReferenceTime, TimeFormat, TraceSeq, VantagePoint}, quic_10::data::Quic10EventData};

#[cfg(feature = "quic-10")]
use crate::quic_10::{data::QuicFrame, events::{PacketReceived, PacketSent}};

#[cfg(feature = "moq-transfork")]
use crate::moq_transfork::data::StreamType;

// Static variable so that a logger variable doesn't need to be passed to every function wherein logging occurs
static QLOG_WRITER: LazyLock<Mutex<QlogWriter>> = LazyLock::new(|| Mutex::new(QlogWriter::init()));

pub struct QlogWriter {
	sender: Option<Sender<String>>,
	file_details_written: bool,
    #[allow(dead_code)]
	cached_events: VecDeque<Event>,
    #[cfg(feature = "quic-10")]
    cached_sent_quic_packets: HashMap<String, PacketSent>,
    #[cfg(feature = "quic-10")]
    cached_received_quic_packets: HashMap<String, (PacketReceived, i64)>
}

impl QlogWriter {
	const RECORD_SEPARATOR: &[u8] = &[0x1E];
	const LINE_FEED: &[u8] = &[0x0A];

	fn init() -> Self {
		match env::var("QLOGFILE") {
			Ok(qlog_file_path) => {
				match File::create(qlog_file_path) {
					Ok(file) => {
                        let writer = BufWriter::new(file);
                        let (sender, receiver) = mpsc::channel::<String>();

                        // TODO: Maybe add more error handling
	                    // Flushes write buffer after every log, otherwise won't write to file when exiting the program using ^C
                        thread::spawn(move || {
                            let mut writer = writer;
                            while let Ok(message) = receiver.recv() {
                                if writer.write_all(Self::RECORD_SEPARATOR).is_err() { break; }
                                if writer.write_all(message.as_bytes()).is_err() { break; }
                                if writer.write_all(Self::LINE_FEED).is_err() { break; }
                                if writer.flush().is_err() { break; }
                            }
                        });

                        Self {
                            sender: Some(sender),
                            file_details_written: false,
                            cached_events: VecDeque::default(),
                            #[cfg(feature = "quic-10")]
                            cached_sent_quic_packets: HashMap::default(),
                            #[cfg(feature = "quic-10")]
                            cached_received_quic_packets: HashMap::default()
                        }
                    },
					Err(e) => panic!("Error creating qlog file: {e}")
				}
			},
			Err(_) => Self {
                sender: None,
                file_details_written: true,
                cached_events: VecDeque::default(),
                #[cfg(feature = "quic-10")]
                cached_sent_quic_packets: HashMap::default(),
                #[cfg(feature = "quic-10")]
                cached_received_quic_packets: HashMap::default()
            }
		}
	}

	/// Logs the needed details so qlog file readers can interpret the logs correctly
	pub fn log_file_details(file_title: Option<String>, file_description: Option<String>, trace_title: Option<String>, trace_description: Option<String>, vantage_point: Option<VantagePoint>, custom_fields: Option<HashMap<String, String>>) {
		let mut qlog_writer = QLOG_WRITER.lock().unwrap();

		if let Some(ref sender) = qlog_writer.sender {
			let log_file_details = LogFile::new(file_title, file_description);

            let common_fields = match custom_fields {
                Some(fields) => CommonFields::new(
                    Some("".to_string()),
                    Some(TimeFormat::default()),
			        Some(ReferenceTime::default()),
                    None,
                    Some(fields)
                ),
                None => CommonFields::default(),
            };

			let trace = TraceSeq::new(trace_title, trace_description, Some(common_fields), vantage_point);

			let qlog_file_seq = QlogFileSeq::new(log_file_details, trace);

			Self::log(sender, &qlog_file_seq);

			qlog_writer.file_details_written = true;
		}
	}

    #[cfg_attr(feature = "moq-transfork", allow(unreachable_code))]
	pub fn log_event(event: Event) {
        #[cfg(feature = "moq-transfork")]
        return Self::log_moq_event(event);

		let qlog_writer = QLOG_WRITER.lock().unwrap();

		if !qlog_writer.file_details_written {
			panic!("Log the qlog file details before logging events, call 'QlogWriter::log_file_details()' somewhere in the beginning of the program");
		}

		if let Some(ref sender) = qlog_writer.sender {
			Self::log(sender, &event);
		}
	}

	fn log(sender: &Sender<String>, data: &impl Serialize) {
		let json = serde_json::to_string_pretty(data).unwrap();

		if let Err(e) = sender.send(json) {
            eprintln!("Error sending log message: {e}");
        }
	}
}

#[cfg(feature = "moq-transfork")]
impl QlogWriter {
    fn log_moq_event(event: Event) {
        let mut qlog_writer = QLOG_WRITER.lock().unwrap();

		if !qlog_writer.file_details_written {
			panic!("Log the qlog file details before logging events, call 'QlogWriter::log_file_details()' somewhere in the beginning of the program");
		}

		let is_session_started_event = event.moq_is_session_started_client();
		let mut session_stream_event_option: Option<Event> = None;

		if is_session_started_event {
			session_stream_event_option = qlog_writer.cached_events.pop_front();
		}

		if let Some(ref sender) = qlog_writer.sender {
			if Self::is_session_stream_without_id(&event) {
				qlog_writer.cached_events.push_back(event);
			}
			else if is_session_started_event {
				if let Some(mut session_stream_event) = session_stream_event_option {
					session_stream_event.set_group_id(event.get_group_id());

					Self::log(sender, &session_stream_event);
					Self::log(sender, &event);
				}
			}
			else {
				Self::log(sender, &event);
			}
		}
    }

	fn is_session_stream_without_id(event: &Event) -> bool {
		if event.get_name() != "moq-transfork-03:stream_created" && event.get_name() != "moq-transfork-03:stream_parsed" {
			return false;
		}

		if !event.get_group_id().is_some_and(|group_id| group_id == "0") {
			return false;
		}

		event.moq_get_stream_type().is_some_and(|stream_type| *stream_type == StreamType::Session)
	}
}

#[cfg(feature = "quic-10")]
impl QlogWriter {
    pub fn cache_quic_packet_sent(cid: String, packet_num: PacketNum, packet: PacketSent) {
        let mut qlog_writer = QLOG_WRITER.lock().unwrap();

        let key = format!("{}:{}", cid, packet_num);
        let log_key = format!("{}...:{}", cid.get(0..5).unwrap(), packet_num);

        let existing_value = qlog_writer.cached_sent_quic_packets.insert(key, packet);

        if existing_value.is_some() {
            println!("KEY {} ALREADY EXISTS, OVERWROTE QUIC PACKET", log_key);
        }
    }

    pub fn quic_packet_sent_add_frame(cid: String, packet_num: PacketNum, frame: QuicFrame) {
        let mut qlog_writer = QLOG_WRITER.lock().unwrap();

        let key = format!("{}:{}", cid, packet_num);

        match qlog_writer.cached_sent_quic_packets.get_mut(&key) {
            Some(packet) => packet.add_frame(frame),
            None => panic!("Tried to add a frame to a non-existing packet")
        }
    }

    pub fn log_quic_packets_sent(cid: String, packet_nums: Vec<PacketNum>) {
        for packet_num in packet_nums {
            // Need to introduce this extra scope so the lock gets dropped before logging
            let event = {
                let mut qlog_writer = QLOG_WRITER.lock().unwrap();

                let key = format!("{}:{}", cid, packet_num);
                let log_key = format!("{}...:{}", cid.get(0..5).unwrap(), packet_num);

                match qlog_writer.cached_sent_quic_packets.remove(&key) {
                    Some(packet) => {
                        // println!("QUIC packets still cached: {:?}", qlog_writer.cached_sent_quic_packets.keys());
                        Some(Event::new_quic_10("packet_sent", Quic10EventData::PacketSent(packet), Some(cid.clone())))
                    },
                    None => {
                        println!("Tried to log a non-existing packet with key {}", log_key);
                        None
                    }
                }
            };

            if let Some(e) = event {
                QlogWriter::log_event(e);
            }
        }
    }

    pub fn update_packet_length(cid: String, packet_num: PacketNum, payload_length: u16) {
        let mut qlog_writer = QLOG_WRITER.lock().unwrap();

        let key = format!("{}:{}", cid, packet_num);

        let packet = qlog_writer.cached_sent_quic_packets.get_mut(&key);

        match packet {
            Some(packet_sent) => packet_sent.update_packet_length(payload_length),
            None => println!("Can't update packet length: no such packet exists"),
        }
    }

    pub fn cache_quic_packet_received(cid: String, packet_num: PacketNum, packet: PacketReceived) {
        let mut qlog_writer = QLOG_WRITER.lock().unwrap();

        let time = Utc::now().timestamp_millis();

        let key = format!("{}:{}", cid, packet_num);
        let log_key = format!("{}...:{}", cid.get(0..5).unwrap(), packet_num);

        // println!("Received packet ({})", log_key);

        let existing_value = qlog_writer.cached_received_quic_packets.insert(key, (packet, time));

        if existing_value.is_some() {
            println!("KEY {} ALREADY EXISTS, OVERWROTE QUIC PACKET", log_key);
        }
    }

    pub fn quic_packet_received_add_frame(cid: String, packet_num: PacketNum, frame: QuicFrame) {
        let mut qlog_writer = QLOG_WRITER.lock().unwrap();

        let key = format!("{}:{}", cid, packet_num);
        let log_key = format!("{}...:{}", cid.get(0..5).unwrap(), packet_num);

        match qlog_writer.cached_received_quic_packets.get_mut(&key) {
            Some((packet, _)) => {
                // println!("Added {:?} to packet {}", frame, log_key);
                packet.add_frame(frame)
            },
            None => panic!("Tried to add a frame to a non-existing packet ({})", log_key)
        }
    }

    pub fn log_quic_packets_received(cid: String, packet_num: PacketNum) {
        // Need to introduce this extra scope so the lock gets dropped before logging
        let event = {
            let mut qlog_writer = QLOG_WRITER.lock().unwrap();

            let key = format!("{}:{}", cid, packet_num);
            let log_key = format!("{}...:{}", cid.get(0..5).unwrap(), packet_num);

            match qlog_writer.cached_received_quic_packets.remove(&key) {
                Some((packet, time)) => {
                    // println!("QUIC packets still cached: {:?}", qlog_writer.cached_received_quic_packets.keys());
                    Some(Event::new_quic_10_with_time("packet_received", Quic10EventData::PacketReceived(packet), Some(cid.clone()), time))
                },
                None => {
                    println!("Tried to log a non-existing packet with key {}", log_key);
                    None
                }
            }
        };

        if let Some(e) = event {
            QlogWriter::log_event(e);
        }
    }
}

#[cfg(feature = "quic-10")]
#[derive(Clone, Copy, Debug)]
pub enum PacketNum {
    Number(PacketNumSpace, u64),
    Retry,
    StatelessReset,
    VersionNegotiation,
    Unknown
}

#[cfg(feature = "quic-10")]
impl std::fmt::Display for PacketNum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketNum::Number(s, n) => write!(f, "{}:{}", s, n),
            PacketNum::Retry => write!(f, "Retry"),
            PacketNum::StatelessReset => write!(f, "StatelessReset"),
            PacketNum::VersionNegotiation => write!(f, "VersionNegotiation"),
            PacketNum::Unknown => write!(f, "Unknown"),
        }
    }
}

#[cfg(feature = "quic-10")]
#[derive(Clone, Copy, Debug)]
pub enum PacketNumSpace {
    Initial,
    Handshake,
    Data
}

#[cfg(feature = "quic-10")]
impl std::fmt::Display for PacketNumSpace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketNumSpace::Initial => write!(f, "Initial"),
            PacketNumSpace::Handshake => write!(f, "Handshake"),
            PacketNumSpace::Data => write!(f, "Data"),
        }
    }
}

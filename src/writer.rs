use std::{collections::VecDeque, env, fs::File, io::{BufWriter, Write}, sync::{mpsc::{self, Sender}, LazyLock, Mutex}, thread};

use serde::Serialize;

use crate::{events::Event, logfile::{CommonFields, LogFile, QlogFileSeq, TraceSeq, VantagePoint}};

#[cfg(feature = "moq-transfork")]
use crate::moq_transfork::data::StreamType;

// Static variable so that a logger variable doesn't need to be passed to every function wherein logging occurs
static QLOG_WRITER: LazyLock<Mutex<QlogWriter>> = LazyLock::new(|| Mutex::new(QlogWriter::init()));

pub struct QlogWriter {
	sender: Option<Sender<String>>,
	file_details_written: bool,
    #[allow(dead_code)]
	cached_events: VecDeque<Event>
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

                        Self { sender: Some(sender), file_details_written: false, cached_events: VecDeque::default() }
                    },
					Err(e) => panic!("Error creating qlog file: {e}")
				}
			},
			Err(_) => Self { sender: None, file_details_written: true, cached_events: VecDeque::default() }
		}
	}

	/// Logs the needed details so qlog file readers can interpret the logs correctly
	pub fn log_file_details(file_title: Option<String>, file_description: Option<String>, trace_title: Option<String>, trace_description: Option<String>, vantage_point: Option<VantagePoint>) {
		let mut qlog_writer = QLOG_WRITER.lock().unwrap();

		if let Some(ref sender) = qlog_writer.sender {
			let log_file_details = LogFile::new(file_title, file_description);
			let trace = TraceSeq::new(trace_title, trace_description, Some(CommonFields::default()), vantage_point);

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

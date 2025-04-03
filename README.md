# qlog-rs

`qlog-rs` is a library that allows you to log qlog events in your network application.
The qlog structure is based on [IETF draft 11](https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-main-schema/11/) of the specification (latest version at the time of writing).
It currently only supports logging to a `.sqlog` file and custom `moq-transfork` events.

## Usage

Call the following function in your application to start the log file with some file details (title, description...).

```rust
QlogWriter::log_file_details(...);
```

When you want to generate logs, run your application with the `QLOGFILE` environment variable, nothing will get logged if this variable isn't specified.

```bash
QLOGFILE="qlog_file.sqlog" cargo run --bin your-application
```

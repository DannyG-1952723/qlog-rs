use std::fmt::Write;

pub const MAX_LOG_DATA_LEN: usize = 64;

pub type PathId = String;
pub type GroupId = String;
pub type HexString = String;

pub fn bytes_to_hexstring(bytes: &[u8]) -> HexString {
    bytes.iter().fold(String::new(), |mut output, b| {
        let _ = write!(output, "{b:02X}");
        output
    })
}

pub fn is_empty_or_none(path: &Option<PathId>) -> bool {
    match path {
        Some(p) => p.is_empty(),
        None => true,
    }
}

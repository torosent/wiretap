//! Redis RESP Protocol Dissector for Wiretap
//!
//! This plugin parses Redis RESP (REdis Serialization Protocol) messages.
//! Supports RESP2 and RESP3 protocols.
//!
//! Build with:
//! ```
//! cargo build --release --target wasm32-wasip1
//! ```

use std::alloc::{alloc, dealloc, Layout};

/// Plugin name constant
static PLUGIN_NAME: &str = "redis-dissector";
/// Plugin version constant
static PLUGIN_VERSION: &str = "1.0.0";

/// RESP data types
#[derive(Debug, Clone)]
enum RespValue {
    SimpleString(String),
    Error(String),
    Integer(i64),
    BulkString(Option<String>),
    Array(Option<Vec<RespValue>>),
}

impl RespValue {
    fn type_name(&self) -> &'static str {
        match self {
            RespValue::SimpleString(_) => "simple_string",
            RespValue::Error(_) => "error",
            RespValue::Integer(_) => "integer",
            RespValue::BulkString(_) => "bulk_string",
            RespValue::Array(_) => "array",
        }
    }
}

/// Parse RESP value from data
fn parse_resp(data: &[u8]) -> Option<(RespValue, usize)> {
    if data.is_empty() {
        return None;
    }

    match data[0] {
        b'+' => parse_simple_string(&data[1..]).map(|(s, len)| (RespValue::SimpleString(s), len + 1)),
        b'-' => parse_simple_string(&data[1..]).map(|(s, len)| (RespValue::Error(s), len + 1)),
        b':' => parse_integer(&data[1..]).map(|(i, len)| (RespValue::Integer(i), len + 1)),
        b'$' => parse_bulk_string(&data[1..]).map(|(s, len)| (RespValue::BulkString(s), len + 1)),
        b'*' => parse_array(&data[1..]).map(|(arr, len)| (RespValue::Array(arr), len + 1)),
        _ => None,
    }
}

/// Parse simple string (until CRLF)
fn parse_simple_string(data: &[u8]) -> Option<(String, usize)> {
    let crlf_pos = find_crlf(data)?;
    let s = String::from_utf8_lossy(&data[..crlf_pos]).to_string();
    Some((s, crlf_pos + 2))
}

/// Parse integer
fn parse_integer(data: &[u8]) -> Option<(i64, usize)> {
    let crlf_pos = find_crlf(data)?;
    let s = std::str::from_utf8(&data[..crlf_pos]).ok()?;
    let i = s.parse::<i64>().ok()?;
    Some((i, crlf_pos + 2))
}

/// Parse bulk string
fn parse_bulk_string(data: &[u8]) -> Option<(Option<String>, usize)> {
    let crlf_pos = find_crlf(data)?;
    let len_str = std::str::from_utf8(&data[..crlf_pos]).ok()?;
    let len = len_str.parse::<i64>().ok()?;

    if len < 0 {
        // Null bulk string
        return Some((None, crlf_pos + 2));
    }

    let len = len as usize;
    let start = crlf_pos + 2;
    let end = start + len;

    if data.len() < end + 2 {
        return None;
    }

    let s = String::from_utf8_lossy(&data[start..end]).to_string();
    Some((Some(s), end + 2))
}

/// Parse array
fn parse_array(data: &[u8]) -> Option<(Option<Vec<RespValue>>, usize)> {
    let crlf_pos = find_crlf(data)?;
    let count_str = std::str::from_utf8(&data[..crlf_pos]).ok()?;
    let count = count_str.parse::<i64>().ok()?;

    if count < 0 {
        // Null array
        return Some((None, crlf_pos + 2));
    }

    let count = count as usize;
    let mut offset = crlf_pos + 2;
    let mut elements = Vec::with_capacity(count);

    for _ in 0..count {
        let (value, len) = parse_resp(&data[offset..])?;
        elements.push(value);
        offset += len;
    }

    Some((Some(elements), offset))
}

/// Find CRLF position
fn find_crlf(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(1) {
        if data[i] == b'\r' && data[i + 1] == b'\n' {
            return Some(i);
        }
    }
    None
}

/// Escape string for JSON
fn escape_json(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }
    result
}

/// Convert RESP value to JSON
fn resp_to_json(value: &RespValue) -> String {
    match value {
        RespValue::SimpleString(s) => format!(r#"{{"type":"simple_string","value":"{}"}}"#, escape_json(s)),
        RespValue::Error(s) => format!(r#"{{"type":"error","value":"{}"}}"#, escape_json(s)),
        RespValue::Integer(i) => format!(r#"{{"type":"integer","value":{}}}"#, i),
        RespValue::BulkString(None) => r#"{"type":"bulk_string","value":null}"#.to_string(),
        RespValue::BulkString(Some(s)) => format!(r#"{{"type":"bulk_string","value":"{}"}}"#, escape_json(s)),
        RespValue::Array(None) => r#"{"type":"array","value":null}"#.to_string(),
        RespValue::Array(Some(arr)) => {
            let elements: Vec<String> = arr.iter().map(resp_to_json).collect();
            format!(r#"{{"type":"array","value":[{}]}}"#, elements.join(","))
        }
    }
}

/// Extract command from RESP array
fn extract_command(value: &RespValue) -> Option<String> {
    if let RespValue::Array(Some(arr)) = value {
        if let Some(RespValue::BulkString(Some(cmd))) = arr.first() {
            return Some(cmd.to_uppercase());
        }
    }
    None
}

/// Extract command arguments
fn extract_args(value: &RespValue) -> Vec<String> {
    if let RespValue::Array(Some(arr)) = value {
        arr.iter()
            .skip(1)
            .filter_map(|v| {
                if let RespValue::BulkString(Some(s)) = v {
                    Some(s.clone())
                } else {
                    None
                }
            })
            .collect()
    } else {
        vec![]
    }
}

/// Detect if this is a Redis RESP message
#[no_mangle]
pub extern "C" fn detect(ptr: *const u8, len: usize) -> i32 {
    if len < 3 {
        return 0;
    }

    let data = unsafe { std::slice::from_raw_parts(ptr, len) };

    // Check for RESP type indicators
    match data[0] {
        b'+' | b'-' | b':' | b'$' | b'*' => {
            // Try to parse to verify it's valid RESP
            if parse_resp(data).is_some() {
                return 1;
            }
        }
        _ => {}
    }

    0
}

/// Parse Redis RESP message and return JSON
#[no_mangle]
pub extern "C" fn parse(in_ptr: *const u8, in_len: usize, out_len_ptr: *mut u32) -> *mut u8 {
    let data = unsafe { std::slice::from_raw_parts(in_ptr, in_len) };

    let (value, _) = match parse_resp(data) {
        Some(v) => v,
        None => return std::ptr::null_mut(),
    };

    let command = extract_command(&value);
    let args = extract_args(&value);

    let app_info = if let Some(ref cmd) = command {
        if !args.is_empty() {
            format!("REDIS {} {}", cmd, args.first().unwrap_or(&String::new()))
        } else {
            format!("REDIS {}", cmd)
        }
    } else {
        format!("REDIS {}", value.type_name())
    };

    let json = if let Some(cmd) = command {
        let args_json: Vec<String> = args.iter().map(|a| format!(r#""{}""#, escape_json(a))).collect();
        format!(
            r#"{{"app_info":"{}","protocol":"REDIS","fields":{{"command":"{}","args":[{}],"raw":{}}}}}"#,
            escape_json(&app_info),
            cmd,
            args_json.join(","),
            resp_to_json(&value)
        )
    } else {
        format!(
            r#"{{"app_info":"{}","protocol":"REDIS","fields":{{"response":{}}}}}"#,
            escape_json(&app_info),
            resp_to_json(&value)
        )
    };

    let bytes = json.into_bytes();
    unsafe { *out_len_ptr = bytes.len() as u32 };

    let layout = Layout::from_size_align(bytes.len(), 1).unwrap();
    let out_ptr = unsafe { alloc(layout) };
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_ptr, bytes.len()) };

    out_ptr
}

/// Allocate memory
#[no_mangle]
pub extern "C" fn alloc(size: usize) -> *mut u8 {
    if size == 0 {
        return std::ptr::null_mut();
    }
    let layout = Layout::from_size_align(size, 1).unwrap();
    unsafe { alloc(layout) }
}

/// Free memory
#[no_mangle]
pub extern "C" fn free(ptr: *mut u8, size: usize) {
    if ptr.is_null() || size == 0 {
        return;
    }
    let layout = Layout::from_size_align(size, 1).unwrap();
    unsafe { dealloc(ptr, layout) };
}

/// Return plugin name
#[no_mangle]
pub extern "C" fn plugin_name() -> (i32, i32) {
    (PLUGIN_NAME.as_ptr() as i32, PLUGIN_NAME.len() as i32)
}

/// Return plugin version
#[no_mangle]
pub extern "C" fn plugin_version() -> (i32, i32) {
    (PLUGIN_VERSION.as_ptr() as i32, PLUGIN_VERSION.len() as i32)
}

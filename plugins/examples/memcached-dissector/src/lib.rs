//! Memcached Protocol Dissector for Wiretap
//!
//! This plugin parses Memcached text and binary protocol messages.
//!
//! Build with:
//! ```
//! cargo build --release --target wasm32-wasip1
//! ```

use std::alloc::{alloc, dealloc, Layout};

/// Plugin name constant
static PLUGIN_NAME: &str = "memcached-dissector";
/// Plugin version constant
static PLUGIN_VERSION: &str = "1.0.0";

/// Memcached binary protocol magic bytes
const BINARY_REQUEST_MAGIC: u8 = 0x80;
const BINARY_RESPONSE_MAGIC: u8 = 0x81;

/// Memcached binary opcodes
fn opcode_name(opcode: u8) -> &'static str {
    match opcode {
        0x00 => "GET",
        0x01 => "SET",
        0x02 => "ADD",
        0x03 => "REPLACE",
        0x04 => "DELETE",
        0x05 => "INCREMENT",
        0x06 => "DECREMENT",
        0x07 => "QUIT",
        0x08 => "FLUSH",
        0x09 => "GETQ",
        0x0a => "NOOP",
        0x0b => "VERSION",
        0x0c => "GETK",
        0x0d => "GETKQ",
        0x0e => "APPEND",
        0x0f => "PREPEND",
        0x10 => "STAT",
        0x11 => "SETQ",
        0x12 => "ADDQ",
        0x13 => "REPLACEQ",
        0x14 => "DELETEQ",
        0x15 => "INCREMENTQ",
        0x16 => "DECREMENTQ",
        0x17 => "QUITQ",
        0x18 => "FLUSHQ",
        0x19 => "APPENDQ",
        0x1a => "PREPENDQ",
        0x20 => "SASL_LIST_MECHS",
        0x21 => "SASL_AUTH",
        0x22 => "SASL_STEP",
        _ => "UNKNOWN",
    }
}

/// Memcached binary response status
fn status_name(status: u16) -> &'static str {
    match status {
        0x0000 => "No error",
        0x0001 => "Key not found",
        0x0002 => "Key exists",
        0x0003 => "Value too large",
        0x0004 => "Invalid arguments",
        0x0005 => "Item not stored",
        0x0006 => "Non-numeric value",
        0x0081 => "Unknown command",
        0x0082 => "Out of memory",
        _ => "Unknown status",
    }
}

/// Memcached text protocol commands
fn text_command(cmd: &str) -> Option<&'static str> {
    match cmd.to_uppercase().as_str() {
        "GET" | "GETS" => Some("GET"),
        "SET" => Some("SET"),
        "ADD" => Some("ADD"),
        "REPLACE" => Some("REPLACE"),
        "APPEND" => Some("APPEND"),
        "PREPEND" => Some("PREPEND"),
        "CAS" => Some("CAS"),
        "DELETE" => Some("DELETE"),
        "INCR" => Some("INCR"),
        "DECR" => Some("DECR"),
        "TOUCH" => Some("TOUCH"),
        "STATS" => Some("STATS"),
        "FLUSH_ALL" => Some("FLUSH_ALL"),
        "VERSION" => Some("VERSION"),
        "QUIT" => Some("QUIT"),
        "VALUE" => Some("VALUE"),
        "END" => Some("END"),
        "STORED" => Some("STORED"),
        "NOT_STORED" => Some("NOT_STORED"),
        "EXISTS" => Some("EXISTS"),
        "NOT_FOUND" => Some("NOT_FOUND"),
        "DELETED" => Some("DELETED"),
        "TOUCHED" => Some("TOUCHED"),
        "ERROR" => Some("ERROR"),
        "CLIENT_ERROR" => Some("CLIENT_ERROR"),
        "SERVER_ERROR" => Some("SERVER_ERROR"),
        _ => None,
    }
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

/// Check if data is binary protocol
fn is_binary_protocol(data: &[u8]) -> bool {
    if data.len() < 24 {
        return false;
    }
    data[0] == BINARY_REQUEST_MAGIC || data[0] == BINARY_RESPONSE_MAGIC
}

/// Parse binary protocol header
fn parse_binary(data: &[u8]) -> Option<String> {
    if data.len() < 24 {
        return None;
    }

    let magic = data[0];
    let opcode = data[1];
    let key_length = ((data[2] as u16) << 8) | (data[3] as u16);
    let extras_length = data[4];
    let _data_type = data[5];
    let status_or_vbucket = ((data[6] as u16) << 8) | (data[7] as u16);
    let total_body_length = ((data[8] as u32) << 24)
        | ((data[9] as u32) << 16)
        | ((data[10] as u32) << 8)
        | (data[11] as u32);
    let opaque = ((data[12] as u32) << 24)
        | ((data[13] as u32) << 16)
        | ((data[14] as u32) << 8)
        | (data[15] as u32);
    let cas = ((data[16] as u64) << 56)
        | ((data[17] as u64) << 48)
        | ((data[18] as u64) << 40)
        | ((data[19] as u64) << 32)
        | ((data[20] as u64) << 24)
        | ((data[21] as u64) << 16)
        | ((data[22] as u64) << 8)
        | (data[23] as u64);

    let opcode_str = opcode_name(opcode);
    let is_request = magic == BINARY_REQUEST_MAGIC;

    // Extract key if present
    let key = if key_length > 0 {
        let key_start = 24 + extras_length as usize;
        let key_end = key_start + key_length as usize;
        if data.len() >= key_end {
            Some(String::from_utf8_lossy(&data[key_start..key_end]).to_string())
        } else {
            None
        }
    } else {
        None
    };

    let app_info = if let Some(ref k) = key {
        format!("MEMCACHED {} {}", opcode_str, k)
    } else {
        format!("MEMCACHED {}", opcode_str)
    };

    let json = if is_request {
        format!(
            r#"{{"app_info":"{}","protocol":"MEMCACHED","fields":{{"type":"request","opcode":"{}","key_length":{},"extras_length":{},"vbucket":{},"body_length":{},"opaque":{},"cas":{},"key":{}}}}}"#,
            escape_json(&app_info),
            opcode_str,
            key_length,
            extras_length,
            status_or_vbucket,
            total_body_length,
            opaque,
            cas,
            key.map(|k| format!(r#""{}""#, escape_json(&k))).unwrap_or_else(|| "null".to_string())
        )
    } else {
        let status_str = status_name(status_or_vbucket);
        format!(
            r#"{{"app_info":"{}","protocol":"MEMCACHED","fields":{{"type":"response","opcode":"{}","status":{},"status_str":"{}","key_length":{},"extras_length":{},"body_length":{},"opaque":{},"cas":{},"key":{}}}}}"#,
            escape_json(&app_info),
            opcode_str,
            status_or_vbucket,
            status_str,
            key_length,
            extras_length,
            total_body_length,
            opaque,
            cas,
            key.map(|k| format!(r#""{}""#, escape_json(&k))).unwrap_or_else(|| "null".to_string())
        )
    };

    Some(json)
}

/// Parse text protocol
fn parse_text(data: &[u8]) -> Option<String> {
    // Find end of line
    let line_end = data.iter().position(|&b| b == b'\r' || b == b'\n')?;
    let line = std::str::from_utf8(&data[..line_end]).ok()?;

    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }

    let cmd = text_command(parts[0])?;

    let app_info = if parts.len() > 1 {
        format!("MEMCACHED {} {}", cmd, parts[1])
    } else {
        format!("MEMCACHED {}", cmd)
    };

    let is_response = matches!(
        cmd,
        "VALUE" | "END" | "STORED" | "NOT_STORED" | "EXISTS" | "NOT_FOUND" | "DELETED" | "TOUCHED" | "ERROR" | "CLIENT_ERROR" | "SERVER_ERROR"
    );

    let args: Vec<String> = parts.iter().skip(1).map(|&s| format!(r#""{}""#, escape_json(s))).collect();

    let json = format!(
        r#"{{"app_info":"{}","protocol":"MEMCACHED","fields":{{"type":"{}","command":"{}","args":[{}]}}}}"#,
        escape_json(&app_info),
        if is_response { "response" } else { "request" },
        cmd,
        args.join(",")
    );

    Some(json)
}

/// Detect if this is a Memcached message
#[no_mangle]
pub extern "C" fn detect(ptr: *const u8, len: usize) -> i32 {
    if len < 4 {
        return 0;
    }

    let data = unsafe { std::slice::from_raw_parts(ptr, len) };

    // Check for binary protocol
    if is_binary_protocol(data) {
        return 1;
    }

    // Check for text protocol commands
    let line_end = data.iter().position(|&b| b == b'\r' || b == b'\n').unwrap_or(len.min(100));
    if let Ok(line) = std::str::from_utf8(&data[..line_end]) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if !parts.is_empty() && text_command(parts[0]).is_some() {
            return 1;
        }
    }

    0
}

/// Parse Memcached message and return JSON
#[no_mangle]
pub extern "C" fn parse(in_ptr: *const u8, in_len: usize, out_len_ptr: *mut u32) -> *mut u8 {
    let data = unsafe { std::slice::from_raw_parts(in_ptr, in_len) };

    let json = if is_binary_protocol(data) {
        match parse_binary(data) {
            Some(j) => j,
            None => return std::ptr::null_mut(),
        }
    } else {
        match parse_text(data) {
            Some(j) => j,
            None => return std::ptr::null_mut(),
        }
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

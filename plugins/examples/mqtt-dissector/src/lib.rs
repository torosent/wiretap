//! MQTT Protocol Dissector for Wiretap
//!
//! This plugin parses MQTT 3.1.1 and 5.0 protocol messages.
//!
//! Build with:
//! ```
//! cargo build --release --target wasm32-wasip1
//! ```

use std::alloc::{alloc, dealloc, Layout};

/// Plugin name constant
static PLUGIN_NAME: &str = "mqtt-dissector";
/// Plugin version constant
static PLUGIN_VERSION: &str = "1.0.0";

/// MQTT packet types
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
enum PacketType {
    Connect = 1,
    Connack = 2,
    Publish = 3,
    Puback = 4,
    Pubrec = 5,
    Pubrel = 6,
    Pubcomp = 7,
    Subscribe = 8,
    Suback = 9,
    Unsubscribe = 10,
    Unsuback = 11,
    Pingreq = 12,
    Pingresp = 13,
    Disconnect = 14,
    Auth = 15,
}

impl PacketType {
    fn from_byte(b: u8) -> Option<Self> {
        match (b >> 4) & 0x0F {
            1 => Some(PacketType::Connect),
            2 => Some(PacketType::Connack),
            3 => Some(PacketType::Publish),
            4 => Some(PacketType::Puback),
            5 => Some(PacketType::Pubrec),
            6 => Some(PacketType::Pubrel),
            7 => Some(PacketType::Pubcomp),
            8 => Some(PacketType::Subscribe),
            9 => Some(PacketType::Suback),
            10 => Some(PacketType::Unsubscribe),
            11 => Some(PacketType::Unsuback),
            12 => Some(PacketType::Pingreq),
            13 => Some(PacketType::Pingresp),
            14 => Some(PacketType::Disconnect),
            15 => Some(PacketType::Auth),
            _ => None,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            PacketType::Connect => "CONNECT",
            PacketType::Connack => "CONNACK",
            PacketType::Publish => "PUBLISH",
            PacketType::Puback => "PUBACK",
            PacketType::Pubrec => "PUBREC",
            PacketType::Pubrel => "PUBREL",
            PacketType::Pubcomp => "PUBCOMP",
            PacketType::Subscribe => "SUBSCRIBE",
            PacketType::Suback => "SUBACK",
            PacketType::Unsubscribe => "UNSUBSCRIBE",
            PacketType::Unsuback => "UNSUBACK",
            PacketType::Pingreq => "PINGREQ",
            PacketType::Pingresp => "PINGRESP",
            PacketType::Disconnect => "DISCONNECT",
            PacketType::Auth => "AUTH",
        }
    }
}

/// Decode MQTT variable length integer
fn decode_remaining_length(data: &[u8]) -> Option<(usize, usize)> {
    let mut multiplier = 1usize;
    let mut value = 0usize;
    let mut idx = 0;

    loop {
        if idx >= data.len() || idx >= 4 {
            return None;
        }

        let byte = data[idx] as usize;
        value += (byte & 0x7F) * multiplier;
        multiplier *= 128;
        idx += 1;

        if byte & 0x80 == 0 {
            break;
        }
    }

    Some((value, idx))
}

/// Decode MQTT UTF-8 string
fn decode_string(data: &[u8]) -> Option<(&str, usize)> {
    if data.len() < 2 {
        return None;
    }

    let len = ((data[0] as usize) << 8) | (data[1] as usize);
    if data.len() < 2 + len {
        return None;
    }

    let s = std::str::from_utf8(&data[2..2 + len]).ok()?;
    Some((s, 2 + len))
}

/// Escape a string for JSON
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

/// Detect if this is an MQTT packet
#[no_mangle]
pub extern "C" fn detect(ptr: *const u8, len: usize) -> i32 {
    if len < 2 {
        return 0;
    }

    let data = unsafe { std::slice::from_raw_parts(ptr, len) };

    // Check if first byte has valid packet type
    let packet_type = (data[0] >> 4) & 0x0F;
    if packet_type < 1 || packet_type > 15 {
        return 0;
    }

    // Try to decode remaining length
    if decode_remaining_length(&data[1..]).is_none() {
        return 0;
    }

    1
}

/// Parse MQTT packet and return JSON
#[no_mangle]
pub extern "C" fn parse(in_ptr: *const u8, in_len: usize, out_len_ptr: *mut u32) -> *mut u8 {
    let data = unsafe { std::slice::from_raw_parts(in_ptr, in_len) };

    if data.len() < 2 {
        return std::ptr::null_mut();
    }

    let packet_type = match PacketType::from_byte(data[0]) {
        Some(pt) => pt,
        None => return std::ptr::null_mut(),
    };

    let flags = data[0] & 0x0F;
    let (remaining_len, header_len) = match decode_remaining_length(&data[1..]) {
        Some((len, hlen)) => (len, 1 + hlen),
        None => return std::ptr::null_mut(),
    };

    let payload = if data.len() > header_len {
        &data[header_len..]
    } else {
        &[]
    };

    // Build JSON based on packet type
    let json = match packet_type {
        PacketType::Connect => parse_connect(payload, remaining_len),
        PacketType::Connack => parse_connack(payload),
        PacketType::Publish => parse_publish(payload, flags),
        PacketType::Subscribe => parse_subscribe(payload),
        PacketType::Disconnect => parse_disconnect(payload),
        _ => format!(
            r#"{{"app_info":"MQTT {}","protocol":"MQTT","fields":{{"type":"{}","flags":{},"remaining_length":{}}}}}"#,
            packet_type.name(),
            packet_type.name(),
            flags,
            remaining_len
        ),
    };

    let bytes = json.into_bytes();
    unsafe { *out_len_ptr = bytes.len() as u32 };

    let layout = Layout::from_size_align(bytes.len(), 1).unwrap();
    let out_ptr = unsafe { alloc(layout) };
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_ptr, bytes.len()) };

    out_ptr
}

fn parse_connect(payload: &[u8], _remaining_len: usize) -> String {
    let mut offset = 0;

    // Protocol name
    let protocol_name = if let Some((name, len)) = decode_string(&payload[offset..]) {
        offset += len;
        name
    } else {
        return format!(
            r#"{{"app_info":"MQTT CONNECT","protocol":"MQTT","fields":{{"type":"CONNECT"}}}}"#
        );
    };

    // Protocol version
    let protocol_version = if offset < payload.len() {
        let v = payload[offset];
        offset += 1;
        v
    } else {
        0
    };

    // Connect flags
    let connect_flags = if offset < payload.len() {
        let f = payload[offset];
        offset += 1;
        f
    } else {
        0
    };

    let clean_session = (connect_flags & 0x02) != 0;
    let will_flag = (connect_flags & 0x04) != 0;
    let will_qos = (connect_flags >> 3) & 0x03;
    let will_retain = (connect_flags & 0x20) != 0;
    let password_flag = (connect_flags & 0x40) != 0;
    let username_flag = (connect_flags & 0x80) != 0;

    // Keep alive
    let keep_alive = if offset + 2 <= payload.len() {
        let ka = ((payload[offset] as u16) << 8) | (payload[offset + 1] as u16);
        offset += 2;
        ka
    } else {
        0
    };

    // Client ID
    let client_id = if let Some((cid, len)) = decode_string(&payload[offset..]) {
        offset += len;
        escape_json(cid)
    } else {
        String::new()
    };

    // Username (if present)
    let username = if username_flag {
        if let Some((u, _)) = decode_string(&payload[offset..]) {
            escape_json(u)
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    format!(
        r#"{{"app_info":"MQTT CONNECT client={}","protocol":"MQTT","fields":{{"type":"CONNECT","protocol_name":"{}","protocol_version":{},"clean_session":{},"will_flag":{},"will_qos":{},"will_retain":{},"username_flag":{},"password_flag":{},"keep_alive":{},"client_id":"{}","username":"{}"}}}}"#,
        client_id,
        protocol_name,
        protocol_version,
        clean_session,
        will_flag,
        will_qos,
        will_retain,
        username_flag,
        password_flag,
        keep_alive,
        client_id,
        username
    )
}

fn parse_connack(payload: &[u8]) -> String {
    if payload.len() < 2 {
        return format!(
            r#"{{"app_info":"MQTT CONNACK","protocol":"MQTT","fields":{{"type":"CONNACK"}}}}"#
        );
    }

    let session_present = (payload[0] & 0x01) != 0;
    let return_code = payload[1];

    let return_code_str = match return_code {
        0 => "Connection Accepted",
        1 => "Unacceptable Protocol Version",
        2 => "Identifier Rejected",
        3 => "Server Unavailable",
        4 => "Bad Username/Password",
        5 => "Not Authorized",
        _ => "Unknown",
    };

    format!(
        r#"{{"app_info":"MQTT CONNACK {}","protocol":"MQTT","fields":{{"type":"CONNACK","session_present":{},"return_code":{},"return_code_str":"{}"}}}}"#,
        return_code_str,
        session_present,
        return_code,
        return_code_str
    )
}

fn parse_publish(payload: &[u8], flags: u8) -> String {
    let dup = (flags & 0x08) != 0;
    let qos = (flags >> 1) & 0x03;
    let retain = (flags & 0x01) != 0;

    let mut offset = 0;

    // Topic name
    let topic = if let Some((t, len)) = decode_string(&payload[offset..]) {
        offset += len;
        escape_json(t)
    } else {
        return format!(
            r#"{{"app_info":"MQTT PUBLISH","protocol":"MQTT","fields":{{"type":"PUBLISH","dup":{},"qos":{},"retain":{}}}}}"#,
            dup, qos, retain
        );
    };

    // Packet ID (only for QoS > 0)
    let packet_id = if qos > 0 && offset + 2 <= payload.len() {
        let pid = ((payload[offset] as u16) << 8) | (payload[offset + 1] as u16);
        offset += 2;
        pid
    } else {
        0
    };

    let payload_len = payload.len().saturating_sub(offset);

    format!(
        r#"{{"app_info":"MQTT PUBLISH topic={}","protocol":"MQTT","fields":{{"type":"PUBLISH","dup":{},"qos":{},"retain":{},"topic":"{}","packet_id":{},"payload_length":{}}}}}"#,
        topic, dup, qos, retain, topic, packet_id, payload_len
    )
}

fn parse_subscribe(payload: &[u8]) -> String {
    if payload.len() < 2 {
        return format!(
            r#"{{"app_info":"MQTT SUBSCRIBE","protocol":"MQTT","fields":{{"type":"SUBSCRIBE"}}}}"#
        );
    }

    let packet_id = ((payload[0] as u16) << 8) | (payload[1] as u16);
    let mut offset = 2;
    let mut topics = Vec::new();

    while offset < payload.len() {
        if let Some((topic, len)) = decode_string(&payload[offset..]) {
            offset += len;
            if offset < payload.len() {
                let qos = payload[offset] & 0x03;
                offset += 1;
                topics.push(format!(r#"{{"topic":"{}","qos":{}}}"#, escape_json(topic), qos));
            }
        } else {
            break;
        }
    }

    let topics_str = topics.join(",");
    let first_topic = if !topics.is_empty() {
        // Extract first topic name for app_info
        if let Some((t, _)) = decode_string(&payload[2..]) {
            escape_json(t)
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    format!(
        r#"{{"app_info":"MQTT SUBSCRIBE topic={}","protocol":"MQTT","fields":{{"type":"SUBSCRIBE","packet_id":{},"topics":[{}]}}}}"#,
        first_topic, packet_id, topics_str
    )
}

fn parse_disconnect(payload: &[u8]) -> String {
    // MQTT 5.0 DISCONNECT has reason code
    let reason_code = if !payload.is_empty() {
        payload[0]
    } else {
        0 // Normal disconnection
    };

    let reason_str = match reason_code {
        0 => "Normal disconnection",
        4 => "Disconnect with Will Message",
        128 => "Unspecified error",
        129 => "Malformed Packet",
        130 => "Protocol Error",
        131 => "Implementation specific error",
        144 => "Topic Name invalid",
        147 => "Receive Maximum exceeded",
        148 => "Topic Alias invalid",
        149 => "Packet too large",
        153 => "Payload format invalid",
        _ => "Unknown",
    };

    format!(
        r#"{{"app_info":"MQTT DISCONNECT {}","protocol":"MQTT","fields":{{"type":"DISCONNECT","reason_code":{},"reason":"{}"}}}}"#,
        reason_str, reason_code, reason_str
    )
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

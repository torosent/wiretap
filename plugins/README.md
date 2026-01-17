# Wiretap WASM Plugins

Wiretap supports custom protocol dissectors via WebAssembly plugins. Plugins run in a secure, sandboxed environment using the [wazero](https://github.com/tetratelabs/wazero) runtime.

## Plugin API

Plugins must export the following functions:

### Required Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `detect` | `(ptr: i32, len: i32) -> i32` | Returns 1 if plugin can parse this data, 0 otherwise |
| `parse` | `(in_ptr: i32, in_len: i32, out_len_ptr: i32) -> i32` | Parses data, returns pointer to JSON output |
| `alloc` | `(size: i32) -> i32` | Allocates memory in plugin, returns pointer |
| `free` | `(ptr: i32, size: i32)` | Frees previously allocated memory |

### Optional Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `plugin_name` | `() -> (ptr: i32, len: i32)` | Returns plugin name |
| `plugin_version` | `() -> (ptr: i32, len: i32)` | Returns plugin version |

## Output Format

The `parse` function should return a JSON object with parsed fields:

```json
{
  "app_info": "Brief description for packet list",
  "protocol": "CUSTOM",
  "fields": {
    "field1": "value1",
    "field2": 123,
    "nested": {
      "key": "value"
    }
  }
}
```

## Building Plugins

### Rust (Recommended)

Rust provides excellent WASM support with small binary sizes.

```bash
cd plugins/examples/mqtt-dissector
cargo build --release --target wasm32-wasip1
cp target/wasm32-wasip1/release/mqtt_dissector.wasm ../../
```

### TinyGo

TinyGo can compile Go to WASM with small binary sizes.

```bash
tinygo build -o plugin.wasm -target wasi ./plugin.go
```

### AssemblyScript

AssemblyScript is TypeScript-like and compiles to WASM.

```bash
asc plugin.ts -o plugin.wasm --optimize
```

## Example: MQTT Dissector (Rust)

See [examples/mqtt-dissector](examples/mqtt-dissector/) for a complete example.

```rust
use std::alloc::{alloc, dealloc, Layout};

#[no_mangle]
pub extern "C" fn detect(ptr: *const u8, len: usize) -> i32 {
    let data = unsafe { std::slice::from_raw_parts(ptr, len) };
    
    // MQTT packets start with a control byte
    // First 4 bits are packet type (1-15)
    if data.is_empty() {
        return 0;
    }
    
    let packet_type = (data[0] >> 4) & 0x0F;
    if packet_type >= 1 && packet_type <= 14 {
        return 1;
    }
    
    0
}

#[no_mangle]
pub extern "C" fn parse(
    in_ptr: *const u8,
    in_len: usize,
    out_len_ptr: *mut u32,
) -> *mut u8 {
    let data = unsafe { std::slice::from_raw_parts(in_ptr, in_len) };
    
    // Parse MQTT packet
    let packet_type = match (data[0] >> 4) & 0x0F {
        1 => "CONNECT",
        2 => "CONNACK",
        3 => "PUBLISH",
        4 => "PUBACK",
        8 => "SUBSCRIBE",
        9 => "SUBACK",
        12 => "PINGREQ",
        13 => "PINGRESP",
        14 => "DISCONNECT",
        _ => "UNKNOWN",
    };
    
    let json = format!(
        r#"{{"app_info":"MQTT {}","protocol":"MQTT","fields":{{"type":"{}"}}}}"#,
        packet_type, packet_type
    );
    
    let bytes = json.into_bytes();
    unsafe { *out_len_ptr = bytes.len() as u32 };
    
    let layout = Layout::from_size_align(bytes.len(), 1).unwrap();
    let out_ptr = unsafe { alloc(layout) };
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_ptr, bytes.len()) };
    
    out_ptr
}

#[no_mangle]
pub extern "C" fn alloc(size: usize) -> *mut u8 {
    let layout = Layout::from_size_align(size, 1).unwrap();
    unsafe { alloc(layout) }
}

#[no_mangle]
pub extern "C" fn free(ptr: *mut u8, size: usize) {
    let layout = Layout::from_size_align(size, 1).unwrap();
    unsafe { dealloc(ptr, layout) };
}

static PLUGIN_NAME: &str = "mqtt-dissector";
static PLUGIN_VERSION: &str = "1.0.0";

#[no_mangle]
pub extern "C" fn plugin_name() -> (i32, i32) {
    (PLUGIN_NAME.as_ptr() as i32, PLUGIN_NAME.len() as i32)
}

#[no_mangle]
pub extern "C" fn plugin_version() -> (i32, i32) {
    (PLUGIN_VERSION.as_ptr() as i32, PLUGIN_VERSION.len() as i32)
}
```

## Loading Plugins

```bash
# Load all plugins from directory
wiretap read capture.pcap --plugin-dir ./plugins/

# Load specific plugin
wiretap read capture.pcap --plugin ./plugins/mqtt-dissector.wasm

# Via configuration file
# ~/.config/wiretap/config.yaml
plugins:
  directory: ~/.config/wiretap/plugins
  enabled:
    - mqtt-dissector.wasm
    - custom-protocol.wasm
```

## Security

Plugins run in a sandboxed WASM environment with:

- **No filesystem access** - Plugins cannot read/write files
- **No network access** - Plugins cannot make network connections
- **Memory isolation** - Each plugin has its own memory space

Note: CPU time limits are not enforced by default.

## Debugging

There is currently no dedicated plugin debug logging flag or environment variable.

## Plugin Directory

Place compiled `.wasm` files in:
- `./plugins/` (current directory)
- `~/.config/wiretap/plugins/` (user config)
- Specify via `--plugin-dir` flag

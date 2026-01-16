# Wiretap WASM Plugins

This directory contains WASM plugins for extending Wiretap with custom protocol dissectors.

## Example Plugins

| Plugin | Description | Protocol |
|--------|-------------|----------|
| [mqtt-dissector](examples/mqtt-dissector/) | MQTT 3.1.1/5.0 protocol parser | IoT messaging |
| [redis-dissector](examples/redis-dissector/) | Redis RESP protocol parser | Cache/database |
| [memcached-dissector](examples/memcached-dissector/) | Memcached text/binary protocol | Cache |

## Building Plugins

```bash
# Build all plugins
./build.sh

# Or build individually
cd examples/mqtt-dissector
cargo build --release --target wasm32-wasip1
```

### Prerequisites

```bash
# Install Rust WASM target
rustup target add wasm32-wasip1
```

## Using Plugins

```bash
# Load all plugins from this directory
wiretap capture -i eth0 --plugin-dir ./plugins/

# Load specific plugin
wiretap capture -i eth0 --plugin ./plugins/mqtt-dissector.wasm
```

## Creating New Plugins

1. Copy an example plugin as a starting point
2. Implement the required functions: `detect`, `parse`, `alloc`, `free`
3. Build with `cargo build --release --target wasm32-wasip1`
4. Copy `.wasm` file to plugins directory

See [README.md](README.md) for the full plugin API documentation.

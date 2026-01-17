# wiretap

[![Test Coverage](https://codecov.io/gh/torosent/wiretap/branch/main/graph/badge.svg)](https://codecov.io/gh/torosent/wiretap)
[![Go Report Card](https://goreportcard.com/badge/github.com/torosent/wiretap)](https://goreportcard.com/report/github.com/torosent/wiretap)

A network packet analyzer written in Go.

## Features

- **Live Packet Capture**: Capture packets from network interfaces in real-time
- **PCAP File Analysis**: Read and analyze pcap/pcapng files
- **Protocol Dissection**: Deep packet inspection for:
  - Ethernet, IPv4, IPv6, ARP
  - TCP, UDP, ICMP
  - DNS
  - HTTP/1.x and HTTP/2 (cleartext h2c)
  - TLS (handshake metadata, SNI, certificates, JA3 fingerprinting)
  - **WebSocket** (frames, masking, text/binary messages)
  - **gRPC** (HTTP/2-based RPC with schema-less decoding; descriptor sets optional)
- **TLS Decryption**: Decrypt HTTPS traffic using SSLKEYLOGFILE
- **Domain Filtering**: Filter by domain patterns, IP addresses/CIDR, and ports
- **WASM Plugins**: Extend with custom protocol dissectors in WebAssembly
- **Memory-Mapped Indexing**: Efficiently handle large capture files (millions of packets)
- **BPF Filters**: Use Berkeley Packet Filter syntax for capture filtering
- **Terminal UI**: Three-pane Wireshark-style interface with packet list, protocol tree, and hex view
- **Export Formats**: JSON, JSONL, CSV for packets; HAR for HTTP conversations

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/torosent/wiretap.git
cd wiretap

# Build
make build

# Install (optional)
make install
```

### Prerequisites

**macOS:**
```bash
# libpcap is included with macOS, but you may need:
xcode-select --install
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt-get install libpcap-dev
```

**Linux (RHEL/Fedora):**
```bash
sudo dnf install libpcap-devel
```

### Permissions

Packet capture requires elevated privileges:

**macOS:**
```bash
# Create the access_bpf group if it doesn't exist
sudo dseditgroup -o create -q access_bpf

# Add yourself to the access_bpf group (requires restart)
sudo dseditgroup -o edit -a $(whoami) -t user access_bpf
```

**Linux:**
```bash
# Set capabilities on the binary
sudo setcap cap_net_raw,cap_net_admin+ep ./build/wiretap

# Or run with sudo
sudo ./build/wiretap capture -i eth0
```

## Usage

### Live Capture

```bash
# Capture on interface eth0
wiretap capture -i eth0

# Capture with BPF filter
wiretap capture -i eth0 -f "tcp port 80 or tcp port 443"

# Capture and save to file
wiretap capture -i eth0 -w capture.pcap

# Capture with packet limit
wiretap capture -i eth0 -c 1000
```

### TLS Decryption

Decrypt HTTPS/TLS traffic using the NSS SSLKEYLOGFILE format:

```bash
# Capture traffic while logging TLS keys (decryption happens during read/export)
wiretap capture -i eth0 -w capture.pcap -f "tcp port 443"

# Read pcap with TLS decryption
wiretap read capture.pcap --decrypt --keylog /path/to/sslkeys.log
```

**Generating SSLKEYLOGFILE:**

Most browsers and applications support exporting TLS keys:

```bash
# Chrome/Chromium
SSLKEYLOGFILE=/tmp/sslkeys.log google-chrome

# Firefox
SSLKEYLOGFILE=/tmp/sslkeys.log firefox

# curl
SSLKEYLOGFILE=/tmp/sslkeys.log curl https://example.com

# Python requests
SSLKEYLOGFILE=/tmp/sslkeys.log python script.py
```

### gRPC Analysis

Analyze gRPC traffic with optional protobuf descriptor sets:

```bash
# Basic gRPC analysis (schema-less decoding)
wiretap read capture.pcap --protocol grpc

# With descriptor sets for better field names
# Generate: protoc --descriptor_set_out=desc.pb your.proto
wiretap read capture.pcap --proto-dir ./protos/

# Specify individual descriptor sets
wiretap read capture.pcap --proto-file api.pb --proto-file types.pb
```

### Domain Filtering

Filter traffic by domain, IP address, or port (domain detection uses HTTP Host, TLS SNI, or DNS queries when available):

```bash
# Include only specific domains
wiretap capture -i eth0 --include-domain "*.example.com"

# Exclude internal traffic
wiretap capture -i eth0 --exclude-domain "internal.corp.com"

# Filter by IP/CIDR
wiretap capture -i eth0 --include-ip "192.168.1.0/24"
wiretap capture -i eth0 --exclude-ip "10.0.0.0/8"

# Filter by port
wiretap capture -i eth0 --include-port "80,443,8080-8090"
wiretap capture -i eth0 --exclude-port "22"

# Combine filters (AND logic)
wiretap capture -i eth0 \
  --include-domain "*.example.com" \
  --exclude-ip "10.0.0.0/8" \
  --include-port "443"
```

**Domain pattern formats:**
- `example.com` - exact match
- `*.example.com` - wildcard (matches subdomains)
- `/regex/` - regular expression (e.g., `/api\..*/`)

### WASM Plugins

Extend wiretap with custom protocol dissectors:

```bash
# Load plugins from directory
wiretap read capture.pcap --plugin-dir ./plugins/

# Load specific plugin
wiretap read capture.pcap --plugin ./plugins/custom-protocol.wasm
```

See [plugins/README.md](plugins/README.md) for plugin development guide.

## Examples

### Example 1: Capture and Decrypt HTTPS Traffic from a Website

This example shows how to capture and decrypt HTTPS traffic when visiting cnn.com (or any HTTPS website).

**Step 1: Create keylog file and start capture**

```bash
# Create keylog file
touch /tmp/sslkeys.log

# Start capturing HTTPS traffic (in Terminal 1)
sudo wiretap capture -i en0 \
  -f "tcp port 443" \
  -w /tmp/https_capture.pcap
```

> Replace `en0` with your network interface. Run `wiretap interfaces` to list available interfaces.

**Step 2: Generate traffic with TLS key logging**

```bash
# Option A: Using Chrome (in Terminal 2)
SSLKEYLOGFILE=/tmp/sslkeys.log open -a "Google Chrome" --args --new-window "https://cnn.com"

# Option B: Using Firefox
SSLKEYLOGFILE=/tmp/sslkeys.log open -a Firefox --args --new-window "https://cnn.com"

# Option C: Using Brave
SSLKEYLOGFILE=/tmp/sslkeys.log open -a "Brave Browser" --args --new-window "https://cnn.com"

# Option D: Using Microsoft Edge
SSLKEYLOGFILE=/tmp/sslkeys.log open -a "Microsoft Edge" --args --new-window "https://cnn.com"

# Option E: Using curl (requires OpenSSL-based curl, not macOS default)
SSLKEYLOGFILE=/tmp/sslkeys.log curl https://cnn.com

# Linux examples:
# SSLKEYLOGFILE=/tmp/sslkeys.log google-chrome https://cnn.com
# SSLKEYLOGFILE=/tmp/sslkeys.log firefox https://cnn.com
# SSLKEYLOGFILE=/tmp/sslkeys.log brave-browser https://cnn.com
# SSLKEYLOGFILE=/tmp/sslkeys.log microsoft-edge https://cnn.com
```

> **Note:** macOS's built-in curl uses SecureTransport which doesn't support SSLKEYLOGFILE. 
> Install OpenSSL curl via Homebrew: `brew install curl` and use `/opt/homebrew/opt/curl/bin/curl`

**Step 3: Stop capture and analyze**

Press `Ctrl+C` in Terminal 1 to stop capturing, then:

```bash
# View in TUI with decrypted content
wiretap read /tmp/https_capture.pcap --decrypt --keylog /tmp/sslkeys.log

# Or export to JSON
wiretap export /tmp/https_capture.pcap \
  --decrypt --keylog /tmp/sslkeys.log \
  --format json -o cnn_traffic.json

# Or export to HAR (viewable in browser DevTools)
wiretap export /tmp/https_capture.pcap \
  --decrypt --keylog /tmp/sslkeys.log \
  --format har -o cnn_traffic.har
```

### Example 2: Monitor API Traffic with Domain Filtering

Capture only traffic to specific API endpoints:

```bash
# Capture traffic to your API
sudo wiretap capture -i en0 \
  --include-domain "*.api.example.com" \
  --include-domain "api.github.com" \
  --exclude-domain "telemetry.*" \
  --include-port "443,8443" \
  -w api_traffic.pcap
```

### Example 3: Analyze gRPC Microservices

> Generate descriptor sets with: `protoc --descriptor_set_out=desc.pb your.proto`

```bash
# Capture gRPC traffic on standard port
sudo wiretap capture -i eth0 \
  -f "tcp port 50051" \
  -w grpc_capture.pcap

# Read with protocol definitions
wiretap read grpc_capture.pcap --proto-dir ./protos/
```

### Example 4: WebSocket Debugging

```bash
# Capture WebSocket traffic (typically starts on HTTP ports)
sudo wiretap capture -i en0 \
  -f "tcp port 80 or tcp port 443 or tcp port 8080" \
  --decrypt --keylog /tmp/sslkeys.log \
  -w websocket_capture.pcap
```

### Read PCAP Files

```bash
# Open pcap in TUI
wiretap read capture.pcap

# Read with BPF filter
wiretap read capture.pcap -f "tcp port 443"

# Build/rebuild index for large files
wiretap index capture.pcap

# Specify custom index directory
wiretap read capture.pcap --index-dir /path/to/indexes
```

### List Interfaces

```bash
wiretap interfaces
```

### Export Data

```bash
# Export packets as JSON
wiretap export capture.pcap --format json -o output.json

# Export packets as JSONL
wiretap export capture.pcap --format jsonl -o output.jsonl

# Export packets as CSV
wiretap export capture.pcap --format csv -o output.csv

# Export as HAR (HTTP Archive)
wiretap export capture.pcap --format har -o output.har

# Export only HTTP traffic
wiretap export capture.pcap --protocol http -o http.json
```

### Configuration

Configuration file location: `~/.config/wiretap/config.yaml`

```yaml
# Index file storage directory
index:
  directory: ~/.cache/wiretap

# Default capture settings
capture:
  snaplen: 65535
  promiscuous: true
  timeout: 1s

# Protocol settings
protocols:
  http:
    max_body_size: 1048576
    parse_h2c: true
  tls:
    parse_certificates: true
    compute_ja3: true
    decrypt: false
    keylog_file: ""
  dns:
    resolve_ptr: false
  grpc:
    proto_dirs: []
    proto_files: []

# Domain filtering
filter:
  include_domains: []
  exclude_domains: []
  include_ips: []
  exclude_ips: []
  include_ports: []
  exclude_ports: []

# Plugin settings
plugins:
  directory: ~/.config/wiretap/plugins
  enabled: []

  # TLS settings
tui:
  theme: dark
  show_hex: true
    # Note: TLS decryption is controlled by CLI flags (--decrypt/--keylog).
    decrypt: false
    keylog_file: ""
export:
  default_format: json
  pretty_json: true

# Logging settings
logging:
  level: info
  file: ""
```

View/edit configuration:
```bash
wiretap config

# Initialize a default config file
wiretap config --init
```

## TUI Keybindings

| Key | Action |
|-----|--------|
| `↑`/`k` | Move up |
| `↓`/`j` | Move down |
| `Enter` | Select packet |
| `/` | Open filter |
| `f` | Follow TCP stream |
| `Tab` | Switch pane |
| `h` | Toggle hex view |
| `?` | Show help |
| `F1` | Show help |
| `q` | Quit |

## Project Structure

```
wiretap/
├── cmd/wiretap/         # Main entry point
├── internal/
│   ├── capture/         # Packet capture engine
│   ├── cli/             # CLI commands
│   ├── config/          # Configuration
│   ├── crypto/          # TLS decryption (keylog, decrypt engine)
│   ├── filter/          # Domain/IP/Port filtering
│   ├── index/           # Memory-mapped indexing
│   ├── model/           # Domain models
│   ├── plugin/          # WASM plugin system
│   ├── protocol/        # Protocol dissectors
│   │   ├── dns.go       # DNS parser
│   │   ├── http1.go     # HTTP/1.x parser
│   │   ├── http2.go     # HTTP/2 parser
│   │   ├── tls.go       # TLS parser
│   │   ├── websocket.go # WebSocket parser
│   │   └── grpc.go      # gRPC parser
│   └── tui/             # Terminal UI
├── plugins/             # WASM plugin examples
│   ├── examples/        # Example plugins in Rust
│   └── README.md        # Plugin development guide
├── configs/             # Example configs
├── Makefile
└── .goreleaser.yaml
```

## Development

```bash
# Run tests
make test

# Run tests with coverage
make test-coverage

# Run linter
make lint

# Format code
make fmt

# Build all platforms
make build-all
```

## Indexing Notes

- Indexing currently supports `.pcap` files only (pcapng indexing is not supported yet).

## Roadmap

### v1 (Complete)
- [x] Live packet capture
- [x] PCAP file reading
- [x] Memory-mapped indexing
- [x] HTTP/1.x parsing
- [x] HTTP/2 cleartext (h2c) parsing
- [x] TLS handshake inspection (SNI, certs, JA3)
- [x] CLI and TUI interfaces

### v2 (Complete)
- [x] TLS decryption via SSLKEYLOGFILE
- [x] HTTP/2 over TLS inspection
- [x] WebSocket protocol support
- [x] gRPC protocol support (schema-less decoding; descriptor sets optional)
- [x] WASM plugin system for custom protocols
- [x] Domain/IP/Port filtering

### v3 (Planned)
- [ ] QUIC/HTTP/3 protocol support
- [ ] Statistics and flow analysis
- [ ] Packet colorization rules
- [ ] Remote capture (rpcap)
- [ ] Plugin marketplace

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [gopacket](https://github.com/gopacket/gopacket) - Packet processing
- [tview](https://github.com/rivo/tview) - Terminal UI
- [cobra](https://github.com/spf13/cobra) - CLI framework
- [wazero](https://github.com/tetratelabs/wazero) - WASM runtime for plugins
- [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) - TLS decryption

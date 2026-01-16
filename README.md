# Wiretap

A Wireshark-like network packet analyzer written in Go with CLI and TUI interfaces.

## Features

- **Live Packet Capture**: Capture packets from network interfaces in real-time
- **PCAP File Analysis**: Read and analyze pcap/pcapng files
- **Protocol Dissection**: Deep packet inspection for:
  - Ethernet, IPv4, IPv6, ARP
  - TCP, UDP, ICMP
  - DNS
  - HTTP/1.x and HTTP/2 (cleartext h2c)
  - TLS (handshake metadata, SNI, certificates, JA3 fingerprinting)
- **Memory-Mapped Indexing**: Efficiently handle large capture files (millions of packets)
- **BPF Filters**: Use Berkeley Packet Filter syntax for capture filtering
- **Terminal UI**: Three-pane Wireshark-style interface with packet list, protocol tree, and hex view
- **Export Formats**: JSON and HAR export for HTTP conversations

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/wiretap/wiretap.git
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

### Read PCAP Files

```bash
# Open pcap in TUI
wiretap read capture.pcap

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
# Export HTTP conversations as JSON
wiretap export capture.pcap --format json -o output.json

# Export as HAR (HTTP Archive)
wiretap export capture.pcap --format har -o output.har
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

# TUI settings
tui:
  theme: dark
  show_hex: true
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
│   ├── index/           # Memory-mapped indexing
│   ├── protocol/        # Protocol dissectors
│   │   ├── http1/       # HTTP/1.x parser
│   │   ├── http2/       # HTTP/2 parser
│   │   ├── tls/         # TLS parser
│   │   └── dns/         # DNS parser
│   ├── model/           # Domain models
│   ├── cli/             # CLI commands
│   ├── tui/             # Terminal UI
│   └── config/          # Configuration
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

## Roadmap

### v1 (Current)
- [x] Live packet capture
- [x] PCAP file reading
- [x] Memory-mapped indexing
- [x] HTTP/1.x parsing
- [x] HTTP/2 cleartext (h2c) parsing
- [x] TLS handshake inspection (SNI, certs, JA3)
- [x] CLI and TUI interfaces

### v2 (Planned)
- [ ] TLS decryption via SSLKEYLOGFILE
- [ ] HTTP/2 over TLS inspection
- [ ] WebSocket protocol support
- [ ] gRPC protocol support
- [ ] Custom protocol plugins
- [ ] Domain filtering (SNI from TLS or DNS queries)

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [gopacket](https://github.com/gopacket/gopacket) - Packet processing
- [tview](https://github.com/rivo/tview) - Terminal UI
- [cobra](https://github.com/spf13/cobra) - CLI framework

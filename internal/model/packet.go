// Package model defines the core domain models for wiretap.
package model

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// Protocol represents a network protocol.
type Protocol uint8

// Protocol constants.
const (
	ProtocolUnknown Protocol = iota
	ProtocolEthernet
	ProtocolARP
	ProtocolIPv4
	ProtocolIPv6
	ProtocolICMP
	ProtocolICMPv6
	ProtocolTCP
	ProtocolUDP
	ProtocolDNS
	ProtocolHTTP
	ProtocolHTTP2
	ProtocolTLS
	ProtocolWebSocket
)

// String returns the protocol name.
func (p Protocol) String() string {
	switch p {
	case ProtocolEthernet:
		return "Ethernet"
	case ProtocolARP:
		return "ARP"
	case ProtocolIPv4:
		return "IPv4"
	case ProtocolIPv6:
		return "IPv6"
	case ProtocolICMP:
		return "ICMP"
	case ProtocolICMPv6:
		return "ICMPv6"
	case ProtocolTCP:
		return "TCP"
	case ProtocolUDP:
		return "UDP"
	case ProtocolDNS:
		return "DNS"
	case ProtocolHTTP:
		return "HTTP"
	case ProtocolHTTP2:
		return "HTTP/2"
	case ProtocolTLS:
		return "TLS"
	case ProtocolWebSocket:
		return "WebSocket"
	default:
		return "Unknown"
	}
}

// TCPFlags represents TCP control flags.
type TCPFlags struct {
	SYN bool
	ACK bool
	FIN bool
	RST bool
	PSH bool
	URG bool
	ECE bool
	CWR bool
	NS  bool
}

// ToUint8 converts flags to a bitmask.
func (f TCPFlags) ToUint8() uint8 {
	var result uint8
	if f.FIN {
		result |= 0x01
	}
	if f.SYN {
		result |= 0x02
	}
	if f.RST {
		result |= 0x04
	}
	if f.PSH {
		result |= 0x08
	}
	if f.ACK {
		result |= 0x10
	}
	if f.URG {
		result |= 0x20
	}
	if f.ECE {
		result |= 0x40
	}
	if f.CWR {
		result |= 0x80
	}
	return result
}

// String returns a string representation of TCP flags.
func (f TCPFlags) String() string {
	var flags []string
	if f.SYN {
		flags = append(flags, "SYN")
	}
	if f.ACK {
		flags = append(flags, "ACK")
	}
	if f.FIN {
		flags = append(flags, "FIN")
	}
	if f.RST {
		flags = append(flags, "RST")
	}
	if f.PSH {
		flags = append(flags, "PSH")
	}
	if f.URG {
		flags = append(flags, "URG")
	}
	if f.ECE {
		flags = append(flags, "ECE")
	}
	if f.CWR {
		flags = append(flags, "CWR")
	}
	if f.NS {
		flags = append(flags, "NS")
	}
	if len(flags) == 0 {
		return "[.]"
	}
	return "[" + strings.Join(flags, " ") + "]"
}

// Has checks if a specific flag is set.
func (f TCPFlags) Has(name string) bool {
	switch strings.ToUpper(name) {
	case "SYN":
		return f.SYN
	case "ACK":
		return f.ACK
	case "FIN":
		return f.FIN
	case "RST":
		return f.RST
	case "PSH":
		return f.PSH
	case "URG":
		return f.URG
	case "ECE":
		return f.ECE
	case "CWR":
		return f.CWR
	case "NS":
		return f.NS
	default:
		return false
	}
}

// Packet represents a captured network packet.
type Packet struct {
	// Index is the packet number in the capture
	Index uint64

	// Timestamp when the packet was captured
	Timestamp time.Time

	// Length is the original packet length on the wire
	Length uint32

	// CapturedLen is the number of bytes captured
	CapturedLen uint32

	// OriginalLen is the original packet length
	OriginalLen uint32

	// CaptureLen is an alias for CapturedLen (for compatibility)
	CaptureLen uint32

	// FileOffset is the offset in the pcap file
	FileOffset int64

	// Layers contains the protocol layer data
	Layers []Layer

	// RawData is the raw packet bytes
	RawData []byte

	// Data is an alias for RawData (for compatibility)
	Data []byte

	// Payload is the application layer data
	Payload []byte

	// Metadata for quick access
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16
	Protocol Protocol
	TCPFlags TCPFlags

	// TCP sequence numbers
	SeqNum uint32
	AckNum uint32
	TTL    uint8

	// Application layer info
	AppProtocol         Protocol
	AppInfo             string // Brief description (e.g., "GET /index.html", "TLS ClientHello")
	ApplicationProtocol string // String name of application protocol

	// Parsed protocol data
	HTTPInfo    *HTTPConversation
	HTTP2Frames []*HTTP2Frame
	TLSInfo     *TLSInfo
	DNSInfo     *DNSInfo
}

// Layer represents a protocol layer in a packet.
type Layer struct {
	Protocol Protocol
	Offset   int // Start offset in raw data
	Length   int // Length of this layer
	Data     interface{}
}

// FiveTuple returns the 5-tuple identifying the flow.
func (p *Packet) FiveTuple() FiveTuple {
	return FiveTuple{
		SrcIP:    p.SrcIP,
		DstIP:    p.DstIP,
		SrcPort:  p.SrcPort,
		DstPort:  p.DstPort,
		Protocol: p.Protocol,
	}
}

// FlowHash returns a hash of the packet's flow (direction-independent).
func (p *Packet) FlowHash() uint64 {
	return p.FiveTuple().Hash()
}

// Summary returns a brief description of the packet.
func (p *Packet) Summary() string {
	if p.AppInfo != "" {
		return p.AppInfo
	}
	switch p.Protocol {
	case ProtocolTCP:
		return fmt.Sprintf("%s %d → %d [%s]",
			p.Protocol, p.SrcPort, p.DstPort, p.TCPFlags)
	case ProtocolUDP:
		return fmt.Sprintf("%s %d → %d len=%d",
			p.Protocol, p.SrcPort, p.DstPort, p.CapturedLen)
	case ProtocolICMP, ProtocolICMPv6:
		return p.Protocol.String()
	default:
		return fmt.Sprintf("%s → %s", p.SrcIP, p.DstIP)
	}
}

// FiveTuple represents a network 5-tuple.
type FiveTuple struct {
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16
	Protocol Protocol
}

// Hash returns a hash of the 5-tuple (direction-independent).
func (f FiveTuple) Hash() uint64 {
	// Normalize direction: smaller IP:port first
	srcIP := f.SrcIP
	dstIP := f.DstIP
	srcPort := f.SrcPort
	dstPort := f.DstPort

	srcKey := f.makeKey(srcIP, srcPort)
	dstKey := f.makeKey(dstIP, dstPort)
	if srcKey > dstKey {
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, srcPort
	}

	// Simple FNV-1a hash
	h := uint64(14695981039346656037)
	for _, b := range srcIP.To16() {
		h ^= uint64(b)
		h *= 1099511628211
	}
	for _, b := range dstIP.To16() {
		h ^= uint64(b)
		h *= 1099511628211
	}
	h ^= uint64(srcPort)
	h *= 1099511628211
	h ^= uint64(dstPort)
	h *= 1099511628211
	h ^= uint64(f.Protocol)
	h *= 1099511628211
	return h
}

// makeKey creates a comparable key from IP and port.
func (f FiveTuple) makeKey(ip net.IP, port uint16) string {
	return fmt.Sprintf("%s:%d", ip.String(), port)
}

// String returns a string representation of the 5-tuple.
func (f FiveTuple) String() string {
	return fmt.Sprintf("%s:%d → %s:%d (%s)",
		f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, f.Protocol)
}

// Reverse returns the reverse of this 5-tuple.
func (f FiveTuple) Reverse() FiveTuple {
	return FiveTuple{
		SrcIP:    f.DstIP,
		DstIP:    f.SrcIP,
		SrcPort:  f.DstPort,
		DstPort:  f.SrcPort,
		Protocol: f.Protocol,
	}
}

// IPToBytes converts an IP to a 16-byte array (for indexing).
func IPToBytes(ip net.IP) [16]byte {
	var result [16]byte
	copy(result[:], ip.To16())
	return result
}

// BytesToIP converts a 16-byte array back to an IP.
func BytesToIP(b [16]byte) net.IP {
	// Check if it's an IPv4-mapped IPv6 address
	if isIPv4Mapped(b) {
		return net.IP(b[12:16])
	}
	return net.IP(b[:])
}

// isIPv4Mapped checks if the bytes represent an IPv4-mapped IPv6 address.
func isIPv4Mapped(b [16]byte) bool {
	for i := 0; i < 10; i++ {
		if b[i] != 0 {
			return false
		}
	}
	return b[10] == 0xff && b[11] == 0xff
}

// PortsToBytes converts ports to a 4-byte slice.
func PortsToBytes(src, dst uint16) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[0:2], src)
	binary.BigEndian.PutUint16(b[2:4], dst)
	return b
}

// BytesToPorts converts bytes back to ports.
func BytesToPorts(b []byte) (src, dst uint16) {
	if len(b) >= 4 {
		src = binary.BigEndian.Uint16(b[0:2])
		dst = binary.BigEndian.Uint16(b[2:4])
	}
	return
}

// DNSInfo represents parsed DNS information.
type DNSInfo struct {
	TransactionID      uint16
	IsResponse         bool
	Opcode             uint8
	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	ResponseCode       uint8
	Questions          []*DNSQuestion
	Answers            []*DNSResourceRecord
	Authority          []*DNSResourceRecord
	Additional         []*DNSResourceRecord
}

// DNSQuestion represents a DNS question.
type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

// DNSResourceRecord represents a DNS resource record.
type DNSResourceRecord struct {
	Name       string
	Type       uint16
	Class      uint16
	TTL        uint32
	Data       []byte
	DataString string
}

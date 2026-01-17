package model

import (
	"net"
	"testing"
	"time"
)

func TestPacket_FiveTuple(t *testing.T) {
	pkt := &Packet{
		SrcIP:    net.ParseIP("192.168.1.1"),
		DstIP:    net.ParseIP("192.168.1.2"),
		SrcPort:  12345,
		DstPort:  80,
		Protocol: ProtocolTCP,
	}

	ft := pkt.FiveTuple()

	if !ft.SrcIP.Equal(pkt.SrcIP) {
		t.Errorf("SrcIP mismatch: got %v, want %v", ft.SrcIP, pkt.SrcIP)
	}
	if !ft.DstIP.Equal(pkt.DstIP) {
		t.Errorf("DstIP mismatch: got %v, want %v", ft.DstIP, pkt.DstIP)
	}
	if ft.SrcPort != pkt.SrcPort {
		t.Errorf("SrcPort mismatch: got %d, want %d", ft.SrcPort, pkt.SrcPort)
	}
	if ft.DstPort != pkt.DstPort {
		t.Errorf("DstPort mismatch: got %d, want %d", ft.DstPort, pkt.DstPort)
	}
	if ft.Protocol != pkt.Protocol {
		t.Errorf("Protocol mismatch: got %v, want %v", ft.Protocol, pkt.Protocol)
	}
}

func TestFiveTuple_Hash(t *testing.T) {
	ft := FiveTuple{
		SrcIP:    net.ParseIP("192.168.1.1"),
		DstIP:    net.ParseIP("192.168.1.2"),
		SrcPort:  12345,
		DstPort:  80,
		Protocol: ProtocolTCP,
	}

	hash := ft.Hash()
	if hash == 0 {
		t.Error("Hash should not be zero")
	}

	// Same five-tuple should produce same hash
	ft2 := FiveTuple{
		SrcIP:    net.ParseIP("192.168.1.1"),
		DstIP:    net.ParseIP("192.168.1.2"),
		SrcPort:  12345,
		DstPort:  80,
		Protocol: ProtocolTCP,
	}

	if ft.Hash() != ft2.Hash() {
		t.Error("Same five-tuple should produce same hash")
	}

	// Reverse five-tuple should produce same hash
	ftReverse := FiveTuple{
		SrcIP:    net.ParseIP("192.168.1.2"),
		DstIP:    net.ParseIP("192.168.1.1"),
		SrcPort:  80,
		DstPort:  12345,
		Protocol: ProtocolTCP,
	}
	if ft.Hash() != ftReverse.Hash() {
		t.Error("Reversed five-tuple should produce same hash")
	}

	// Different five-tuple should produce different hash
	ft3 := FiveTuple{
		SrcIP:    net.ParseIP("192.168.1.3"),
		DstIP:    net.ParseIP("192.168.1.2"),
		SrcPort:  12345,
		DstPort:  80,
		Protocol: ProtocolTCP,
	}

	if ft.Hash() == ft3.Hash() {
		t.Error("Different five-tuple should produce different hash")
	}
}

func TestFiveTuple_Reverse(t *testing.T) {
	ft := FiveTuple{
		SrcIP:    net.ParseIP("192.168.1.1"),
		DstIP:    net.ParseIP("192.168.1.2"),
		SrcPort:  12345,
		DstPort:  80,
		Protocol: ProtocolTCP,
	}

	rev := ft.Reverse()

	if !rev.SrcIP.Equal(ft.DstIP) {
		t.Errorf("Reversed SrcIP should be %v, got %v", ft.DstIP, rev.SrcIP)
	}
	if !rev.DstIP.Equal(ft.SrcIP) {
		t.Errorf("Reversed DstIP should be %v, got %v", ft.SrcIP, rev.DstIP)
	}
	if rev.SrcPort != ft.DstPort {
		t.Errorf("Reversed SrcPort should be %d, got %d", ft.DstPort, rev.SrcPort)
	}
	if rev.DstPort != ft.SrcPort {
		t.Errorf("Reversed DstPort should be %d, got %d", ft.SrcPort, rev.DstPort)
	}
}

func TestProtocol_String(t *testing.T) {
	tests := []struct {
		proto Protocol
		want  string
	}{
		{ProtocolTCP, "TCP"},
		{ProtocolUDP, "UDP"},
		{ProtocolICMP, "ICMP"},
		{Protocol(255), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.proto.String(); got != tt.want {
				t.Errorf("Protocol.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTCPFlags_String(t *testing.T) {
	tests := []struct {
		name  string
		flags TCPFlags
		want  string
	}{
		{
			name:  "SYN only",
			flags: TCPFlags{SYN: true},
			want:  "[SYN]",
		},
		{
			name:  "SYN-ACK",
			flags: TCPFlags{SYN: true, ACK: true},
			want:  "[SYN ACK]",
		},
		{
			name:  "FIN-ACK",
			flags: TCPFlags{FIN: true, ACK: true},
			want:  "[ACK FIN]",
		},
		{
			name:  "RST",
			flags: TCPFlags{RST: true},
			want:  "[RST]",
		},
		{
			name:  "Empty",
			flags: TCPFlags{},
			want:  "[.]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.flags.String()
			if got != tt.want {
				t.Errorf("TCPFlags.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTCPFlags_ToUint8(t *testing.T) {
	tests := []struct {
		name  string
		flags TCPFlags
		want  uint8
	}{
		{
			name:  "SYN",
			flags: TCPFlags{SYN: true},
			want:  0x02,
		},
		{
			name:  "ACK",
			flags: TCPFlags{ACK: true},
			want:  0x10,
		},
		{
			name:  "SYN-ACK",
			flags: TCPFlags{SYN: true, ACK: true},
			want:  0x12,
		},
		{
			name:  "FIN",
			flags: TCPFlags{FIN: true},
			want:  0x01,
		},
		{
			name:  "RST",
			flags: TCPFlags{RST: true},
			want:  0x04,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.flags.ToUint8()
			if got != tt.want {
				t.Errorf("TCPFlags.ToUint8() = %x, want %x", got, tt.want)
			}
		})
	}
}

func TestTCPFlags_Has(t *testing.T) {
	flags := TCPFlags{SYN: true, ACK: true}
	if !flags.Has("SYN") {
		t.Error("Expected SYN flag")
	}
	if !flags.Has("ACK") {
		t.Error("Expected ACK flag")
	}
	if flags.Has("FIN") {
		t.Error("Did not expect FIN flag")
	}
}

func TestDNSInfo_Fields(t *testing.T) {
	query := DNSInfo{IsResponse: false, TransactionID: 1234}
	response := DNSInfo{IsResponse: true, TransactionID: 1234}

	if query.IsResponse {
		t.Error("Query should not be a response")
	}
	if !response.IsResponse {
		t.Error("Response should be a response")
	}
	if query.TransactionID != 1234 {
		t.Errorf("TransactionID = %d, want 1234", query.TransactionID)
	}
}

func TestPacket_Duration(t *testing.T) {
	start := time.Now()
	end := start.Add(5 * time.Second)

	// For testing duration with two packets
	pkt1 := &Packet{Timestamp: start}
	pkt2 := &Packet{Timestamp: end}

	duration := pkt2.Timestamp.Sub(pkt1.Timestamp)
	if duration != 5*time.Second {
		t.Errorf("Expected 5s duration, got %v", duration)
	}
}

func TestIPToBytes(t *testing.T) {
	ipv4 := net.ParseIP("192.168.1.1")
	bytes := IPToBytes(ipv4)

	// Should be IPv4-mapped IPv6
	if bytes[10] != 0xff || bytes[11] != 0xff {
		t.Error("IPv4 should be mapped to IPv6 format")
	}
	if bytes[12] != 192 || bytes[13] != 168 || bytes[14] != 1 || bytes[15] != 1 {
		t.Error("IPv4 bytes not preserved correctly")
	}
}

func TestBytesToIP_IPv4(t *testing.T) {
	// IPv4-mapped IPv6 format
	var bytes [16]byte
	bytes[10] = 0xff
	bytes[11] = 0xff
	bytes[12] = 192
	bytes[13] = 168
	bytes[14] = 1
	bytes[15] = 1

	ip := BytesToIP(bytes)
	expected := net.ParseIP("192.168.1.1").To4()

	if !ip.Equal(expected) {
		t.Errorf("BytesToIP = %v, want %v", ip, expected)
	}
}

func TestPortsToBytes_RoundTrip(t *testing.T) {
	src := uint16(1234)
	dst := uint16(443)
	bytes := PortsToBytes(src, dst)
	gotSrc, gotDst := BytesToPorts(bytes)
	if gotSrc != src || gotDst != dst {
		t.Errorf("Round trip failed: got %d/%d", gotSrc, gotDst)
	}
}

func TestBytesToPorts_ShortInput(t *testing.T) {
	src, dst := BytesToPorts([]byte{0x00})
	if src != 0 || dst != 0 {
		t.Errorf("Expected zero ports for short input, got %d/%d", src, dst)
	}
}

func TestBytesToIP_IPv6(t *testing.T) {
	var bytes [16]byte
	bytes[0] = 0x20
	bytes[1] = 0x01
	bytes[15] = 0x01
	if ip := BytesToIP(bytes); ip == nil || ip.To16() == nil {
		t.Error("Expected valid IPv6 address")
	}
}

func TestPacket_Summary(t *testing.T) {
	packet := &Packet{Protocol: ProtocolTCP, SrcPort: 1234, DstPort: 80, TCPFlags: TCPFlags{SYN: true}}
	if summary := packet.Summary(); summary == "" {
		t.Error("Expected summary for TCP packet")
	}

	packet.Protocol = ProtocolUDP
	packet.CapturedLen = 42
	if summary := packet.Summary(); summary == "" {
		t.Error("Expected summary for UDP packet")
	}

	packet.Protocol = ProtocolICMP
	if summary := packet.Summary(); summary == "" {
		t.Error("Expected summary for ICMP packet")
	}
}

func TestFiveTuple_String(t *testing.T) {
	ft := FiveTuple{
		SrcIP:    net.ParseIP("192.168.1.1"),
		DstIP:    net.ParseIP("192.168.1.2"),
		SrcPort:  12345,
		DstPort:  80,
		Protocol: ProtocolTCP,
	}

	s := ft.String()
	if s == "" {
		t.Error("String should not be empty")
	}
	// Should contain ports and IPs
	if len(s) < 20 {
		t.Errorf("String too short: %s", s)
	}
}

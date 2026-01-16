package protocol

import (
	"testing"
	"time"

	"github.com/wiretap/wiretap/internal/model"
)

func TestTLSDissectorName(t *testing.T) {
	d := NewTLSDissector()
	if d.Name() != "TLS" {
		t.Errorf("expected name TLS, got %s", d.Name())
	}
}

func TestTLSDissectorDetect(t *testing.T) {
	d := NewTLSDissector()

	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name: "TLS 1.2 Client Hello",
			data: []byte{
				0x16,       // Handshake
				0x03, 0x01, // TLS 1.0 record version (for Client Hello)
				0x00, 0x05, // Length
				0x01, 0x00, 0x00, 0x01, 0x00, // Minimal handshake
			},
			expected: true,
		},
		{
			name: "TLS Alert",
			data: []byte{
				0x15,       // Alert
				0x03, 0x03, // TLS 1.2
				0x00, 0x02, // Length
				0x02, 0x00, // Fatal close_notify
			},
			expected: true,
		},
		{
			name: "TLS Application Data",
			data: []byte{
				0x17,       // Application Data
				0x03, 0x03, // TLS 1.2
				0x00, 0x10, // Length
				// Data follows...
			},
			expected: true,
		},
		{
			name:     "Empty",
			data:     []byte{},
			expected: false,
		},
		{
			name:     "Too short",
			data:     []byte{0x16, 0x03},
			expected: false,
		},
		{
			name:     "Invalid record type",
			data:     []byte{0x00, 0x03, 0x03, 0x00, 0x05},
			expected: false,
		},
		{
			name:     "Invalid version",
			data:     []byte{0x16, 0x02, 0x00, 0x00, 0x05},
			expected: false,
		},
		{
			name:     "HTTP data",
			data:     []byte("GET / HTTP/1.1\r\n"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := d.Detect(tt.data)
			if result != tt.expected {
				t.Errorf("Detect() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestTLSDissectorParseClientHello(t *testing.T) {
	d := NewTLSDissector()

	// Minimal TLS 1.2 Client Hello with SNI
	data := buildClientHello("example.com")

	pkt := &model.Packet{Timestamp: time.Now()}
	err := d.Parse(data, pkt)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if pkt.ApplicationProtocol != "TLS" {
		t.Errorf("expected protocol TLS, got %s", pkt.ApplicationProtocol)
	}

	if pkt.TLSInfo == nil {
		t.Fatal("expected TLSInfo to be set")
	}

	if !pkt.TLSInfo.IsClientHello {
		t.Error("expected IsClientHello to be true")
	}

	if pkt.TLSInfo.ClientHello == nil {
		t.Fatal("expected ClientHello to be set")
	}

	if pkt.TLSInfo.ClientHello.SNI != "example.com" {
		t.Errorf("expected SNI example.com, got %s", pkt.TLSInfo.ClientHello.SNI)
	}

	if len(pkt.TLSInfo.ClientHello.CipherSuites) == 0 {
		t.Error("expected cipher suites to be parsed")
	}

	if pkt.TLSInfo.ClientHello.JA3 == "" {
		t.Error("expected JA3 to be calculated")
	}

	if pkt.TLSInfo.ClientHello.JA3Hash == "" {
		t.Error("expected JA3Hash to be calculated")
	}
}

func TestTLSDissectorParseServerHello(t *testing.T) {
	d := NewTLSDissector()

	// Minimal TLS 1.2 Server Hello
	data := buildServerHello()

	pkt := &model.Packet{Timestamp: time.Now()}
	err := d.Parse(data, pkt)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if pkt.TLSInfo == nil {
		t.Fatal("expected TLSInfo to be set")
	}

	if !pkt.TLSInfo.IsServerHello {
		t.Error("expected IsServerHello to be true")
	}

	if pkt.TLSInfo.ServerHello == nil {
		t.Fatal("expected ServerHello to be set")
	}

	// Check JA3S was calculated
	if pkt.TLSInfo.ServerHello.JA3S == "" {
		t.Error("expected JA3S to be calculated")
	}
}

func TestTLSCipherSuiteName(t *testing.T) {
	tests := []struct {
		suite model.TLSCipherSuite
		want  string
	}{
		{0x1301, "TLS_AES_128_GCM_SHA256"},
		{0x1302, "TLS_AES_256_GCM_SHA384"},
		{0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		{0x0000, "TLS_NULL_WITH_NULL_NULL"},
		{0xFFFF, "Unknown (0xFFFF)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := TLSCipherSuiteName(tt.suite)
			if got != tt.want {
				t.Errorf("TLSCipherSuiteName(%x) = %s, want %s", tt.suite, got, tt.want)
			}
		})
	}
}

func TestTLSVersionName(t *testing.T) {
	tests := []struct {
		ver  model.TLSVersion
		want string
	}{
		{model.TLSVersion10, "TLS 1.0"},
		{model.TLSVersion11, "TLS 1.1"},
		{model.TLSVersion12, "TLS 1.2"},
		{model.TLSVersion13, "TLS 1.3"},
		{model.TLSVersionSSL30, "SSL 3.0"},
		{0x0000, "Unknown (0x0000)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := TLSVersionName(tt.ver)
			if got != tt.want {
				t.Errorf("TLSVersionName(%x) = %s, want %s", tt.ver, got, tt.want)
			}
		})
	}
}

func TestTLSAlertName(t *testing.T) {
	tests := []struct {
		desc uint8
		want string
	}{
		{0, "close_notify"},
		{40, "handshake_failure"},
		{42, "bad_certificate"},
		{48, "unknown_ca"},
		{255, "unknown_alert_255"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := TLSAlertName(tt.desc)
			if got != tt.want {
				t.Errorf("TLSAlertName(%d) = %s, want %s", tt.desc, got, tt.want)
			}
		})
	}
}

func TestIsGREASE(t *testing.T) {
	greaseValues := []uint16{
		0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A,
		0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
		0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
		0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
	}

	for _, v := range greaseValues {
		if !isGREASE(v) {
			t.Errorf("isGREASE(%x) = false, want true", v)
		}
	}

	nonGreaseValues := []uint16{
		0x0000, 0x1301, 0xC02F, 0x0035,
	}

	for _, v := range nonGreaseValues {
		if isGREASE(v) {
			t.Errorf("isGREASE(%x) = true, want false", v)
		}
	}
}

func TestFormatJA3(t *testing.T) {
	ja3 := "771,4866-4867-4865,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"

	formatted := FormatJA3(ja3)

	if formatted == ja3 {
		t.Error("expected formatted output to differ from input")
	}

	// Check it contains expected sections
	tests := []string{"Version:", "Ciphers:", "Extensions:", "Curves:", "Point Formats:"}
	for _, s := range tests {
		if !containsString(formatted, s) {
			t.Errorf("expected formatted output to contain %q", s)
		}
	}
}

func TestParseCipherSuites(t *testing.T) {
	s := "4866-4867-4865"
	suites := ParseCipherSuites(s)

	if len(suites) != 3 {
		t.Fatalf("expected 3 suites, got %d", len(suites))
	}

	expected := []model.TLSCipherSuite{4866, 4867, 4865}
	for i, suite := range suites {
		if suite != expected[i] {
			t.Errorf("suite[%d] = %d, want %d", i, suite, expected[i])
		}
	}

	// Empty string
	empty := ParseCipherSuites("")
	if len(empty) != 0 {
		t.Errorf("expected 0 suites for empty string, got %d", len(empty))
	}
}

// Helper functions

func buildClientHello(sni string) []byte {
	// Build a minimal TLS Client Hello
	var clientHello []byte

	// Version (TLS 1.2 in handshake)
	clientHello = append(clientHello, 0x03, 0x03)

	// Random (32 bytes)
	clientHello = append(clientHello, make([]byte, 32)...)

	// Session ID length (0)
	clientHello = append(clientHello, 0x00)

	// Cipher suites (2 suites)
	clientHello = append(clientHello, 0x00, 0x04) // length
	clientHello = append(clientHello, 0x13, 0x01) // TLS_AES_128_GCM_SHA256
	clientHello = append(clientHello, 0xC0, 0x2F) // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

	// Compression methods
	clientHello = append(clientHello, 0x01, 0x00) // 1 method: null

	// Extensions
	extensions := buildSNIExtension(sni)
	clientHello = append(clientHello, byte(len(extensions)>>8), byte(len(extensions)))
	clientHello = append(clientHello, extensions...)

	// Wrap in handshake message
	handshake := []byte{0x01} // Client Hello type
	handshake = append(handshake, byte(len(clientHello)>>16), byte(len(clientHello)>>8), byte(len(clientHello)))
	handshake = append(handshake, clientHello...)

	// Wrap in TLS record
	record := []byte{0x16, 0x03, 0x01} // Handshake, TLS 1.0 record version
	record = append(record, byte(len(handshake)>>8), byte(len(handshake)))
	record = append(record, handshake...)

	return record
}

func buildSNIExtension(name string) []byte {
	// SNI extension
	var ext []byte

	// Extension type (0x0000 = server_name)
	ext = append(ext, 0x00, 0x00)

	// Extension length
	nameLen := len(name)
	extDataLen := 5 + nameLen // list length (2) + type (1) + name length (2) + name
	ext = append(ext, byte(extDataLen>>8), byte(extDataLen))

	// Server name list length
	listLen := 3 + nameLen
	ext = append(ext, byte(listLen>>8), byte(listLen))

	// Server name type (0 = hostname)
	ext = append(ext, 0x00)

	// Server name length and value
	ext = append(ext, byte(nameLen>>8), byte(nameLen))
	ext = append(ext, []byte(name)...)

	return ext
}

func buildServerHello() []byte {
	// Build a minimal TLS Server Hello
	var serverHello []byte

	// Version (TLS 1.2)
	serverHello = append(serverHello, 0x03, 0x03)

	// Random (32 bytes)
	serverHello = append(serverHello, make([]byte, 32)...)

	// Session ID length (0)
	serverHello = append(serverHello, 0x00)

	// Cipher suite
	serverHello = append(serverHello, 0x13, 0x01) // TLS_AES_128_GCM_SHA256

	// Compression method
	serverHello = append(serverHello, 0x00) // null

	// Extensions length (0)
	serverHello = append(serverHello, 0x00, 0x00)

	// Wrap in handshake message
	handshake := []byte{0x02} // Server Hello type
	handshake = append(handshake, byte(len(serverHello)>>16), byte(len(serverHello)>>8), byte(len(serverHello)))
	handshake = append(handshake, serverHello...)

	// Wrap in TLS record
	record := []byte{0x16, 0x03, 0x03} // Handshake, TLS 1.2
	record = append(record, byte(len(handshake)>>8), byte(len(handshake)))
	record = append(record, handshake...)

	return record
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findString(s, substr)))
}

func findString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

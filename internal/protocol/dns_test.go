package protocol

import (
	"testing"
	"time"

	"github.com/wiretap/wiretap/internal/model"
)

func TestDNSDissectorName(t *testing.T) {
	d := NewDNSDissector()
	if d.Name() != "DNS" {
		t.Errorf("expected name DNS, got %s", d.Name())
	}
}

func TestDNSDissectorDetect(t *testing.T) {
	d := NewDNSDissector()

	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name: "Valid DNS query",
			data: []byte{
				0x00, 0x01, // Transaction ID
				0x01, 0x00, // Flags: standard query
				0x00, 0x01, // Questions: 1
				0x00, 0x00, // Answers: 0
				0x00, 0x00, // Authority: 0
				0x00, 0x00, // Additional: 0
			},
			expected: true,
		},
		{
			name: "Valid DNS response",
			data: []byte{
				0x00, 0x01, // Transaction ID
				0x81, 0x80, // Flags: response, recursion desired/available
				0x00, 0x01, // Questions: 1
				0x00, 0x01, // Answers: 1
				0x00, 0x00, // Authority: 0
				0x00, 0x00, // Additional: 0
			},
			expected: true,
		},
		{
			name:     "Too short",
			data:     []byte{0x00, 0x01},
			expected: false,
		},
		{
			name: "Invalid opcode",
			data: []byte{
				0x00, 0x01,
				0x78, 0x00, // Invalid opcode (15)
				0x00, 0x01,
				0x00, 0x00,
				0x00, 0x00,
				0x00, 0x00,
			},
			expected: false,
		},
		{
			name:     "Empty",
			data:     []byte{},
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

func TestDNSDissectorParseQuery(t *testing.T) {
	d := NewDNSDissector()

	// DNS query for example.com A record
	data := buildDNSQuery("example.com", dnsTypeA)

	pkt := &model.Packet{Timestamp: time.Now()}
	err := d.Parse(data, pkt)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if pkt.ApplicationProtocol != "DNS" {
		t.Errorf("expected protocol DNS, got %s", pkt.ApplicationProtocol)
	}

	if pkt.DNSInfo == nil {
		t.Fatal("expected DNSInfo to be set")
	}

	dns := pkt.DNSInfo
	if dns.IsResponse {
		t.Error("expected IsResponse to be false for query")
	}

	if len(dns.Questions) != 1 {
		t.Fatalf("expected 1 question, got %d", len(dns.Questions))
	}

	q := dns.Questions[0]
	if q.Name != "example.com" {
		t.Errorf("expected name example.com, got %s", q.Name)
	}

	if q.Type != dnsTypeA {
		t.Errorf("expected type A (1), got %d", q.Type)
	}
}

func TestDNSDissectorParseResponse(t *testing.T) {
	d := NewDNSDissector()

	// DNS response with A record
	data := buildDNSResponse("example.com", "93.184.216.34")

	pkt := &model.Packet{Timestamp: time.Now()}
	err := d.Parse(data, pkt)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	dns := pkt.DNSInfo
	if dns == nil {
		t.Fatal("expected DNSInfo to be set")
	}

	if !dns.IsResponse {
		t.Error("expected IsResponse to be true")
	}

	if len(dns.Answers) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(dns.Answers))
	}

	a := dns.Answers[0]
	if a.Type != dnsTypeA {
		t.Errorf("expected type A (1), got %d", a.Type)
	}

	if a.DataString != "93.184.216.34" {
		t.Errorf("expected IP 93.184.216.34, got %s", a.DataString)
	}
}

func TestDNSTypeName(t *testing.T) {
	tests := []struct {
		t    uint16
		want string
	}{
		{dnsTypeA, "A"},
		{dnsTypeAAAA, "AAAA"},
		{dnsTypeCNAME, "CNAME"},
		{dnsTypeMX, "MX"},
		{dnsTypeTXT, "TXT"},
		{dnsTypeNS, "NS"},
		{dnsTypePTR, "PTR"},
		{dnsTypeSRV, "SRV"},
		{dnsTypeSOA, "SOA"},
		{999, "TYPE999"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := DNSTypeName(tt.t)
			if got != tt.want {
				t.Errorf("DNSTypeName(%d) = %s, want %s", tt.t, got, tt.want)
			}
		})
	}
}

func TestDNSClassName(t *testing.T) {
	tests := []struct {
		c    uint16
		want string
	}{
		{1, "IN"},
		{3, "CH"},
		{4, "HS"},
		{255, "ANY"},
		{99, "CLASS99"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := DNSClassName(tt.c)
			if got != tt.want {
				t.Errorf("DNSClassName(%d) = %s, want %s", tt.c, got, tt.want)
			}
		})
	}
}

func TestDNSRcodeName(t *testing.T) {
	tests := []struct {
		rcode uint8
		want  string
	}{
		{dnsRcodeNoError, "NOERROR"},
		{dnsRcodeFormatError, "FORMERR"},
		{dnsRcodeServerFailure, "SERVFAIL"},
		{dnsRcodeNameError, "NXDOMAIN"},
		{dnsRcodeNotImplemented, "NOTIMP"},
		{dnsRcodeRefused, "REFUSED"},
		{99, "RCODE99"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := DNSRcodeName(tt.rcode)
			if got != tt.want {
				t.Errorf("DNSRcodeName(%d) = %s, want %s", tt.rcode, got, tt.want)
			}
		})
	}
}

func TestFormatDNSQuery(t *testing.T) {
	dns := &model.DNSInfo{
		Questions: []*model.DNSQuestion{
			{Name: "example.com", Type: dnsTypeA, Class: 1},
		},
	}

	result := FormatDNSQuery(dns)
	expected := "DNS Query: example.com A"

	if result != expected {
		t.Errorf("FormatDNSQuery() = %q, want %q", result, expected)
	}

	// Empty questions
	emptyDNS := &model.DNSInfo{}
	result = FormatDNSQuery(emptyDNS)
	if result != "DNS Query (no questions)" {
		t.Errorf("unexpected result for empty questions: %q", result)
	}
}

func TestFormatDNSResponse(t *testing.T) {
	dns := &model.DNSInfo{
		IsResponse:   true,
		ResponseCode: dnsRcodeNoError,
		Answers: []*model.DNSResourceRecord{
			{Name: "example.com", Type: dnsTypeA, DataString: "93.184.216.34"},
		},
	}

	result := FormatDNSResponse(dns)

	if !containsString(result, "NOERROR") {
		t.Error("expected result to contain NOERROR")
	}

	if !containsString(result, "93.184.216.34") {
		t.Error("expected result to contain IP address")
	}
}

func TestDNSDissectorParseName(t *testing.T) {
	d := NewDNSDissector()

	tests := []struct {
		name   string
		data   []byte
		offset int
		want   string
	}{
		{
			name: "Simple name",
			// "test" label
			data:   []byte{0x04, 't', 'e', 's', 't', 0x00},
			offset: 0,
			want:   "test",
		},
		{
			name: "Multi-label",
			// "www.example.com"
			data:   []byte{0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00},
			offset: 0,
			want:   "www.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := d.parseName(tt.data, tt.offset)
			if err != nil {
				t.Fatalf("parseName failed: %v", err)
			}
			if got != tt.want {
				t.Errorf("parseName() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Helper functions

func buildDNSQuery(name string, qtype uint16) []byte {
	var dns []byte

	// Header
	dns = append(dns, 0x00, 0x01) // Transaction ID
	dns = append(dns, 0x01, 0x00) // Flags: standard query, recursion desired
	dns = append(dns, 0x00, 0x01) // Questions: 1
	dns = append(dns, 0x00, 0x00) // Answers: 0
	dns = append(dns, 0x00, 0x00) // Authority: 0
	dns = append(dns, 0x00, 0x00) // Additional: 0

	// Question section
	dns = append(dns, encodeDNSName(name)...)
	dns = append(dns, byte(qtype>>8), byte(qtype)) // Type
	dns = append(dns, 0x00, 0x01)                  // Class IN

	return dns
}

func buildDNSResponse(name, ip string) []byte {
	var dns []byte

	// Header
	dns = append(dns, 0x00, 0x01) // Transaction ID
	dns = append(dns, 0x81, 0x80) // Flags: response, recursion desired/available
	dns = append(dns, 0x00, 0x01) // Questions: 1
	dns = append(dns, 0x00, 0x01) // Answers: 1
	dns = append(dns, 0x00, 0x00) // Authority: 0
	dns = append(dns, 0x00, 0x00) // Additional: 0

	// Question section
	dns = append(dns, encodeDNSName(name)...)
	dns = append(dns, 0x00, 0x01) // Type A
	dns = append(dns, 0x00, 0x01) // Class IN

	// Answer section (using pointer to question name)
	dns = append(dns, 0xC0, 0x0C)             // Name pointer to offset 12
	dns = append(dns, 0x00, 0x01)             // Type A
	dns = append(dns, 0x00, 0x01)             // Class IN
	dns = append(dns, 0x00, 0x00, 0x00, 0x3C) // TTL: 60 seconds
	dns = append(dns, 0x00, 0x04)             // RDLENGTH: 4

	// Parse IP and add as A record data
	ipBytes := parseIPv4(ip)
	dns = append(dns, ipBytes...)

	return dns
}

func encodeDNSName(name string) []byte {
	var result []byte
	labels := splitLabels(name)

	for _, label := range labels {
		result = append(result, byte(len(label)))
		result = append(result, []byte(label)...)
	}
	result = append(result, 0x00) // Null terminator

	return result
}

func splitLabels(name string) []string {
	var labels []string
	current := ""

	for _, c := range name {
		if c == '.' {
			if current != "" {
				labels = append(labels, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}

	if current != "" {
		labels = append(labels, current)
	}

	return labels
}

func parseIPv4(ip string) []byte {
	var result []byte
	var current byte
	var count int

	for _, c := range ip {
		if c >= '0' && c <= '9' {
			current = current*10 + byte(c-'0')
		} else if c == '.' {
			result = append(result, current)
			current = 0
			count++
		}
	}
	result = append(result, current)

	// Pad if needed
	for len(result) < 4 {
		result = append(result, 0)
	}

	return result[:4]
}

func TestDissectorRegistry(t *testing.T) {
	r := NewRegistry()

	// Check default dissectors
	names := r.List()
	expected := []string{"HTTP/2", "WebSocket", "HTTP/1.x", "TLS", "DNS", "gRPC"}

	if len(names) != len(expected) {
		t.Errorf("expected %d dissectors, got %d", len(expected), len(names))
	}

	for i, name := range names {
		if name != expected[i] {
			t.Errorf("expected dissector %d to be %s, got %s", i, expected[i], name)
		}
	}

	// Test Get
	http1 := r.Get("HTTP/1.x")
	if http1 == nil {
		t.Error("expected to find HTTP/1.x dissector")
	}

	unknown := r.Get("Unknown")
	if unknown != nil {
		t.Error("expected nil for unknown dissector")
	}

	// Test Detect
	httpData := []byte("GET / HTTP/1.1\r\n")
	d := r.Detect(httpData)
	if d == nil || d.Name() != "HTTP/1.x" {
		t.Error("expected to detect HTTP/1.x")
	}

	// Test Parse
	pkt := &model.Packet{Timestamp: time.Now()}
	err := r.Parse(httpData, pkt)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if pkt.ApplicationProtocol != "HTTP/1.x" {
		t.Errorf("expected protocol HTTP/1.x, got %s", pkt.ApplicationProtocol)
	}
}

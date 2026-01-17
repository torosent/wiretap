package protocol

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/wiretap/wiretap/internal/model"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type stubDissector struct {
	name   string
	detect bool
	parsed bool
}

func (s *stubDissector) Name() string            { return s.name }
func (s *stubDissector) Detect(data []byte) bool { return s.detect }
func (s *stubDissector) Parse(data []byte, pkt *model.Packet) error {
	s.parsed = true
	pkt.AppInfo = s.name
	return nil
}

func TestDissectorRegistry_Basics(t *testing.T) {
	registry := &DissectorRegistry{dissectors: make([]Dissector, 0)}
	stub := &stubDissector{name: "stub", detect: true}
	registry.Register(stub)

	if registry.Get("stub") == nil {
		t.Fatal("Expected to get registered dissector")
	}

	if len(registry.List()) != 1 {
		t.Errorf("Expected 1 dissector, got %d", len(registry.List()))
	}

	d := registry.Detect([]byte("data"))
	if d == nil {
		t.Fatal("Expected to detect dissector")
	}

	pkt := &model.Packet{}
	if err := registry.Parse([]byte("data"), pkt); err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if pkt.AppInfo != "stub" {
		t.Error("Expected dissector to populate packet")
	}
}

func TestParseRequestAndResponseLine(t *testing.T) {
	method, uri, version, err := ParseRequestLine([]byte("GET /index HTTP/1.1\r\n"))
	if err != nil {
		t.Fatalf("ParseRequestLine failed: %v", err)
	}
	if method != model.HTTPMethodGET || uri != "/index" {
		t.Errorf("Unexpected request line parse: %s %s", method, uri)
	}
	if version != model.HTTPVersion11 {
		t.Errorf("Expected HTTP/1.1 version")
	}

	version, status, text, err := ParseResponseLine([]byte("HTTP/1.1 404 Not Found\r\n"))
	if err != nil {
		t.Fatalf("ParseResponseLine failed: %v", err)
	}
	if status != 404 || text != "Not Found" {
		t.Errorf("Unexpected response parse: %d %s", status, text)
	}
	if version != model.HTTPVersion11 {
		t.Errorf("Expected HTTP/1.1 version")
	}
}

func TestHTTP1StreamParser(t *testing.T) {
	parser := NewStreamParser(false)
	parser.Feed([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n"))
	if conv, err := parser.Parse(); err != nil || conv != nil {
		t.Fatal("Expected incomplete parse")
	}

	parser.Feed([]byte("\r\n"))
	conv, err := parser.Parse()
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if conv == nil || conv.Request == nil {
		t.Fatal("Expected parsed request")
	}

	parser.Reset()
	if conv, err := parser.Parse(); err != nil || conv != nil {
		t.Fatal("Expected empty parser after reset")
	}
}

func TestHTTP2ParseHeadersFrame(t *testing.T) {
	d := NewHTTP2Dissector()
	decoder := hpack.NewDecoder(4096, nil)

	var buf bytes.Buffer
	encoder := hpack.NewEncoder(&buf)
	_ = encoder.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
	_ = encoder.WriteField(hpack.HeaderField{Name: ":path", Value: "/"})

	frame := &model.HTTP2Frame{Payload: buf.Bytes(), Flags: http2.FlagHeadersEndHeaders}
	d.parseHeadersFrame(frame, decoder)
	if len(frame.Headers) == 0 {
		t.Fatal("Expected headers to be parsed")
	}
}

func TestTLSHelpers(t *testing.T) {
	d := NewTLSDissector()

	certs := d.parseCertificates([]byte{0x00, 0x00, 0x00})
	if certs != nil {
		t.Error("Expected no certificates for empty data")
	}

	info := &model.TLSInfo{}
	d.parseAlert([]byte{1, 2}, info)
	if info.AlertLevel != 1 || info.AlertDescription != 2 {
		t.Error("Expected TLS alert fields to be set")
	}

	suites := []model.TLSCipherSuite{0x1301, 0x0005, 0x1302}
	SortCipherSuites(suites)
	if suites[0] != 0x0005 {
		t.Error("Expected suites to be sorted in ascending order")
	}
}

func TestFormatRData(t *testing.T) {
	d := NewDNSDissector()
	a := d.formatRData(1, []byte{8, 8, 8, 8}, 0, 4)
	if a != "8.8.8.8" {
		t.Errorf("formatRData A = %s", a)
	}

	aaaa := d.formatRData(28, bytes.Repeat([]byte{0}, 16), 0, 16)
	if aaaa == "" {
		t.Error("Expected IPv6 string")
	}

	mx := make([]byte, 3)
	binary.BigEndian.PutUint16(mx[0:2], 10)
	mx = append(mx, []byte("mail")...)
	if result := d.formatRData(15, mx, 0, len(mx)); result == "" {
		t.Error("Expected MX formatting")
	}
}

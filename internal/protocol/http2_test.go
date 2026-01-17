package protocol

import (
	"bytes"
	"testing"
	"time"

	"github.com/wiretap/wiretap/internal/model"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestHTTP2DissectorName(t *testing.T) {
	d := NewHTTP2Dissector()
	if d.Name() != "HTTP/2" {
		t.Errorf("expected name HTTP/2, got %s", d.Name())
	}
}

func TestHTTP2DissectorDetectPreface(t *testing.T) {
	d := NewHTTP2Dissector()

	// HTTP/2 connection preface
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	if !d.Detect(preface) {
		t.Error("expected to detect HTTP/2 preface")
	}
}

func TestHTTP2DissectorDetectFrame(t *testing.T) {
	d := NewHTTP2Dissector()

	// Valid SETTINGS frame: length=0, type=4, flags=0, stream=0
	frame := []byte{
		0x00, 0x00, 0x00, // length = 0
		0x04,                   // type = SETTINGS
		0x00,                   // flags = 0
		0x00, 0x00, 0x00, 0x00, // stream ID = 0
	}

	if !d.Detect(frame) {
		t.Error("expected to detect HTTP/2 SETTINGS frame")
	}
}

func TestHTTP2DissectorDetectInvalid(t *testing.T) {
	d := NewHTTP2Dissector()

	tests := []struct {
		name string
		data []byte
	}{
		{"Empty", []byte{}},
		{"Short", []byte{0x00, 0x00}},
		{"Invalid type", []byte{0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00}},
		// TLS records should NOT be detected as HTTP/2
		{"TLS Handshake", []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00}},
		{"TLS Application Data", []byte{0x17, 0x03, 0x03, 0x00, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05}},
		{"TLS Alert", []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00}},
		{"TLS ChangeCipherSpec", []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00}},
		// Invalid HTTP/2 flags
		{"Invalid DATA flags", []byte{0x00, 0x00, 0x05, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x01}},
		// Stream ID constraints: SETTINGS must use stream 0
		{"SETTINGS non-zero stream", []byte{0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x01}},
		// Stream ID constraints: DATA must not use stream 0
		{"DATA stream zero", []byte{0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if d.Detect(tt.data) {
				t.Error("expected not to detect invalid data")
			}
		})
	}
}

func TestHTTP2DissectorParseSettings(t *testing.T) {
	d := NewHTTP2Dissector()

	// SETTINGS frame with one setting: HEADER_TABLE_SIZE = 4096
	frame := []byte{
		0x00, 0x00, 0x06, // length = 6
		0x04,                   // type = SETTINGS
		0x00,                   // flags = 0
		0x00, 0x00, 0x00, 0x00, // stream ID = 0
		// Setting: HEADER_TABLE_SIZE (1) = 4096
		0x00, 0x01, // ID
		0x00, 0x00, 0x10, 0x00, // Value
	}

	pkt := &model.Packet{Timestamp: time.Now()}
	err := d.Parse(frame, pkt)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if pkt.ApplicationProtocol != "HTTP/2" {
		t.Errorf("expected protocol HTTP/2, got %s", pkt.ApplicationProtocol)
	}

	if len(pkt.HTTP2Frames) == 0 {
		t.Fatal("expected at least one frame")
	}

	f := pkt.HTTP2Frames[0]
	if f.Type != http2.FrameSettings {
		t.Errorf("expected SETTINGS frame, got %v", f.Type)
	}

	if v, ok := f.Settings[http2.SettingHeaderTableSize]; !ok || v != 4096 {
		t.Errorf("expected HEADER_TABLE_SIZE=4096, got %v", f.Settings)
	}
}

func TestHTTP2DissectorParseData(t *testing.T) {
	d := NewHTTP2Dissector()

	// DATA frame with payload
	payload := []byte("Hello, World!")
	frame := make([]byte, 9+len(payload))
	frame[0] = 0x00
	frame[1] = 0x00
	frame[2] = byte(len(payload)) // length
	frame[3] = 0x00               // type = DATA
	frame[4] = 0x01               // flags = END_STREAM
	frame[5] = 0x00
	frame[6] = 0x00
	frame[7] = 0x00
	frame[8] = 0x01 // stream ID = 1
	copy(frame[9:], payload)

	pkt := &model.Packet{Timestamp: time.Now()}
	err := d.Parse(frame, pkt)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(pkt.HTTP2Frames) == 0 {
		t.Fatal("expected at least one frame")
	}

	f := pkt.HTTP2Frames[0]
	if f.Type != http2.FrameData {
		t.Errorf("expected DATA frame, got %v", f.Type)
	}

	if f.StreamID != 1 {
		t.Errorf("expected stream ID 1, got %d", f.StreamID)
	}

	if string(f.Payload) != "Hello, World!" {
		t.Errorf("expected payload 'Hello, World!', got %q", f.Payload)
	}
}

func TestHTTP2DissectorParseGRPC(t *testing.T) {
	var buf bytes.Buffer
	fr := http2.NewFramer(&buf, nil)

	// Build HPACK headers indicating gRPC content.
	var hbuf bytes.Buffer
	enc := hpack.NewEncoder(&hbuf)
	_ = enc.WriteField(hpack.HeaderField{Name: ":method", Value: "POST"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":path", Value: "/svc.Test/Method"})
	_ = enc.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/grpc"})

	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: hbuf.Bytes(),
		EndHeaders:    true,
	}); err != nil {
		t.Fatalf("WriteHeaders failed: %v", err)
	}

	grpcPayload := []byte{0x00, 0x00, 0x00, 0x00, 0x02, 'h', 'i'}
	if err := fr.WriteData(1, true, grpcPayload); err != nil {
		t.Fatalf("WriteData failed: %v", err)
	}

	packet := &model.Packet{Timestamp: time.Now()}
	d := NewHTTP2Dissector()
	if err := d.Parse(buf.Bytes(), packet); err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if packet.ApplicationProtocol != "gRPC" {
		t.Fatalf("expected ApplicationProtocol gRPC, got %s", packet.ApplicationProtocol)
	}
	if len(packet.GRPCMessages) != 1 {
		t.Fatalf("expected 1 gRPC message, got %d", len(packet.GRPCMessages))
	}
	if packet.GRPCMessages[0].ServiceMethod != "/svc.Test/Method" {
		t.Errorf("ServiceMethod = %s", packet.GRPCMessages[0].ServiceMethod)
	}
}

func TestHTTP2StreamParser_ProcessFrame(t *testing.T) {
	parser := NewHTTP2StreamParser()

	headersFrame := &model.HTTP2Frame{
		Type:     http2.FrameHeaders,
		StreamID: 1,
		Flags:    http2.FlagHeadersEndHeaders,
		Headers:  []model.Header{{Name: ":path", Value: "/"}},
	}
	if err := parser.ProcessFrame(headersFrame); err != nil {
		t.Fatalf("ProcessFrame headers failed: %v", err)
	}

	dataFrame := &model.HTTP2Frame{
		Type:     http2.FrameData,
		StreamID: 1,
		Flags:    http2.FlagDataEndStream,
		Payload:  []byte("hello"),
	}
	if err := parser.ProcessFrame(dataFrame); err != nil {
		t.Fatalf("ProcessFrame data failed: %v", err)
	}

	stream, err := parser.GetStream(1)
	if err != nil {
		t.Fatalf("GetStream failed: %v", err)
	}
	if string(stream.Data) != "hello" {
		t.Fatalf("unexpected stream data: %s", string(stream.Data))
	}

	if _, err := parser.GetStream(2); err == nil {
		t.Fatal("expected error for missing stream")
	}
}

func TestHTTP2DissectorParseGoAway(t *testing.T) {
	d := NewHTTP2Dissector()

	// GOAWAY frame
	frame := []byte{
		0x00, 0x00, 0x08, // length = 8
		0x07,                   // type = GOAWAY
		0x00,                   // flags = 0
		0x00, 0x00, 0x00, 0x00, // stream ID = 0
		// Payload
		0x00, 0x00, 0x00, 0x05, // last stream ID = 5
		0x00, 0x00, 0x00, 0x00, // error code = NO_ERROR
	}

	pkt := &model.Packet{Timestamp: time.Now()}
	err := d.Parse(frame, pkt)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(pkt.HTTP2Frames) == 0 {
		t.Fatal("expected at least one frame")
	}

	f := pkt.HTTP2Frames[0]
	if f.Type != http2.FrameGoAway {
		t.Errorf("expected GOAWAY frame, got %v", f.Type)
	}

	if f.LastStreamID != 5 {
		t.Errorf("expected last stream ID 5, got %d", f.LastStreamID)
	}

	if f.ErrorCode != http2.ErrCodeNo {
		t.Errorf("expected NO_ERROR, got %v", f.ErrorCode)
	}
}

func TestHTTP2StreamParser(t *testing.T) {
	parser := NewHTTP2StreamParser()

	// Process HEADERS frame
	headersFrame := &model.HTTP2Frame{
		Type:     http2.FrameHeaders,
		Flags:    http2.FlagHeadersEndHeaders,
		StreamID: 1,
		Headers: []model.Header{
			{Name: ":method", Value: "GET"},
			{Name: ":path", Value: "/"},
		},
	}

	err := parser.ProcessFrame(headersFrame)
	if err != nil {
		t.Fatalf("ProcessFrame failed: %v", err)
	}

	// Process DATA frame
	dataFrame := &model.HTTP2Frame{
		Type:     http2.FrameData,
		Flags:    http2.FlagDataEndStream,
		StreamID: 1,
		Payload:  []byte("body"),
	}

	err = parser.ProcessFrame(dataFrame)
	if err != nil {
		t.Fatalf("ProcessFrame failed: %v", err)
	}

	// Get stream
	stream, err := parser.GetStream(1)
	if err != nil {
		t.Fatalf("GetStream failed: %v", err)
	}

	if stream == nil {
		t.Fatal("expected non-nil stream")
	}

	if string(stream.Data) != "body" {
		t.Errorf("expected body 'body', got %q", stream.Data)
	}

	// Test non-existent stream
	_, err = parser.GetStream(99)
	if err == nil {
		t.Error("expected error for non-existent stream")
	}

	// Test reset
	parser.Reset()
	_, err = parser.GetStream(1)
	if err == nil {
		t.Error("expected error after reset")
	}
}

func TestHTTP2DissectorSkipPreface(t *testing.T) {
	d := NewHTTP2Dissector()

	// Connection preface followed by SETTINGS frame
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	settings := []byte{
		0x00, 0x00, 0x00, // length = 0
		0x04,                   // type = SETTINGS
		0x00,                   // flags = 0
		0x00, 0x00, 0x00, 0x00, // stream ID = 0
	}

	data := append(preface, settings...)

	pkt := &model.Packet{Timestamp: time.Now()}
	err := d.Parse(data, pkt)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(pkt.HTTP2Frames) == 0 {
		t.Fatal("expected at least one frame after preface")
	}

	if pkt.HTTP2Frames[0].Type != http2.FrameSettings {
		t.Errorf("expected SETTINGS frame, got %v", pkt.HTTP2Frames[0].Type)
	}
}

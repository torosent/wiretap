package protocol

import (
	"testing"

	"github.com/wiretap/wiretap/internal/model"
)

func TestNewWebSocketDissector(t *testing.T) {
	d := NewWebSocketDissector()
	if d == nil {
		t.Fatal("NewWebSocketDissector returned nil")
	}
	if d.Name() != "WebSocket" {
		t.Errorf("Expected name 'WebSocket', got '%s'", d.Name())
	}
}

func TestWebSocketDissector_Detect(t *testing.T) {
	d := NewWebSocketDissector()

	tests := []struct {
		name   string
		data   []byte
		expect bool
	}{
		{
			name: "upgrade request",
			data: []byte("GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"),
			expect: true,
		},
		{
			name: "upgrade response",
			data: []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"),
			expect: true,
		},
		{
			name: "text frame",
			data: []byte{0x81, 0x05, 'h', 'e', 'l', 'l', 'o'},
			expect: true,
		},
		{
			name: "binary frame",
			data: []byte{0x82, 0x04, 0x01, 0x02, 0x03, 0x04},
			expect: true,
		},
		{
			name: "close frame",
			data: []byte{0x88, 0x02, 0x03, 0xe8},
			expect: true,
		},
		{
			name: "ping frame",
			data: []byte{0x89, 0x00},
			expect: true,
		},
		{
			name: "pong frame",
			data: []byte{0x8A, 0x00},
			expect: true,
		},
		{
			name: "regular HTTP",
			data: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expect: false,
		},
		{
			name: "TLS data",
			data: []byte{0x16, 0x03, 0x01, 0x00, 0x05},
			expect: false,
		},
		{
			name: "short data",
			data: []byte{0x81},
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := d.Detect(tt.data)
			if got != tt.expect {
				t.Errorf("Detect() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestWebSocketDissector_ParseUpgradeRequest(t *testing.T) {
	d := NewWebSocketDissector()
	pkt := &model.Packet{}

	data := []byte("GET /chat HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")

	err := d.Parse(data, pkt)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if pkt.ApplicationProtocol != "WebSocket" {
		t.Errorf("ApplicationProtocol = %s, want WebSocket", pkt.ApplicationProtocol)
	}
	if pkt.WebSocketHandshake == nil {
		t.Fatal("WebSocketHandshake is nil")
	}
	if !pkt.WebSocketHandshake.IsRequest {
		t.Error("Expected IsRequest to be true")
	}
	if pkt.WebSocketHandshake.ResourcePath != "/chat" {
		t.Errorf("ResourcePath = %s, want /chat", pkt.WebSocketHandshake.ResourcePath)
	}
	if pkt.WebSocketHandshake.Headers["Sec-WebSocket-Key"] != "dGhlIHNhbXBsZSBub25jZQ==" {
		t.Errorf("Sec-WebSocket-Key not parsed correctly")
	}
}

func TestWebSocketDissector_ParseUpgradeResponse(t *testing.T) {
	d := NewWebSocketDissector()
	pkt := &model.Packet{}

	data := []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")

	err := d.Parse(data, pkt)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if pkt.WebSocketHandshake == nil {
		t.Fatal("WebSocketHandshake is nil")
	}
	if pkt.WebSocketHandshake.IsRequest {
		t.Error("Expected IsRequest to be false")
	}
}

func TestWebSocketDissector_ParseTextFrame(t *testing.T) {
	d := NewWebSocketDissector()
	pkt := &model.Packet{}

	// Unmasked text frame with "hello"
	data := []byte{0x81, 0x05, 'h', 'e', 'l', 'l', 'o'}

	err := d.Parse(data, pkt)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(pkt.WebSocketFrames) != 1 {
		t.Fatalf("Expected 1 frame, got %d", len(pkt.WebSocketFrames))
	}

	frame := pkt.WebSocketFrames[0]
	if !frame.FIN {
		t.Error("Expected FIN to be true")
	}
	if frame.Opcode != 0x1 {
		t.Errorf("Opcode = %d, want 1", frame.Opcode)
	}
	if frame.Masked {
		t.Error("Expected Masked to be false")
	}
	if frame.PayloadLength != 5 {
		t.Errorf("PayloadLength = %d, want 5", frame.PayloadLength)
	}
	if string(frame.Payload) != "hello" {
		t.Errorf("Payload = %q, want 'hello'", frame.Payload)
	}
}

func TestWebSocketDissector_ParseMaskedFrame(t *testing.T) {
	d := NewWebSocketDissector()
	pkt := &model.Packet{}

	// Masked text frame with "hello"
	// Masking key: 0x37, 0xfa, 0x21, 0x3d
	// Masked "hello": h^0x37=0x5f, e^0xfa=0x9f, l^0x21=0x4d, l^0x3d=0x51, o^0x37=0x58
	data := []byte{
		0x81, 0x85, // FIN=1, opcode=1, MASK=1, len=5
		0x37, 0xfa, 0x21, 0x3d, // Masking key
		0x5f, 0x9f, 0x4d, 0x51, 0x58, // Masked payload
	}

	err := d.Parse(data, pkt)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(pkt.WebSocketFrames) != 1 {
		t.Fatalf("Expected 1 frame, got %d", len(pkt.WebSocketFrames))
	}

	frame := pkt.WebSocketFrames[0]
	if !frame.Masked {
		t.Error("Expected Masked to be true")
	}
	if string(frame.Payload) != "hello" {
		t.Errorf("Payload = %q, want 'hello'", frame.Payload)
	}
}

func TestWebSocketDissector_ParseExtendedLength16(t *testing.T) {
	d := NewWebSocketDissector()
	pkt := &model.Packet{}

	// Frame with 16-bit extended length (200 bytes)
	payload := make([]byte, 200)
	for i := range payload {
		payload[i] = byte(i)
	}

	data := []byte{0x82, 0x7E, 0x00, 0xC8} // FIN=1, opcode=2, len=126 indicator, len=200
	data = append(data, payload...)

	err := d.Parse(data, pkt)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(pkt.WebSocketFrames) != 1 {
		t.Fatalf("Expected 1 frame, got %d", len(pkt.WebSocketFrames))
	}

	frame := pkt.WebSocketFrames[0]
	if frame.PayloadLength != 200 {
		t.Errorf("PayloadLength = %d, want 200", frame.PayloadLength)
	}
}

func TestWebSocketDissector_ParseCloseFrame(t *testing.T) {
	d := NewWebSocketDissector()
	pkt := &model.Packet{}

	// Close frame with code 1000 (normal closure) and reason "goodbye"
	data := []byte{0x88, 0x09, 0x03, 0xe8, 'g', 'o', 'o', 'd', 'b', 'y', 'e'}

	err := d.Parse(data, pkt)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	frame := pkt.WebSocketFrames[0]
	if frame.Opcode != 0x8 {
		t.Errorf("Opcode = %d, want 8", frame.Opcode)
	}
	if !frame.IsClose() {
		t.Error("IsClose() should return true")
	}
	if frame.CloseCode() != 1000 {
		t.Errorf("CloseCode() = %d, want 1000", frame.CloseCode())
	}
	if frame.CloseReason() != "goodbye" {
		t.Errorf("CloseReason() = %q, want 'goodbye'", frame.CloseReason())
	}
}

func TestWebSocketDissector_ParseMultipleFrames(t *testing.T) {
	d := NewWebSocketDissector()
	pkt := &model.Packet{}

	// Two text frames: "foo" and "bar"
	data := []byte{
		0x81, 0x03, 'f', 'o', 'o', // Frame 1
		0x81, 0x03, 'b', 'a', 'r', // Frame 2
	}

	err := d.Parse(data, pkt)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(pkt.WebSocketFrames) != 2 {
		t.Fatalf("Expected 2 frames, got %d", len(pkt.WebSocketFrames))
	}

	if string(pkt.WebSocketFrames[0].Payload) != "foo" {
		t.Errorf("Frame 0 payload = %q, want 'foo'", pkt.WebSocketFrames[0].Payload)
	}
	if string(pkt.WebSocketFrames[1].Payload) != "bar" {
		t.Errorf("Frame 1 payload = %q, want 'bar'", pkt.WebSocketFrames[1].Payload)
	}
}

func TestWebSocketDissector_IncompleteFrame(t *testing.T) {
	d := NewWebSocketDissector()
	pkt := &model.Packet{}

	// Incomplete frame (header says 10 bytes, but only 5 present)
	data := []byte{0x81, 0x0A, 'h', 'e', 'l', 'l', 'o'}

	err := d.Parse(data, pkt)
	// Should return error or no frames
	if err == nil && len(pkt.WebSocketFrames) > 0 {
		t.Error("Should not parse incomplete frame successfully")
	}
}

func TestWebSocketFrame_Summary(t *testing.T) {
	tests := []struct {
		name   string
		frame  *model.WebSocketFrame
		expect string
	}{
		{
			name: "text frame",
			frame: &model.WebSocketFrame{
				Opcode:  0x1,
				Payload: []byte("hello world"),
			},
			expect: `WebSocket Text: "hello world"`,
		},
		{
			name: "long text frame",
			frame: &model.WebSocketFrame{
				Opcode:  0x1,
				Payload: []byte("this is a very long message that exceeds fifty characters in length"),
			},
			expect: `WebSocket Text: "this is a very long message that exceeds fifty cha..."`,
		},
		{
			name: "binary frame",
			frame: &model.WebSocketFrame{
				Opcode:        0x2,
				PayloadLength: 100,
			},
			expect: "WebSocket Binary (100 bytes)",
		},
		{
			name: "ping frame",
			frame: &model.WebSocketFrame{
				Opcode: 0x9,
			},
			expect: "WebSocket Ping",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.frame.Summary()
			if got != tt.expect {
				t.Errorf("Summary() = %q, want %q", got, tt.expect)
			}
		})
	}
}

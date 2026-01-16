// Package model defines WebSocket-related types.
package model

import "fmt"

// WebSocketOpcode represents a WebSocket frame opcode.
type WebSocketOpcode uint8

// WebSocket opcode constants.
const (
	WebSocketOpcodeContinuation WebSocketOpcode = 0x0
	WebSocketOpcodeText         WebSocketOpcode = 0x1
	WebSocketOpcodeBinary       WebSocketOpcode = 0x2
	WebSocketOpcodeClose        WebSocketOpcode = 0x8
	WebSocketOpcodePing         WebSocketOpcode = 0x9
	WebSocketOpcodePong         WebSocketOpcode = 0xA
)

// String returns the opcode name.
func (o WebSocketOpcode) String() string {
	switch o {
	case WebSocketOpcodeContinuation:
		return "Continuation"
	case WebSocketOpcodeText:
		return "Text"
	case WebSocketOpcodeBinary:
		return "Binary"
	case WebSocketOpcodeClose:
		return "Close"
	case WebSocketOpcodePing:
		return "Ping"
	case WebSocketOpcodePong:
		return "Pong"
	default:
		return fmt.Sprintf("Unknown(%d)", o)
	}
}

// IsControl returns true if the opcode is a control frame.
func (o WebSocketOpcode) IsControl() bool {
	return o >= 0x8
}

// WebSocketHandshake contains WebSocket upgrade handshake information.
type WebSocketHandshake struct {
	// IsRequest indicates if this is an upgrade request (vs response).
	IsRequest bool

	// ResourcePath is the requested WebSocket path (request only).
	ResourcePath string

	// Headers from the handshake.
	Headers map[string]string

	// Key is the Sec-WebSocket-Key (request) or Sec-WebSocket-Accept (response).
	Key string

	// Protocol is the negotiated subprotocol.
	Protocol string

	// Extensions are the negotiated extensions.
	Extensions []string

	// Version is the WebSocket version.
	Version string
}

// SecWebSocketKey returns the Sec-WebSocket-Key header value.
func (h *WebSocketHandshake) SecWebSocketKey() string {
	if h.Headers != nil {
		if key, ok := h.Headers["Sec-WebSocket-Key"]; ok {
			return key
		}
	}
	return h.Key
}

// SecWebSocketProtocol returns the Sec-WebSocket-Protocol header value.
func (h *WebSocketHandshake) SecWebSocketProtocol() string {
	if h.Headers != nil {
		if proto, ok := h.Headers["Sec-WebSocket-Protocol"]; ok {
			return proto
		}
	}
	return h.Protocol
}

// WebSocketFrame represents a single WebSocket frame.
type WebSocketFrame struct {
	// FIN indicates this is the final fragment.
	FIN bool

	// RSV1-3 are reserved bits.
	RSV1 bool
	RSV2 bool
	RSV3 bool

	// Opcode identifies the frame type.
	Opcode uint8

	// Masked indicates the payload is masked.
	Masked bool

	// MaskingKey is the 4-byte masking key (if Masked).
	MaskingKey []byte

	// PayloadLength is the length of the payload.
	PayloadLength uint64

	// Payload is the (unmasked) frame payload.
	Payload []byte
}

// OpcodeType returns the opcode as a WebSocketOpcode type.
func (f *WebSocketFrame) OpcodeType() WebSocketOpcode {
	return WebSocketOpcode(f.Opcode)
}

// IsControl returns true if this is a control frame.
func (f *WebSocketFrame) IsControl() bool {
	return f.Opcode >= 0x8
}

// IsText returns true if this is a text frame.
func (f *WebSocketFrame) IsText() bool {
	return f.Opcode == uint8(WebSocketOpcodeText)
}

// IsBinary returns true if this is a binary frame.
func (f *WebSocketFrame) IsBinary() bool {
	return f.Opcode == uint8(WebSocketOpcodeBinary)
}

// IsClose returns true if this is a close frame.
func (f *WebSocketFrame) IsClose() bool {
	return f.Opcode == uint8(WebSocketOpcodeClose)
}

// IsPing returns true if this is a ping frame.
func (f *WebSocketFrame) IsPing() bool {
	return f.Opcode == uint8(WebSocketOpcodePing)
}

// IsPong returns true if this is a pong frame.
func (f *WebSocketFrame) IsPong() bool {
	return f.Opcode == uint8(WebSocketOpcodePong)
}

// Summary returns a brief description of the frame.
func (f *WebSocketFrame) Summary() string {
	opName := WebSocketOpcode(f.Opcode).String()
	if f.IsText() && len(f.Payload) > 0 {
		preview := string(f.Payload)
		if len(preview) > 50 {
			preview = preview[:50] + "..."
		}
		return fmt.Sprintf("WebSocket %s: %q", opName, preview)
	}
	if f.PayloadLength > 0 {
		return fmt.Sprintf("WebSocket %s (%d bytes)", opName, f.PayloadLength)
	}
	return fmt.Sprintf("WebSocket %s", opName)
}

// CloseCode returns the close code if this is a close frame.
func (f *WebSocketFrame) CloseCode() uint16 {
	if f.Opcode != uint8(WebSocketOpcodeClose) || len(f.Payload) < 2 {
		return 0
	}
	return uint16(f.Payload[0])<<8 | uint16(f.Payload[1])
}

// CloseReason returns the close reason if this is a close frame.
func (f *WebSocketFrame) CloseReason() string {
	if f.Opcode != uint8(WebSocketOpcodeClose) || len(f.Payload) <= 2 {
		return ""
	}
	return string(f.Payload[2:])
}

// TextPayload returns the payload as a string.
func (f *WebSocketFrame) TextPayload() string {
	return string(f.Payload)
}

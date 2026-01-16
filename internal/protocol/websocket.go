// Package protocol provides WebSocket frame parsing.
package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/wiretap/wiretap/internal/model"
)

// WebSocket opcode constants.
const (
	wsOpcodeContinuation = 0x0
	wsOpcodeText         = 0x1
	wsOpcodeBinary       = 0x2
	wsOpcodeClose        = 0x8
	wsOpcodePing         = 0x9
	wsOpcodePong         = 0xA
)

// WebSocket frame header bytes.
const (
	wsFIN   = 0x80
	wsMask  = 0x80
	wsLen7  = 0x7F
	wsLen16 = 126
	wsLen64 = 127
)

// Common WebSocket errors.
var (
	ErrInvalidWebSocketFrame = errors.New("invalid WebSocket frame")
	ErrWebSocketFrameTooLarge = errors.New("WebSocket frame too large")
)

// WebSocketDissector parses WebSocket protocol traffic.
type WebSocketDissector struct{}

// NewWebSocketDissector creates a new WebSocket dissector.
func NewWebSocketDissector() *WebSocketDissector {
	return &WebSocketDissector{}
}

// Name returns the dissector name.
func (d *WebSocketDissector) Name() string {
	return "WebSocket"
}

// Detect checks if data looks like a WebSocket handshake or frame.
func (d *WebSocketDissector) Detect(data []byte) bool {
	// Check for WebSocket upgrade request.
	if bytes.HasPrefix(data, []byte("GET ")) {
		if bytes.Contains(data, []byte("Upgrade: websocket")) ||
			bytes.Contains(data, []byte("upgrade: websocket")) {
			return true
		}
	}

	// Check for WebSocket upgrade response.
	if bytes.HasPrefix(data, []byte("HTTP/1.1 101")) {
		if bytes.Contains(data, []byte("Upgrade: websocket")) ||
			bytes.Contains(data, []byte("upgrade: websocket")) {
			return true
		}
	}

	// Check for WebSocket frame header.
	if len(data) >= 2 {
		opcode := data[0] & 0x0F
		// Valid opcodes: 0-2 (data frames) and 8-10 (control frames).
		if opcode <= 2 || (opcode >= 8 && opcode <= 10) {
			// Check if length byte looks valid.
			lenByte := data[1] & wsLen7
			if lenByte <= 125 || lenByte == wsLen16 || lenByte == wsLen64 {
				return true
			}
		}
	}

	return false
}

// Parse extracts WebSocket frame information.
func (d *WebSocketDissector) Parse(data []byte, pkt *model.Packet) error {
	// Check for WebSocket handshake.
	if bytes.HasPrefix(data, []byte("GET ")) || bytes.HasPrefix(data, []byte("HTTP/")) {
		return d.parseHandshake(data, pkt)
	}

	// Parse as WebSocket frames.
	frames, err := d.parseFrames(data)
	if err != nil {
		return err
	}

	if len(frames) == 0 {
		return ErrIncompleteData
	}

	pkt.ApplicationProtocol = "WebSocket"
	pkt.WebSocketFrames = frames

	// Set AppInfo based on first frame.
	if len(frames) > 0 {
		pkt.AppInfo = frames[0].Summary()
	}

	return nil
}

// parseHandshake parses a WebSocket handshake request/response.
func (d *WebSocketDissector) parseHandshake(data []byte, pkt *model.Packet) error {
	pkt.ApplicationProtocol = "WebSocket"

	if bytes.HasPrefix(data, []byte("GET ")) {
		// Parse upgrade request.
		pkt.AppInfo = "WebSocket Upgrade Request"
		pkt.WebSocketHandshake = &model.WebSocketHandshake{
			IsRequest: true,
			Headers:   d.extractHeaders(data),
		}

		// Extract resource path.
		if endPath := bytes.Index(data, []byte(" HTTP/")); endPath > 4 {
			pkt.WebSocketHandshake.ResourcePath = string(data[4:endPath])
		}
	} else if bytes.HasPrefix(data, []byte("HTTP/1.1 101")) {
		// Parse upgrade response.
		pkt.AppInfo = "WebSocket Upgrade Response"
		pkt.WebSocketHandshake = &model.WebSocketHandshake{
			IsRequest: false,
			Headers:   d.extractHeaders(data),
		}
	}

	return nil
}

// extractHeaders extracts headers from HTTP-style data.
func (d *WebSocketDissector) extractHeaders(data []byte) map[string]string {
	headers := make(map[string]string)

	lines := bytes.Split(data, []byte("\r\n"))
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if len(line) == 0 {
			break
		}
		colonIdx := bytes.Index(line, []byte(": "))
		if colonIdx > 0 {
			key := string(line[:colonIdx])
			value := string(line[colonIdx+2:])
			headers[key] = value
		}
	}

	return headers
}

// parseFrames extracts all WebSocket frames from the data.
func (d *WebSocketDissector) parseFrames(data []byte) ([]*model.WebSocketFrame, error) {
	var frames []*model.WebSocketFrame
	offset := 0

	for offset < len(data) {
		frame, consumed, err := d.parseFrame(data[offset:])
		if err != nil {
			break
		}
		if consumed == 0 {
			break
		}
		frames = append(frames, frame)
		offset += consumed
	}

	return frames, nil
}

// parseFrame parses a single WebSocket frame.
// Returns the frame, bytes consumed, and any error.
func (d *WebSocketDissector) parseFrame(data []byte) (*model.WebSocketFrame, int, error) {
	if len(data) < 2 {
		return nil, 0, ErrIncompleteData
	}

	frame := &model.WebSocketFrame{}

	// First byte: FIN + RSV + Opcode.
	frame.FIN = (data[0] & wsFIN) != 0
	frame.RSV1 = (data[0] & 0x40) != 0
	frame.RSV2 = (data[0] & 0x20) != 0
	frame.RSV3 = (data[0] & 0x10) != 0
	frame.Opcode = data[0] & 0x0F

	// Second byte: Mask flag + Payload length.
	frame.Masked = (data[1] & wsMask) != 0
	lenByte := data[1] & wsLen7

	offset := 2
	var payloadLen uint64

	switch {
	case lenByte <= 125:
		payloadLen = uint64(lenByte)
	case lenByte == wsLen16:
		if len(data) < 4 {
			return nil, 0, ErrIncompleteData
		}
		payloadLen = uint64(binary.BigEndian.Uint16(data[2:4]))
		offset = 4
	case lenByte == wsLen64:
		if len(data) < 10 {
			return nil, 0, ErrIncompleteData
		}
		payloadLen = binary.BigEndian.Uint64(data[2:10])
		offset = 10
	}

	frame.PayloadLength = payloadLen

	// Validate payload length.
	if payloadLen > 16*1024*1024 { // 16MB max.
		return nil, 0, ErrWebSocketFrameTooLarge
	}

	// Read masking key if present.
	if frame.Masked {
		if len(data) < offset+4 {
			return nil, 0, ErrIncompleteData
		}
		frame.MaskingKey = make([]byte, 4)
		copy(frame.MaskingKey, data[offset:offset+4])
		offset += 4
	}

	// Read payload.
	payloadEnd := offset + int(payloadLen)
	if len(data) < payloadEnd {
		return nil, 0, ErrIncompleteData
	}

	payload := make([]byte, payloadLen)
	copy(payload, data[offset:payloadEnd])

	// Unmask payload if necessary.
	if frame.Masked && len(frame.MaskingKey) == 4 {
		for i := range payload {
			payload[i] ^= frame.MaskingKey[i%4]
		}
	}

	frame.Payload = payload

	return frame, payloadEnd, nil
}

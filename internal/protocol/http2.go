package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/wiretap/wiretap/internal/model"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// HTTP/2 magic prefix (connection preface)
var http2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// HTTP2Dissector parses HTTP/2 protocol traffic (cleartext h2c).
type HTTP2Dissector struct{}

// NewHTTP2Dissector creates a new HTTP/2 dissector.
func NewHTTP2Dissector() *HTTP2Dissector {
	return &HTTP2Dissector{}
}

// Name returns the dissector name.
func (d *HTTP2Dissector) Name() string {
	return "HTTP/2"
}

// Detect checks if data looks like HTTP/2 traffic.
func (d *HTTP2Dissector) Detect(data []byte) bool {
	// Check for HTTP/2 connection preface
	if bytes.HasPrefix(data, http2Preface) {
		return true
	}

	// Check for HTTP/2 frame (if already past the preface)
	// Frame format: 9-byte header (3 length + 1 type + 1 flags + 4 stream ID)
	if len(data) >= 9 {
		// First check: reject TLS records (content type 0x14-0x18, 0xff)
		// TLS records start with: type (1 byte), version (2 bytes), length (2 bytes)
		if data[0] >= 0x14 && data[0] <= 0x18 {
			// Likely TLS: ChangeCipherSpec(20), Alert(21), Handshake(22), AppData(23), Heartbeat(24)
			return false
		}
		if data[0] == 0xff {
			// TLS reserved
			return false
		}

		// Parse potential HTTP/2 frame header
		length := int(data[0])<<16 | int(data[1])<<8 | int(data[2])
		frameType := data[3]
		flags := data[4]
		streamID := binary.BigEndian.Uint32(data[5:9]) & 0x7FFFFFFF // Mask reserved bit

		// Valid frame type (0-9 defined in RFC 7540)
		if frameType > 9 {
			return false
		}

		// Sanity checks for HTTP/2 frames
		// Frame length should be reasonable (max 16KB default, 16MB max)
		if length > 16*1024*1024 {
			return false
		}

		// Validate flags based on frame type
		validFlags := false
		switch frameType {
		case 0: // DATA: END_STREAM(0x1), PADDED(0x8)
			validFlags = flags&^0x09 == 0
		case 1: // HEADERS: END_STREAM(0x1), END_HEADERS(0x4), PADDED(0x8), PRIORITY(0x20)
			validFlags = flags&^0x2d == 0
		case 2: // PRIORITY: no flags
			validFlags = flags == 0
		case 3: // RST_STREAM: no flags
			validFlags = flags == 0
		case 4: // SETTINGS: ACK(0x1)
			validFlags = flags&^0x01 == 0
		case 5: // PUSH_PROMISE: END_HEADERS(0x4), PADDED(0x8)
			validFlags = flags&^0x0c == 0
		case 6: // PING: ACK(0x1)
			validFlags = flags&^0x01 == 0
		case 7: // GOAWAY: no flags
			validFlags = flags == 0
		case 8: // WINDOW_UPDATE: no flags
			validFlags = flags == 0
		case 9: // CONTINUATION: END_HEADERS(0x4)
			validFlags = flags&^0x04 == 0
		}

		if !validFlags {
			return false
		}

		// Stream ID constraints
		// SETTINGS, PING, GOAWAY must use stream 0
		if (frameType == 4 || frameType == 6 || frameType == 7) && streamID != 0 {
			return false
		}
		// DATA, HEADERS, PRIORITY, RST_STREAM, PUSH_PROMISE, CONTINUATION must not use stream 0
		if (frameType == 0 || frameType == 1 || frameType == 2 || frameType == 3 || frameType == 5 || frameType == 9) && streamID == 0 {
			return false
		}

		return true
	}

	return false
}

// Parse extracts HTTP/2 frame information.
func (d *HTTP2Dissector) Parse(data []byte, pkt *model.Packet) error {
	// Skip connection preface if present
	data = bytes.TrimPrefix(data, http2Preface)

	decoder := hpack.NewDecoder(4096, nil) // Per-parse decoder to avoid cross-connection state bleed.

	if len(data) < 9 {
		return ErrIncompleteData
	}

	frames, err := d.parseFrames(data, decoder)
	if err != nil {
		return err
	}

	if len(frames) == 0 {
		return ErrIncompleteData
	}

	pkt.ApplicationProtocol = "HTTP/2"
	pkt.HTTP2Frames = frames

	// Try to reconstruct HTTP request/response from HEADERS frames
	for _, frame := range frames {
		if frame.Type == http2.FrameHeaders {
			if conv := d.extractConversation(frame); conv != nil {
				pkt.HTTPInfo = conv
				break
			}
		}
	}

	// Attempt gRPC parsing from HTTP/2 DATA frames when content-type is application/grpc.
	if grpcMessages := d.extractGRPCMessages(frames); len(grpcMessages) > 0 {
		pkt.GRPCMessages = grpcMessages
		pkt.ApplicationProtocol = "gRPC"
		if pkt.AppInfo == "" {
			pkt.AppInfo = grpcMessages[0].Summary()
		}
	}

	return nil
}

type grpcStreamInfo struct {
	method    string
	isRequest bool
}

func (d *HTTP2Dissector) extractGRPCMessages(frames []*model.HTTP2Frame) []*model.GRPCMessage {
	grpcStreams := make(map[uint32]grpcStreamInfo)
	dataByStream := make(map[uint32]*bytes.Buffer)

	for _, frame := range frames {
		if frame.Type != http2.FrameHeaders {
			continue
		}

		var contentType string
		var method string
		var path string
		for _, h := range frame.Headers {
			name := strings.ToLower(h.Name)
			switch name {
			case ":method":
				method = h.Value
			case ":path":
				path = h.Value
			case "content-type":
				contentType = h.Value
			}
		}

		if strings.Contains(strings.ToLower(contentType), "application/grpc") {
			grpcStreams[frame.StreamID] = grpcStreamInfo{method: path, isRequest: method != ""}
		}
	}

	if len(grpcStreams) == 0 {
		return nil
	}

	for _, frame := range frames {
		if frame.Type != http2.FrameData {
			continue
		}
		if _, ok := grpcStreams[frame.StreamID]; !ok {
			continue
		}
		buf := dataByStream[frame.StreamID]
		if buf == nil {
			buf = &bytes.Buffer{}
			dataByStream[frame.StreamID] = buf
		}
		buf.Write(frame.Payload)
	}

	if len(dataByStream) == 0 {
		return nil
	}

	grpcDissector := DefaultGRPCDissector()
	var messages []*model.GRPCMessage

	for streamID, buf := range dataByStream {
		msgs, _ := grpcDissector.parseFrames(buf.Bytes())
		info := grpcStreams[streamID]
		for _, msg := range msgs {
			msg.ServiceMethod = info.method
			msg.IsRequest = info.isRequest
			messages = append(messages, msg)
		}
	}

	return messages
}

// parseFrames extracts all HTTP/2 frames from the data.
func (d *HTTP2Dissector) parseFrames(data []byte, decoder *hpack.Decoder) ([]*model.HTTP2Frame, error) {
	var frames []*model.HTTP2Frame
	reader := bytes.NewReader(data)

	for {
		frame, err := d.parseFrame(reader, decoder)
		if err == io.EOF {
			break
		}
		if err != nil {
			// Return what we have so far
			break
		}
		frames = append(frames, frame)
	}

	return frames, nil
}

// parseFrame parses a single HTTP/2 frame.
func (d *HTTP2Dissector) parseFrame(r *bytes.Reader, decoder *hpack.Decoder) (*model.HTTP2Frame, error) {
	// Read 9-byte frame header
	header := make([]byte, 9)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	// Parse header
	length := uint32(header[0])<<16 | uint32(header[1])<<8 | uint32(header[2])
	frameType := http2.FrameType(header[3])
	flags := http2.Flags(header[4])
	streamID := binary.BigEndian.Uint32(header[5:9]) & 0x7FFFFFFF

	// Sanity check frame length
	if length > 16384 { // Default max frame size
		// Try to read what's available
		available := int64(r.Len())
		if available > 0 && uint32(available) < length {
			length = uint32(available)
		}
	}

	// Read frame payload
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, err
		}
	}

	frame := &model.HTTP2Frame{
		Type:     frameType,
		Flags:    flags,
		StreamID: streamID,
		Length:   length,
		Payload:  payload,
	}

	// Parse frame-specific data
	switch frameType {
	case http2.FrameHeaders:
		d.parseHeadersFrame(frame, decoder)
	case http2.FrameData:
		// Data frames don't need special parsing
	case http2.FrameSettings:
		d.parseSettingsFrame(frame)
	case http2.FrameGoAway:
		d.parseGoAwayFrame(frame)
	case http2.FrameRSTStream:
		d.parseRSTStreamFrame(frame)
	case http2.FramePriority:
		d.parsePriorityFrame(frame)
	case http2.FrameWindowUpdate:
		d.parseWindowUpdateFrame(frame)
	}

	return frame, nil
}

// parseHeadersFrame decodes HPACK headers.
func (d *HTTP2Dissector) parseHeadersFrame(frame *model.HTTP2Frame, decoder *hpack.Decoder) {
	payload := frame.Payload

	// Check for padding
	if frame.Flags&http2.FlagHeadersPadded != 0 && len(payload) > 0 {
		padLen := int(payload[0])
		if padLen < len(payload)-1 {
			payload = payload[1 : len(payload)-padLen]
		}
	}

	// Check for priority
	if frame.Flags&http2.FlagHeadersPriority != 0 && len(payload) >= 5 {
		payload = payload[5:]
	}

	// Decode HPACK
	decoder.SetEmitFunc(func(hf hpack.HeaderField) {
		frame.Headers = append(frame.Headers, model.Header{
			Name:  hf.Name,
			Value: hf.Value,
		})
	})

	if _, err := decoder.Write(payload); err != nil {
		// Decoding failed, headers remain empty
		return
	}
}

// parseSettingsFrame extracts settings values.
func (d *HTTP2Dissector) parseSettingsFrame(frame *model.HTTP2Frame) {
	if frame.Flags&http2.FlagSettingsAck != 0 {
		// Settings ACK has no payload
		return
	}

	payload := frame.Payload
	settings := make(map[http2.SettingID]uint32)

	for len(payload) >= 6 {
		id := http2.SettingID(binary.BigEndian.Uint16(payload[0:2]))
		val := binary.BigEndian.Uint32(payload[2:6])
		settings[id] = val
		payload = payload[6:]
	}

	frame.Settings = settings
}

// parseGoAwayFrame extracts error information.
func (d *HTTP2Dissector) parseGoAwayFrame(frame *model.HTTP2Frame) {
	if len(frame.Payload) < 8 {
		return
	}

	frame.LastStreamID = binary.BigEndian.Uint32(frame.Payload[0:4]) & 0x7FFFFFFF
	frame.ErrorCode = http2.ErrCode(binary.BigEndian.Uint32(frame.Payload[4:8]))

	if len(frame.Payload) > 8 {
		frame.DebugData = frame.Payload[8:]
	}
}

// parseRSTStreamFrame extracts error code.
func (d *HTTP2Dissector) parseRSTStreamFrame(frame *model.HTTP2Frame) {
	if len(frame.Payload) >= 4 {
		frame.ErrorCode = http2.ErrCode(binary.BigEndian.Uint32(frame.Payload[0:4]))
	}
}

// parsePriorityFrame extracts priority data.
func (d *HTTP2Dissector) parsePriorityFrame(frame *model.HTTP2Frame) {
	if len(frame.Payload) >= 5 {
		frame.DependsOn = binary.BigEndian.Uint32(frame.Payload[0:4]) & 0x7FFFFFFF
		frame.Weight = frame.Payload[4]
		frame.Exclusive = frame.Payload[0]&0x80 != 0
	}
}

// parseWindowUpdateFrame extracts window increment.
func (d *HTTP2Dissector) parseWindowUpdateFrame(frame *model.HTTP2Frame) {
	if len(frame.Payload) >= 4 {
		frame.WindowIncrement = binary.BigEndian.Uint32(frame.Payload[0:4]) & 0x7FFFFFFF
	}
}

// extractConversation creates an HTTPConversation from a HEADERS frame.
func (d *HTTP2Dissector) extractConversation(frame *model.HTTP2Frame) *model.HTTPConversation {
	headers := make(map[string][]string)
	var method, path, status, authority, scheme string

	for _, h := range frame.Headers {
		switch h.Name {
		case ":method":
			method = h.Value
		case ":path":
			path = h.Value
		case ":status":
			status = h.Value
		case ":authority":
			authority = h.Value
		case ":scheme":
			scheme = h.Value
		default:
			headers[h.Name] = append(headers[h.Name], h.Value)
		}
	}

	conv := &model.HTTPConversation{
		Version: model.HTTPVersion20,
	}

	if method != "" {
		// Request
		httpMethod, _ := parseHTTPMethod(method)
		conv.Request = &model.HTTPRequest{
			Method:      httpMethod,
			URI:         path,
			Version:     model.HTTPVersion20,
			Headers:     headers,
			Host:        authority,
			ContentType: getFirstHeader(headers, "content-type"),
		}
		_ = scheme // Could use for full URL reconstruction
	}

	if status != "" {
		// Response
		var statusCode int
		fmt.Sscanf(status, "%d", &statusCode)
		conv.Response = &model.HTTPResponse{
			StatusCode:  statusCode,
			Version:     model.HTTPVersion20,
			Headers:     headers,
			ContentType: getFirstHeader(headers, "content-type"),
		}
	}

	if conv.Request == nil && conv.Response == nil {
		return nil
	}

	return conv
}

func getFirstHeader(h map[string][]string, key string) string {
	if v, ok := h[key]; ok && len(v) > 0 {
		return v[0]
	}
	return ""
}

// HTTP2StreamParser parses HTTP/2 streams with state tracking.
type HTTP2StreamParser struct {
	decoder     *hpack.Decoder
	streams     map[uint32]*http2Stream
	maxStreamID uint32
}

type http2Stream struct {
	id         uint32
	state      http2StreamState
	headers    []model.Header
	data       bytes.Buffer
	endHeaders bool
	endStream  bool
}

type http2StreamState int

const (
	http2StreamIdle http2StreamState = iota
	http2StreamOpen
	http2StreamHalfClosedLocal
	http2StreamHalfClosedRemote
	http2StreamClosed
)

// NewHTTP2StreamParser creates a new stream parser.
func NewHTTP2StreamParser() *HTTP2StreamParser {
	return &HTTP2StreamParser{
		decoder: hpack.NewDecoder(4096, nil),
		streams: make(map[uint32]*http2Stream),
	}
}

// ProcessFrame updates stream state based on a frame.
func (p *HTTP2StreamParser) ProcessFrame(frame *model.HTTP2Frame) error {
	if frame.StreamID == 0 {
		// Connection-level frame
		return nil
	}

	stream := p.getOrCreateStream(frame.StreamID)

	switch frame.Type {
	case http2.FrameHeaders:
		stream.state = http2StreamOpen
		stream.headers = append(stream.headers, frame.Headers...)
		if frame.Flags&http2.FlagHeadersEndHeaders != 0 {
			stream.endHeaders = true
		}
		if frame.Flags&http2.FlagHeadersEndStream != 0 {
			stream.endStream = true
			stream.state = http2StreamHalfClosedRemote
		}

	case http2.FrameData:
		stream.data.Write(frame.Payload)
		if frame.Flags&http2.FlagDataEndStream != 0 {
			stream.endStream = true
			stream.state = http2StreamHalfClosedRemote
		}

	case http2.FrameRSTStream:
		stream.state = http2StreamClosed
	}

	return nil
}

// GetStream returns stream data if available.
func (p *HTTP2StreamParser) GetStream(id uint32) (*model.Stream, error) {
	stream, ok := p.streams[id]
	if !ok {
		return nil, errors.New("stream not found")
	}

	return &model.Stream{
		ID:   id,
		Data: stream.data.Bytes(),
	}, nil
}

func (p *HTTP2StreamParser) getOrCreateStream(id uint32) *http2Stream {
	if s, ok := p.streams[id]; ok {
		return s
	}

	stream := &http2Stream{
		id:    id,
		state: http2StreamIdle,
	}
	p.streams[id] = stream

	if id > p.maxStreamID {
		p.maxStreamID = id
	}

	return stream
}

// Reset clears all stream state.
func (p *HTTP2StreamParser) Reset() {
	p.streams = make(map[uint32]*http2Stream)
	p.maxStreamID = 0
}

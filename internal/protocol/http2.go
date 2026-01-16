package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/wiretap/wiretap/internal/model"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// HTTP/2 magic prefix (connection preface)
var http2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// HTTP2Dissector parses HTTP/2 protocol traffic (cleartext h2c).
type HTTP2Dissector struct {
	decoder *hpack.Decoder
}

// NewHTTP2Dissector creates a new HTTP/2 dissector.
func NewHTTP2Dissector() *HTTP2Dissector {
	return &HTTP2Dissector{
		decoder: hpack.NewDecoder(4096, nil),
	}
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
		frameType := data[3]
		flags := data[4]
		streamID := binary.BigEndian.Uint32(data[5:9]) & 0x7FFFFFFF // Mask reserved bit

		// Valid frame type (0-9 defined in RFC 7540)
		if frameType <= 9 {
			// Heuristic: reasonable flags and stream ID
			_ = flags
			_ = streamID
			return true
		}
	}

	return false
}

// Parse extracts HTTP/2 frame information.
func (d *HTTP2Dissector) Parse(data []byte, pkt *model.Packet) error {
	// Skip connection preface if present
	if bytes.HasPrefix(data, http2Preface) {
		data = data[len(http2Preface):]
	}

	if len(data) < 9 {
		return ErrIncompleteData
	}

	frames, err := d.parseFrames(data)
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

	return nil
}

// parseFrames extracts all HTTP/2 frames from the data.
func (d *HTTP2Dissector) parseFrames(data []byte) ([]*model.HTTP2Frame, error) {
	var frames []*model.HTTP2Frame
	reader := bytes.NewReader(data)

	for {
		frame, err := d.parseFrame(reader)
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
func (d *HTTP2Dissector) parseFrame(r *bytes.Reader) (*model.HTTP2Frame, error) {
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
		d.parseHeadersFrame(frame)
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
func (d *HTTP2Dissector) parseHeadersFrame(frame *model.HTTP2Frame) {
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
	d.decoder.SetEmitFunc(func(hf hpack.HeaderField) {
		frame.Headers = append(frame.Headers, model.Header{
			Name:  hf.Name,
			Value: hf.Value,
		})
	})

	if _, err := d.decoder.Write(payload); err != nil {
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

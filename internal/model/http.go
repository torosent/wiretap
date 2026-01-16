// Package model defines HTTP-related types.
package model

import (
	"fmt"
	"net/url"
	"time"

	"golang.org/x/net/http2"
)

// HTTPVersion represents the HTTP version.
type HTTPVersion uint8

// HTTP versions.
const (
	HTTPVersion10 HTTPVersion = iota
	HTTPVersion11
	HTTPVersion20
	HTTPVersion2 = HTTPVersion20 // Alias for compatibility
)

// String returns the HTTP version string.
func (v HTTPVersion) String() string {
	switch v {
	case HTTPVersion10:
		return "HTTP/1.0"
	case HTTPVersion11:
		return "HTTP/1.1"
	case HTTPVersion2:
		return "HTTP/2"
	default:
		return "Unknown"
	}
}

// HTTPMethod represents an HTTP method.
type HTTPMethod string

// Common HTTP methods.
const (
	HTTPMethodGET     HTTPMethod = "GET"
	HTTPMethodPOST    HTTPMethod = "POST"
	HTTPMethodPUT     HTTPMethod = "PUT"
	HTTPMethodDELETE  HTTPMethod = "DELETE"
	HTTPMethodHEAD    HTTPMethod = "HEAD"
	HTTPMethodOPTIONS HTTPMethod = "OPTIONS"
	HTTPMethodPATCH   HTTPMethod = "PATCH"
	HTTPMethodCONNECT HTTPMethod = "CONNECT"
	HTTPMethodTRACE   HTTPMethod = "TRACE"
)

// HTTPConversation represents an HTTP request/response pair.
type HTTPConversation struct {
	// ID is a unique identifier for this conversation
	ID uint64

	// Connection ID this conversation belongs to
	ConnectionID uint64

	// HTTP version
	Version HTTPVersion

	// Request details
	Request *HTTPRequest

	// Response details (may be nil if no response captured)
	Response *HTTPResponse

	// Timing
	StartTime    time.Time
	EndTime      time.Time
	ResponseTime time.Duration

	// Packet indices for this conversation
	RequestPackets  []uint64
	ResponsePackets []uint64

	// HTTP/2 specific
	StreamID uint32
}

// Summary returns a brief summary of the conversation.
func (c *HTTPConversation) Summary() string {
	if c.Request == nil {
		return "Incomplete request"
	}

	status := ""
	if c.Response != nil {
		status = fmt.Sprintf(" → %d", c.Response.StatusCode)
	}

	return fmt.Sprintf("%s %s%s", c.Request.Method, c.Request.Path, status)
}

// HTTPRequest represents an HTTP request.
type HTTPRequest struct {
	// Method (GET, POST, etc.)
	Method HTTPMethod

	// URL components
	URI         string
	Path        string
	RawPath     string
	QueryString string
	ParsedURL   *url.URL

	// HTTP version
	Version HTTPVersion

	// Host (from Host header or URL)
	Host string

	// Headers
	Headers map[string][]string

	// Body
	Body            []byte
	ContentLength   int64
	ContentType     string
	ContentEncoding string

	// Body was truncated
	BodyTruncated bool

	// Raw request line
	RawRequestLine string

	// Timestamp when request started
	Timestamp time.Time
}

// GetHeader returns the first value of a header (case-insensitive).
func (r *HTTPRequest) GetHeader(name string) string {
	// Headers are typically stored with canonical capitalization
	if values, ok := r.Headers[name]; ok && len(values) > 0 {
		return values[0]
	}
	return ""
}

// HTTPResponse represents an HTTP response.
type HTTPResponse struct {
	// Status code
	StatusCode int

	// Status text
	StatusText string

	// HTTP version
	Version HTTPVersion

	// Headers
	Headers map[string][]string

	// Body
	Body            []byte
	ContentLength   int64
	ContentType     string
	ContentEncoding string

	// Body was truncated
	BodyTruncated bool

	// Raw status line
	RawStatusLine string

	// Timestamp when response started
	Timestamp time.Time
}

// GetHeader returns the first value of a header (case-insensitive).
func (r *HTTPResponse) GetHeader(name string) string {
	if values, ok := r.Headers[name]; ok && len(values) > 0 {
		return values[0]
	}
	return ""
}

// IsSuccess returns true if the status code indicates success (2xx).
func (r *HTTPResponse) IsSuccess() bool {
	return r.StatusCode >= 200 && r.StatusCode < 300
}

// IsRedirect returns true if the status code indicates a redirect (3xx).
func (r *HTTPResponse) IsRedirect() bool {
	return r.StatusCode >= 300 && r.StatusCode < 400
}

// IsClientError returns true if the status code indicates client error (4xx).
func (r *HTTPResponse) IsClientError() bool {
	return r.StatusCode >= 400 && r.StatusCode < 500
}

// IsServerError returns true if the status code indicates server error (5xx).
func (r *HTTPResponse) IsServerError() bool {
	return r.StatusCode >= 500 && r.StatusCode < 600
}

// Header represents an HTTP/2 header name-value pair.
type Header struct {
	Name  string
	Value string
}

// HTTP2Frame represents an HTTP/2 frame.
type HTTP2Frame struct {
	// Frame type (using golang.org/x/net/http2 types)
	Type http2.FrameType

	// Frame flags
	Flags http2.Flags

	// Stream ID
	StreamID uint32

	// Frame length
	Length uint32

	// Raw frame data/payload
	Data    []byte
	Payload []byte

	// Parsed headers for HEADERS frames
	Headers []Header

	// Settings from SETTINGS frames
	Settings map[http2.SettingID]uint32

	// GOAWAY frame fields
	LastStreamID uint32
	ErrorCode    http2.ErrCode
	DebugData    []byte

	// PRIORITY frame fields
	DependsOn uint32
	Weight    uint8
	Exclusive bool

	// WINDOW_UPDATE frame field
	WindowIncrement uint32

	// Parsed content (depends on frame type)
	Parsed interface{}
}

// HTTP2FrameType represents HTTP/2 frame types.
type HTTP2FrameType uint8

// HTTP/2 frame types.
const (
	HTTP2FrameData         HTTP2FrameType = 0x0
	HTTP2FrameHeaders      HTTP2FrameType = 0x1
	HTTP2FramePriority     HTTP2FrameType = 0x2
	HTTP2FrameRSTStream    HTTP2FrameType = 0x3
	HTTP2FrameSettings     HTTP2FrameType = 0x4
	HTTP2FramePushPromise  HTTP2FrameType = 0x5
	HTTP2FramePing         HTTP2FrameType = 0x6
	HTTP2FrameGoAway       HTTP2FrameType = 0x7
	HTTP2FrameWindowUpdate HTTP2FrameType = 0x8
	HTTP2FrameContinuation HTTP2FrameType = 0x9
)

// String returns the frame type name.
func (t HTTP2FrameType) String() string {
	switch t {
	case HTTP2FrameData:
		return "DATA"
	case HTTP2FrameHeaders:
		return "HEADERS"
	case HTTP2FramePriority:
		return "PRIORITY"
	case HTTP2FrameRSTStream:
		return "RST_STREAM"
	case HTTP2FrameSettings:
		return "SETTINGS"
	case HTTP2FramePushPromise:
		return "PUSH_PROMISE"
	case HTTP2FramePing:
		return "PING"
	case HTTP2FrameGoAway:
		return "GOAWAY"
	case HTTP2FrameWindowUpdate:
		return "WINDOW_UPDATE"
	case HTTP2FrameContinuation:
		return "CONTINUATION"
	default:
		return fmt.Sprintf("UNKNOWN(0x%x)", uint8(t))
	}
}

// HTTP2FrameFlags represents HTTP/2 frame flags.
type HTTP2FrameFlags uint8

// HTTP/2 frame flags.
const (
	HTTP2FlagEndStream  HTTP2FrameFlags = 0x1
	HTTP2FlagEndHeaders HTTP2FrameFlags = 0x4
	HTTP2FlagPadded     HTTP2FrameFlags = 0x8
	HTTP2FlagPriority   HTTP2FrameFlags = 0x20
)

// Has checks if a flag is set.
func (f HTTP2FrameFlags) Has(flag HTTP2FrameFlags) bool {
	return f&flag != 0
}

// String returns a string representation of the flags.
func (f HTTP2FrameFlags) String() string {
	var flags string
	if f.Has(HTTP2FlagEndStream) {
		flags += "END_STREAM,"
	}
	if f.Has(HTTP2FlagEndHeaders) {
		flags += "END_HEADERS,"
	}
	if f.Has(HTTP2FlagPadded) {
		flags += "PADDED,"
	}
	if f.Has(HTTP2FlagPriority) {
		flags += "PRIORITY,"
	}
	if len(flags) > 0 {
		flags = flags[:len(flags)-1] // Remove trailing comma
	}
	return flags
}

// HTTP2Headers represents decoded HTTP/2 headers.
type HTTP2Headers struct {
	// Pseudo-headers
	Method    string
	Scheme    string
	Authority string
	Path      string
	Status    string

	// Regular headers
	Headers map[string][]string
}

// HTTP2Settings represents HTTP/2 settings.
type HTTP2Settings struct {
	HeaderTableSize      uint32
	EnablePush           bool
	MaxConcurrentStreams uint32
	InitialWindowSize    uint32
	MaxFrameSize         uint32
	MaxHeaderListSize    uint32
}

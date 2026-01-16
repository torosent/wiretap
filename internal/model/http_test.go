package model

import (
	"testing"
)

func TestHTTPVersionString(t *testing.T) {
	tests := []struct {
		version  HTTPVersion
		expected string
	}{
		{HTTPVersion10, "HTTP/1.0"},
		{HTTPVersion11, "HTTP/1.1"},
		{HTTPVersion2, "HTTP/2"},
	}

	for _, tt := range tests {
		result := tt.version.String()
		if result != tt.expected {
			t.Errorf("HTTPVersion(%d).String() = %q, expected %q", tt.version, result, tt.expected)
		}
	}
}

func TestHTTPConversationSummary(t *testing.T) {
	tests := []struct {
		name     string
		conv     *HTTPConversation
		expected string
	}{
		{
			name: "with request and response",
			conv: &HTTPConversation{
				Request: &HTTPRequest{
					Method: HTTPMethodGET,
					Path:   "/index.html",
				},
				Response: &HTTPResponse{
					StatusCode: 200,
				},
			},
			expected: "GET /index.html → 200",
		},
		{
			name: "request only",
			conv: &HTTPConversation{
				Request: &HTTPRequest{
					Method: HTTPMethodPOST,
					Path:   "/api/users",
				},
			},
			expected: "POST /api/users",
		},
		{
			name:     "no request",
			conv:     &HTTPConversation{},
			expected: "Incomplete request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.conv.Summary()
			if result != tt.expected {
				t.Errorf("Summary() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestHTTPRequestGetHeader(t *testing.T) {
	req := &HTTPRequest{
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
			"Accept":       {"text/html", "application/json"},
		},
	}

	if ct := req.GetHeader("Content-Type"); ct != "application/json" {
		t.Errorf("expected 'application/json', got %q", ct)
	}

	if accept := req.GetHeader("Accept"); accept != "text/html" {
		t.Errorf("expected 'text/html' (first value), got %q", accept)
	}

	if missing := req.GetHeader("X-Missing"); missing != "" {
		t.Errorf("expected empty string for missing header, got %q", missing)
	}
}

func TestHTTPResponseStatusChecks(t *testing.T) {
	tests := []struct {
		statusCode    int
		isSuccess     bool
		isRedirect    bool
		isClientError bool
		isServerError bool
	}{
		{200, true, false, false, false},
		{201, true, false, false, false},
		{301, false, true, false, false},
		{302, false, true, false, false},
		{400, false, false, true, false},
		{404, false, false, true, false},
		{500, false, false, false, true},
		{503, false, false, false, true},
	}

	for _, tt := range tests {
		resp := &HTTPResponse{StatusCode: tt.statusCode}

		if resp.IsSuccess() != tt.isSuccess {
			t.Errorf("status %d: IsSuccess() = %v, expected %v", tt.statusCode, resp.IsSuccess(), tt.isSuccess)
		}

		if resp.IsRedirect() != tt.isRedirect {
			t.Errorf("status %d: IsRedirect() = %v, expected %v", tt.statusCode, resp.IsRedirect(), tt.isRedirect)
		}

		if resp.IsClientError() != tt.isClientError {
			t.Errorf("status %d: IsClientError() = %v, expected %v", tt.statusCode, resp.IsClientError(), tt.isClientError)
		}

		if resp.IsServerError() != tt.isServerError {
			t.Errorf("status %d: IsServerError() = %v, expected %v", tt.statusCode, resp.IsServerError(), tt.isServerError)
		}
	}
}

func TestHTTP2FrameTypeString(t *testing.T) {
	tests := []struct {
		frameType HTTP2FrameType
		expected  string
	}{
		{HTTP2FrameData, "DATA"},
		{HTTP2FrameHeaders, "HEADERS"},
		{HTTP2FrameSettings, "SETTINGS"},
		{HTTP2FramePing, "PING"},
		{HTTP2FrameGoAway, "GOAWAY"},
		{HTTP2FrameWindowUpdate, "WINDOW_UPDATE"},
		{HTTP2FrameType(0xFF), "UNKNOWN(0xff)"},
	}

	for _, tt := range tests {
		result := tt.frameType.String()
		if result != tt.expected {
			t.Errorf("HTTP2FrameType(%d).String() = %q, expected %q", tt.frameType, result, tt.expected)
		}
	}
}

func TestHTTP2FrameFlagsHas(t *testing.T) {
	flags := HTTP2FlagEndStream | HTTP2FlagEndHeaders

	if !flags.Has(HTTP2FlagEndStream) {
		t.Error("expected END_STREAM flag to be set")
	}

	if !flags.Has(HTTP2FlagEndHeaders) {
		t.Error("expected END_HEADERS flag to be set")
	}

	if flags.Has(HTTP2FlagPadded) {
		t.Error("expected PADDED flag to not be set")
	}
}

func TestHTTP2FrameFlagsString(t *testing.T) {
	tests := []struct {
		flags    HTTP2FrameFlags
		expected string
	}{
		{0, ""},
		{HTTP2FlagEndStream, "END_STREAM"},
		{HTTP2FlagEndStream | HTTP2FlagEndHeaders, "END_STREAM,END_HEADERS"},
	}

	for _, tt := range tests {
		result := tt.flags.String()
		if result != tt.expected {
			t.Errorf("HTTP2FrameFlags(%d).String() = %q, expected %q", tt.flags, result, tt.expected)
		}
	}
}

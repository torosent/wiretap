package protocol

import (
	"encoding/binary"
	"testing"

	"github.com/wiretap/wiretap/internal/model"
)

func TestHTTP2Dissector_ExtractConversation_Request(t *testing.T) {
	d := &HTTP2Dissector{}
	frame := &model.HTTP2Frame{
		Headers: []model.Header{
			{Name: ":method", Value: "GET"},
			{Name: ":path", Value: "/"},
			{Name: ":authority", Value: "example.com"},
			{Name: "content-type", Value: "text/plain"},
		},
	}

	conv := d.extractConversation(frame)
	if conv == nil || conv.Request == nil {
		t.Fatal("Expected request conversation")
	}
	if conv.Request.Method != model.HTTPMethodGET {
		t.Errorf("Method = %s, want GET", conv.Request.Method)
	}
	if conv.Request.URI != "/" {
		t.Errorf("URI = %s, want /", conv.Request.URI)
	}
	if conv.Request.Host != "example.com" {
		t.Errorf("Host = %s, want example.com", conv.Request.Host)
	}
}

func TestHTTP2Dissector_ExtractConversation_Response(t *testing.T) {
	d := &HTTP2Dissector{}
	frame := &model.HTTP2Frame{
		Headers: []model.Header{
			{Name: ":status", Value: "200"},
			{Name: "content-type", Value: "application/json"},
		},
	}

	conv := d.extractConversation(frame)
	if conv == nil || conv.Response == nil {
		t.Fatal("Expected response conversation")
	}
	if conv.Response.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", conv.Response.StatusCode)
	}
}

func TestHTTP2Dissector_ParseFrames(t *testing.T) {
	d := &HTTP2Dissector{}

	rst := &model.HTTP2Frame{Payload: make([]byte, 4)}
	binary.BigEndian.PutUint32(rst.Payload[:4], 0x00000008)
	d.parseRSTStreamFrame(rst)
	if rst.ErrorCode == 0 {
		t.Error("Expected error code to be parsed")
	}

	priority := &model.HTTP2Frame{Payload: []byte{0x80, 0, 0, 1, 10}}
	d.parsePriorityFrame(priority)
	if priority.Weight == 0 {
		t.Error("Expected priority weight to be parsed")
	}
	if !priority.Exclusive {
		t.Error("Expected exclusive flag to be true")
	}

	window := &model.HTTP2Frame{Payload: make([]byte, 4)}
	binary.BigEndian.PutUint32(window.Payload[:4], 1024)
	d.parseWindowUpdateFrame(window)
	if window.WindowIncrement != 1024 {
		t.Errorf("WindowIncrement = %d, want 1024", window.WindowIncrement)
	}
}

func TestGetFirstHeader(t *testing.T) {
	headers := map[string][]string{"content-type": {"text/plain"}}
	if value := getFirstHeader(headers, "content-type"); value != "text/plain" {
		t.Errorf("getFirstHeader = %s", value)
	}
	if value := getFirstHeader(headers, "missing"); value != "" {
		t.Errorf("Expected empty value, got %s", value)
	}
}

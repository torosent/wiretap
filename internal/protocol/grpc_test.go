package protocol

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/wiretap/wiretap/internal/model"
)

func TestNewGRPCDissector(t *testing.T) {
	d := NewGRPCDissector()
	if d == nil {
		t.Fatal("NewGRPCDissector returned nil")
	}
	if d.Name() != "gRPC" {
		t.Errorf("Expected name 'gRPC', got '%s'", d.Name())
	}
}

func TestGRPCDissector_Detect(t *testing.T) {
	d := NewGRPCDissector()

	tests := []struct {
		name   string
		data   []byte
		expect bool
	}{
		{
			name:   "grpc content type",
			data:   []byte("content-type: application/grpc\r\n"),
			expect: true,
		},
		{
			name:   "grpc frame uncompressed",
			data:   createGRPCFrame(false, []byte("test")),
			expect: true,
		},
		{
			name:   "grpc frame compressed",
			data:   createGRPCFrame(true, []byte("test")),
			expect: true,
		},
		{
			name:   "short data",
			data:   []byte{0x00, 0x00},
			expect: false,
		},
		{
			name:   "invalid flags",
			data:   []byte{0x10, 0x00, 0x00, 0x00, 0x04, 't', 'e', 's', 't'},
			expect: false,
		},
		{
			name:   "http request",
			data:   []byte("GET / HTTP/1.1\r\n"),
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

func TestGRPCDissector_ParseSimpleMessage(t *testing.T) {
	d := NewGRPCDissector()
	pkt := &model.Packet{}

	// Create a simple gRPC frame with protobuf payload.
	// Protobuf: field 1 (string) = "hello"
	protoPayload := []byte{
		0x0a, 0x05, // field 1, wire type 2 (bytes), length 5
		'h', 'e', 'l', 'l', 'o',
	}
	data := createGRPCFrame(false, protoPayload)

	err := d.Parse(data, pkt)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if pkt.ApplicationProtocol != "gRPC" {
		t.Errorf("ApplicationProtocol = %s, want gRPC", pkt.ApplicationProtocol)
	}
	if len(pkt.GRPCMessages) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(pkt.GRPCMessages))
	}

	msg := pkt.GRPCMessages[0]
	if msg.Compressed {
		t.Error("Expected Compressed to be false")
	}
	if msg.Length != uint32(len(protoPayload)) {
		t.Errorf("Length = %d, want %d", msg.Length, len(protoPayload))
	}
	if len(msg.DecodedFields) == 0 {
		t.Error("Expected DecodedFields to be populated")
	}
	if val, ok := msg.DecodedFields[1]; !ok || val != "hello" {
		t.Errorf("DecodedFields[1] = %v, want 'hello'", val)
	}
}

func TestGRPCDissector_ParseCompressedMessage(t *testing.T) {
	d := NewGRPCDissector()
	pkt := &model.Packet{}

	// Create a compressed gRPC frame.
	payload := []byte{0x0a, 0x03, 'f', 'o', 'o'}
	data := createGRPCFrame(true, payload)

	err := d.Parse(data, pkt)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	msg := pkt.GRPCMessages[0]
	if !msg.Compressed {
		t.Error("Expected Compressed to be true")
	}
}

func TestGRPCDissector_ParseMultipleMessages(t *testing.T) {
	d := NewGRPCDissector()
	pkt := &model.Packet{}

	// Create two gRPC frames.
	frame1 := createGRPCFrame(false, []byte{0x0a, 0x03, 'o', 'n', 'e'})
	frame2 := createGRPCFrame(false, []byte{0x0a, 0x03, 't', 'w', 'o'})
	data := append(frame1, frame2...)

	err := d.Parse(data, pkt)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(pkt.GRPCMessages) != 2 {
		t.Fatalf("Expected 2 messages, got %d", len(pkt.GRPCMessages))
	}
}

func TestGRPCDissector_ParseIntegerFields(t *testing.T) {
	d := NewGRPCDissector()
	pkt := &model.Packet{}

	// Protobuf with various integer fields.
	protoPayload := []byte{
		0x08, 0x2a, // field 1, varint, value 42
		0x10, 0x96, 0x01, // field 2, varint, value 150
	}
	data := createGRPCFrame(false, protoPayload)

	err := d.Parse(data, pkt)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	msg := pkt.GRPCMessages[0]
	if val, ok := msg.DecodedFields[1]; !ok || val != uint64(42) {
		t.Errorf("DecodedFields[1] = %v, want 42", val)
	}
	if val, ok := msg.DecodedFields[2]; !ok || val != uint64(150) {
		t.Errorf("DecodedFields[2] = %v, want 150", val)
	}
}

func TestGRPCDissector_ParseNestedMessage(t *testing.T) {
	d := NewGRPCDissector()
	pkt := &model.Packet{}

	// Protobuf with nested message.
	// Field 1 = "outer", Field 2 = nested(Field 1 = "inner")
	innerMsg := []byte{0x0a, 0x05, 'i', 'n', 'n', 'e', 'r'}
	protoPayload := []byte{
		0x0a, 0x05, 'o', 'u', 't', 'e', 'r', // field 1 = "outer"
		0x12, byte(len(innerMsg)), // field 2 = nested message
	}
	protoPayload = append(protoPayload, innerMsg...)
	data := createGRPCFrame(false, protoPayload)

	err := d.Parse(data, pkt)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	msg := pkt.GRPCMessages[0]
	if val, ok := msg.DecodedFields[1]; !ok || val != "outer" {
		t.Errorf("DecodedFields[1] = %v, want 'outer'", val)
	}

	// Field 2 should be decoded as nested message.
	if nested, ok := msg.DecodedFields[2].(map[uint32]interface{}); ok {
		if val, ok := nested[1]; !ok || val != "inner" {
			t.Errorf("nested[1] = %v, want 'inner'", val)
		}
	}
}

func TestGRPCDissector_ParseRepeatedField(t *testing.T) {
	d := NewGRPCDissector()
	pkt := &model.Packet{}

	// Protobuf with repeated field.
	protoPayload := []byte{
		0x08, 0x01, // field 1, varint, value 1
		0x08, 0x02, // field 1, varint, value 2
		0x08, 0x03, // field 1, varint, value 3
	}
	data := createGRPCFrame(false, protoPayload)

	err := d.Parse(data, pkt)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	msg := pkt.GRPCMessages[0]
	arr, ok := msg.DecodedFields[1].([]interface{})
	if !ok {
		t.Fatalf("DecodedFields[1] is not an array: %T", msg.DecodedFields[1])
	}
	if len(arr) != 3 {
		t.Errorf("Expected 3 values, got %d", len(arr))
	}
}

func TestGRPCDissector_IncompleteFrame(t *testing.T) {
	d := NewGRPCDissector()
	pkt := &model.Packet{}

	// Frame header says 100 bytes, but only 5 bytes of payload.
	data := []byte{0x00, 0x00, 0x00, 0x00, 0x64} // flags=0, length=100
	data = append(data, []byte("short")...)

	err := d.Parse(data, pkt)
	// Should return error or no messages.
	if err == nil && len(pkt.GRPCMessages) > 0 {
		t.Error("Should not parse incomplete frame successfully")
	}
}

func TestGRPCDissector_SetProtoDirs(t *testing.T) {
	d := NewGRPCDissector()

	dirs := []string{"/path/to/protos", "/another/path"}
	d.SetProtoDirs(dirs)

	// Can't easily verify internal state, but ensure no panic.
}

func TestGRPCDissector_AddProtoDir(t *testing.T) {
	d := NewGRPCDissector()

	d.AddProtoDir("/path/to/protos")
	d.AddProtoDir("/another/path")

	// Can't easily verify internal state, but ensure no panic.
}

func TestGRPCMessage_Summary(t *testing.T) {
	tests := []struct {
		name   string
		msg    *model.GRPCMessage
		expect string
	}{
		{
			name: "with service method",
			msg: &model.GRPCMessage{
				ServiceMethod: "/example.Greeter/SayHello",
				Length:        100,
			},
			expect: "gRPC /example.Greeter/SayHello (100 bytes)",
		},
		{
			name: "with message type",
			msg: &model.GRPCMessage{
				MessageType: "example.HelloRequest",
				Length:      50,
			},
			expect: "gRPC example.HelloRequest (50 bytes)",
		},
		{
			name: "without type info",
			msg: &model.GRPCMessage{
				Length: 25,
			},
			expect: "gRPC message (25 bytes)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.msg.Summary()
			if got != tt.expect {
				t.Errorf("Summary() = %q, want %q", got, tt.expect)
			}
		})
	}
}

func TestGRPCStatus_String(t *testing.T) {
	tests := []struct {
		status model.GRPCStatus
		expect string
	}{
		{model.GRPCStatusOK, "OK"},
		{model.GRPCStatusCancelled, "CANCELLED"},
		{model.GRPCStatusInvalidArgument, "INVALID_ARGUMENT"},
		{model.GRPCStatus(999), "STATUS(999)"},
	}

	for _, tt := range tests {
		got := tt.status.String()
		if got != tt.expect {
			t.Errorf("GRPCStatus(%d).String() = %s, want %s", tt.status, got, tt.expect)
		}
	}
}

func TestGRPCStream_Summary(t *testing.T) {
	stream := &model.GRPCStream{
		Method: "/example.Greeter/SayHello",
		Status: model.GRPCStatusOK,
	}
	stream.AddRequest(&model.GRPCMessage{Length: 10})
	stream.AddResponse(&model.GRPCMessage{Length: 20})

	summary := stream.Summary()
	expected := "gRPC /example.Greeter/SayHello (req:1, resp:1, status:OK)"
	if summary != expected {
		t.Errorf("Summary() = %q, want %q", summary, expected)
	}
}

func TestFieldsToJSON(t *testing.T) {
	fields := map[uint32]interface{}{
		1: "hello",
		2: uint64(42),
	}

	json := FieldsToJSON(fields)
	if json == "{}" {
		t.Error("Expected non-empty JSON")
	}
	if !contains(json, "field_1") || !contains(json, "field_2") {
		t.Errorf("JSON missing field names: %s", json)
	}
}

func TestFieldsToJSON_Empty(t *testing.T) {
	fields := make(map[uint32]interface{})
	json := FieldsToJSON(fields)
	if json != "{}" {
		t.Errorf("Expected '{}', got %s", json)
	}
}

func TestGRPCDissector_ParseFixed64Field(t *testing.T) {
	d := NewGRPCDissector()
	pkt := &model.Packet{}

	// Protobuf with fixed64 field (wire type 1).
	// Field 1 with wire type 1 (fixed64): tag = (1 << 3) | 1 = 0x09
	protoPayload := []byte{
		0x09, // field 1, wire type 1 (fixed64)
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // value = 1
	}
	data := createGRPCFrame(false, protoPayload)

	err := d.Parse(data, pkt)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	msg := pkt.GRPCMessages[0]
	if val, ok := msg.DecodedFields[1]; !ok || val != uint64(1) {
		t.Errorf("DecodedFields[1] = %v (%T), want 1", val, val)
	}
}

func TestGRPCDissector_ParseFixed32Field(t *testing.T) {
	d := NewGRPCDissector()
	pkt := &model.Packet{}

	// Protobuf with fixed32 field (wire type 5).
	// Field 1 with wire type 5 (fixed32): tag = (1 << 3) | 5 = 0x0d
	protoPayload := []byte{
		0x0d, // field 1, wire type 5 (fixed32)
		0x2a, 0x00, 0x00, 0x00, // value = 42
	}
	data := createGRPCFrame(false, protoPayload)

	err := d.Parse(data, pkt)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	msg := pkt.GRPCMessages[0]
	if val, ok := msg.DecodedFields[1]; !ok || val != uint32(42) {
		t.Errorf("DecodedFields[1] = %v (%T), want 42", val, val)
	}
}

func TestGRPCDissector_ParseBinaryBytes(t *testing.T) {
	d := NewGRPCDissector()
	pkt := &model.Packet{}

	// Protobuf with binary bytes field (not valid UTF-8).
	protoPayload := []byte{
		0x0a, 0x05, // field 1, length 5
		0x00, 0x01, 0x02, 0xFF, 0xFE, // binary data (not UTF-8)
	}
	data := createGRPCFrame(false, protoPayload)

	err := d.Parse(data, pkt)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	msg := pkt.GRPCMessages[0]
	// Should decode as bytes or nested message, not string.
	if _, ok := msg.DecodedFields[1].(string); ok {
		t.Error("Binary data should not be decoded as string")
	}
}

func TestGRPCDissector_ParseEmptyPayload(t *testing.T) {
	d := NewGRPCDissector()
	pkt := &model.Packet{}

	// Empty gRPC frame.
	data := createGRPCFrame(false, []byte{})

	err := d.Parse(data, pkt)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(pkt.GRPCMessages) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(pkt.GRPCMessages))
	}
	if len(pkt.GRPCMessages[0].DecodedFields) != 0 {
		t.Error("Expected empty DecodedFields for empty payload")
	}
}

func TestGRPCDissector_DetectLengthMismatch(t *testing.T) {
	d := NewGRPCDissector()

	// Frame header says 100 bytes, but we only have partial data.
	data := []byte{0x00, 0x00, 0x00, 0x00, 0x64} // flags=0, length=100
	data = append(data, make([]byte, 10)...)     // only 10 bytes of payload

	// Should detect but not parse fully.
	detected := d.Detect(data)
	if detected {
		t.Error("Should not detect frame with insufficient data")
	}
}

func TestGRPCDissector_ParseTruncatedTag(t *testing.T) {
	d := NewGRPCDissector()
	pkt := &model.Packet{}

	// Truncated protobuf message (invalid tag).
	protoPayload := []byte{0x80} // incomplete varint tag
	data := createGRPCFrame(false, protoPayload)

	err := d.Parse(data, pkt)
	// Should not error, but fields should be empty.
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
}

func TestGRPCDissector_ParseTooLargeFrame(t *testing.T) {
	d := NewGRPCDissector()

	// Frame header says 20MB (> 16MB max).
	data := []byte{0x00, 0x01, 0x40, 0x00, 0x00} // flags=0, length=20MB
	detected := d.Detect(data)
	if detected {
		t.Error("Should not detect frame larger than 16MB")
	}
}

func TestGRPCMessage_HasDecodedFields(t *testing.T) {
	msg := &model.GRPCMessage{}
	if msg.HasDecodedFields() {
		t.Error("Empty message should not have decoded fields")
	}

	msg.DecodedFields = map[uint32]interface{}{1: "test"}
	if !msg.HasDecodedFields() {
		t.Error("Message with fields should have decoded fields")
	}
}

func TestGRPCStatus_IsOK(t *testing.T) {
	if !model.GRPCStatusOK.IsOK() {
		t.Error("GRPCStatusOK.IsOK() should return true")
	}
	if model.GRPCStatusCancelled.IsOK() {
		t.Error("GRPCStatusCancelled.IsOK() should return false")
	}
}

func TestGRPCStatus_IsError(t *testing.T) {
	if model.GRPCStatusOK.IsError() {
		t.Error("GRPCStatusOK.IsError() should return false")
	}
	if !model.GRPCStatusCancelled.IsError() {
		t.Error("GRPCStatusCancelled.IsError() should return true")
	}
}

func TestAllGRPCStatusStrings(t *testing.T) {
	statuses := []struct {
		status model.GRPCStatus
		name   string
	}{
		{model.GRPCStatusOK, "OK"},
		{model.GRPCStatusCancelled, "CANCELLED"},
		{model.GRPCStatusUnknown, "UNKNOWN"},
		{model.GRPCStatusInvalidArgument, "INVALID_ARGUMENT"},
		{model.GRPCStatusDeadlineExceeded, "DEADLINE_EXCEEDED"},
		{model.GRPCStatusNotFound, "NOT_FOUND"},
		{model.GRPCStatusAlreadyExists, "ALREADY_EXISTS"},
		{model.GRPCStatusPermissionDenied, "PERMISSION_DENIED"},
		{model.GRPCStatusResourceExhausted, "RESOURCE_EXHAUSTED"},
		{model.GRPCStatusFailedPrecondition, "FAILED_PRECONDITION"},
		{model.GRPCStatusAborted, "ABORTED"},
		{model.GRPCStatusOutOfRange, "OUT_OF_RANGE"},
		{model.GRPCStatusUnimplemented, "UNIMPLEMENTED"},
		{model.GRPCStatusInternal, "INTERNAL"},
		{model.GRPCStatusUnavailable, "UNAVAILABLE"},
		{model.GRPCStatusDataLoss, "DATA_LOSS"},
		{model.GRPCStatusUnauthenticated, "UNAUTHENTICATED"},
	}

	for _, tt := range statuses {
		if tt.status.String() != tt.name {
			t.Errorf("GRPCStatus(%d).String() = %s, want %s", tt.status, tt.status.String(), tt.name)
		}
	}
}

func TestGRPCStream_AddRequestResponse(t *testing.T) {
	stream := &model.GRPCStream{
		Method: "/test.Service/Method",
	}

	reqMsg := &model.GRPCMessage{Length: 10}
	stream.AddRequest(reqMsg)
	if !reqMsg.IsRequest {
		t.Error("AddRequest should set IsRequest to true")
	}

	respMsg := &model.GRPCMessage{Length: 20}
	stream.AddResponse(respMsg)
	if respMsg.IsRequest {
		t.Error("AddResponse should set IsRequest to false")
	}

	if len(stream.RequestMessages) != 1 {
		t.Errorf("Expected 1 request, got %d", len(stream.RequestMessages))
	}
	if len(stream.ResponseMessages) != 1 {
		t.Errorf("Expected 1 response, got %d", len(stream.ResponseMessages))
	}
}

func TestGRPCDissector_ParseTruncatedVarint(t *testing.T) {
	d := NewGRPCDissector()
	pkt := &model.Packet{}

	// Protobuf with truncated varint value.
	protoPayload := []byte{
		0x08,       // field 1, wire type 0 (varint)
		0x80, 0x80, // incomplete varint (needs more bytes)
	}
	data := createGRPCFrame(false, protoPayload)

	_ = d.Parse(data, pkt)
	// Should handle gracefully without panic.
}

func TestGRPCDissector_ParseTruncatedFixed64(t *testing.T) {
	d := NewGRPCDissector()
	pkt := &model.Packet{}

	// Protobuf with truncated fixed64 value.
	protoPayload := []byte{
		0x09,             // field 1, wire type 1 (fixed64)
		0x01, 0x02, 0x03, // only 3 bytes instead of 8
	}
	data := createGRPCFrame(false, protoPayload)

	_ = d.Parse(data, pkt)
	// Should handle gracefully without panic.
}

func TestGRPCDissector_ParseTruncatedFixed32(t *testing.T) {
	d := NewGRPCDissector()
	pkt := &model.Packet{}

	// Protobuf with truncated fixed32 value.
	protoPayload := []byte{
		0x0d,       // field 1, wire type 5 (fixed32)
		0x01, 0x02, // only 2 bytes instead of 4
	}
	data := createGRPCFrame(false, protoPayload)

	_ = d.Parse(data, pkt)
	// Should handle gracefully without panic.
}

func TestGRPCDissector_ParseTruncatedBytes(t *testing.T) {
	d := NewGRPCDissector()
	pkt := &model.Packet{}

	// Protobuf with truncated bytes value.
	protoPayload := []byte{
		0x0a, 0x10, // field 1, length 16
		'a', 'b', 'c', // only 3 bytes
	}
	data := createGRPCFrame(false, protoPayload)

	_ = d.Parse(data, pkt)
	// Should handle gracefully without panic.
}

func TestIsValidUTF8(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		expect bool
	}{
		{"ascii", []byte("hello"), true},
		{"empty", []byte{}, true},
		{"utf8_multibyte", []byte("hëllo"), true},
		{"control_chars", []byte{0x00, 0x01, 0x02}, false},
		{"invalid_utf8", []byte{0xFF, 0xFE}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We can't directly test isValidUTF8, but we can test via the decodeProtobuf behavior.
			d := NewGRPCDissector()
			pkt := &model.Packet{}

			// Create protobuf with bytes field.
			protoPayload := append([]byte{0x0a, byte(len(tt.data))}, tt.data...)
			data := createGRPCFrame(false, protoPayload)

			_ = d.Parse(data, pkt)
			// Test passes if no panic.
		})
	}
}

func TestGRPCDissector_LoadProtoFile_NotFound(t *testing.T) {
	d := NewGRPCDissector()
	err := d.LoadProtoFile("/nonexistent/path/to/proto.pb")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestGRPCDissector_LoadProtoDir_NotFound(t *testing.T) {
	d := NewGRPCDissector()
	err := d.LoadProtoDir("/nonexistent/path/to/protos")
	if err == nil {
		t.Error("Expected error for non-existent directory")
	}
}

func TestGRPCDissector_DecodeWithSchema_NotFound(t *testing.T) {
	d := NewGRPCDissector()
	_, err := d.DecodeWithSchema([]byte{0x08, 0x01}, "nonexistent.Message")
	if err == nil {
		t.Error("Expected error for unknown message type")
	}
}

func TestGRPCDissector_ParseGroupWireType(t *testing.T) {
	d := NewGRPCDissector()
	pkt := &model.Packet{}

	// Protobuf with deprecated group wire type (3).
	// Field 1 with wire type 3 (start group): tag = (1 << 3) | 3 = 0x0b
	protoPayload := []byte{
		0x0b, // field 1, wire type 3 (start group) - deprecated, should be skipped
	}
	data := createGRPCFrame(false, protoPayload)

	_ = d.Parse(data, pkt)
	// Should handle gracefully without panic.
}

func TestGRPCDissector_ParseUnknownWireType(t *testing.T) {
	d := NewGRPCDissector()
	pkt := &model.Packet{}

	// Protobuf with invalid wire type (6 or 7).
	// Field 1 with wire type 6: tag = (1 << 3) | 6 = 0x0e
	protoPayload := []byte{
		0x0e, // field 1, wire type 6 (invalid)
		0x00, // some data
	}
	data := createGRPCFrame(false, protoPayload)

	_ = d.Parse(data, pkt)
	// Should handle gracefully without panic.
}

func TestGRPCDissector_ParseEmptyData(t *testing.T) {
	d := NewGRPCDissector()
	pkt := &model.Packet{}

	err := d.Parse([]byte{}, pkt)
	if err == nil {
		t.Error("Expected error for empty data")
	}
}

func TestGRPCDissector_ParsePartialHeader(t *testing.T) {
	d := NewGRPCDissector()
	pkt := &model.Packet{}

	// Only 3 bytes, not enough for header.
	err := d.Parse([]byte{0x00, 0x00, 0x00}, pkt)
	if err == nil {
		t.Error("Expected error for partial header")
	}
}

func TestGRPCDissector_FrameTooLarge(t *testing.T) {
	d := NewGRPCDissector()
	pkt := &model.Packet{}

	// Frame with length > 16MB.
	// flags=0, length=0x01400000 (20MB)
	data := []byte{0x00, 0x01, 0x40, 0x00, 0x00}
	data = append(data, make([]byte, 100)...)

	err := d.Parse(data, pkt)
	// Should error or return incomplete.
	if err == nil && len(pkt.GRPCMessages) > 0 {
		t.Error("Should not parse frame larger than 16MB")
	}
}

func TestGRPCDissector_LoadProtoFile_InvalidProto(t *testing.T) {
	d := NewGRPCDissector()

	// Create a temporary file with invalid proto content.
	tmpFile := "/tmp/invalid_proto_test.pb"
	err := writeTestFile(tmpFile, []byte("not a valid protobuf descriptor"))
	if err != nil {
		t.Skipf("Could not create temp file: %v", err)
	}
	defer removeTestFile(tmpFile)

	err = d.LoadProtoFile(tmpFile)
	if err == nil {
		t.Error("Expected error for invalid proto content")
	}
}

// Helper functions for file tests.
func writeTestFile(path string, content []byte) error {
	return os.WriteFile(path, content, 0644)
}

func removeTestFile(path string) {
	os.Remove(path)
}

// createGRPCFrame creates a gRPC wire format frame.
func createGRPCFrame(compressed bool, payload []byte) []byte {
	frame := make([]byte, 5+len(payload))

	if compressed {
		frame[0] = 0x01
	} else {
		frame[0] = 0x00
	}

	binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload)))
	copy(frame[5:], payload)

	return frame
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

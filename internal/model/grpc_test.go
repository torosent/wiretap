package model

import "testing"

func TestGRPCMessage_Summary(t *testing.T) {
	tests := []struct {
		name   string
		msg    GRPCMessage
		expect string
	}{
		{
			name: "with service method",
			msg: GRPCMessage{
				ServiceMethod: "/example.Greeter/SayHello",
				Length:        100,
			},
			expect: "gRPC /example.Greeter/SayHello (100 bytes)",
		},
		{
			name: "with message type",
			msg: GRPCMessage{
				MessageType: "example.HelloRequest",
				Length:      50,
			},
			expect: "gRPC example.HelloRequest (50 bytes)",
		},
		{
			name: "without type info",
			msg: GRPCMessage{
				Length: 25,
			},
			expect: "gRPC message (25 bytes)",
		},
		{
			name: "service method takes precedence",
			msg: GRPCMessage{
				ServiceMethod: "/service/Method",
				MessageType:   "SomeType",
				Length:        10,
			},
			expect: "gRPC /service/Method (10 bytes)",
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

func TestGRPCMessage_HasDecodedFields(t *testing.T) {
	msg := &GRPCMessage{}
	if msg.HasDecodedFields() {
		t.Error("Empty message should not have decoded fields")
	}

	msg.DecodedFields = map[uint32]interface{}{}
	if msg.HasDecodedFields() {
		t.Error("Message with empty map should not have decoded fields")
	}

	msg.DecodedFields = map[uint32]interface{}{1: "test"}
	if !msg.HasDecodedFields() {
		t.Error("Message with fields should have decoded fields")
	}
}

func TestGRPCStatus_String(t *testing.T) {
	tests := []struct {
		status GRPCStatus
		expect string
	}{
		{GRPCStatusOK, "OK"},
		{GRPCStatusCancelled, "CANCELLED"},
		{GRPCStatusUnknown, "UNKNOWN"},
		{GRPCStatusInvalidArgument, "INVALID_ARGUMENT"},
		{GRPCStatusDeadlineExceeded, "DEADLINE_EXCEEDED"},
		{GRPCStatusNotFound, "NOT_FOUND"},
		{GRPCStatusAlreadyExists, "ALREADY_EXISTS"},
		{GRPCStatusPermissionDenied, "PERMISSION_DENIED"},
		{GRPCStatusResourceExhausted, "RESOURCE_EXHAUSTED"},
		{GRPCStatusFailedPrecondition, "FAILED_PRECONDITION"},
		{GRPCStatusAborted, "ABORTED"},
		{GRPCStatusOutOfRange, "OUT_OF_RANGE"},
		{GRPCStatusUnimplemented, "UNIMPLEMENTED"},
		{GRPCStatusInternal, "INTERNAL"},
		{GRPCStatusUnavailable, "UNAVAILABLE"},
		{GRPCStatusDataLoss, "DATA_LOSS"},
		{GRPCStatusUnauthenticated, "UNAUTHENTICATED"},
		{GRPCStatus(999), "STATUS(999)"},
		{GRPCStatus(-1), "STATUS(-1)"},
	}

	for _, tt := range tests {
		t.Run(tt.expect, func(t *testing.T) {
			got := tt.status.String()
			if got != tt.expect {
				t.Errorf("GRPCStatus(%d).String() = %s, want %s", tt.status, got, tt.expect)
			}
		})
	}
}

func TestGRPCStatus_IsOK(t *testing.T) {
	if !GRPCStatusOK.IsOK() {
		t.Error("GRPCStatusOK.IsOK() should return true")
	}
	if GRPCStatusCancelled.IsOK() {
		t.Error("GRPCStatusCancelled.IsOK() should return false")
	}
	if GRPCStatusInternal.IsOK() {
		t.Error("GRPCStatusInternal.IsOK() should return false")
	}
}

func TestGRPCStatus_IsError(t *testing.T) {
	if GRPCStatusOK.IsError() {
		t.Error("GRPCStatusOK.IsError() should return false")
	}
	if !GRPCStatusCancelled.IsError() {
		t.Error("GRPCStatusCancelled.IsError() should return true")
	}
	if !GRPCStatusInternal.IsError() {
		t.Error("GRPCStatusInternal.IsError() should return true")
	}
}

func TestGRPCStream_AddRequest(t *testing.T) {
	stream := &GRPCStream{
		Method: "/test.Service/Method",
	}

	msg1 := &GRPCMessage{Length: 10}
	msg2 := &GRPCMessage{Length: 20}

	stream.AddRequest(msg1)
	stream.AddRequest(msg2)

	if len(stream.RequestMessages) != 2 {
		t.Errorf("Expected 2 requests, got %d", len(stream.RequestMessages))
	}
	if !stream.RequestMessages[0].IsRequest {
		t.Error("First message should have IsRequest=true")
	}
	if !stream.RequestMessages[1].IsRequest {
		t.Error("Second message should have IsRequest=true")
	}
}

func TestGRPCStream_AddResponse(t *testing.T) {
	stream := &GRPCStream{
		Method: "/test.Service/Method",
	}

	msg1 := &GRPCMessage{Length: 100}
	msg2 := &GRPCMessage{Length: 200}

	stream.AddResponse(msg1)
	stream.AddResponse(msg2)

	if len(stream.ResponseMessages) != 2 {
		t.Errorf("Expected 2 responses, got %d", len(stream.ResponseMessages))
	}
	if stream.ResponseMessages[0].IsRequest {
		t.Error("First message should have IsRequest=false")
	}
	if stream.ResponseMessages[1].IsRequest {
		t.Error("Second message should have IsRequest=false")
	}
}

func TestGRPCStream_Summary(t *testing.T) {
	tests := []struct {
		name   string
		stream GRPCStream
		expect string
	}{
		{
			name: "empty stream",
			stream: GRPCStream{
				Method: "/test.Service/Empty",
				Status: GRPCStatusOK,
			},
			expect: "gRPC /test.Service/Empty (req:0, resp:0, status:OK)",
		},
		{
			name: "unary call",
			stream: GRPCStream{
				Method:           "/test.Service/Unary",
				Status:           GRPCStatusOK,
				RequestMessages:  []*GRPCMessage{{Length: 10}},
				ResponseMessages: []*GRPCMessage{{Length: 20}},
			},
			expect: "gRPC /test.Service/Unary (req:1, resp:1, status:OK)",
		},
		{
			name: "client streaming",
			stream: GRPCStream{
				Method:           "/test.Service/ClientStream",
				Status:           GRPCStatusOK,
				RequestMessages:  []*GRPCMessage{{}, {}, {}},
				ResponseMessages: []*GRPCMessage{{}},
			},
			expect: "gRPC /test.Service/ClientStream (req:3, resp:1, status:OK)",
		},
		{
			name: "server streaming",
			stream: GRPCStream{
				Method:           "/test.Service/ServerStream",
				Status:           GRPCStatusOK,
				RequestMessages:  []*GRPCMessage{{}},
				ResponseMessages: []*GRPCMessage{{}, {}, {}, {}},
			},
			expect: "gRPC /test.Service/ServerStream (req:1, resp:4, status:OK)",
		},
		{
			name: "error status",
			stream: GRPCStream{
				Method:           "/test.Service/Error",
				Status:           GRPCStatusInternal,
				RequestMessages:  []*GRPCMessage{{}},
				ResponseMessages: []*GRPCMessage{},
			},
			expect: "gRPC /test.Service/Error (req:1, resp:0, status:INTERNAL)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.stream.Summary()
			if got != tt.expect {
				t.Errorf("Summary() = %q, want %q", got, tt.expect)
			}
		})
	}
}

func TestGRPCStream_Metadata(t *testing.T) {
	stream := &GRPCStream{
		Method: "/test.Service/Method",
		Metadata: map[string][]string{
			"content-type": {"application/grpc"},
			"user-agent":   {"grpc-go/1.0"},
		},
	}

	if len(stream.Metadata) != 2 {
		t.Errorf("Expected 2 metadata entries, got %d", len(stream.Metadata))
	}
	if stream.Metadata["content-type"][0] != "application/grpc" {
		t.Error("Expected content-type metadata")
	}
}

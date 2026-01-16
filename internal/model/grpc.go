// Package model defines gRPC-related types.
package model

import "fmt"

// GRPCMessage represents a single gRPC message.
type GRPCMessage struct {
	// Compressed indicates if the message is compressed.
	Compressed bool

	// Length is the message payload length.
	Length uint32

	// Payload is the raw protobuf message bytes.
	Payload []byte

	// DecodedFields contains decoded protobuf fields (schema-less).
	DecodedFields map[uint32]interface{}

	// DecodedMessage contains the fully decoded message (with schema).
	DecodedMessage interface{}

	// MessageType is the protobuf message type name (if known).
	MessageType string

	// ServiceMethod is the gRPC service/method (from HTTP/2 :path).
	ServiceMethod string

	// IsRequest indicates if this is a request (vs response).
	IsRequest bool

	// Status is the gRPC status code (response only).
	Status GRPCStatus

	// StatusMessage is the gRPC status message.
	StatusMessage string
}

// Summary returns a brief description of the gRPC message.
func (m *GRPCMessage) Summary() string {
	if m.ServiceMethod != "" {
		return fmt.Sprintf("gRPC %s (%d bytes)", m.ServiceMethod, m.Length)
	}
	if m.MessageType != "" {
		return fmt.Sprintf("gRPC %s (%d bytes)", m.MessageType, m.Length)
	}
	return fmt.Sprintf("gRPC message (%d bytes)", m.Length)
}

// HasDecodedFields returns true if the message was decoded.
func (m *GRPCMessage) HasDecodedFields() bool {
	return len(m.DecodedFields) > 0
}

// GRPCStatus represents a gRPC status code.
type GRPCStatus int32

// gRPC status codes.
const (
	GRPCStatusOK                 GRPCStatus = 0
	GRPCStatusCancelled          GRPCStatus = 1
	GRPCStatusUnknown            GRPCStatus = 2
	GRPCStatusInvalidArgument    GRPCStatus = 3
	GRPCStatusDeadlineExceeded   GRPCStatus = 4
	GRPCStatusNotFound           GRPCStatus = 5
	GRPCStatusAlreadyExists      GRPCStatus = 6
	GRPCStatusPermissionDenied   GRPCStatus = 7
	GRPCStatusResourceExhausted  GRPCStatus = 8
	GRPCStatusFailedPrecondition GRPCStatus = 9
	GRPCStatusAborted            GRPCStatus = 10
	GRPCStatusOutOfRange         GRPCStatus = 11
	GRPCStatusUnimplemented      GRPCStatus = 12
	GRPCStatusInternal           GRPCStatus = 13
	GRPCStatusUnavailable        GRPCStatus = 14
	GRPCStatusDataLoss           GRPCStatus = 15
	GRPCStatusUnauthenticated    GRPCStatus = 16
)

// String returns the status code name.
func (s GRPCStatus) String() string {
	names := map[GRPCStatus]string{
		GRPCStatusOK:                 "OK",
		GRPCStatusCancelled:          "CANCELLED",
		GRPCStatusUnknown:            "UNKNOWN",
		GRPCStatusInvalidArgument:    "INVALID_ARGUMENT",
		GRPCStatusDeadlineExceeded:   "DEADLINE_EXCEEDED",
		GRPCStatusNotFound:           "NOT_FOUND",
		GRPCStatusAlreadyExists:      "ALREADY_EXISTS",
		GRPCStatusPermissionDenied:   "PERMISSION_DENIED",
		GRPCStatusResourceExhausted:  "RESOURCE_EXHAUSTED",
		GRPCStatusFailedPrecondition: "FAILED_PRECONDITION",
		GRPCStatusAborted:            "ABORTED",
		GRPCStatusOutOfRange:         "OUT_OF_RANGE",
		GRPCStatusUnimplemented:      "UNIMPLEMENTED",
		GRPCStatusInternal:           "INTERNAL",
		GRPCStatusUnavailable:        "UNAVAILABLE",
		GRPCStatusDataLoss:           "DATA_LOSS",
		GRPCStatusUnauthenticated:    "UNAUTHENTICATED",
	}

	if name, ok := names[s]; ok {
		return name
	}
	return fmt.Sprintf("STATUS(%d)", s)
}

// IsOK returns true if the status is OK.
func (s GRPCStatus) IsOK() bool {
	return s == GRPCStatusOK
}

// IsError returns true if the status indicates an error.
func (s GRPCStatus) IsError() bool {
	return s != GRPCStatusOK
}

// GRPCStream represents a gRPC stream (may contain multiple messages).
type GRPCStream struct {
	// Method is the full method path (e.g., "/package.Service/Method").
	Method string

	// ServiceName is the service name.
	ServiceName string

	// MethodName is the method name.
	MethodName string

	// IsClientStream indicates client-side streaming.
	IsClientStream bool

	// IsServerStream indicates server-side streaming.
	IsServerStream bool

	// RequestMessages contains request messages.
	RequestMessages []*GRPCMessage

	// ResponseMessages contains response messages.
	ResponseMessages []*GRPCMessage

	// Status is the final status code.
	Status GRPCStatus

	// StatusMessage is the final status message.
	StatusMessage string

	// Metadata contains gRPC metadata (headers/trailers).
	Metadata map[string][]string
}

// AddRequest adds a request message to the stream.
func (s *GRPCStream) AddRequest(msg *GRPCMessage) {
	msg.IsRequest = true
	s.RequestMessages = append(s.RequestMessages, msg)
}

// AddResponse adds a response message to the stream.
func (s *GRPCStream) AddResponse(msg *GRPCMessage) {
	msg.IsRequest = false
	s.ResponseMessages = append(s.ResponseMessages, msg)
}

// Summary returns a brief description of the stream.
func (s *GRPCStream) Summary() string {
	reqCount := len(s.RequestMessages)
	respCount := len(s.ResponseMessages)
	return fmt.Sprintf("gRPC %s (req:%d, resp:%d, status:%s)",
		s.Method, reqCount, respCount, s.Status)
}

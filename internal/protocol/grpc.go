// Package protocol provides gRPC protocol parsing.
package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/wiretap/wiretap/internal/model"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// gRPC wire format constants.
const (
	grpcFlagCompressed = 0x01
	grpcHeaderSize     = 5 // 1 byte flags + 4 bytes length
)

// Common gRPC errors.
var (
	ErrInvalidGRPCFrame  = errors.New("invalid gRPC frame")
	ErrGRPCFrameTooLarge = errors.New("gRPC frame too large")
	ErrProtoNotFound     = errors.New("protobuf descriptor not found")
)

// GRPCDissector parses gRPC protocol traffic.
type GRPCDissector struct {
	mu        sync.RWMutex
	registry  *protoregistry.Files
	types     *protoregistry.Types
	protoDirs []string // Directories to search for .proto files
}

var defaultGRPCMu sync.Mutex
var defaultGRPCDissector = NewGRPCDissector()

// NewGRPCDissector creates a new gRPC dissector.
func NewGRPCDissector() *GRPCDissector {
	return &GRPCDissector{
		registry: new(protoregistry.Files),
		types:    new(protoregistry.Types),
	}
}

// DefaultGRPCDissector returns the shared gRPC dissector instance.
func DefaultGRPCDissector() *GRPCDissector {
	defaultGRPCMu.Lock()
	defer defaultGRPCMu.Unlock()
	if defaultGRPCDissector == nil {
		defaultGRPCDissector = NewGRPCDissector()
	}
	return defaultGRPCDissector
}

// ConfigureGRPCDissector loads proto descriptor sets into the shared dissector.
func ConfigureGRPCDissector(protoDirs, protoFiles []string) error {
	d := NewGRPCDissector()
	for _, dir := range protoDirs {
		if err := d.LoadProtoDir(dir); err != nil {
			return err
		}
	}
	for _, file := range protoFiles {
		if err := d.LoadProtoFile(file); err != nil {
			return err
		}
	}

	defaultGRPCMu.Lock()
	defaultGRPCDissector = d
	defaultGRPCMu.Unlock()
	return nil
}

// Name returns the dissector name.
func (d *GRPCDissector) Name() string {
	return "gRPC"
}

// SetProtoDirs sets directories to search for .proto files.
func (d *GRPCDissector) SetProtoDirs(dirs []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.protoDirs = dirs
}

// AddProtoDir adds a directory to search for .proto files.
func (d *GRPCDissector) AddProtoDir(dir string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.protoDirs = append(d.protoDirs, dir)
}

// Detect checks if data looks like gRPC traffic.
// gRPC runs over HTTP/2, so we look for gRPC content types and frame patterns.
func (d *GRPCDissector) Detect(data []byte) bool {
	// Check for gRPC content type in HTTP/2 headers.
	if bytes.Contains(data, []byte("application/grpc")) {
		return true
	}

	// Check for gRPC frame header pattern.
	// gRPC frames have: 1 byte compressed flag + 4 byte length (big endian).
	if len(data) >= grpcHeaderSize {
		flags := data[0]
		// Flags should be 0x00 (uncompressed) or 0x01 (compressed).
		if flags <= 0x01 {
			length := binary.BigEndian.Uint32(data[1:5])
			// Sanity check: length should be reasonable.
			if length > 0 && length <= 16*1024*1024 { // Max 16MB
				// Check if we have enough data.
				if len(data) >= int(grpcHeaderSize+length) {
					return true
				}
			}
		}
	}

	return false
}

// Parse extracts gRPC message information.
func (d *GRPCDissector) Parse(data []byte, pkt *model.Packet) error {
	// Parse gRPC frames.
	frames, err := d.parseFrames(data)
	if err != nil {
		return err
	}

	if len(frames) == 0 {
		return ErrIncompleteData
	}

	pkt.ApplicationProtocol = "gRPC"
	pkt.GRPCMessages = frames

	// Set AppInfo from first message.
	if len(frames) > 0 {
		pkt.AppInfo = frames[0].Summary()
	}

	return nil
}

// parseFrames extracts all gRPC messages from the data.
func (d *GRPCDissector) parseFrames(data []byte) ([]*model.GRPCMessage, error) {
	var messages []*model.GRPCMessage
	offset := 0

	for offset < len(data) {
		msg, consumed, err := d.parseFrame(data[offset:])
		if err != nil {
			break
		}
		if consumed == 0 {
			break
		}
		messages = append(messages, msg)
		offset += consumed
	}

	return messages, nil
}

// parseFrame parses a single gRPC frame.
func (d *GRPCDissector) parseFrame(data []byte) (*model.GRPCMessage, int, error) {
	if len(data) < grpcHeaderSize {
		return nil, 0, ErrIncompleteData
	}

	msg := &model.GRPCMessage{}

	// Parse header.
	msg.Compressed = (data[0] & grpcFlagCompressed) != 0
	msg.Length = binary.BigEndian.Uint32(data[1:5])

	// Validate length.
	if msg.Length > 16*1024*1024 { // 16MB max
		return nil, 0, ErrGRPCFrameTooLarge
	}

	totalLen := grpcHeaderSize + int(msg.Length)
	if len(data) < totalLen {
		return nil, 0, ErrIncompleteData
	}

	// Extract payload.
	msg.Payload = make([]byte, msg.Length)
	copy(msg.Payload, data[grpcHeaderSize:totalLen])

	// Try to decode protobuf.
	msg.DecodedFields = d.decodeProtobuf(msg.Payload)

	return msg, totalLen, nil
}

// decodeProtobuf attempts to decode protobuf message without a schema.
// Returns a map of field numbers to decoded values.
func (d *GRPCDissector) decodeProtobuf(data []byte) map[uint32]interface{} {
	fields := make(map[uint32]interface{})
	offset := 0

decodeLoop:
	for offset < len(data) {
		// Parse field tag.
		fieldNum, wireType, n := protowire.ConsumeTag(data[offset:])
		if n < 0 {
			break decodeLoop
		}
		offset += n

		// Parse field value.
		var value interface{}
		var consumed int

		switch wireType {
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(data[offset:])
			if n < 0 {
				break decodeLoop
			}
			value = v
			consumed = n

		case protowire.Fixed64Type:
			v, n := protowire.ConsumeFixed64(data[offset:])
			if n < 0 {
				break decodeLoop
			}
			value = v
			consumed = n

		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(data[offset:])
			if n < 0 {
				break decodeLoop
			}
			// Try to interpret as string if it looks like UTF-8.
			if isValidUTF8(v) {
				value = string(v)
			} else {
				// Try to decode as nested message.
				nested := d.decodeProtobuf(v)
				if len(nested) > 0 {
					value = nested
				} else {
					value = v
				}
			}
			consumed = n

		case protowire.StartGroupType:
			// Skip groups (deprecated).
			break decodeLoop

		case protowire.Fixed32Type:
			v, n := protowire.ConsumeFixed32(data[offset:])
			if n < 0 {
				break decodeLoop
			}
			value = v
			consumed = n

		default:
			break decodeLoop
		}

		if consumed == 0 {
			break decodeLoop
		}

		offset += consumed

		// Store field (handle repeated fields).
		if existing, ok := fields[uint32(fieldNum)]; ok {
			// Convert to array if needed.
			if arr, isArr := existing.([]interface{}); isArr {
				fields[uint32(fieldNum)] = append(arr, value)
			} else {
				fields[uint32(fieldNum)] = []interface{}{existing, value}
			}
		} else {
			fields[uint32(fieldNum)] = value
		}
	}

	return fields
}

// LoadProtoFile loads a .proto file descriptor set.
func (d *GRPCDissector) LoadProtoFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read proto file: %w", err)
	}

	// Parse as FileDescriptorSet.
	fds := &descriptorpb.FileDescriptorSet{}
	if err := proto.Unmarshal(data, fds); err != nil {
		// Try as single FileDescriptor.
		fd := &descriptorpb.FileDescriptorProto{}
		if err := proto.Unmarshal(data, fd); err != nil {
			return fmt.Errorf("parse proto descriptor: %w", err)
		}
		fds.File = append(fds.File, fd)
	}

	// Register files.
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, fdp := range fds.File {
		fd, err := protodesc.NewFile(fdp, d.registry)
		if err != nil {
			continue
		}
		if err := d.registry.RegisterFile(fd); err != nil {
			continue
		}

		// Register message types.
		messages := fd.Messages()
		for i := 0; i < messages.Len(); i++ {
			msg := messages.Get(i)
			mt := dynamicpb.NewMessageType(msg)
			d.types.RegisterMessage(mt)
		}
	}

	return nil
}

// LoadProtoDir loads all .proto files from a directory.
func (d *GRPCDissector) LoadProtoDir(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".pb") {
			if loadErr := d.LoadProtoFile(path); loadErr != nil {
				// Log but continue.
				fmt.Fprintf(os.Stderr, "Warning: failed to load %s: %v\n", path, loadErr)
			}
		}
		return nil
	})
}

// DecodeWithSchema decodes a protobuf message using a known schema.
func (d *GRPCDissector) DecodeWithSchema(data []byte, messageName string) (interface{}, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// Find message type.
	mt, err := d.types.FindMessageByName(protoreflect.FullName(messageName))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrProtoNotFound, messageName)
	}

	// Unmarshal.
	msg := dynamicpb.NewMessage(mt.Descriptor())
	if err := unmarshalDynamic(data, msg); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	// Convert to map.
	return messageToMap(msg), nil
}

// unmarshalDynamic unmarshals data into a dynamic message.
func unmarshalDynamic(data []byte, msg *dynamicpb.Message) error {
	offset := 0
	for offset < len(data) {
		fieldNum, wireType, n := protowire.ConsumeTag(data[offset:])
		if n < 0 {
			return errors.New("invalid tag")
		}
		offset += n

		fd := msg.Descriptor().Fields().ByNumber(fieldNum)
		if fd == nil {
			// Unknown field, skip it.
			switch wireType {
			case protowire.VarintType:
				_, n = protowire.ConsumeVarint(data[offset:])
			case protowire.Fixed64Type:
				_, n = protowire.ConsumeFixed64(data[offset:])
			case protowire.BytesType:
				_, n = protowire.ConsumeBytes(data[offset:])
			case protowire.Fixed32Type:
				_, n = protowire.ConsumeFixed32(data[offset:])
			default:
				return fmt.Errorf("unknown wire type: %d", wireType)
			}
			if n < 0 {
				return errors.New("invalid field value")
			}
			offset += n
			continue
		}

		// Parse and set field value.
		var consumed int
		switch wireType {
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(data[offset:])
			if n < 0 {
				return errors.New("invalid varint")
			}
			setVarintField(msg, fd, v)
			consumed = n

		case protowire.Fixed64Type:
			v, n := protowire.ConsumeFixed64(data[offset:])
			if n < 0 {
				return errors.New("invalid fixed64")
			}
			msg.Set(fd, protoreflect.ValueOfUint64(v))
			consumed = n

		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(data[offset:])
			if n < 0 {
				return errors.New("invalid bytes")
			}
			if fd.Kind() == protoreflect.MessageKind {
				nested := dynamicpb.NewMessage(fd.Message())
				if err := unmarshalDynamic(v, nested); err == nil {
					msg.Set(fd, protoreflect.ValueOfMessage(nested))
				}
			} else {
				msg.Set(fd, protoreflect.ValueOfBytes(v))
			}
			consumed = n

		case protowire.Fixed32Type:
			v, n := protowire.ConsumeFixed32(data[offset:])
			if n < 0 {
				return errors.New("invalid fixed32")
			}
			msg.Set(fd, protoreflect.ValueOfUint32(v))
			consumed = n
		}

		offset += consumed
	}

	return nil
}

// setVarintField sets a varint field value based on field type.
func setVarintField(msg *dynamicpb.Message, fd protoreflect.FieldDescriptor, v uint64) {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		msg.Set(fd, protoreflect.ValueOfBool(v != 0))
	case protoreflect.EnumKind:
		msg.Set(fd, protoreflect.ValueOfEnum(protoreflect.EnumNumber(v)))
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		msg.Set(fd, protoreflect.ValueOfInt32(int32(v)))
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		msg.Set(fd, protoreflect.ValueOfInt64(int64(v)))
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		msg.Set(fd, protoreflect.ValueOfUint32(uint32(v)))
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		msg.Set(fd, protoreflect.ValueOfUint64(v))
	}
}

// messageToMap converts a dynamic message to a map.
func messageToMap(msg *dynamicpb.Message) map[string]interface{} {
	result := make(map[string]interface{})

	msg.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		name := string(fd.Name())

		switch fd.Kind() {
		case protoreflect.MessageKind:
			if fd.IsList() {
				list := v.List()
				arr := make([]interface{}, list.Len())
				for i := 0; i < list.Len(); i++ {
					if nested, ok := list.Get(i).Message().Interface().(*dynamicpb.Message); ok {
						arr[i] = messageToMap(nested)
					}
				}
				result[name] = arr
			} else {
				if nested, ok := v.Message().Interface().(*dynamicpb.Message); ok {
					result[name] = messageToMap(nested)
				}
			}
		case protoreflect.BytesKind:
			result[name] = v.Bytes()
		default:
			result[name] = v.Interface()
		}

		return true
	})

	return result
}

// isValidUTF8 checks if data is valid UTF-8.
func isValidUTF8(data []byte) bool {
	// Check for valid UTF-8 and printable characters.
	for _, b := range data {
		if b < 0x20 && b != '\t' && b != '\n' && b != '\r' {
			return false
		}
		if b >= 0x80 {
			// Multi-byte UTF-8, validate properly.
			s := string(data)
			for i := 0; i < len(s); i++ {
				if s[i] >= 0x80 {
					// Check for valid UTF-8 sequence.
					r := []rune(s)
					for _, c := range r {
						if c == 0xFFFD { // Replacement character
							return false
						}
					}
					return true
				}
			}
		}
	}
	return true
}

// FieldsToJSON converts decoded fields to JSON string.
func FieldsToJSON(fields map[uint32]interface{}) string {
	// Convert field numbers to strings for JSON.
	stringFields := make(map[string]interface{})
	for k, v := range fields {
		stringFields[fmt.Sprintf("field_%d", k)] = v
	}

	data, err := json.MarshalIndent(stringFields, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(data)
}

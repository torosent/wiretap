package protocol

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/wiretap/wiretap/internal/model"
)

// HTTP1Dissector parses HTTP/1.x protocol traffic.
type HTTP1Dissector struct{}

// NewHTTP1Dissector creates a new HTTP/1.x dissector.
func NewHTTP1Dissector() *HTTP1Dissector {
	return &HTTP1Dissector{}
}

// Name returns the dissector name.
func (d *HTTP1Dissector) Name() string {
	return "HTTP/1.x"
}

// Detect checks if data looks like HTTP/1.x traffic.
func (d *HTTP1Dissector) Detect(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	// Check for common HTTP methods
	methods := [][]byte{
		[]byte("GET "),
		[]byte("POST "),
		[]byte("PUT "),
		[]byte("DELETE "),
		[]byte("HEAD "),
		[]byte("OPTIONS "),
		[]byte("PATCH "),
		[]byte("CONNECT "),
		[]byte("TRACE "),
	}

	for _, m := range methods {
		if bytes.HasPrefix(data, m) {
			return true
		}
	}

	// Check for HTTP response
	if bytes.HasPrefix(data, []byte("HTTP/1.")) {
		return true
	}

	return false
}

// Parse extracts HTTP/1.x request or response information.
func (d *HTTP1Dissector) Parse(data []byte, pkt *model.Packet) error {
	if len(data) == 0 {
		return ErrIncompleteData
	}

	// Determine if request or response
	if bytes.HasPrefix(data, []byte("HTTP/1.")) {
		return d.parseResponse(data, pkt)
	}

	return d.parseRequest(data, pkt)
}

// parseRequest parses an HTTP request.
func (d *HTTP1Dissector) parseRequest(data []byte, pkt *model.Packet) error {
	reader := bufio.NewReader(bytes.NewReader(data))

	// Read request line
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return ErrIncompleteData
	}

	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) < 2 {
		return ErrInvalidProtocol
	}

	method, err := parseHTTPMethod(parts[0])
	if err != nil {
		return err
	}

	uri := parts[1]
	version := model.HTTPVersion10
	if len(parts) >= 3 && strings.Contains(parts[2], "1.1") {
		version = model.HTTPVersion11
	}

	// Read headers
	tp := textproto.NewReader(reader)
	headers, err := tp.ReadMIMEHeader()
	if err != nil && err != io.EOF {
		// Headers might be incomplete, that's OK
		headers = make(textproto.MIMEHeader)
	}

	// Calculate body length
	var bodyLen int64
	if cl := headers.Get("Content-Length"); cl != "" {
		bodyLen, _ = strconv.ParseInt(cl, 10, 64)
	}

	req := &model.HTTPRequest{
		Method:        method,
		URI:           uri,
		Version:       version,
		Headers:       headerToMap(headers),
		Host:          headers.Get("Host"),
		ContentType:   headers.Get("Content-Type"),
		ContentLength: bodyLen,
		Timestamp:     pkt.Timestamp,
	}

	// Store parsed data
	pkt.ApplicationProtocol = "HTTP/1.x"
	pkt.HTTPInfo = &model.HTTPConversation{
		Request: req,
		Version: version,
	}

	return nil
}

// parseResponse parses an HTTP response.
func (d *HTTP1Dissector) parseResponse(data []byte, pkt *model.Packet) error {
	reader := bufio.NewReader(bytes.NewReader(data))

	// Read status line
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return ErrIncompleteData
	}

	parts := strings.SplitN(strings.TrimSpace(line), " ", 3)
	if len(parts) < 2 {
		return ErrInvalidProtocol
	}

	version := model.HTTPVersion10
	if strings.Contains(parts[0], "1.1") {
		version = model.HTTPVersion11
	}

	statusCode, err := strconv.Atoi(parts[1])
	if err != nil {
		return ErrInvalidProtocol
	}

	statusText := ""
	if len(parts) >= 3 {
		statusText = parts[2]
	}

	// Read headers
	tp := textproto.NewReader(reader)
	headers, err := tp.ReadMIMEHeader()
	if err != nil && err != io.EOF {
		headers = make(textproto.MIMEHeader)
	}

	// Calculate body length
	var bodyLen int64
	if cl := headers.Get("Content-Length"); cl != "" {
		bodyLen, _ = strconv.ParseInt(cl, 10, 64)
	}

	resp := &model.HTTPResponse{
		StatusCode:    statusCode,
		StatusText:    statusText,
		Version:       version,
		Headers:       headerToMap(headers),
		ContentType:   headers.Get("Content-Type"),
		ContentLength: bodyLen,
		Timestamp:     pkt.Timestamp,
	}

	pkt.ApplicationProtocol = "HTTP/1.x"
	pkt.HTTPInfo = &model.HTTPConversation{
		Response: resp,
		Version:  version,
	}

	return nil
}

// ParseRequestLine parses just the HTTP request line.
func ParseRequestLine(data []byte) (method model.HTTPMethod, uri string, version model.HTTPVersion, err error) {
	line := string(bytes.SplitN(data, []byte("\r\n"), 2)[0])
	parts := strings.Fields(line)

	if len(parts) < 2 {
		err = ErrInvalidProtocol
		return
	}

	method, err = parseHTTPMethod(parts[0])
	if err != nil {
		return
	}

	uri = parts[1]
	version = model.HTTPVersion10

	if len(parts) >= 3 && strings.Contains(parts[2], "1.1") {
		version = model.HTTPVersion11
	}

	return
}

// ParseResponseLine parses just the HTTP response status line.
func ParseResponseLine(data []byte) (version model.HTTPVersion, statusCode int, statusText string, err error) {
	line := string(bytes.SplitN(data, []byte("\r\n"), 2)[0])
	parts := strings.SplitN(line, " ", 3)

	if len(parts) < 2 {
		err = ErrInvalidProtocol
		return
	}

	version = model.HTTPVersion10
	if strings.Contains(parts[0], "1.1") {
		version = model.HTTPVersion11
	}

	statusCode, err = strconv.Atoi(parts[1])
	if err != nil {
		err = ErrInvalidProtocol
		return
	}

	if len(parts) >= 3 {
		statusText = parts[2]
	}

	return
}

func parseHTTPMethod(s string) (model.HTTPMethod, error) {
	switch strings.ToUpper(s) {
	case "GET":
		return model.HTTPMethodGET, nil
	case "POST":
		return model.HTTPMethodPOST, nil
	case "PUT":
		return model.HTTPMethodPUT, nil
	case "DELETE":
		return model.HTTPMethodDELETE, nil
	case "HEAD":
		return model.HTTPMethodHEAD, nil
	case "OPTIONS":
		return model.HTTPMethodOPTIONS, nil
	case "PATCH":
		return model.HTTPMethodPATCH, nil
	case "CONNECT":
		return model.HTTPMethodCONNECT, nil
	case "TRACE":
		return model.HTTPMethodTRACE, nil
	default:
		return "", fmt.Errorf("%w: unknown method %s", ErrUnsupportedMethod, s)
	}
}

func headerToMap(h textproto.MIMEHeader) map[string][]string {
	result := make(map[string][]string, len(h))
	for k, v := range h {
		result[k] = v
	}
	return result
}

// StreamParser parses HTTP messages from a stream of data.
type StreamParser struct {
	buffer   bytes.Buffer
	isServer bool
}

// NewStreamParser creates a new stream parser.
// Set isServer to true when parsing server-to-client (response) traffic.
func NewStreamParser(isServer bool) *StreamParser {
	return &StreamParser{
		isServer: isServer,
	}
}

// Feed adds data to the parser buffer.
func (p *StreamParser) Feed(data []byte) {
	p.buffer.Write(data)
}

// Parse attempts to parse a complete HTTP message from the buffer.
// Returns nil if no complete message is available yet.
func (p *StreamParser) Parse() (*model.HTTPConversation, error) {
	data := p.buffer.Bytes()
	if len(data) == 0 {
		return nil, nil
	}

	// Find end of headers
	headerEnd := bytes.Index(data, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		return nil, nil // Need more data
	}

	// Parse headers to get content length
	headerSection := data[:headerEnd]
	reader := bufio.NewReader(bytes.NewReader(headerSection))

	// Skip first line (request/status line)
	_, err := reader.ReadString('\n')
	if err != nil {
		return nil, nil
	}

	// Read headers
	tp := textproto.NewReader(reader)
	headers, _ := tp.ReadMIMEHeader()

	// Determine body length
	bodyLen := 0
	if cl := headers.Get("Content-Length"); cl != "" {
		bodyLen, _ = strconv.Atoi(cl)
	}

	// Check if we have the complete message
	totalLen := headerEnd + 4 + bodyLen // +4 for \r\n\r\n
	if len(data) < totalLen {
		return nil, nil // Need more data
	}

	// Extract the message
	msgData := data[:totalLen]
	p.buffer.Next(totalLen) // Remove parsed data from buffer

	pkt := &model.Packet{Timestamp: time.Now()}
	dissector := NewHTTP1Dissector()
	if err := dissector.Parse(msgData, pkt); err != nil {
		return nil, err
	}

	return pkt.HTTPInfo, nil
}

// Reset clears the parser buffer.
func (p *StreamParser) Reset() {
	p.buffer.Reset()
}

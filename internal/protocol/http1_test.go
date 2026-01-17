package protocol

import (
	"testing"

	"github.com/wiretap/wiretap/internal/model"
)

func TestHTTP1Dissector_Name(t *testing.T) {
	d := NewHTTP1Dissector()
	if d.Name() != "HTTP/1.x" {
		t.Errorf("Name = %s, want HTTP/1.x", d.Name())
	}
}

func TestHTTP1Dissector_Detect(t *testing.T) {
	d := NewHTTP1Dissector()

	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{
			name: "GET request",
			data: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			want: true,
		},
		{
			name: "POST request",
			data: []byte("POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n"),
			want: true,
		},
		{
			name: "PUT request",
			data: []byte("PUT /resource HTTP/1.0\r\nHost: example.com\r\n\r\n"),
			want: true,
		},
		{
			name: "DELETE request",
			data: []byte("DELETE /item HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			want: true,
		},
		{
			name: "HEAD request",
			data: []byte("HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			want: true,
		},
		{
			name: "OPTIONS request",
			data: []byte("OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			want: true,
		},
		{
			name: "PATCH request",
			data: []byte("PATCH /resource HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			want: true,
		},
		{
			name: "HTTP response 200",
			data: []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"),
			want: true,
		},
		{
			name: "HTTP response 404",
			data: []byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"),
			want: true,
		},
		{
			name: "HTTP/1.0 response",
			data: []byte("HTTP/1.0 301 Moved Permanently\r\nLocation: /new\r\n\r\n"),
			want: true,
		},
		{
			name: "TLS data",
			data: []byte{0x16, 0x03, 0x01, 0x00, 0x05},
			want: false,
		},
		{
			name: "Random binary",
			data: []byte{0x00, 0x01, 0x02, 0x03, 0x04},
			want: false,
		},
		{
			name: "Empty data",
			data: []byte{},
			want: false,
		},
		{
			name: "Partial GET",
			data: []byte("GET"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := d.Detect(tt.data); got != tt.want {
				t.Errorf("Detect() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHTTP1Dissector_Parse_Request(t *testing.T) {
	d := NewHTTP1Dissector()

	tests := []struct {
		name       string
		data       string
		wantMethod model.HTTPMethod
		wantURI    string
		wantHost   string
	}{
		{
			name:       "Simple GET",
			data:       "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantMethod: model.HTTPMethodGET,
			wantURI:    "/",
			wantHost:   "example.com",
		},
		{
			name:       "GET with path",
			data:       "GET /api/v1/users HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
			wantMethod: model.HTTPMethodGET,
			wantURI:    "/api/v1/users",
			wantHost:   "api.example.com",
		},
		{
			name:       "POST with body",
			data:       "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"key\":\"val\"}",
			wantMethod: model.HTTPMethodPOST,
			wantURI:    "/submit",
			wantHost:   "example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := &model.Packet{}
			err := d.Parse([]byte(tt.data), pkt)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}

			if pkt.HTTPInfo == nil {
				t.Fatal("HTTPInfo is nil")
			}
			if pkt.HTTPInfo.Request == nil {
				t.Fatal("Request is nil")
			}

			req := pkt.HTTPInfo.Request
			if req.Method != tt.wantMethod {
				t.Errorf("Method = %v, want %v", req.Method, tt.wantMethod)
			}
			if req.URI != tt.wantURI {
				t.Errorf("URI = %s, want %s", req.URI, tt.wantURI)
			}
			if req.Host != tt.wantHost {
				t.Errorf("Host = %s, want %s", req.Host, tt.wantHost)
			}
		})
	}
}

func TestHTTP1Dissector_Parse_Response(t *testing.T) {
	d := NewHTTP1Dissector()

	tests := []struct {
		name        string
		data        string
		wantStatus  int
		wantVersion model.HTTPVersion
	}{
		{
			name:        "200 OK",
			data:        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello",
			wantStatus:  200,
			wantVersion: model.HTTPVersion11,
		},
		{
			name:        "404 Not Found",
			data:        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
			wantStatus:  404,
			wantVersion: model.HTTPVersion11,
		},
		{
			name:        "302 Found",
			data:        "HTTP/1.1 302 Found\r\nLocation: /new-path\r\n\r\n",
			wantStatus:  302,
			wantVersion: model.HTTPVersion11,
		},
		{
			name:        "500 Internal Server Error",
			data:        "HTTP/1.1 500 Internal Server Error\r\n\r\n",
			wantStatus:  500,
			wantVersion: model.HTTPVersion11,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := &model.Packet{}
			err := d.Parse([]byte(tt.data), pkt)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}

			if pkt.HTTPInfo == nil {
				t.Fatal("HTTPInfo is nil")
			}
			if pkt.HTTPInfo.Response == nil {
				t.Fatal("Response is nil")
			}

			resp := pkt.HTTPInfo.Response
			if resp.StatusCode != tt.wantStatus {
				t.Errorf("StatusCode = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
			if resp.Version != tt.wantVersion {
				t.Errorf("Version = %v, want %v", resp.Version, tt.wantVersion)
			}
		})
	}
}

func TestHTTP1Dissector_Parse_Headers(t *testing.T) {
	d := NewHTTP1Dissector()

	data := "GET / HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"User-Agent: TestClient/1.0\r\n" +
		"Accept: */*\r\n" +
		"X-Custom-Header: custom-value\r\n" +
		"\r\n"

	pkt := &model.Packet{}
	err := d.Parse([]byte(data), pkt)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if pkt.HTTPInfo == nil || pkt.HTTPInfo.Request == nil {
		t.Fatal("Request not parsed")
	}

	headers := pkt.HTTPInfo.Request.Headers
	expectedHeaders := map[string]string{
		"Host":            "example.com",
		"User-Agent":      "TestClient/1.0",
		"Accept":          "*/*",
		"X-Custom-Header": "custom-value",
	}

	for name, wantValue := range expectedHeaders {
		values, ok := headers[name]
		if !ok || len(values) == 0 {
			t.Errorf("Header %s not found", name)
			continue
		}
		if values[0] != wantValue {
			t.Errorf("Header %s = %s, want %s", name, values[0], wantValue)
		}
	}
}

func TestHTTP1Dissector_Parse_Version(t *testing.T) {
	d := NewHTTP1Dissector()

	tests := []struct {
		name        string
		data        string
		wantVersion model.HTTPVersion
	}{
		{
			name:        "HTTP/1.1 request",
			data:        "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantVersion: model.HTTPVersion11,
		},
		{
			name:        "HTTP/1.0 request",
			data:        "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n",
			wantVersion: model.HTTPVersion10,
		},
		{
			name:        "HTTP/1.1 response",
			data:        "HTTP/1.1 200 OK\r\n\r\n",
			wantVersion: model.HTTPVersion11,
		},
		{
			name:        "HTTP/1.0 response",
			data:        "HTTP/1.0 200 OK\r\n\r\n",
			wantVersion: model.HTTPVersion10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := &model.Packet{}
			err := d.Parse([]byte(tt.data), pkt)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}

			if pkt.HTTPInfo == nil {
				t.Fatal("HTTPInfo is nil")
			}

			if pkt.HTTPInfo.Request != nil {
				if pkt.HTTPInfo.Request.Version != tt.wantVersion {
					t.Errorf("Version = %v, want %v", pkt.HTTPInfo.Request.Version, tt.wantVersion)
				}
			}
			if pkt.HTTPInfo.Response != nil {
				if pkt.HTTPInfo.Response.Version != tt.wantVersion {
					t.Errorf("Version = %v, want %v", pkt.HTTPInfo.Response.Version, tt.wantVersion)
				}
			}
		})
	}
}

func TestHTTP1Dissector_Parse_ContentLength(t *testing.T) {
	d := NewHTTP1Dissector()

	data := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\n\r\nHello World"

	pkt := &model.Packet{}
	err := d.Parse([]byte(data), pkt)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if pkt.HTTPInfo == nil || pkt.HTTPInfo.Response == nil {
		t.Fatal("Response not parsed")
	}

	if pkt.HTTPInfo.Response.ContentLength != 11 {
		t.Errorf("ContentLength = %d, want 11", pkt.HTTPInfo.Response.ContentLength)
	}
}

func TestHTTP1Dissector_Parse_InvalidData(t *testing.T) {
	d := NewHTTP1Dissector()

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "Empty data",
			data: []byte{},
		},
		{
			name: "Binary data",
			data: []byte{0x00, 0x01, 0x02, 0x03},
		},
		{
			name: "Incomplete request line",
			data: []byte("GET"), // Only method, no URI
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := &model.Packet{}
			err := d.Parse(tt.data, pkt)
			// Should either return error or leave HTTPInfo nil
			if err == nil && pkt.HTTPInfo != nil {
				t.Error("Expected error or nil HTTPInfo for invalid data")
			}
		})
	}
}

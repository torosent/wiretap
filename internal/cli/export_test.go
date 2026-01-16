package cli

import (
	"encoding/json"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/spf13/cobra"
	"github.com/wiretap/wiretap/internal/model"
)

func buildHTTPPacket(t *testing.T, payload []byte) []byte {
	t.Helper()

	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP("192.168.1.10"),
		DstIP:    net.ParseIP("192.168.1.20"),
	}
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(12345),
		DstPort: layers.TCPPort(80),
		SYN:     true,
		ACK:     true,
	}
	tcp.SetNetworkLayerForChecksum(&ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("SerializeLayers failed: %v", err)
	}

	return buf.Bytes()
}

func writeHTTPPcap(t *testing.T, path string) {
	t.Helper()

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer f.Close()

	writer := pcapgo.NewWriter(f)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("WriteFileHeader failed: %v", err)
	}

	payload := []byte("GET /search?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	data := buildHTTPPacket(t, payload)
	ci := gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(data), Length: len(data)}
	if err := writer.WritePacket(ci, data); err != nil {
		t.Fatalf("WritePacket failed: %v", err)
	}
}

func newExportTestCommand() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("output", "", "")
	cmd.Flags().String("format", "json", "")
	cmd.Flags().Int("count", 0, "")
	cmd.Flags().String("filter", "", "")
	cmd.Flags().StringSlice("protocol", nil, "")
	cmd.Flags().Bool("dissect", true, "")
	cmd.Flags().Bool("pretty", false, "")
	return cmd
}

func TestRunExport_HAR(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "http.pcap")
	outPath := filepath.Join(tmpDir, "out.har")

	writeHTTPPcap(t, pcapPath)

	cmd := newExportTestCommand()
	cmd.Flags().Set("output", outPath)
	cmd.Flags().Set("format", "har")
	cmd.Flags().Set("dissect", "true")

	if err := runExport(cmd, []string{pcapPath}); err != nil {
		t.Fatalf("runExport failed: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	var har HAR
	if err := json.Unmarshal(data, &har); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if len(har.Log.Entries) != 1 {
		t.Fatalf("Expected 1 HAR entry, got %d", len(har.Log.Entries))
	}

	entry := har.Log.Entries[0]
	if entry.Request.Method != "GET" {
		t.Errorf("Request method = %s, want GET", entry.Request.Method)
	}
	if entry.Request.URL == "" {
		t.Error("Expected request URL to be populated")
	}
	if len(entry.Request.QueryString) == 0 {
		t.Error("Expected query string values")
	}
}

func TestRunExport_JSON(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "http.pcap")
	outPath := filepath.Join(tmpDir, "out.json")

	writeHTTPPcap(t, pcapPath)

	cmd := newExportTestCommand()
	cmd.Flags().Set("output", outPath)
	cmd.Flags().Set("format", "json")
	cmd.Flags().Set("pretty", "true")

	if err := runExport(cmd, []string{pcapPath}); err != nil {
		t.Fatalf("runExport failed: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("Expected JSON output")
	}
}

func TestRunExport_CSVAndJSONL(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "http.pcap")
	writeHTTPPcap(t, pcapPath)

	// CSV
	csvPath := filepath.Join(tmpDir, "out.csv")
	cmd := newExportTestCommand()
	cmd.Flags().Set("output", csvPath)
	cmd.Flags().Set("format", "csv")
	if err := runExport(cmd, []string{pcapPath}); err != nil {
		t.Fatalf("CSV export failed: %v", err)
	}
	if data, _ := os.ReadFile(csvPath); len(data) == 0 {
		t.Fatal("Expected CSV output")
	}

	// JSONL
	jsonlPath := filepath.Join(tmpDir, "out.jsonl")
	cmd = newExportTestCommand()
	cmd.Flags().Set("output", jsonlPath)
	cmd.Flags().Set("format", "jsonl")
	if err := runExport(cmd, []string{pcapPath}); err != nil {
		t.Fatalf("JSONL export failed: %v", err)
	}
	if data, _ := os.ReadFile(jsonlPath); len(data) == 0 {
		t.Fatal("Expected JSONL output")
	}
}

func TestRunExport_InvalidFormat(t *testing.T) {
	cmd := newExportTestCommand()
	cmd.Flags().Set("format", "unknown")
	if err := runExport(cmd, []string{"/tmp/doesnotexist.pcap"}); err == nil {
		t.Fatal("Expected error for unsupported format")
	}
}

func TestBuildDissectionMap(t *testing.T) {
	packet := &model.Packet{
		HTTPInfo: &model.HTTPConversation{Request: &model.HTTPRequest{Method: model.HTTPMethodGET, URI: "/"}},
		TLSInfo:  &model.TLSInfo{Version: model.TLSVersion12, ClientHello: &model.TLSClientHello{SNI: "example.com"}},
		DNSInfo:  &model.DNSInfo{IsResponse: true},
	}

	data := buildDissectionMap(packet)
	if _, ok := data["http"]; !ok {
		t.Error("Expected HTTP dissection data")
	}
	if _, ok := data["tls"]; !ok {
		t.Error("Expected TLS dissection data")
	}
	if _, ok := data["dns"]; !ok {
		t.Error("Expected DNS dissection data")
	}
}

func TestHARHelpers(t *testing.T) {
	har := newHAR()
	if har.Log.Version != "1.2" {
		t.Errorf("HAR version = %s, want 1.2", har.Log.Version)
	}
	if har.Log.Creator.Name != "wiretap" {
		t.Errorf("HAR creator = %s, want wiretap", har.Log.Creator.Name)
	}
	if len(har.Log.Entries) != 0 {
		t.Errorf("Expected empty HAR entries, got %d", len(har.Log.Entries))
	}

	parsedURL, _ := url.Parse("https://example.com/abs?q=1")
	req := &model.HTTPRequest{
		Method:        model.HTTPMethodGET,
		URI:           "/search?q=1",
		Version:       model.HTTPVersion11,
		Host:          "example.com",
		Headers:       map[string][]string{"X-Test": {"a", "b"}},
		ContentLength: 12,
	}
	pkt := &model.Packet{DstPort: 443, TLSInfo: &model.TLSInfo{Version: model.TLSVersion12}}

	request := buildHARRequest(req, pkt)
	if request.URL != "https://example.com/search?q=1" {
		t.Errorf("Request URL = %s", request.URL)
	}
	if len(request.QueryString) == 0 {
		t.Error("Expected query params")
	}
	if request.BodySize != req.ContentLength {
		t.Errorf("Request BodySize = %d, want %d", request.BodySize, req.ContentLength)
	}
	if len(request.Headers) != 2 {
		t.Errorf("Expected 2 headers, got %d", len(request.Headers))
	}

	if urlStr := buildRequestURL(&model.HTTPRequest{ParsedURL: parsedURL}, nil); urlStr != parsedURL.String() {
		t.Errorf("buildRequestURL ParsedURL = %s, want %s", urlStr, parsedURL.String())
	}
	if urlStr := buildRequestURL(&model.HTTPRequest{URI: "http://example.com/raw"}, nil); urlStr != "http://example.com/raw" {
		t.Errorf("buildRequestURL raw = %s", urlStr)
	}

	resp := &model.HTTPResponse{
		StatusCode: 200,
		StatusText: "OK",
		Version:    model.HTTPVersion11,
		Headers:    map[string][]string{"Content-Type": {"text/plain"}},
		Body:       []byte("ok"),
		ContentType: "text/plain",
	}
	response := buildHARResponse(resp)
	if response.Status != 200 {
		t.Errorf("Response status = %d, want 200", response.Status)
	}
	if response.Content.Text != "ok" {
		t.Errorf("Response content text = %s", response.Content.Text)
	}
	if response.BodySize != int64(len(resp.Body)) {
		t.Errorf("Response BodySize = %d, want %d", response.BodySize, len(resp.Body))
	}

	entryReq := *req
	entryResp := *resp
	entryReq.Timestamp = time.Now()
	entryResp.Timestamp = entryReq.Timestamp.Add(50 * time.Millisecond)

	entry := buildHAREntry(&model.Packet{
		Timestamp: time.Now(),
		HTTPInfo: &model.HTTPConversation{
			Request:  &entryReq,
			Response: &entryResp,
		},
	})
	if entry == nil {
		t.Fatal("Expected HAR entry")
	}
	if entry.Time <= 0 {
		t.Errorf("Expected entry time > 0, got %f", entry.Time)
	}

	pairs := headerMapToPairs(map[string][]string{"A": {"1", "2"}})
	if len(pairs) != 2 {
		t.Errorf("Expected 2 header pairs, got %d", len(pairs))
	}

	params := extractQueryParams("https://example.com/search?q=1&x=2")
	if len(params) != 2 {
		t.Errorf("Expected 2 query params, got %d", len(params))
	}
	if params = extractQueryParams("%zz"); params != nil {
		t.Error("Expected nil params for invalid URL")
	}
}

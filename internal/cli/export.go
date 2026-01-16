package cli

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/wiretap/wiretap/internal/capture"
	"github.com/wiretap/wiretap/internal/model"
	"github.com/wiretap/wiretap/internal/protocol"
)

var exportCmd = &cobra.Command{
	Use:   "export <pcap-file>",
	Short: "Export packet data to various formats",
	Long: `Export packet data from a pcap file to JSON, CSV, JSONL, or HAR formats.

Examples:
  # Export to JSON
  wiretap export capture.pcap -o packets.json -f json

  # Export to CSV
  wiretap export capture.pcap -o packets.csv -f csv

	# Export HTTP as HAR
	wiretap export capture.pcap -o http.har -f har

  # Export only HTTP traffic
  wiretap export capture.pcap -o http.json --protocol http

  # Export with packet limit
  wiretap export capture.pcap -o packets.json -c 1000`,
	Args: cobra.ExactArgs(1),
	RunE: runExport,
}

func init() {
	exportCmd.Flags().StringP("output", "o", "", "output file (required)")
	exportCmd.Flags().StringP("format", "f", "json", "output format (json, csv, jsonl, har)")
	exportCmd.Flags().IntP("count", "c", 0, "maximum packets to export (0 = all)")
	exportCmd.Flags().String("filter", "", "BPF filter expression")
	exportCmd.Flags().StringSlice("protocol", nil, "filter by protocol (http, tls, dns)")
	exportCmd.Flags().Bool("dissect", true, "include protocol dissection")
	exportCmd.Flags().Bool("pretty", false, "pretty-print JSON output")

	exportCmd.MarkFlagRequired("output")
}

// ExportPacket represents a packet for export.
type ExportPacket struct {
	Number      int                    `json:"number"`
	Timestamp   string                 `json:"timestamp"`
	TimestampNs int64                  `json:"timestamp_ns"`
	SrcIP       string                 `json:"src_ip"`
	DstIP       string                 `json:"dst_ip"`
	SrcPort     uint16                 `json:"src_port,omitempty"`
	DstPort     uint16                 `json:"dst_port,omitempty"`
	Protocol    string                 `json:"protocol"`
	Length      int                    `json:"length"`
	CapturedLen int                    `json:"captured_len"`
	TCPFlags    string                 `json:"tcp_flags,omitempty"`
	Dissection  map[string]interface{} `json:"dissection,omitempty"`
}

func runExport(cmd *cobra.Command, args []string) error {
	pcapFile := args[0]
	outputFile, _ := cmd.Flags().GetString("output")
	format, _ := cmd.Flags().GetString("format")
	count, _ := cmd.Flags().GetInt("count")
	bpfFilter, _ := cmd.Flags().GetString("filter")
	protocols, _ := cmd.Flags().GetStringSlice("protocol")
	dissect, _ := cmd.Flags().GetBool("dissect")
	pretty, _ := cmd.Flags().GetBool("pretty")

	// Validate format
	format = strings.ToLower(format)
	if format != "json" && format != "csv" && format != "jsonl" && format != "har" {
		return fmt.Errorf("unsupported format: %s (use json, csv, jsonl, or har)", format)
	}
	if format == "har" {
		dissect = true
	}

	// Open pcap file
	reader, err := capture.OpenPcap(pcapFile)
	if err != nil {
		return fmt.Errorf("failed to open pcap file: %w", err)
	}
	defer reader.Close()

	// Note: BPF filter for offline files would require re-implementation
	_ = bpfFilter

	// Create output file
	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	// Create dissector registry
	registry := protocol.NewRegistry()

	// Collect packets
	var packets []ExportPacket
	var harLog *HAR
	packetNum := 0
	exported := 0

	if format == "har" {
		harLog = newHAR()
	}

	iter := capture.NewPacketIterator(reader)
	for {
		pkt, ok := iter.Next()
		if !ok {
			break
		}
		packetNum++

		// Protocol filter
		if len(protocols) > 0 {
			protoMatch := false
			pktProto := strings.ToLower(pkt.Protocol.String())
			for _, p := range protocols {
				if strings.ToLower(p) == pktProto {
					protoMatch = true
					break
				}
			}
			if !protoMatch {
				continue
			}
		}

		exported++

		// Create export packet
		ep := ExportPacket{
			Number:      packetNum,
			Timestamp:   pkt.Timestamp.Format("2006-01-02T15:04:05.000000Z07:00"),
			TimestampNs: pkt.Timestamp.UnixNano(),
			SrcIP:       pkt.SrcIP.String(),
			DstIP:       pkt.DstIP.String(),
			SrcPort:     pkt.SrcPort,
			DstPort:     pkt.DstPort,
			Protocol:    pkt.Protocol.String(),
			Length:      int(pkt.OriginalLen),
			CapturedLen: int(pkt.CapturedLen),
		}

		// Add TCP flags
		if pkt.TCPFlags.ToUint8() != 0 {
			ep.TCPFlags = pkt.TCPFlags.String()
		}

		// Dissect if requested
		if dissect && len(pkt.Payload) > 0 {
			if err := registry.Parse(pkt.Payload, pkt); err == nil {
				ep.Dissection = buildDissectionMap(pkt)
			}
		}

		if format == "har" {
			entry := buildHAREntry(pkt)
			if entry != nil {
				harLog.Log.Entries = append(harLog.Log.Entries, *entry)
				exported++
			}
		} else {
			packets = append(packets, ep)
			exported++
		}

		// Check count limit
		if count > 0 && exported >= count {
			break
		}

		// For JSONL, write immediately
		if format == "jsonl" {
			data, _ := json.Marshal(ep)
			outFile.Write(data)
			outFile.WriteString("\n")
		}
	}

	// Write output based on format
	switch format {
	case "json":
		encoder := json.NewEncoder(outFile)
		if pretty {
			encoder.SetIndent("", "  ")
		}
		if err := encoder.Encode(packets); err != nil {
			return fmt.Errorf("failed to write JSON: %w", err)
		}

	case "csv":
		writer := csv.NewWriter(outFile)
		defer writer.Flush()

		// Write header
		header := []string{"number", "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "length", "tcp_flags"}
		writer.Write(header)

		// Write data
		for _, p := range packets {
			record := []string{
				strconv.Itoa(p.Number),
				p.Timestamp,
				p.SrcIP,
				p.DstIP,
				strconv.Itoa(int(p.SrcPort)),
				strconv.Itoa(int(p.DstPort)),
				p.Protocol,
				strconv.Itoa(p.Length),
				p.TCPFlags,
			}
			writer.Write(record)
		}

	case "jsonl":
		// Already written
	case "har":
		encoder := json.NewEncoder(outFile)
		if pretty {
			encoder.SetIndent("", "  ")
		}
		if err := encoder.Encode(harLog); err != nil {
			return fmt.Errorf("failed to write HAR: %w", err)
		}
	}

	fmt.Printf("Exported %d packets to %s\n", exported, outputFile)
	return nil
}

type HAR struct {
	Log HARLog `json:"log"`
}

type HARLog struct {
	Version string      `json:"version"`
	Creator HARCreator  `json:"creator"`
	Entries []HAREntry  `json:"entries"`
}

type HARCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type HAREntry struct {
	StartedDateTime string     `json:"startedDateTime"`
	Time            float64    `json:"time"`
	Request         HARRequest `json:"request"`
	Response        HARResponse `json:"response"`
	Cache           HARCache   `json:"cache"`
	Timings         HARTimings `json:"timings"`
}

type HARRequest struct {
	Method      string        `json:"method"`
	URL         string        `json:"url"`
	HTTPVersion string        `json:"httpVersion"`
	Headers     []HARNameValue `json:"headers"`
	QueryString []HARNameValue `json:"queryString"`
	Cookies     []HARCookie   `json:"cookies"`
	HeadersSize int64         `json:"headersSize"`
	BodySize    int64         `json:"bodySize"`
}

type HARResponse struct {
	Status      int           `json:"status"`
	StatusText  string        `json:"statusText"`
	HTTPVersion string        `json:"httpVersion"`
	Headers     []HARNameValue `json:"headers"`
	Cookies     []HARCookie   `json:"cookies"`
	Content     HARContent    `json:"content"`
	RedirectURL string        `json:"redirectURL"`
	HeadersSize int64         `json:"headersSize"`
	BodySize    int64         `json:"bodySize"`
}

type HARContent struct {
	Size     int64  `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
	Encoding string `json:"encoding,omitempty"`
}

type HARCookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HARNameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HARCache struct{}

type HARTimings struct {
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
}

func newHAR() *HAR {
	return &HAR{
		Log: HARLog{
			Version: "1.2",
			Creator: HARCreator{Name: "wiretap", Version: "v1"},
			Entries: make([]HAREntry, 0),
		},
	}
}

func buildHAREntry(pkt *model.Packet) *HAREntry {
	if pkt == nil || pkt.HTTPInfo == nil {
		return nil
	}

	request := pkt.HTTPInfo.Request
	response := pkt.HTTPInfo.Response

	startTime := pkt.Timestamp
	if request != nil && !request.Timestamp.IsZero() {
		startTime = request.Timestamp
	} else if response != nil && !response.Timestamp.IsZero() {
		startTime = response.Timestamp
	}

	entry := &HAREntry{
		StartedDateTime: startTime.Format(time.RFC3339Nano),
		Time:            0,
		Cache:           HARCache{},
		Timings:         HARTimings{Send: 0, Wait: 0, Receive: 0},
	}

	if request != nil && response != nil {
		entry.Time = response.Timestamp.Sub(request.Timestamp).Seconds() * 1000
	}

	entry.Request = buildHARRequest(request, pkt)
	entry.Response = buildHARResponse(response)

	return entry
}

func buildHARRequest(req *model.HTTPRequest, pkt *model.Packet) HARRequest {
	if req == nil {
		return HARRequest{HeadersSize: -1, BodySize: -1}
	}

	urlStr := buildRequestURL(req, pkt)
	query := extractQueryParams(urlStr)
	headers := headerMapToPairs(req.Headers)
	bodySize := int64(len(req.Body))
	if bodySize == 0 && req.ContentLength > 0 {
		bodySize = req.ContentLength
	}

	return HARRequest{
		Method:      string(req.Method),
		URL:         urlStr,
		HTTPVersion: req.Version.String(),
		Headers:     headers,
		QueryString: query,
		Cookies:     []HARCookie{},
		HeadersSize: -1,
		BodySize:    bodySize,
	}
}

func buildHARResponse(resp *model.HTTPResponse) HARResponse {
	if resp == nil {
		return HARResponse{Status: 0, StatusText: "", HTTPVersion: "", Headers: []HARNameValue{}, Cookies: []HARCookie{}, Content: HARContent{Size: 0, MimeType: ""}, RedirectURL: "", HeadersSize: -1, BodySize: -1}
	}

	bodySize := int64(len(resp.Body))
	if bodySize == 0 && resp.ContentLength > 0 {
		bodySize = resp.ContentLength
	}

	content := HARContent{
		Size:     bodySize,
		MimeType: resp.ContentType,
	}
	if len(resp.Body) > 0 {
		content.Text = string(resp.Body)
	}

	return HARResponse{
		Status:      resp.StatusCode,
		StatusText:  resp.StatusText,
		HTTPVersion: resp.Version.String(),
		Headers:     headerMapToPairs(resp.Headers),
		Cookies:     []HARCookie{},
		Content:     content,
		RedirectURL: "",
		HeadersSize: -1,
		BodySize:    bodySize,
	}
}

func buildRequestURL(req *model.HTTPRequest, pkt *model.Packet) string {
	if req == nil {
		return ""
	}
	if req.ParsedURL != nil && req.ParsedURL.IsAbs() {
		return req.ParsedURL.String()
	}

	scheme := "http"
	if pkt != nil {
		if pkt.TLSInfo != nil || pkt.DstPort == 443 || pkt.SrcPort == 443 {
			scheme = "https"
		}
	}

	host := req.Host
	if host == "" && pkt != nil && pkt.DstIP != nil {
		host = pkt.DstIP.String()
	}

	path := req.URI
	if path == "" {
		path = req.Path
	}
	if path == "" {
		path = "/"
	}
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	return fmt.Sprintf("%s://%s%s", scheme, host, path)
}

func headerMapToPairs(headers map[string][]string) []HARNameValue {
	result := make([]HARNameValue, 0)
	for name, values := range headers {
		for _, value := range values {
			result = append(result, HARNameValue{Name: name, Value: value})
		}
	}
	return result
}

func extractQueryParams(urlStr string) []HARNameValue {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return nil
	}

	params := make([]HARNameValue, 0)
	for name, values := range parsed.Query() {
		for _, value := range values {
			params = append(params, HARNameValue{Name: name, Value: value})
		}
	}
	return params
}

func buildDissectionMap(pkt *model.Packet) map[string]interface{} {
	result := make(map[string]interface{})

	if pkt.HTTPInfo != nil {
		http := make(map[string]interface{})
		if pkt.HTTPInfo.Request != nil {
			http["is_request"] = true
			http["method"] = pkt.HTTPInfo.Request.Method
			http["uri"] = pkt.HTTPInfo.Request.URI
			http["version"] = pkt.HTTPInfo.Request.Version
			if len(pkt.HTTPInfo.Request.Headers) > 0 {
				http["headers"] = pkt.HTTPInfo.Request.Headers
			}
		}
		if pkt.HTTPInfo.Response != nil {
			http["is_request"] = false
			http["status_code"] = pkt.HTTPInfo.Response.StatusCode
			http["status_text"] = pkt.HTTPInfo.Response.StatusText
			http["version"] = pkt.HTTPInfo.Response.Version
			if len(pkt.HTTPInfo.Response.Headers) > 0 {
				http["headers"] = pkt.HTTPInfo.Response.Headers
			}
		}
		result["http"] = http
	}

	if pkt.TLSInfo != nil {
		tls := make(map[string]interface{})
		tls["version"] = pkt.TLSInfo.Version.String()
		if pkt.TLSInfo.SNI() != "" {
			tls["sni"] = pkt.TLSInfo.SNI()
		}
		result["tls"] = tls
	}

	if pkt.DNSInfo != nil {
		dns := make(map[string]interface{})
		dns["is_response"] = pkt.DNSInfo.IsResponse
		dns["questions"] = pkt.DNSInfo.Questions
		if pkt.DNSInfo.IsResponse {
			dns["answers"] = pkt.DNSInfo.Answers
		}
		result["dns"] = dns
	}

	return result
}

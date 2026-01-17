package cli

import (
	"net"
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

func buildTestPacket(t *testing.T) []byte {
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
		SrcIP:    net.ParseIP("192.168.1.1"),
		DstIP:    net.ParseIP("192.168.1.2"),
	}
	tcp := layers.TCP{SrcPort: 1234, DstPort: 80, SYN: true}
	tcp.SetNetworkLayerForChecksum(&ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp, gopacket.Payload([]byte("GET / HTTP/1.1\r\n\r\n"))); err != nil {
		t.Fatalf("SerializeLayers failed: %v", err)
	}

	return buf.Bytes()
}

func writeTestPcapFile(t *testing.T, path string) {
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

	data := buildTestPacket(t)
	ci := gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(data), Length: len(data)}
	if err := writer.WritePacket(ci, data); err != nil {
		t.Fatalf("WritePacket failed: %v", err)
	}
}

func newReadTestCommand() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("filter", "", "")
	cmd.Flags().Int("count", 0, "")
	cmd.Flags().Int("skip", 0, "")
	cmd.Flags().Bool("dissect", false, "")
	cmd.Flags().Bool("hex", false, "")
	cmd.Flags().Bool("summary", true, "")
	cmd.Flags().StringSlice("protocol", nil, "")
	cmd.Flags().String("src-ip", "", "")
	cmd.Flags().String("dst-ip", "", "")
	cmd.Flags().Int("src-port", 0, "")
	cmd.Flags().Int("dst-port", 0, "")
	cmd.Flags().String("index-dir", "", "")
	cmd.Flags().Bool("decrypt", false, "")
	cmd.Flags().String("keylog", "", "")
	cmd.Flags().String("plugin-dir", "", "")
	cmd.Flags().StringSlice("plugin", nil, "")
	cmd.Flags().StringSlice("proto-dir", nil, "")
	cmd.Flags().StringSlice("proto-file", nil, "")
	return cmd
}

func TestRunRead_Success(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "read.pcap")

	writeTestPcapFile(t, pcapPath)

	cmd := newReadTestCommand()
	cmd.Flags().Set("count", "1")
	cmd.Flags().Set("summary", "false")

	if err := runRead(cmd, []string{pcapPath}); err != nil {
		t.Fatalf("runRead failed: %v", err)
	}
}

func TestRunRead_InvalidIP(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "read.pcap")

	writeTestPcapFile(t, pcapPath)

	cmd := newReadTestCommand()
	cmd.Flags().Set("src-ip", "not-an-ip")

	if err := runRead(cmd, []string{pcapPath}); err == nil {
		t.Fatal("Expected error for invalid IP")
	}
}

func TestRunRead_DissectHex(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "read.pcap")

	writeTestPcapFile(t, pcapPath)

	cmd := newReadTestCommand()
	cmd.Flags().Set("dissect", "true")
	cmd.Flags().Set("hex", "true")
	cmd.Flags().Set("count", "1")

	if err := runRead(cmd, []string{pcapPath}); err != nil {
		t.Fatalf("runRead failed: %v", err)
	}
}

func TestRunRead_BPF(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "read.pcap")

	writeTestPcapFile(t, pcapPath)

	cmd := newReadTestCommand()
	cmd.Flags().Set("filter", "tcp port 80")
	cmd.Flags().Set("count", "1")
	cmd.Flags().Set("summary", "false")

	if err := runRead(cmd, []string{pcapPath}); err != nil {
		t.Fatalf("runRead with BPF failed: %v", err)
	}
}

func TestFormatBasicInfo(t *testing.T) {
	pkt := &model.Packet{Protocol: model.ProtocolTCP, TCPFlags: model.TCPFlags{SYN: true}}
	if info := formatBasicInfo(pkt); info == "" {
		t.Error("Expected basic info for TCP")
	}

	pkt.Protocol = model.ProtocolUDP
	pkt.CapturedLen = 42
	if info := formatBasicInfo(pkt); info == "" {
		t.Error("Expected basic info for UDP")
	}

	pkt.Protocol = model.ProtocolICMP
	if info := formatBasicInfo(pkt); info != "ICMP" {
		t.Errorf("Expected ICMP info, got %s", info)
	}
}

func TestFormatDissectedInfo(t *testing.T) {
	packet := &model.Packet{
		HTTPInfo: &model.HTTPConversation{Request: &model.HTTPRequest{Method: model.HTTPMethodGET, URI: "/"}},
	}
	if info := formatDissectedInfo(packet); info == "" {
		t.Error("Expected HTTP dissected info")
	}

	packet = &model.Packet{
		HTTPInfo: &model.HTTPConversation{Response: &model.HTTPResponse{Version: model.HTTPVersion11, StatusCode: 200, StatusText: "OK"}},
	}
	if info := formatDissectedInfo(packet); info == "" {
		t.Error("Expected HTTP response dissected info")
	}

	packet = &model.Packet{TLSInfo: &model.TLSInfo{Version: model.TLSVersion12}}
	if info := formatDissectedInfo(packet); info == "" {
		t.Error("Expected TLS dissected info")
	}

	packet = &model.Packet{DNSInfo: &model.DNSInfo{IsResponse: true}}
	if info := formatDissectedInfo(packet); info == "" {
		t.Error("Expected DNS response dissected info")
	}

	packet = &model.Packet{DNSInfo: &model.DNSInfo{IsResponse: false}}
	if info := formatDissectedInfo(packet); info == "" {
		t.Error("Expected DNS query dissected info")
	}
}

func TestFormatAddr(t *testing.T) {
	if addr := formatAddr(nil, 0); addr != "?" {
		t.Errorf("Expected ?, got %s", addr)
	}
	if addr := formatAddr(net.ParseIP("192.168.1.1"), 0); addr != "192.168.1.1" {
		t.Errorf("Expected IP only, got %s", addr)
	}
	if addr := formatAddr(net.ParseIP("192.168.1.1"), 443); addr != "192.168.1.1:443" {
		t.Errorf("Expected IP:port, got %s", addr)
	}
}

func TestPrintHexDump(t *testing.T) {
	printHexDump([]byte("hello"))
}

func TestBuildIndex_Default(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "index.pcap")

	writeTestPcapFile(t, pcapPath)

	if err := buildIndex(pcapPath, tmpDir, true, false); err != nil {
		t.Fatalf("buildIndex failed: %v", err)
	}
}

package index

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/wiretap/wiretap/internal/model"
)

func buildTCPPacket(t *testing.T, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) []byte {
	t.Helper()

	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		DstMAC:       net.HardwareAddr{0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
	}
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
	}
	tcp.SetNetworkLayerForChecksum(&ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("SerializeLayers failed: %v", err)
	}

	return buf.Bytes()
}

func writeTestPcap(t *testing.T, path string, packets [][]byte) {
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

	for i, data := range packets {
		ci := gopacket.CaptureInfo{
			Timestamp:     time.Now().Add(time.Duration(i) * time.Millisecond),
			CaptureLength: len(data),
			Length:        len(data),
		}
		if err := writer.WritePacket(ci, data); err != nil {
			t.Fatalf("WritePacket failed: %v", err)
		}
	}
}

func TestBuilder_BuildAndSearch(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "test.pcap")
	indexPath := filepath.Join(tmpDir, "test.idx")

	packets := [][]byte{
		buildTCPPacket(t, "192.168.1.10", "192.168.1.20", 12345, 80, []byte("GET / HTTP/1.1\r\n\r\n")),
		buildTCPPacket(t, "192.168.1.20", "192.168.1.10", 80, 12345, []byte("HTTP/1.1 200 OK\r\n\r\n")),
	}
	writeTestPcap(t, pcapPath, packets)

	builder := NewBuilder(pcapPath, indexPath)
	if err := builder.Build(); err != nil {
		t.Fatalf("Build failed: %v", err)
	}

	idx, err := Open(indexPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer idx.Close()

	if idx.PacketCount() != 2 {
		t.Errorf("PacketCount = %d, want 2", idx.PacketCount())
	}
	if idx.ConnectionCount() != 1 {
		t.Errorf("ConnectionCount = %d, want 1", idx.ConnectionCount())
	}

	conn, err := idx.GetConnection(0)
	if err != nil {
		t.Fatalf("GetConnection failed: %v", err)
	}
	if conn.SrcPort == 0 || conn.DstPort == 0 {
		t.Error("Expected connection ports to be populated")
	}

	results, err := idx.SearchByPort(80)
	if err != nil {
		t.Fatalf("SearchByPort failed: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("Expected results for port 80")
	}

	protoResults, err := idx.SearchByProtocol(model.ProtocolTCP)
	if err != nil {
		t.Fatalf("SearchByProtocol failed: %v", err)
	}
	if len(protoResults) != 2 {
		t.Errorf("SearchByProtocol returned %d results, want 2", len(protoResults))
	}

	start := time.Now().Add(-time.Minute)
	end := time.Now().Add(time.Minute)
	byTime, err := idx.SearchByTime(start, end)
	if err != nil {
		t.Fatalf("SearchByTime failed: %v", err)
	}
	if len(byTime) != 2 {
		t.Errorf("SearchByTime returned %d results, want 2", len(byTime))
	}

	ipResults, err := idx.SearchByIP(net.ParseIP("192.168.1.10"))
	if err != nil {
		t.Fatalf("SearchByIP failed: %v", err)
	}
	if len(ipResults) != 2 {
		t.Errorf("SearchByIP returned %d results, want 2", len(ipResults))
	}

	if err := idx.Verify(pcapPath); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
}

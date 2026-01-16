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
)

func buildIndexTestPacket(t *testing.T) []byte {
	t.Helper()

	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		DstMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP("192.168.0.1"),
		DstIP:    net.ParseIP("192.168.0.2"),
	}
	tcp := layers.TCP{SrcPort: 1234, DstPort: 443, SYN: true}
	tcp.SetNetworkLayerForChecksum(&ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp, gopacket.Payload([]byte("GET / HTTP/1.1\r\n\r\n"))); err != nil {
		t.Fatalf("SerializeLayers failed: %v", err)
	}

	return buf.Bytes()
}

func writeIndexTestPcap(t *testing.T, path string) {
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

	data := buildIndexTestPacket(t)
	ci := gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(data), Length: len(data)}
	if err := writer.WritePacket(ci, data); err != nil {
		t.Fatalf("WritePacket failed: %v", err)
	}
}

func newIndexSearchCommand() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("ip", "", "")
	cmd.Flags().String("start", "", "")
	cmd.Flags().String("end", "", "")
	cmd.Flags().Int("port", 0, "")
	cmd.Flags().Int("limit", 100, "")
	return cmd
}

func TestRunIndexInfoAndSearch(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "test.pcap")
	writeIndexTestPcap(t, pcapPath)

	if err := buildIndex(pcapPath, tmpDir, true, false); err != nil {
		t.Fatalf("buildIndex failed: %v", err)
	}

	indexPath := filepath.Join(tmpDir, "test.idx")

	infoCmd := &cobra.Command{}
	if err := runIndexInfo(infoCmd, []string{indexPath}); err != nil {
		t.Fatalf("runIndexInfo failed: %v", err)
	}

	searchCmd := newIndexSearchCommand()
	searchCmd.Flags().Set("ip", "192.168.0.1")
	if err := runIndexSearch(searchCmd, []string{indexPath}); err != nil {
		t.Fatalf("runIndexSearch failed: %v", err)
	}

	searchCmd = newIndexSearchCommand()
	searchCmd.Flags().Set("port", "443")
	if err := runIndexSearch(searchCmd, []string{indexPath}); err != nil {
		t.Fatalf("runIndexSearch by port failed: %v", err)
	}

	searchCmd = newIndexSearchCommand()
	start := time.Now().Add(-time.Minute).Format("2006-01-02 15:04:05")
	end := time.Now().Add(time.Minute).Format("2006-01-02 15:04:05")
	searchCmd.Flags().Set("start", start)
	searchCmd.Flags().Set("end", end)
	if err := runIndexSearch(searchCmd, []string{indexPath}); err != nil {
		t.Fatalf("runIndexSearch by time failed: %v", err)
	}
}

func TestRunIndexBuild_WithProgress(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "test.pcap")
	writeIndexTestPcap(t, pcapPath)

	cmd := &cobra.Command{}
	cmd.Flags().String("output", "", "")
	cmd.Flags().Bool("force", false, "")
	cmd.Flags().Bool("progress", true, "")

	cmd.Flags().Set("output", tmpDir)
	cmd.Flags().Set("force", "true")
	cmd.Flags().Set("progress", "true")

	if err := runIndexBuild(cmd, []string{pcapPath}); err != nil {
		t.Fatalf("runIndexBuild failed: %v", err)
	}
}

func TestRunIndexSearch_InvalidIP(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "test.pcap")
	writeIndexTestPcap(t, pcapPath)

	if err := buildIndex(pcapPath, tmpDir, true, false); err != nil {
		t.Fatalf("buildIndex failed: %v", err)
	}

	indexPath := filepath.Join(tmpDir, "test.idx")
	searchCmd := newIndexSearchCommand()
	searchCmd.Flags().Set("ip", "invalid-ip")
	if err := runIndexSearch(searchCmd, []string{indexPath}); err == nil {
		t.Fatal("Expected error for invalid IP")
	}
}

func TestRunIndexSearch_InvalidTime(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "test.pcap")
	writeIndexTestPcap(t, pcapPath)

	if err := buildIndex(pcapPath, tmpDir, true, false); err != nil {
		t.Fatalf("buildIndex failed: %v", err)
	}

	indexPath := filepath.Join(tmpDir, "test.idx")
	searchCmd := newIndexSearchCommand()
	searchCmd.Flags().Set("start", "invalid-time")
	if err := runIndexSearch(searchCmd, []string{indexPath}); err == nil {
		t.Fatal("Expected error for invalid start time")
	}
}

func TestRunIndexDefault_NoArgs(t *testing.T) {
	cmd := &cobra.Command{}
	called := false
	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		called = true
	})

	if err := runIndexDefault(cmd, nil); err != nil {
		t.Fatalf("runIndexDefault failed: %v", err)
	}
	if !called {
		t.Fatal("Expected help to be called")
	}
}

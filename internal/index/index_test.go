package index

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wiretap/wiretap/internal/model"
)

func TestIndexHeader_Constants(t *testing.T) {
	if MagicNumber != 0x57545049 {
		t.Errorf("MagicNumber = %x, want 0x57545049", MagicNumber)
	}
	if CurrentVersion != 1 {
		t.Errorf("CurrentVersion = %d, want 1", CurrentVersion)
	}
	if HeaderSize != 64 {
		t.Errorf("HeaderSize = %d, want 64", HeaderSize)
	}
	if PacketEntrySize != 48 {
		t.Errorf("PacketEntrySize = %d, want 48", PacketEntrySize)
	}
	if ConnectionEntrySize != 72 {
		t.Errorf("ConnectionEntrySize = %d, want 72", ConnectionEntrySize)
	}
}

func createTestIndex(t *testing.T) string {
	t.Helper()

	tmpDir := t.TempDir()
	indexPath := filepath.Join(tmpDir, "test.wtidx")

	// Create test data
	header := &IndexHeader{
		Magic:           MagicNumber,
		Version:         CurrentVersion,
		PacketCount:     3,
		ConnectionCount: 1,
		CreatedAt:       time.Now().Unix(),
		PcapFileSize:    1024,
	}

	packets := []*PacketIndexEntry{
		{
			Offset:    0,
			Length:    100,
			Timestamp: time.Now().UnixNano(),
			Protocol:  uint16(model.ProtocolTCP),
			Flags:     0x02, // SYN
			ConnID:    0,
			SrcPort:   12345,
			DstPort:   80,
		},
		{
			Offset:    100,
			Length:    150,
			Timestamp: time.Now().Add(time.Millisecond).UnixNano(),
			Protocol:  uint16(model.ProtocolTCP),
			Flags:     0x12, // SYN-ACK
			ConnID:    0,
			SrcPort:   80,
			DstPort:   12345,
		},
		{
			Offset:    250,
			Length:    200,
			Timestamp: time.Now().Add(2 * time.Millisecond).UnixNano(),
			Protocol:  uint16(model.ProtocolTCP),
			Flags:     0x10, // ACK
			ConnID:    0,
			SrcPort:   12345,
			DstPort:   80,
		},
	}

	srcIP := net.ParseIP("192.168.1.1").To16()
	dstIP := net.ParseIP("192.168.1.2").To16()

	conns := []*ConnectionIndexEntry{
		{
			SrcPort:     12345,
			DstPort:     80,
			Protocol:    uint16(model.ProtocolTCP),
			IsIPv6:      0,
			State:       1, // Established
			FirstPacket: 0,
			LastPacket:  2,
			PacketCount: 3,
			ByteCount:   450,
		},
	}
	copy(conns[0].SrcIP[:], srcIP)
	copy(conns[0].DstIP[:], dstIP)

	// Write index file
	var buf bytes.Buffer
	if err := Write(&buf, header, packets, conns); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	if err := os.WriteFile(indexPath, buf.Bytes(), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	return indexPath
}

func TestIndex_Open(t *testing.T) {
	indexPath := createTestIndex(t)

	idx, err := Open(indexPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer idx.Close()

	if idx.PacketCount() != 3 {
		t.Errorf("PacketCount = %d, want 3", idx.PacketCount())
	}
	if idx.ConnectionCount() != 1 {
		t.Errorf("ConnectionCount = %d, want 1", idx.ConnectionCount())
	}
}

func TestIndex_Open_InvalidMagic(t *testing.T) {
	tmpDir := t.TempDir()
	indexPath := filepath.Join(tmpDir, "invalid.wtidx")

	// Write file with invalid magic
	data := make([]byte, HeaderSize)
	data[0] = 0xFF // Invalid magic
	if err := os.WriteFile(indexPath, data, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	_, err := Open(indexPath)
	if err != ErrInvalidMagic {
		t.Errorf("Expected ErrInvalidMagic, got %v", err)
	}
}

func TestIndex_Open_NonExistent(t *testing.T) {
	_, err := Open("/nonexistent/path/test.wtidx")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestIndex_GetPacket(t *testing.T) {
	indexPath := createTestIndex(t)

	idx, err := Open(indexPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer idx.Close()

	// Get first packet
	entry, err := idx.GetPacket(0)
	if err != nil {
		t.Fatalf("GetPacket(0) failed: %v", err)
	}
	if entry.Length != 100 {
		t.Errorf("entry.Length = %d, want 100", entry.Length)
	}
	if entry.SrcPort != 12345 {
		t.Errorf("entry.SrcPort = %d, want 12345", entry.SrcPort)
	}
	if entry.DstPort != 80 {
		t.Errorf("entry.DstPort = %d, want 80", entry.DstPort)
	}

	// Get last packet
	entry, err = idx.GetPacket(2)
	if err != nil {
		t.Fatalf("GetPacket(2) failed: %v", err)
	}
	if entry.Length != 200 {
		t.Errorf("entry.Length = %d, want 200", entry.Length)
	}
}

func TestIndex_GetPacket_OutOfBounds(t *testing.T) {
	indexPath := createTestIndex(t)

	idx, err := Open(indexPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer idx.Close()

	_, err = idx.GetPacket(100)
	if err != ErrOutOfBounds {
		t.Errorf("Expected ErrOutOfBounds, got %v", err)
	}
}

func TestIndex_GetPacketRange(t *testing.T) {
	indexPath := createTestIndex(t)

	idx, err := Open(indexPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer idx.Close()

	entries, err := idx.GetPacketRange(0, 3)
	if err != nil {
		t.Fatalf("GetPacketRange failed: %v", err)
	}
	if len(entries) != 3 {
		t.Errorf("Got %d entries, want 3", len(entries))
	}

	// Verify order
	if entries[0].Length != 100 {
		t.Error("First entry should have length 100")
	}
	if entries[1].Length != 150 {
		t.Error("Second entry should have length 150")
	}
	if entries[2].Length != 200 {
		t.Error("Third entry should have length 200")
	}
}

func TestIndex_GetConnection(t *testing.T) {
	indexPath := createTestIndex(t)

	idx, err := Open(indexPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer idx.Close()

	conn, err := idx.GetConnection(0)
	if err != nil {
		t.Fatalf("GetConnection(0) failed: %v", err)
	}

	if conn.SrcPort != 12345 {
		t.Errorf("conn.SrcPort = %d, want 12345", conn.SrcPort)
	}
	if conn.DstPort != 80 {
		t.Errorf("conn.DstPort = %d, want 80", conn.DstPort)
	}
	if conn.PacketCount != 3 {
		t.Errorf("conn.PacketCount = %d, want 3", conn.PacketCount)
	}
}

func TestIndex_SearchByPort(t *testing.T) {
	indexPath := createTestIndex(t)

	idx, err := Open(indexPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer idx.Close()

	// Search for port 80
	results, err := idx.SearchByPort(80)
	if err != nil {
		t.Fatalf("SearchByPort failed: %v", err)
	}
	if len(results) != 3 {
		t.Errorf("Got %d results, want 3", len(results))
	}

	// Search for non-existent port
	results, err = idx.SearchByPort(443)
	if err != nil {
		t.Fatalf("SearchByPort failed: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("Got %d results, want 0", len(results))
	}
}

func TestIndex_SearchByProtocol(t *testing.T) {
	indexPath := createTestIndex(t)

	idx, err := Open(indexPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer idx.Close()

	// Search for TCP
	results, err := idx.SearchByProtocol(model.ProtocolTCP)
	if err != nil {
		t.Fatalf("SearchByProtocol failed: %v", err)
	}
	if len(results) != 3 {
		t.Errorf("Got %d results, want 3", len(results))
	}

	// Search for UDP
	results, err = idx.SearchByProtocol(model.ProtocolUDP)
	if err != nil {
		t.Fatalf("SearchByProtocol failed: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("Got %d results, want 0", len(results))
	}
}

func TestIndex_Header(t *testing.T) {
	indexPath := createTestIndex(t)

	idx, err := Open(indexPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer idx.Close()

	header := idx.Header()
	if header == nil {
		t.Fatal("Header returned nil")
	}
	if header.Magic != MagicNumber {
		t.Errorf("header.Magic = %x, want %x", header.Magic, MagicNumber)
	}
	if header.Version != CurrentVersion {
		t.Errorf("header.Version = %d, want %d", header.Version, CurrentVersion)
	}
	if header.PacketCount != 3 {
		t.Errorf("header.PacketCount = %d, want 3", header.PacketCount)
	}
}

func TestIndex_Close(t *testing.T) {
	indexPath := createTestIndex(t)

	idx, err := Open(indexPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if err := idx.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Operations after close should fail
	_, err = idx.GetPacket(0)
	if err != ErrIndexNotOpen {
		t.Errorf("Expected ErrIndexNotOpen after close, got %v", err)
	}
}

func TestWrite_RoundTrip(t *testing.T) {
	header := &IndexHeader{
		Magic:           MagicNumber,
		Version:         CurrentVersion,
		PacketCount:     2,
		ConnectionCount: 1,
		CreatedAt:       time.Now().Unix(),
		PcapFileSize:    512,
	}

	packets := []*PacketIndexEntry{
		{Offset: 0, Length: 100, Timestamp: 1000, Protocol: 6, SrcPort: 1234, DstPort: 80},
		{Offset: 100, Length: 200, Timestamp: 2000, Protocol: 6, SrcPort: 80, DstPort: 1234},
	}

	conns := []*ConnectionIndexEntry{
		{SrcPort: 1234, DstPort: 80, Protocol: 6, PacketCount: 2, ByteCount: 300},
	}

	var buf bytes.Buffer
	if err := Write(&buf, header, packets, conns); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Write to temp file and open
	tmpDir := t.TempDir()
	indexPath := filepath.Join(tmpDir, "roundtrip.wtidx")
	if err := os.WriteFile(indexPath, buf.Bytes(), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	idx, err := Open(indexPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer idx.Close()

	// Verify data
	if idx.PacketCount() != 2 {
		t.Errorf("PacketCount = %d, want 2", idx.PacketCount())
	}

	pkt, _ := idx.GetPacket(0)
	if pkt.Length != 100 {
		t.Errorf("pkt.Length = %d, want 100", pkt.Length)
	}
	if pkt.SrcPort != 1234 {
		t.Errorf("pkt.SrcPort = %d, want 1234", pkt.SrcPort)
	}
}

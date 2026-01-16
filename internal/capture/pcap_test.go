package capture

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/wiretap/wiretap/internal/model"
)

type nopWriteCloser struct {
	*bytes.Buffer
	closed bool
}

func (n *nopWriteCloser) Close() error {
	n.closed = true
	return nil
}

func buildTCPPacket(t *testing.T, payload []byte) []byte {
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
	cp := layers.TCP{
		SrcPort: layers.TCPPort(12345),
		DstPort: layers.TCPPort(80),
		SYN:     true,
		ACK:     true,
	}
	cp.SetNetworkLayerForChecksum(&ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &cp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("SerializeLayers failed: %v", err)
	}

	return buf.Bytes()
}

func buildUDPPacket(t *testing.T, payload []byte) []byte {
	t.Helper()

	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		DstMAC:       net.HardwareAddr{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP("10.0.0.1"),
		DstIP:    net.ParseIP("10.0.0.2"),
	}
	udp := layers.UDP{
		SrcPort: layers.UDPPort(53),
		DstPort: layers.UDPPort(5353),
	}
	udp.SetNetworkLayerForChecksum(&ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp, gopacket.Payload(payload)); err != nil {
		t.Fatalf("SerializeLayers failed: %v", err)
	}

	return buf.Bytes()
}

func buildARPPacket(t *testing.T) []byte {
	t.Helper()

	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		SourceProtAddress: []byte{192, 168, 1, 1},
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte{192, 168, 1, 2},
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		t.Fatalf("SerializeLayers failed: %v", err)
	}

	return buf.Bytes()
}

func buildICMPPacket(t *testing.T) []byte {
	t.Helper()

	eth := layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee},
		DstMAC:       net.HardwareAddr{0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    net.ParseIP("172.16.0.1"),
		DstIP:    net.ParseIP("172.16.0.2"),
	}
	icmp := layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &icmp); err != nil {
		t.Fatalf("SerializeLayers failed: %v", err)
	}

	return buf.Bytes()
}

func writePcap(t *testing.T, path string, packets [][]byte) {
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

func writePcapng(t *testing.T, path string, packets [][]byte) {
	t.Helper()

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer f.Close()

	writer, err := pcapgo.NewNgWriter(f, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatalf("NewNgWriter failed: %v", err)
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

	if err := writer.Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}
}

func TestOpenPcap_ReadAll_Pcap(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "test.pcap")

	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	writePcap(t, pcapPath, [][]byte{buildTCPPacket(t, payload)})

	reader, err := OpenPcap(pcapPath)
	if err != nil {
		t.Fatalf("OpenPcap failed: %v", err)
	}
	defer reader.Close()

	var got *model.Packet
	if err := reader.ReadAll(func(pkt *model.Packet) error {
		got = pkt
		return io.EOF
	}); err != nil && err != io.EOF {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if got == nil {
		t.Fatal("Expected packet, got nil")
	}
	if got.Protocol != model.ProtocolTCP {
		t.Errorf("Protocol = %s, want TCP", got.Protocol)
	}
	if len(got.Payload) == 0 {
		t.Error("Expected payload data")
	}
}

func TestOpenPcap_ReadPacket_Pcapng(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "test.pcapng")

	writePcapng(t, pcapPath, [][]byte{buildUDPPacket(t, []byte("dns"))})

	reader, err := OpenPcap(pcapPath)
	if err != nil {
		t.Fatalf("OpenPcap failed: %v", err)
	}
	defer reader.Close()

	ci, data, err := reader.ReadPacket()
	if err != nil {
		t.Fatalf("ReadPacket failed: %v", err)
	}
	if ci.Length != len(data) {
		t.Errorf("Capture length mismatch: %d vs %d", ci.Length, len(data))
	}
	if reader.LinkType() != layers.LinkTypeEthernet {
		t.Errorf("LinkType = %v, want Ethernet", reader.LinkType())
	}
}

func TestReadAllWithOffset(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "offset.pcap")

	writePcap(t, pcapPath, [][]byte{buildUDPPacket(t, []byte("abc"))})

	reader, err := OpenPcap(pcapPath)
	if err != nil {
		t.Fatalf("OpenPcap failed: %v", err)
	}
	defer reader.Close()

	var offsets []int64
	if err := reader.ReadAllWithOffset(func(pkt *model.Packet, offset int64) error {
		offsets = append(offsets, offset)
		return nil
	}); err != nil {
		t.Fatalf("ReadAllWithOffset failed: %v", err)
	}

	if len(offsets) != 1 || offsets[0] != -1 {
		t.Errorf("Expected offset -1, got %v", offsets)
	}
}

func TestGetFileInfo(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "info.pcap")

	writePcap(t, pcapPath, [][]byte{buildUDPPacket(t, []byte("abc"))})

	info, err := GetFileInfo(pcapPath)
	if err != nil {
		t.Fatalf("GetFileInfo failed: %v", err)
	}
	if info.PacketCount != 1 {
		t.Errorf("PacketCount = %d, want 1", info.PacketCount)
	}
	if info.FileSize == 0 {
		t.Error("Expected non-zero file size")
	}
}

func TestPcapWriter(t *testing.T) {
	buf := &nopWriteCloser{Buffer: &bytes.Buffer{}}
	writer, err := NewPcapWriter(buf, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatalf("NewPcapWriter failed: %v", err)
	}

	data := buildARPPacket(t)
	ci := gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(data), Length: len(data)}
	if err := writer.WritePacket(ci, data); err != nil {
		t.Fatalf("WritePacket failed: %v", err)
	}

	if writer.Count() != 1 {
		t.Errorf("Count = %d, want 1", writer.Count())
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if !buf.closed {
		t.Error("Expected writer to close underlying writer")
	}
}

func TestPacketIterator_Count(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "iter.pcap")

	writePcap(t, pcapPath, [][]byte{buildICMPPacket(t), buildARPPacket(t)})

	reader, err := OpenPcap(pcapPath)
	if err != nil {
		t.Fatalf("OpenPcap failed: %v", err)
	}
	defer reader.Close()

	iter := NewPacketIterator(reader)
	for {
		_, ok := iter.Next()
		if !ok {
			break
		}
	}
	if iter.Count() != 2 {
		t.Errorf("Count = %d, want 2", iter.Count())
	}
}

func TestPacketIterator_Protocols(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "proto.pcap")

	writePcap(t, pcapPath, [][]byte{buildICMPPacket(t), buildARPPacket(t)})

	reader, err := OpenPcap(pcapPath)
	if err != nil {
		t.Fatalf("OpenPcap failed: %v", err)
	}
	defer reader.Close()

	iter := NewPacketIterator(reader)
	packet1, ok := iter.Next()
	if !ok || packet1 == nil {
		t.Fatal("Expected first packet")
	}
	packet2, ok := iter.Next()
	if !ok || packet2 == nil {
		t.Fatal("Expected second packet")
	}

	if packet1.Protocol != model.ProtocolICMP {
		t.Errorf("Packet1 protocol = %s, want ICMP", packet1.Protocol)
	}
	if packet2.Protocol != model.ProtocolARP {
		t.Errorf("Packet2 protocol = %s, want ARP", packet2.Protocol)
	}
}

func TestOpenPcap_DirPath(t *testing.T) {
	tmpDir := t.TempDir()
	_, err := OpenPcap(tmpDir)
	if err == nil {
		t.Fatal("Expected error for directory path")
	}
}

func TestCapture_ProcessPacket(t *testing.T) {
	data := buildTCPPacket(t, []byte("payload"))
	gp := gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Default)

	cap := &Capture{}
	called := false
	cap.SetHandler(func(pkt *model.Packet) {
		called = true
		if pkt.Protocol != model.ProtocolTCP {
			t.Errorf("Protocol = %s, want TCP", pkt.Protocol)
		}
	})

	cap.processPacket(gp)
	if !called {
		t.Fatal("Expected handler to be called")
	}

	stats := cap.Stats()
	if stats.PacketsReceived != 1 {
		t.Errorf("PacketsReceived = %d, want 1", stats.PacketsReceived)
	}
}

func TestCapture_Start_InvalidInterface(t *testing.T) {
	cap := NewCapture(&CaptureOptions{Interface: "invalid0", SnapLen: 65535, Promiscuous: false})
	if err := cap.Start(context.Background()); err == nil {
		t.Fatal("Expected error for invalid interface")
	}
}

func TestCapture_Stop_WithOfflineHandle(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "offline.pcap")
	writePcap(t, pcapPath, [][]byte{buildTCPPacket(t, []byte("payload"))})

	handle, err := pcap.OpenOffline(pcapPath)
	if err != nil {
		t.Fatalf("OpenOffline failed: %v", err)
	}

	cap := &Capture{
		handle:  handle,
		running: true,
		done:    make(chan struct{}),
	}

	ctx, cancel := context.WithCancel(context.Background())
	cap.cancel = cancel
	cap.SetHandler(func(pkt *model.Packet) {})

	go cap.captureLoop(ctx)

	if err := cap.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	if cap.IsRunning() {
		t.Error("Expected capture to stop")
	}
}

func TestCapture_Start_WithOfflineHandle(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "offline.pcap")
	writePcap(t, pcapPath, [][]byte{buildTCPPacket(t, []byte("payload"))})

	cap := NewCapture(&CaptureOptions{
		Interface:   "dummy0",
		SnapLen:     65535,
		Promiscuous: false,
		Timeout:     time.Millisecond,
		BPFFilter:   "tcp",
	})
	cap.openLive = func(device string, snaplen int32, promisc bool, timeout time.Duration) (*pcap.Handle, error) {
		return pcap.OpenOffline(pcapPath)
	}

	got := make(chan struct{}, 1)
	cap.SetHandler(func(pkt *model.Packet) {
		select {
		case got <- struct{}{}:
		default:
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := cap.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	select {
	case <-got:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Timed out waiting for packet")
	}

	if err := cap.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}

func TestFindInterfaceByName_NotFound(t *testing.T) {
	_, err := FindInterfaceByName("nonexistent0")
	if err == nil {
		t.Fatal("Expected error for invalid interface")
	}
}

func TestFindInterfaceByName_Found(t *testing.T) {
	ifaces, err := ListInterfaces()
	if err != nil {
		t.Fatalf("ListInterfaces failed: %v", err)
	}
	if len(ifaces) == 0 {
		t.Skip("No interfaces available")
	}
	if _, err := FindInterfaceByName(ifaces[0].Name); err != nil {
		t.Fatalf("FindInterfaceByName failed: %v", err)
	}
}

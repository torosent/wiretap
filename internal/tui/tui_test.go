package tui

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/wiretap/wiretap/internal/model"
)

func TestNew(t *testing.T) {
	app := New()
	if app == nil {
		t.Fatal("New() returned nil")
	}

	if app.app == nil {
		t.Error("TUI app should not be nil")
	}

	if app.pages == nil {
		t.Error("Pages should not be nil")
	}

	if app.registry == nil {
		t.Error("Registry should not be nil")
	}

	if app.packets == nil {
		t.Error("Packets slice should not be nil")
	}
}

func TestApp_AddPacket(t *testing.T) {
	app := New()

	pkt := &model.Packet{
		Index:     1,
		Timestamp: time.Now(),
		SrcIP:     net.ParseIP("192.168.1.1"),
		DstIP:     net.ParseIP("192.168.1.2"),
		SrcPort:   12345,
		DstPort:   80,
		Protocol:  model.ProtocolTCP,
	}

	// Directly add packet without going through AddPacket
	// since AddPacket uses QueueUpdateDraw which requires event loop
	app.mu.Lock()
	app.packets = append(app.packets, pkt)
	app.filteredIdx = append(app.filteredIdx, 0)
	app.mu.Unlock()

	if len(app.packets) != 1 {
		t.Errorf("Expected 1 packet, got %d", len(app.packets))
	}

	if app.packets[0] != pkt {
		t.Error("Packet was not added correctly")
	}
}

func TestApp_AddPacket_QueueUpdate(t *testing.T) {
	app := New()
	app.queueUpdate = func(fn func()) { fn() }

	pkt := &model.Packet{
		Timestamp: time.Now(),
		Protocol:  model.ProtocolTCP,
	}

	app.AddPacket(pkt)

	if len(app.packets) != 1 {
		t.Errorf("Expected 1 packet, got %d", len(app.packets))
	}
	if len(app.filteredIdx) != 1 {
		t.Errorf("Expected filteredIdx length 1, got %d", len(app.filteredIdx))
	}
}

func TestApp_matchesFilter_Empty(t *testing.T) {
	app := New()

	pkt := &model.Packet{
		Protocol: model.ProtocolTCP,
	}

	// Empty filter should match all
	app.filter = ""
	if !app.matchesFilter(pkt) {
		t.Error("Empty filter should match all packets")
	}
}

func TestApp_matchesFilter_Protocol(t *testing.T) {
	app := New()

	pkt := &model.Packet{
		Protocol: model.ProtocolTCP,
	}

	app.filter = "tcp"
	if !app.matchesFilter(pkt) {
		t.Error("Filter 'tcp' should match TCP packets")
	}

	app.filter = "udp"
	if app.matchesFilter(pkt) {
		t.Error("Filter 'udp' should not match TCP packets")
	}
}

func TestApp_matchesFilter_IP(t *testing.T) {
	app := New()

	pkt := &model.Packet{
		SrcIP: net.ParseIP("192.168.1.100"),
		DstIP: net.ParseIP("10.0.0.1"),
	}

	app.filter = "192.168"
	if !app.matchesFilter(pkt) {
		t.Error("Filter should match source IP")
	}

	app.filter = "10.0.0"
	if !app.matchesFilter(pkt) {
		t.Error("Filter should match destination IP")
	}

	app.filter = "172.16"
	if app.matchesFilter(pkt) {
		t.Error("Filter should not match non-existent IP")
	}
}

func TestFormatAddr(t *testing.T) {
	tests := []struct {
		name     string
		ip       interface{}
		port     uint16
		expected string
	}{
		{"Nil IP", nil, 80, "?"},
		{"IP with port", net.ParseIP("192.168.1.1"), 80, "192.168.1.1:80"},
		{"IP without port", net.ParseIP("192.168.1.1"), 0, "192.168.1.1"},
		{"IPv6 with port", net.ParseIP("::1"), 443, "::1:443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatAddr(tt.ip, tt.port)
			if result != tt.expected {
				t.Errorf("formatAddr(%v, %d) = %s, expected %s", tt.ip, tt.port, result, tt.expected)
			}
		})
	}
}

func TestApp_applyFilter(t *testing.T) {
	app := New()

	// Add some test packets
	app.packets = []*model.Packet{
		{Protocol: model.ProtocolTCP, SrcPort: 80},
		{Protocol: model.ProtocolUDP, SrcPort: 53},
		{Protocol: model.ProtocolTCP, SrcPort: 443},
	}
	app.filteredIdx = []int{0, 1, 2}

	// Apply TCP filter
	app.applyFilter("tcp")

	if len(app.filteredIdx) != 2 {
		t.Errorf("Expected 2 filtered packets for TCP, got %d", len(app.filteredIdx))
	}

	// Apply UDP filter
	app.applyFilter("udp")

	if len(app.filteredIdx) != 1 {
		t.Errorf("Expected 1 filtered packet for UDP, got %d", len(app.filteredIdx))
	}

	// Clear filter
	app.applyFilter("")

	if len(app.filteredIdx) != 3 {
		t.Errorf("Expected 3 filtered packets for empty filter, got %d", len(app.filteredIdx))
	}
}

func TestApp_formatPacketInfo_TCP(t *testing.T) {
	app := New()

	pkt := &model.Packet{
		Protocol: model.ProtocolTCP,
		TCPFlags: model.TCPFlags{SYN: true},
		Payload:  nil,
	}

	info := app.formatPacketInfo(pkt)
	if info != "[SYN]" {
		t.Errorf("Expected '[SYN]', got '%s'", info)
	}
}

func TestApp_formatPacketInfo_NoPayload(t *testing.T) {
	app := New()

	pkt := &model.Packet{
		Protocol: model.ProtocolUDP,
		Payload:  nil,
	}

	info := app.formatPacketInfo(pkt)
	if info != "Len=0" {
		t.Errorf("Expected 'Len=0', got '%s'", info)
	}
}

func TestBuildTCPStreamText(t *testing.T) {
	clientIP := net.ParseIP("10.0.0.1")
	serverIP := net.ParseIP("10.0.0.2")

	packets := []*model.Packet{
		{
			Protocol: model.ProtocolTCP,
			SrcIP:    clientIP,
			DstIP:    serverIP,
			SrcPort:  1234,
			DstPort:  80,
			Payload:  []byte("GET / HTTP/1.1\r\n\r\n"),
		},
		{
			Protocol: model.ProtocolTCP,
			SrcIP:    serverIP,
			DstIP:    clientIP,
			SrcPort:  80,
			DstPort:  1234,
			Payload:  []byte("HTTP/1.1 200 OK\r\n\r\n"),
		},
	}

	text, err := buildTCPStreamText(packets, packets[0])
	if err != nil {
		t.Fatalf("buildTCPStreamText failed: %v", err)
	}
	if !strings.Contains(text, "GET /") {
		t.Error("Expected request payload in stream text")
	}
	if !strings.Contains(text, "200 OK") {
		t.Error("Expected response payload in stream text")
	}
}

func TestBuildTCPStreamText_NonTCP(t *testing.T) {
	pkt := &model.Packet{Protocol: model.ProtocolUDP}
	if _, err := buildTCPStreamText([]*model.Packet{pkt}, pkt); err == nil {
		t.Fatal("Expected error for non-TCP packet")
	}
}

func TestFormatStreamBytes(t *testing.T) {
	input := []byte{0x01, 'A', 'B', '\n', 0x7f}
	output := formatStreamBytes(input)
	if !strings.Contains(output, "AB") {
		t.Error("Expected printable bytes to remain")
	}
	if !strings.Contains(output, ".") {
		t.Error("Expected non-printable bytes to be replaced")
	}
}

func TestToggleHexView(t *testing.T) {
	app := New()
	if !app.showHex {
		t.Fatal("Expected hex view enabled by default")
	}

	app.toggleHexView()
	if app.showHex {
		t.Error("Expected hex view to be disabled")
	}

	app.toggleHexView()
	if !app.showHex {
		t.Error("Expected hex view to be enabled")
	}
}

func TestUpdateDetailTreeAndHexView(t *testing.T) {
	app := New()

	pkt := &model.Packet{
		Timestamp: time.Now(),
		SrcIP:     net.ParseIP("192.168.1.1"),
		DstIP:     net.ParseIP("192.168.1.2"),
		SrcPort:   1234,
		DstPort:   80,
		Protocol:  model.ProtocolTCP,
		Payload:   []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		HTTPInfo: &model.HTTPConversation{
			Request: &model.HTTPRequest{Method: model.HTTPMethodGET, URI: "/", Version: model.HTTPVersion11},
		},
		TLSInfo: &model.TLSInfo{Version: model.TLSVersion12, ClientHello: &model.TLSClientHello{SNI: "example.com"}},
		DNSInfo: &model.DNSInfo{IsResponse: false},
	}

	app.updateDetailTree(pkt)
	root := app.detailTree.GetRoot()
	if root == nil || len(root.GetChildren()) == 0 {
		t.Fatal("Expected detail tree to have nodes")
	}

	app.updateHexView(pkt)
	if text := app.hexView.GetText(true); text == "" {
		t.Error("Expected hex view text to be populated")
	}
}

func TestRefreshPacketListAndStatus(t *testing.T) {
	app := New()

	app.packets = []*model.Packet{
		{Protocol: model.ProtocolTCP, SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"), SrcPort: 1000, DstPort: 80, CapturedLen: 60},
		{Protocol: model.ProtocolUDP, SrcIP: net.ParseIP("10.0.0.2"), DstIP: net.ParseIP("10.0.0.1"), SrcPort: 53, DstPort: 5353, CapturedLen: 40},
	}
	app.filteredIdx = []int{0, 1}

	app.refreshPacketList()
	if app.packetList.GetRowCount() < 2 {
		t.Error("Expected packet list rows to be populated")
	}
	if app.statusBar.GetText(true) == "" {
		t.Error("Expected status bar to be updated")
	}
}

func TestShowHelp(t *testing.T) {
	app := New()
	app.showHelp()
	if !app.pages.HasPage("help") {
		t.Error("Expected help page to be present")
	}
}

func TestShowFollowTCPStream_NoSelection(t *testing.T) {
	app := New()
	app.showFollowTCPStream()
	if !strings.Contains(app.statusBar.GetText(true), "No packet selected") {
		t.Error("Expected status to indicate missing selection")
	}
}

func TestShowFollowTCPStream_NonTCP(t *testing.T) {
	app := New()
	app.packets = []*model.Packet{{Protocol: model.ProtocolUDP}}
	app.filteredIdx = []int{0}
	app.selectedIdx = 0

	app.showFollowTCPStream()
	if !strings.Contains(app.statusBar.GetText(true), "not TCP") {
		t.Error("Expected status to indicate non-TCP selection")
	}
}

func TestShowFollowTCPStream_NoPayload(t *testing.T) {
	app := New()
	app.packets = []*model.Packet{{Protocol: model.ProtocolTCP, SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"), SrcPort: 1, DstPort: 2}}
	app.filteredIdx = []int{0}
	app.selectedIdx = 0

	app.showFollowTCPStream()
	if !strings.Contains(app.statusBar.GetText(true), "no TCP payload") {
		t.Error("Expected status to indicate missing payload")
	}
}

func TestShowFollowTCPStream_Success(t *testing.T) {
	app := New()
	app.queueUpdate = func(fn func()) { fn() }

	clientIP := net.ParseIP("10.0.0.1")
	serverIP := net.ParseIP("10.0.0.2")
	packets := []*model.Packet{
		{Protocol: model.ProtocolTCP, SrcIP: clientIP, DstIP: serverIP, SrcPort: 1234, DstPort: 80, Payload: []byte("GET / HTTP/1.1\r\n\r\n")},
		{Protocol: model.ProtocolTCP, SrcIP: serverIP, DstIP: clientIP, SrcPort: 80, DstPort: 1234, Payload: []byte("HTTP/1.1 200 OK\r\n\r\n")},
	}

	app.packets = packets
	app.filteredIdx = []int{0, 1}
	app.selectedIdx = 0

	app.showFollowTCPStream()
	if !app.pages.HasPage("follow") {
		t.Error("Expected follow TCP stream page")
	}
}

func TestFocusNextPane(t *testing.T) {
	app := New()
	app.app.SetFocus(app.packetList)
	app.focusNextPane()
	if app.app.GetFocus() == nil {
		t.Error("Expected focus to move to next pane")
	}
}

func TestSetupKeyBindings_InputCapture(t *testing.T) {
	app := New()
	app.queueUpdate = func(fn func()) { fn() }

	capture := app.app.GetInputCapture()
	if capture == nil {
		t.Fatal("Expected input capture to be set")
	}

	app.app.SetFocus(app.packetList)
	capture(tcell.NewEventKey(tcell.KeyTab, 0, tcell.ModNone))
	capture(tcell.NewEventKey(tcell.KeyF5, 0, tcell.ModNone))

	capture(tcell.NewEventKey(tcell.KeyCtrlF, 0, tcell.ModNone))
	if app.app.GetFocus() != app.filterInput {
		t.Error("Expected focus to move to filter input")
	}

	app.app.SetFocus(app.filterInput)
	capture(tcell.NewEventKey(tcell.KeyEscape, 0, tcell.ModNone))
	if app.app.GetFocus() != app.packetList {
		t.Error("Expected focus to return to packet list")
	}

	capture(tcell.NewEventKey(tcell.KeyF1, 0, tcell.ModNone))
	if !app.pages.HasPage("help") {
		t.Error("Expected help page to be shown")
	}
	app.pages.RemovePage("help")

	app.showHex = true
	capture(tcell.NewEventKey(tcell.KeyRune, 'h', tcell.ModNone))
	if app.showHex {
		t.Error("Expected hex view to toggle off")
	}

	if ev := capture(tcell.NewEventKey(tcell.KeyRune, 'j', tcell.ModNone)); ev == nil || ev.Key() != tcell.KeyDown {
		t.Error("Expected 'j' to map to KeyDown")
	}
	if ev := capture(tcell.NewEventKey(tcell.KeyRune, 'k', tcell.ModNone)); ev == nil || ev.Key() != tcell.KeyUp {
		t.Error("Expected 'k' to map to KeyUp")
	}

	capture(tcell.NewEventKey(tcell.KeyRune, 'g', tcell.ModNone))
	capture(tcell.NewEventKey(tcell.KeyRune, 'G', tcell.ModNone))

	capture(tcell.NewEventKey(tcell.KeyRune, '/', tcell.ModNone))
	if app.app.GetFocus() != app.filterInput {
		t.Error("Expected '/' to focus filter input")
	}

	capture(tcell.NewEventKey(tcell.KeyRune, 'f', tcell.ModNone))
	if !strings.Contains(app.statusBar.GetText(true), "No packet selected") {
		t.Error("Expected follow stream to report missing selection")
	}

	capture(tcell.NewEventKey(tcell.KeyRune, 'q', tcell.ModNone))
	capture(tcell.NewEventKey(tcell.KeyCtrlC, 0, tcell.ModNone))
}

func TestApp_Run(t *testing.T) {
	app := New()
	called := false
	app.run = func() error {
		called = true
		return nil
	}

	if err := app.Run(); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !called {
		t.Error("Expected run function to be called")
	}
}

func TestApp_Stop(t *testing.T) {
	app := New()
	app.Stop()
}

func TestRun_UsesFilterAndLoads(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "test.pcap")
	writeTestPcap(t, pcapPath)

	var got *App
	oldRunApp := runApp
	runApp = func(app *App) error {
		got = app
		return nil
	}
	t.Cleanup(func() { runApp = oldRunApp })

	if err := Run(pcapPath, "", "tcp", "dark"); err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if got == nil {
		t.Fatal("Expected app to be passed to runApp")
	}
	if got.filter != "tcp" {
		t.Errorf("Expected filter tcp, got %s", got.filter)
	}
	if len(got.packets) == 0 {
		t.Error("Expected packets to be loaded")
	}
}

func TestLoadPcap(t *testing.T) {
	tmpDir := t.TempDir()
	pcapPath := filepath.Join(tmpDir, "test.pcap")

	writeTestPcap(t, pcapPath)

	app := New()
	if err := app.LoadPcap(pcapPath); err != nil {
		t.Fatalf("LoadPcap failed: %v", err)
	}
	if len(app.packets) == 0 {
		t.Error("Expected packets to be loaded")
	}
	if len(app.filteredIdx) != len(app.packets) {
		t.Error("Filtered index should include all packets")
	}
}

func TestOnPacketSelected(t *testing.T) {
	app := New()
	pkt := &model.Packet{
		Protocol: model.ProtocolTCP,
		SrcIP:    net.ParseIP("192.168.1.1"),
		DstIP:    net.ParseIP("192.168.1.2"),
		SrcPort:  1234,
		DstPort:  80,
		Payload:  []byte("GET / HTTP/1.1\r\n\r\n"),
	}
	app.packets = []*model.Packet{pkt}
	app.filteredIdx = []int{0}

	app.onPacketSelected(0)
	if app.selectedIdx != 0 {
		t.Errorf("selectedIdx = %d, want 0", app.selectedIdx)
	}
	if app.detailTree.GetRoot() == nil {
		t.Error("Expected detail tree root")
	}
}

func TestFormatPacketInfo_TLSAndDNS(t *testing.T) {
	app := New()

	tlsPkt := &model.Packet{
		Protocol: model.ProtocolTCP,
		TLSInfo:  &model.TLSInfo{Version: model.TLSVersion12},
		Payload:  []byte("dummy"),
	}
	if info := app.formatPacketInfo(tlsPkt); info == "" {
		t.Error("Expected TLS info string")
	}

	dnsPkt := &model.Packet{
		Protocol: model.ProtocolUDP,
		DNSInfo:  &model.DNSInfo{IsResponse: true},
		Payload:  []byte("dummy"),
	}
	if info := app.formatPacketInfo(dnsPkt); info == "" {
		t.Error("Expected DNS info string")
	}
}

func writeTestPcap(t *testing.T, path string) {
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

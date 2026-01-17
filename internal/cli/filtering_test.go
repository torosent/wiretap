package cli

import (
	"net"
	"testing"

	"github.com/gopacket/gopacket/layers"
	"github.com/wiretap/wiretap/internal/filter"
	"github.com/wiretap/wiretap/internal/model"
	"github.com/wiretap/wiretap/internal/protocol"
)

func TestCompileBPFFilter_Invalid(t *testing.T) {
	_, err := compileBPFFilter(layers.LinkTypeEthernet, "tcp and")
	if err == nil {
		t.Fatal("expected error for invalid BPF expression")
	}
}

func TestCompileBPFFilter_Valid(t *testing.T) {
	bpf, err := compileBPFFilter(layers.LinkTypeEthernet, "tcp")
	if err != nil {
		t.Fatalf("expected valid BPF expression, got %v", err)
	}
	if bpf == nil {
		t.Fatal("expected non-nil BPF")
	}
}

func TestPacketMatchesProtocols_HTTP(t *testing.T) {
	registry := protocol.NewRegistry()
	pkt := &model.Packet{
		Payload: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	}

	if !packetMatchesProtocols(pkt, []string{"http"}, registry) {
		t.Fatal("expected http protocol match")
	}
	if packetMatchesProtocols(pkt, []string{"tls"}, registry) {
		t.Fatal("expected no tls match")
	}
}

func TestPacketMatchesProtocols_Transport(t *testing.T) {
	pkt := &model.Packet{Protocol: model.ProtocolUDP}
	if !packetMatchesProtocols(pkt, []string{"udp"}, nil) {
		t.Fatal("expected udp transport match")
	}
}

func TestPacketMatchesProtocols_AppProtocol(t *testing.T) {
	pkt := &model.Packet{ApplicationProtocol: "WebSocket"}
	if !packetMatchesProtocols(pkt, []string{"websocket"}, nil) {
		t.Fatal("expected websocket match")
	}
	pkt.ApplicationProtocol = "HTTP/2"
	if !packetMatchesProtocols(pkt, []string{"http2"}, nil) {
		t.Fatal("expected http2 match")
	}
	pkt.ApplicationProtocol = "gRPC"
	if !packetMatchesProtocols(pkt, []string{"grpc"}, nil) {
		t.Fatal("expected grpc match")
	}
}

func TestPacketFilter_Match(t *testing.T) {
	pf, err := newPacketFilter(&filter.FilterConfig{
		IncludeDomains: []string{"example.com"},
		IncludeIPs:     []string{"10.0.0.1"},
		ExcludePorts:   []string{"22"},
	})
	if err != nil {
		t.Fatalf("newPacketFilter failed: %v", err)
	}

	pkt := &model.Packet{
		SrcIP:   net.ParseIP("10.0.0.1"),
		DstIP:   net.ParseIP("10.0.0.2"),
		DstPort: 443,
		HTTPInfo: &model.HTTPConversation{
			Request: &model.HTTPRequest{Host: "example.com"},
		},
	}

	if !pf.matches(pkt, extractPacketDomain(pkt)) {
		t.Fatal("expected packet to match include filters")
	}

	pkt.DstPort = 22
	if pf.matches(pkt, extractPacketDomain(pkt)) {
		t.Fatal("expected packet to be excluded by port filter")
	}
}

func TestExtractPacketDomain_TLSAndDNS(t *testing.T) {
	tlsPkt := &model.Packet{TLSInfo: &model.TLSInfo{ClientHello: &model.TLSClientHello{SNI: "tls.example"}}}
	if domain := extractPacketDomain(tlsPkt); domain != "tls.example" {
		t.Fatalf("expected tls.example, got %s", domain)
	}

	dnsPkt := &model.Packet{DNSInfo: &model.DNSInfo{Questions: []*model.DNSQuestion{{Name: "dns.example"}}}}
	if domain := extractPacketDomain(dnsPkt); domain != "dns.example" {
		t.Fatalf("expected dns.example, got %s", domain)
	}
}

func TestPacketFilter_ExcludeIP(t *testing.T) {
	pf, err := newPacketFilter(&filter.FilterConfig{ExcludeIPs: []string{"10.0.0.1"}})
	if err != nil {
		t.Fatalf("newPacketFilter failed: %v", err)
	}

	pkt := &model.Packet{SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2")}
	if pf.matches(pkt, "") {
		t.Fatal("expected packet to be excluded by IP filter")
	}
}

func TestLoadAndRegisterPlugins_MissingDir(t *testing.T) {
	registry := protocol.NewRegistry()
	mgr, err := loadAndRegisterPlugins(registry, "/nonexistent/plugins", nil)
	if err != nil {
		t.Fatalf("expected no error for missing plugin dir: %v", err)
	}
	if mgr != nil {
		t.Fatal("expected nil manager when no plugins are loaded")
	}
}

func TestLoadAndRegisterPlugins_MissingFile(t *testing.T) {
	registry := protocol.NewRegistry()
	_, err := loadAndRegisterPlugins(registry, "", []string{"/nonexistent/plugin.wasm"})
	if err == nil {
		t.Fatal("expected error for missing plugin file")
	}
}

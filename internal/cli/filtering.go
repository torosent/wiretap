package cli

import (
	"strings"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/wiretap/wiretap/internal/model"
	"github.com/wiretap/wiretap/internal/protocol"
)

const defaultSnapLen = 65535

func compileBPFFilter(linkType layers.LinkType, expr string) (*pcap.BPF, error) {
	if expr == "" {
		return nil, nil
	}
	return pcap.NewBPF(linkType, defaultSnapLen, expr)
}

func packetMatchesProtocols(pkt *model.Packet, filters []string, registry *protocol.DissectorRegistry) bool {
	if len(filters) == 0 {
		return true
	}

	// Attempt application-layer detection when possible.
	if registry != nil && pkt != nil && pkt.ApplicationProtocol == "" && len(pkt.Payload) > 0 {
		_ = registry.Parse(pkt.Payload, pkt)
	}

	appProto := strings.ToLower(pkt.ApplicationProtocol)
	transport := strings.ToLower(pkt.Protocol.String())

	for _, raw := range filters {
		f := strings.ToLower(strings.TrimSpace(raw))
		switch f {
		case "http":
			if strings.HasPrefix(appProto, "http/") || appProto == "http" {
				return true
			}
		case "http2", "h2":
			if strings.Contains(appProto, "http/2") {
				return true
			}
		case "tls":
			if strings.HasPrefix(appProto, "tls") {
				return true
			}
		case "dns":
			if strings.HasPrefix(appProto, "dns") {
				return true
			}
		case "grpc":
			if strings.HasPrefix(appProto, "grpc") {
				return true
			}
		case "websocket", "ws":
			if strings.HasPrefix(appProto, "websocket") {
				return true
			}
		default:
			if transport == f {
				return true
			}
		}
	}

	return false
}

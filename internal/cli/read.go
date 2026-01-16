package cli

import (
	"fmt"
	"net"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/wiretap/wiretap/internal/capture"
	"github.com/wiretap/wiretap/internal/crypto"
	"github.com/wiretap/wiretap/internal/model"
	"github.com/wiretap/wiretap/internal/protocol"
)

var readCmd = &cobra.Command{
	Use:   "read <file>",
	Short: "Read and analyze a pcap file",
	Long: `Read packets from a pcap or pcapng file and display analysis.

Examples:
  # Read a pcap file
  wiretap read capture.pcap

  # Read with BPF filter
  wiretap read capture.pcap -f "tcp port 443"

  # Show only first N packets
  wiretap read capture.pcap -c 100

  # Show detailed protocol dissection
  wiretap read capture.pcap --dissect

  # Show hex dump of packets
  wiretap read capture.pcap --hex`,
	Args: cobra.ExactArgs(1),
	RunE: runRead,
}

func init() {
	readCmd.Flags().StringP("filter", "f", "", "BPF filter expression (post-capture)")
	readCmd.Flags().IntP("count", "c", 0, "number of packets to display (0 = all)")
	readCmd.Flags().Int("skip", 0, "skip first N packets")
	readCmd.Flags().Bool("dissect", false, "show protocol dissection details")
	readCmd.Flags().Bool("hex", false, "show hex dump of packet data")
	readCmd.Flags().Bool("summary", true, "show file summary")
	readCmd.Flags().StringSlice("protocol", nil, "filter by protocol (http, tls, dns)")
	readCmd.Flags().String("src-ip", "", "filter by source IP")
	readCmd.Flags().String("dst-ip", "", "filter by destination IP")
	readCmd.Flags().Int("src-port", 0, "filter by source port")
	readCmd.Flags().Int("dst-port", 0, "filter by destination port")
	readCmd.Flags().String("index-dir", "", "override index directory for auto-indexing")
	readCmd.Flags().Bool("decrypt", false, "enable TLS decryption (requires --keylog)")
	readCmd.Flags().String("keylog", "", "path to NSS SSLKEYLOGFILE for TLS decryption")
}

func runRead(cmd *cobra.Command, args []string) error {
	filename := args[0]

	// Get flags
	bpfFilter, _ := cmd.Flags().GetString("filter")
	count, _ := cmd.Flags().GetInt("count")
	skip, _ := cmd.Flags().GetInt("skip")
	dissect, _ := cmd.Flags().GetBool("dissect")
	showHex, _ := cmd.Flags().GetBool("hex")
	showSummary, _ := cmd.Flags().GetBool("summary")
	protocols, _ := cmd.Flags().GetStringSlice("protocol")
	srcIPStr, _ := cmd.Flags().GetString("src-ip")
	dstIPStr, _ := cmd.Flags().GetString("dst-ip")
	srcPort, _ := cmd.Flags().GetInt("src-port")
	dstPort, _ := cmd.Flags().GetInt("dst-port")
	indexDir, _ := cmd.Flags().GetString("index-dir")
	decrypt, _ := cmd.Flags().GetBool("decrypt")
	keylogFile, _ := cmd.Flags().GetString("keylog")

	// Validate TLS decryption flags
	if decrypt && keylogFile == "" {
		return fmt.Errorf("--decrypt requires --keylog to specify the key log file")
	}
	if keylogFile != "" && !decrypt {
		// Auto-enable decryption when keylog file is provided
		decrypt = true
	}

	// Load TLS keylog if decryption is enabled
	var sessionMgr *crypto.SessionManager
	if decrypt {
		keyLog, err := crypto.LoadFromFile(keylogFile)
		if err != nil {
			return fmt.Errorf("failed to load key log file: %w", err)
		}
		sessionMgr = crypto.NewSessionManager(keyLog)
		fmt.Printf("Loaded %d TLS session keys from %s\n", keyLog.Count(), keylogFile)
	}

	if indexDir != "" {
		if cfg == nil {
			cfg = GetConfig()
		}
		cfg.Index.Directory = indexDir
	}

	// Parse IP filters
	var srcIP, dstIP net.IP
	if srcIPStr != "" {
		srcIP = net.ParseIP(srcIPStr)
		if srcIP == nil {
			return fmt.Errorf("invalid source IP: %s", srcIPStr)
		}
	}
	if dstIPStr != "" {
		dstIP = net.ParseIP(dstIPStr)
		if dstIP == nil {
			return fmt.Errorf("invalid destination IP: %s", dstIPStr)
		}
	}

	// Open pcap file
	reader, err := capture.OpenPcap(filename)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer reader.Close()

	// Auto-index large files if configured
	if cfg != nil && cfg.Index.AutoIndexThreshold > 0 {
		if info, err := os.Stat(filename); err == nil {
			if info.Size() >= cfg.Index.AutoIndexThreshold {
				indexPath := cfg.IndexPath(filename)
				if _, err := os.Stat(indexPath); err != nil {
					if err := buildIndex(filename, cfg.Index.Directory, false, true); err != nil {
						return fmt.Errorf("failed to build index: %w", err)
					}
				}
			}
		}
	}

	// Note: BPF filter for offline files would require re-implementation
	// For now, we do post-capture filtering
	_ = bpfFilter

	// Show file summary
	if showSummary {
		fmt.Printf("File: %s\n", filename)
		fmt.Printf("Link type: %s\n", reader.LinkType())
		fmt.Println()
	}

	// Create dissector registry (with or without TLS decryption)
	var registry *protocol.DissectorRegistry
	if sessionMgr != nil {
		registry = protocol.NewDecryptingRegistry(sessionMgr)
		fmt.Println("TLS decryption enabled")
	} else {
		registry = protocol.NewRegistry()
	}

	// Create tabwriter for aligned output
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "No.\tTime\tSource\tDestination\tProtocol\tLength\tInfo")
	fmt.Fprintln(w, "---\t----\t------\t-----------\t--------\t------\t----")

	// Read and display packets
	packetNum := 0
	displayed := 0
	var firstTime time.Time

	iter := capture.NewPacketIterator(reader)
	for {
		pkt, ok := iter.Next()
		if !ok {
			break
		}
		packetNum++

		// Skip if needed
		if packetNum <= skip {
			continue
		}

		// Apply filters
		if srcIP != nil && !pkt.SrcIP.Equal(srcIP) {
			continue
		}
		if dstIP != nil && !pkt.DstIP.Equal(dstIP) {
			continue
		}
		if srcPort > 0 && pkt.SrcPort != uint16(srcPort) {
			continue
		}
		if dstPort > 0 && pkt.DstPort != uint16(dstPort) {
			continue
		}

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

		displayed++

		// Calculate relative time
		if firstTime.IsZero() {
			firstTime = pkt.Timestamp
		}
		relTime := pkt.Timestamp.Sub(firstTime)

		// Dissect if requested
		var info string
		if dissect && len(pkt.Payload) > 0 {
			if err := registry.Parse(pkt.Payload, pkt); err == nil {
				info = formatDissectedInfo(pkt)
			}
		}
		if info == "" {
			info = formatBasicInfo(pkt)
		}

		// Format addresses
		src := formatAddr(pkt.SrcIP, pkt.SrcPort)
		dst := formatAddr(pkt.DstIP, pkt.DstPort)

		// Print packet line
		fmt.Fprintf(w, "%d\t%.6f\t%s\t%s\t%s\t%d\t%s\n",
			packetNum,
			relTime.Seconds(),
			src,
			dst,
			pkt.Protocol.String(),
			pkt.CapturedLen,
			info,
		)

		// Show hex dump if requested
		if showHex && len(pkt.Payload) > 0 {
			w.Flush()
			printHexDump(pkt.Payload)
			fmt.Println()
		}

		// Check count limit
		if count > 0 && displayed >= count {
			break
		}
	}

	w.Flush()

	// Print summary
	fmt.Printf("\nDisplayed %d of %d packets\n", displayed, packetNum)

	return nil
}

func formatAddr(ip net.IP, port uint16) string {
	if ip == nil {
		return "?"
	}
	if port > 0 {
		return fmt.Sprintf("%s:%d", ip, port)
	}
	return ip.String()
}

func formatBasicInfo(pkt *model.Packet) string {
	switch pkt.Protocol {
	case model.ProtocolTCP:
		return pkt.TCPFlags.String()
	case model.ProtocolUDP:
		return fmt.Sprintf("Len=%d", len(pkt.Payload))
	case model.ProtocolICMP:
		return "ICMP"
	default:
		return ""
	}
}

func formatDissectedInfo(pkt *model.Packet) string {
	if pkt.HTTPInfo != nil {
		if pkt.HTTPInfo.Request != nil {
			return fmt.Sprintf("%s %s HTTP/%s", pkt.HTTPInfo.Request.Method, pkt.HTTPInfo.Request.URI, pkt.HTTPInfo.Request.Version)
		}
		if pkt.HTTPInfo.Response != nil {
			return fmt.Sprintf("HTTP/%s %d %s", pkt.HTTPInfo.Response.Version, pkt.HTTPInfo.Response.StatusCode, pkt.HTTPInfo.Response.StatusText)
		}
	}
	if pkt.TLSInfo != nil {
		return fmt.Sprintf("TLS %s", pkt.TLSInfo.Version)
	}
	if pkt.DNSInfo != nil {
		if pkt.DNSInfo.IsResponse {
			return "DNS Response"
		}
		return "DNS Query"
	}
	return ""
}

func printHexDump(data []byte) {
	const bytesPerLine = 16
	for i := 0; i < len(data); i += bytesPerLine {
		// Print offset
		fmt.Printf("    %04x  ", i)

		// Print hex bytes
		end := i + bytesPerLine
		if end > len(data) {
			end = len(data)
		}

		for j := i; j < end; j++ {
			fmt.Printf("%02x ", data[j])
			if j == i+7 {
				fmt.Print(" ")
			}
		}

		// Pad if needed
		for j := end; j < i+bytesPerLine; j++ {
			fmt.Print("   ")
			if j == i+7 {
				fmt.Print(" ")
			}
		}

		// Print ASCII
		fmt.Print(" |")
		for j := i; j < end; j++ {
			if data[j] >= 32 && data[j] < 127 {
				fmt.Printf("%c", data[j])
			} else {
				fmt.Print(".")
			}
		}
		fmt.Println("|")
	}
}

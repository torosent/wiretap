package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/spf13/cobra"

	"github.com/wiretap/wiretap/internal/capture"
	"github.com/wiretap/wiretap/internal/filter"
	"github.com/wiretap/wiretap/internal/model"
	"github.com/wiretap/wiretap/internal/protocol"
)

type liveCapture interface {
	SetHandler(capture.LivePacketHandler)
	Start(ctx context.Context) error
	Stop() error
	Stats() capture.CaptureStats
}

var newLiveCapture = func(opts *capture.CaptureOptions) liveCapture {
	return capture.NewCapture(opts)
}

var captureCmd = &cobra.Command{
	Use:   "capture",
	Short: "Capture network packets",
	Long: `Capture network packets from an interface or read from a file.

Examples:
  # Capture from default interface
  wiretap capture

  # Capture from specific interface
  wiretap capture -i eth0

  # Capture with BPF filter
  wiretap capture -i eth0 -f "tcp port 80"

  # Capture and save to file
  wiretap capture -i eth0 -w capture.pcap

  # Capture with packet limit
  wiretap capture -i eth0 -c 1000`,
	RunE: runCapture,
}

func init() {
	captureCmd.Flags().StringP("interface", "i", "", "network interface to capture from")
	captureCmd.Flags().StringP("filter", "f", "", "BPF filter expression")
	captureCmd.Flags().StringP("write", "w", "", "write packets to file (pcap format)")
	captureCmd.Flags().IntP("count", "c", 0, "number of packets to capture (0 = unlimited)")
	captureCmd.Flags().IntP("snaplen", "s", 65535, "snapshot length (bytes per packet)")
	captureCmd.Flags().DurationP("timeout", "t", 0, "capture duration (0 = unlimited)")
	captureCmd.Flags().Bool("promisc", true, "enable promiscuous mode")
	captureCmd.Flags().Bool("stats", false, "show capture statistics on exit")
	captureCmd.Flags().Bool("decrypt", false, "enable TLS decryption (requires --keylog)")
	captureCmd.Flags().String("keylog", "", "path to NSS SSLKEYLOGFILE for TLS decryption")
	captureCmd.Flags().StringSlice("proto-dir", nil, "directories containing .pb descriptor sets for gRPC decoding")
	captureCmd.Flags().StringSlice("proto-file", nil, "individual .pb descriptor sets for gRPC decoding")
	captureCmd.Flags().StringSlice("include-domain", nil, "include domains (wildcards or /regex/)")
	captureCmd.Flags().StringSlice("exclude-domain", nil, "exclude domains (wildcards or /regex/)")
	captureCmd.Flags().StringSlice("include-ip", nil, "include IPs or CIDRs")
	captureCmd.Flags().StringSlice("exclude-ip", nil, "exclude IPs or CIDRs")
	captureCmd.Flags().StringSlice("include-port", nil, "include ports or ranges (e.g., 80,443,8000-8080)")
	captureCmd.Flags().StringSlice("exclude-port", nil, "exclude ports or ranges (e.g., 22,3306)")
}

func runCapture(cmd *cobra.Command, args []string) error {
	iface, _ := cmd.Flags().GetString("interface")
	bpfFilter, _ := cmd.Flags().GetString("filter")
	outputFile, _ := cmd.Flags().GetString("write")
	count, _ := cmd.Flags().GetInt("count")
	snaplen, _ := cmd.Flags().GetInt("snaplen")
	timeout, _ := cmd.Flags().GetDuration("timeout")
	promisc, _ := cmd.Flags().GetBool("promisc")
	showStats, _ := cmd.Flags().GetBool("stats")
	decrypt, _ := cmd.Flags().GetBool("decrypt")
	keylogFile, _ := cmd.Flags().GetString("keylog")
	protoDirs, _ := cmd.Flags().GetStringSlice("proto-dir")
	protoFiles, _ := cmd.Flags().GetStringSlice("proto-file")
	includeDomains, _ := cmd.Flags().GetStringSlice("include-domain")
	excludeDomains, _ := cmd.Flags().GetStringSlice("exclude-domain")
	includeIPs, _ := cmd.Flags().GetStringSlice("include-ip")
	excludeIPs, _ := cmd.Flags().GetStringSlice("exclude-ip")
	includePorts, _ := cmd.Flags().GetStringSlice("include-port")
	excludePorts, _ := cmd.Flags().GetStringSlice("exclude-port")

	// Apply config defaults when flags are not set
	cfg := GetConfig()
	if iface == "" && !cmd.Flags().Changed("interface") && cfg.Capture.Interface != "" {
		iface = cfg.Capture.Interface
	}
	if !cmd.Flags().Changed("snaplen") {
		snaplen = cfg.Capture.Snaplen
	}
	if !cmd.Flags().Changed("promisc") {
		promisc = cfg.Capture.Promiscuous
	}

	pcapTimeout := cfg.Capture.Timeout
	if pcapTimeout <= 0 {
		pcapTimeout = time.Second
	}

	if !cmd.Flags().Changed("include-domain") {
		includeDomains = cfg.Filter.IncludeDomains
	}
	if !cmd.Flags().Changed("exclude-domain") {
		excludeDomains = cfg.Filter.ExcludeDomains
	}
	if !cmd.Flags().Changed("include-ip") {
		includeIPs = cfg.Filter.IncludeIPs
	}
	if !cmd.Flags().Changed("exclude-ip") {
		excludeIPs = cfg.Filter.ExcludeIPs
	}
	if !cmd.Flags().Changed("include-port") {
		includePorts = cfg.Filter.IncludePorts
	}
	if !cmd.Flags().Changed("exclude-port") {
		excludePorts = cfg.Filter.ExcludePorts
	}

	// Validate TLS decryption flags
	if decrypt && keylogFile == "" {
		return fmt.Errorf("--decrypt requires --keylog to specify the key log file")
	}
	if keylogFile != "" && !decrypt {
		// Auto-enable decryption when keylog file is provided
		decrypt = true
	}

	// Allow interface to be passed as positional argument
	if iface == "" && len(args) > 0 {
		iface = args[0]
	}

	// If no interface specified, try to find one
	if iface == "" {
		interfaces, err := capture.ListInterfaces()
		if err != nil {
			return fmt.Errorf("failed to list interfaces: %w", err)
		}
		if len(interfaces) == 0 {
			return fmt.Errorf("no network interfaces found")
		}
		// Pick the first non-loopback interface
		for _, i := range interfaces {
			if i.Name != "lo" && i.Name != "lo0" {
				iface = i.Name
				break
			}
		}
		if iface == "" {
			iface = interfaces[0].Name
		}
	}

	// Create capture options
	opts := &capture.CaptureOptions{
		Interface:      iface,
		SnapLen:        int32(snaplen),
		Promiscuous:    promisc,
		Timeout:        pcapTimeout, // pcap read timeout
		BPFFilter:      bpfFilter,
		TLSDecrypt:     decrypt,
		TLSKeyLogFile:  keylogFile,
		GRPCProtoDirs:  protoDirs,
		GRPCProtoFiles: protoFiles,
	}

	// Build include/exclude filters
	packetFilter, err := newPacketFilter(&filter.FilterConfig{
		IncludeDomains: includeDomains,
		ExcludeDomains: excludeDomains,
		IncludeIPs:     includeIPs,
		ExcludeIPs:     excludeIPs,
		IncludePorts:   includePorts,
		ExcludePorts:   excludePorts,
	})
	if err != nil {
		return fmt.Errorf("invalid filters: %w", err)
	}

	var registry *protocol.DissectorRegistry
	if packetFilter != nil && packetFilter.needsDomain() {
		registry = protocol.NewRegistry()
	}

	// Create capture instance
	cap := newLiveCapture(opts)

	// Set up output file if specified
	var writer *capture.PcapWriter
	if outputFile != "" {
		file, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer file.Close()

		linkType, err := capture.LinkTypeForInterface(opts.Interface, opts.SnapLen, opts.Promiscuous, opts.Timeout)
		if err != nil {
			return fmt.Errorf("failed to determine link type: %w", err)
		}

		writer, err = capture.NewPcapWriter(file, linkType)
		if err != nil {
			return fmt.Errorf("failed to create pcap writer: %w", err)
		}
		defer writer.Close()
	}

	// Set up signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Set up timeout if specified
	if timeout > 0 {
		var timeoutCancel context.CancelFunc
		ctx, timeoutCancel = context.WithTimeout(ctx, timeout)
		defer timeoutCancel()
	}

	// Packet counter
	packetCount := 0
	startTime := time.Now()

	// Print capture info
	fmt.Printf("Capturing on interface %s\n", iface)
	if bpfFilter != "" {
		fmt.Printf("Filter: %s\n", bpfFilter)
	}
	if outputFile != "" {
		fmt.Printf("Writing to: %s\n", outputFile)
	}
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println()

	// Set packet handler
	cap.SetHandler(func(pkt *model.Packet) {
		if packetFilter != nil {
			if packetFilter.needsDomain() && registry != nil && len(pkt.Payload) > 0 {
				_ = registry.Parse(pkt.Payload, pkt)
			}
			domain := extractPacketDomain(pkt)
			if !packetFilter.matches(pkt, domain) {
				return
			}
		}

		packetCount++

		// Write to file if output is specified
		if writer != nil {
			ci := gopacket.CaptureInfo{
				Timestamp:     pkt.Timestamp,
				CaptureLength: int(pkt.CaptureLen),
				Length:        int(pkt.Length),
			}
			if err := writer.WritePacket(ci, pkt.Data); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing packet: %v\n", err)
			}
		}

		// Print packet summary
		verbose, _ := cmd.Flags().GetBool("verbose")
		if verbose {
			fmt.Printf("%d\t%s\t%d bytes\n", packetCount, pkt.Timestamp.Format("15:04:05.000000"), len(pkt.Data))
		} else if packetCount%100 == 0 {
			fmt.Printf("\rCaptured %d packets...", packetCount)
		}

		// Check if we've reached the packet limit
		if count > 0 && packetCount >= count {
			cancel()
		}
	})

	// Start capture
	errChan := make(chan error, 1)
	go func() {
		if err := cap.Start(ctx); err != nil {
			errChan <- err
		}
		// Block until context is cancelled - don't send nil
		<-ctx.Done()
	}()

	// Wait for completion
	select {
	case <-sigChan:
		fmt.Println("\nStopping capture...")
		cancel()
	case err := <-errChan:
		if err != nil && err != context.Canceled {
			return fmt.Errorf("capture error: %w", err)
		}
	case <-ctx.Done():
		// Timeout or packet limit reached
	}

	// Wait for capture to finish
	cap.Stop()

	// Print statistics
	duration := time.Since(startTime)
	fmt.Printf("\n\nCapture complete:\n")
	fmt.Printf("  Packets: %d\n", packetCount)
	fmt.Printf("  Duration: %s\n", duration.Round(time.Millisecond))
	if packetCount > 0 && duration > 0 {
		pps := float64(packetCount) / duration.Seconds()
		fmt.Printf("  Rate: %.2f packets/sec\n", pps)
	}

	if showStats {
		stats := cap.Stats()
		fmt.Printf("  Received: %d\n", stats.PacketsReceived)
		fmt.Printf("  Dropped: %d\n", stats.PacketsDropped)
		fmt.Printf("  Interface drops: %d\n", stats.PacketsIfDropped)
	}

	return nil
}

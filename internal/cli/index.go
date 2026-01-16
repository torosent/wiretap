package cli

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/wiretap/wiretap/internal/index"
)

var indexCmd = &cobra.Command{
	Use:   "index [pcap-file]",
	Short: "Manage packet index files",
	Long: `Create and manage packet index files for fast searching.

Index files enable quick packet lookup by time, IP address, or connection
without loading entire pcap files into memory.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runIndexDefault,
}

var indexBuildCmd = &cobra.Command{
	Use:   "build <pcap-file>",
	Short: "Build an index for a pcap file",
	Long: `Build an index file for the specified pcap file.

The index file will be created in the configured index directory
or alongside the pcap file with a .idx extension.

Examples:
  # Build index (default location)
  wiretap index build capture.pcap

  # Build index in specific directory
  wiretap index build capture.pcap --output /path/to/indices/

  # Force rebuild existing index
  wiretap index build capture.pcap --force`,
	Args: cobra.ExactArgs(1),
	RunE: runIndexBuild,
}

var indexInfoCmd = &cobra.Command{
	Use:   "info <index-file>",
	Short: "Show index file information",
	Long: `Display information about an index file.

Examples:
  wiretap index info capture.idx`,
	Args: cobra.ExactArgs(1),
	RunE: runIndexInfo,
}

var indexSearchCmd = &cobra.Command{
	Use:   "search <index-file>",
	Short: "Search an index file",
	Long: `Search an index file for packets matching criteria.

Examples:
  # Search by IP
  wiretap index search capture.idx --ip 192.168.1.1

  # Search by time range
  wiretap index search capture.idx --start "2024-01-01 10:00:00" --end "2024-01-01 11:00:00"

  # Search by port
  wiretap index search capture.idx --port 443`,
	Args: cobra.ExactArgs(1),
	RunE: runIndexSearch,
}

func init() {
	indexCmd.AddCommand(indexBuildCmd)
	indexCmd.AddCommand(indexInfoCmd)
	indexCmd.AddCommand(indexSearchCmd)

	// Build flags
	indexBuildCmd.Flags().StringP("output", "o", "", "output directory for index file")
	indexBuildCmd.Flags().BoolP("force", "f", false, "force rebuild existing index")
	indexBuildCmd.Flags().Bool("progress", true, "show build progress")

	// Search flags
	indexSearchCmd.Flags().String("ip", "", "search by IP address")
	indexSearchCmd.Flags().String("start", "", "start time (format: 2006-01-02 15:04:05)")
	indexSearchCmd.Flags().String("end", "", "end time (format: 2006-01-02 15:04:05)")
	indexSearchCmd.Flags().Int("port", 0, "search by port number")
	indexSearchCmd.Flags().IntP("limit", "n", 100, "maximum number of results")
}

func runIndexBuild(cmd *cobra.Command, args []string) error {
	pcapFile := args[0]
	outputDir, _ := cmd.Flags().GetString("output")
	force, _ := cmd.Flags().GetBool("force")
	showProgress, _ := cmd.Flags().GetBool("progress")

	return buildIndex(pcapFile, outputDir, force, showProgress)
}

func runIndexDefault(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return cmd.Help()
	}

	return buildIndex(args[0], "", false, true)
}

func buildIndex(pcapFile, outputDir string, force, showProgress bool) error {
	// Determine index file path
	var indexPath string
	if outputDir != "" {
		base := filepath.Base(pcapFile)
		ext := filepath.Ext(base)
		name := base[:len(base)-len(ext)]
		indexPath = filepath.Join(outputDir, name+".idx")
	} else if cfg != nil && cfg.Index.Directory != "" {
		base := filepath.Base(pcapFile)
		ext := filepath.Ext(base)
		name := base[:len(base)-len(ext)]
		indexPath = filepath.Join(cfg.Index.Directory, name+".idx")
	} else {
		ext := filepath.Ext(pcapFile)
		indexPath = pcapFile[:len(pcapFile)-len(ext)] + ".idx"
	}

	// Check if index already exists
	if !force {
		if _, err := os.Stat(indexPath); err == nil {
			return fmt.Errorf("index file already exists: %s (use --force to rebuild)", indexPath)
		}
	}

	// Ensure output directory exists
	dir := filepath.Dir(indexPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	fmt.Printf("Building index for: %s\n", pcapFile)
	fmt.Printf("Output: %s\n", indexPath)

	// Build with progress if requested
	startTime := time.Now()

	if showProgress {
		progress := make(chan index.BuildProgress)
		go index.BuildAsync(pcapFile, indexPath, progress)

		for p := range progress {
			if p.Error != nil {
				return fmt.Errorf("build failed: %w", p.Error)
			}
			if p.Finished {
				fmt.Printf("\rProgress: 100%% - %d packets indexed\n", p.PacketsProcessed)
				break
			}
			fmt.Printf("\rProcessing... %d packets, %d connections", p.PacketsProcessed, p.ConnectionsFound)
		}
	} else {
		builder := index.NewBuilder(pcapFile, indexPath)
		if err := builder.Build(); err != nil {
			return fmt.Errorf("build failed: %w", err)
		}
	}

	duration := time.Since(startTime)
	fmt.Printf("Build complete in %s\n", duration.Round(time.Millisecond))

	return nil
}

func runIndexInfo(cmd *cobra.Command, args []string) error {
	indexPath := args[0]

	idx, err := index.Open(indexPath)
	if err != nil {
		return fmt.Errorf("failed to open index: %w", err)
	}
	defer idx.Close()

	header := idx.Header()

	fmt.Printf("Index file: %s\n", indexPath)
	fmt.Printf("Version: %d\n", header.Version)
	fmt.Printf("Packets: %d\n", header.PacketCount)
	fmt.Printf("Connections: %d\n", header.ConnectionCount)
	fmt.Printf("Created: %s\n", time.Unix(header.CreatedAt, 0).Format("2006-01-02 15:04:05"))
	fmt.Printf("Original file size: %d bytes\n", header.PcapFileSize)

	return nil
}

func runIndexSearch(cmd *cobra.Command, args []string) error {
	indexPath := args[0]
	ipStr, _ := cmd.Flags().GetString("ip")
	startStr, _ := cmd.Flags().GetString("start")
	endStr, _ := cmd.Flags().GetString("end")
	port, _ := cmd.Flags().GetInt("port")
	limit, _ := cmd.Flags().GetInt("limit")

	idx, err := index.Open(indexPath)
	if err != nil {
		return fmt.Errorf("failed to open index: %w", err)
	}
	defer idx.Close()

	var results []*index.PacketIndexEntry

	// Search by IP
	if ipStr != "" {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return fmt.Errorf("invalid IP address: %s", ipStr)
		}
		results, err = idx.SearchByIP(ip)
		if err != nil {
			return fmt.Errorf("search failed: %w", err)
		}
	}

	// Search by time range
	if startStr != "" || endStr != "" {
		var start, end time.Time

		if startStr != "" {
			start, err = time.Parse("2006-01-02 15:04:05", startStr)
			if err != nil {
				return fmt.Errorf("invalid start time: %w", err)
			}
		} else {
			start = time.Time{} // Zero time
		}

		if endStr != "" {
			end, err = time.Parse("2006-01-02 15:04:05", endStr)
			if err != nil {
				return fmt.Errorf("invalid end time: %w", err)
			}
		} else {
			end = time.Now() // Current time as default end
		}

		results, err = idx.SearchByTime(start, end)
		if err != nil {
			return fmt.Errorf("search failed: %w", err)
		}
	}

	// Search by port only
	if port > 0 && ipStr == "" && startStr == "" && endStr == "" {
		results, err = idx.SearchByPort(uint16(port))
		if err != nil {
			return fmt.Errorf("search failed: %w", err)
		}
	} else if port > 0 && len(results) > 0 {
		// Filter existing results by port
		filtered := make([]*index.PacketIndexEntry, 0)
		for _, r := range results {
			if r.SrcPort == uint16(port) || r.DstPort == uint16(port) {
				filtered = append(filtered, r)
			}
		}
		results = filtered
	}

	// Apply limit
	if limit > 0 && len(results) > limit {
		results = results[:limit]
	}

	// Display results
	if len(results) == 0 {
		fmt.Println("No matching packets found")
		return nil
	}

	fmt.Printf("Found %d packets:\n\n", len(results))
	fmt.Printf("%-10s %-20s %-8s %-8s %-6s %s\n", "Offset", "Time", "SrcPort", "DstPort", "Proto", "Len")
	fmt.Printf("%-10s %-20s %-8s %-8s %-6s %s\n", "------", "----", "-------", "-------", "-----", "---")

	for _, r := range results {
		ts := time.Unix(0, r.Timestamp)

		fmt.Printf("%-10d %-20s %-8d %-8d %-6d %d\n",
			r.Offset,
			ts.Format("15:04:05.000000"),
			r.SrcPort,
			r.DstPort,
			r.Protocol,
			r.Length,
		)
	}

	return nil
}

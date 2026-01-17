package cli

import (
	"github.com/spf13/cobra"
	"github.com/wiretap/wiretap/internal/protocol"
	"github.com/wiretap/wiretap/internal/tui"
)

var runTUIFn = tui.Run

var tuiCmd = &cobra.Command{
	Use:   "tui [pcap-file]",
	Short: "Launch the terminal user interface",
	Long: `Launch the interactive terminal UI for packet analysis.

The TUI provides a Wireshark-like interface with:
  - Packet list with filtering and sorting
  - Protocol detail tree view
  - Hex dump display
  - Connection tracking

Examples:
  # Launch TUI
  wiretap tui

  # Open a pcap file in TUI
  wiretap tui capture.pcap

  # Open with initial filter
  wiretap tui capture.pcap -f "tcp port 443"`,
	Args: cobra.MaximumNArgs(1),
	RunE: runTUI,
}

func init() {
	tuiCmd.Flags().StringP("filter", "f", "", "initial display filter")
	tuiCmd.Flags().StringP("interface", "i", "", "start capturing from interface")
	tuiCmd.Flags().String("theme", "default", "color theme (default, dark, light)")
	tuiCmd.Flags().String("plugin-dir", "", "directory containing WASM plugins")
	tuiCmd.Flags().StringSlice("plugin", nil, "WASM plugin file(s) to load")
	tuiCmd.Flags().StringSlice("proto-dir", nil, "directories containing .pb descriptor sets for gRPC decoding")
	tuiCmd.Flags().StringSlice("proto-file", nil, "individual .pb descriptor sets for gRPC decoding")
}

func runTUI(cmd *cobra.Command, args []string) error {
	filter, _ := cmd.Flags().GetString("filter")
	iface, _ := cmd.Flags().GetString("interface")
	theme, _ := cmd.Flags().GetString("theme")
	pluginDir, _ := cmd.Flags().GetString("plugin-dir")
	pluginFiles, _ := cmd.Flags().GetStringSlice("plugin")
	protoDirs, _ := cmd.Flags().GetStringSlice("proto-dir")
	protoFiles, _ := cmd.Flags().GetStringSlice("proto-file")

	cfg := GetConfig()
	if !cmd.Flags().Changed("plugin-dir") {
		pluginDir = cfg.Plugins.Directory
	}
	if !cmd.Flags().Changed("plugin") {
		pluginFiles = cfg.Plugins.Enabled
	}
	if !cmd.Flags().Changed("proto-dir") {
		protoDirs = cfg.Protocols.GRPC.ProtoDirs
	}
	if !cmd.Flags().Changed("proto-file") {
		protoFiles = cfg.Protocols.GRPC.ProtoFiles
	}

	if err := protocol.ConfigureGRPCDissector(protoDirs, protoFiles); err != nil {
		return err
	}

	var pcapFile string
	if len(args) > 0 {
		pcapFile = args[0]
	}

	// Import tui package and run
	return runTUIFn(pcapFile, iface, filter, theme, pluginDir, pluginFiles)
}

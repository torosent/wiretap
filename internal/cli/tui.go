package cli

import (
	"github.com/spf13/cobra"
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
}

func runTUI(cmd *cobra.Command, args []string) error {
	filter, _ := cmd.Flags().GetString("filter")
	iface, _ := cmd.Flags().GetString("interface")
	theme, _ := cmd.Flags().GetString("theme")

	var pcapFile string
	if len(args) > 0 {
		pcapFile = args[0]
	}

	// Import tui package and run
	return runTUIFn(pcapFile, iface, filter, theme)
}

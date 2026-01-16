package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/wiretap/wiretap/internal/capture"
)

var interfacesCmd = &cobra.Command{
	Use:     "interfaces",
	Aliases: []string{"if", "ifaces"},
	Short:   "List available network interfaces",
	Long: `List all network interfaces available for packet capture.

Examples:
  wiretap interfaces
  wiretap if`,
	RunE: runInterfaces,
}

func init() {
	interfacesCmd.Flags().BoolP("verbose", "V", false, "show detailed interface information")
	interfacesCmd.Flags().Bool("up", false, "show only interfaces that are up")
}

func runInterfaces(cmd *cobra.Command, args []string) error {
	verbose, _ := cmd.Flags().GetBool("verbose")
	upOnly, _ := cmd.Flags().GetBool("up")

	interfaces, err := capture.ListInterfaces()
	if err != nil {
		return fmt.Errorf("failed to list interfaces: %w", err)
	}

	if len(interfaces) == 0 {
		fmt.Println("No network interfaces found")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	if verbose {
		fmt.Fprintln(w, "Name\tDescription\tFlags\tAddresses")
		fmt.Fprintln(w, "----\t-----------\t-----\t---------")
	} else {
		fmt.Fprintln(w, "Name\tDescription\tAddresses")
		fmt.Fprintln(w, "----\t-----------\t---------")
	}

	for _, iface := range interfaces {
		// Skip if filtering for up interfaces
		if upOnly && (iface.Flags&0x1) == 0 {
			continue
		}

		// Format addresses
		addrs := ""
		for i, addr := range iface.Addresses {
			if i > 0 {
				addrs += ", "
			}
			addrs += addr.IP
		}
		if addrs == "" {
			addrs = "-"
		}

		// Format flags
		flags := formatInterfaceFlags(iface.Flags)

		if verbose {
			desc := iface.Description
			if desc == "" {
				desc = "-"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", iface.Name, desc, flags, addrs)
		} else {
			desc := iface.Description
			if desc == "" {
				desc = "-"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\n", iface.Name, desc, addrs)
		}
	}

	w.Flush()
	return nil
}

func formatInterfaceFlags(flags uint32) string {
	var parts []string

	if flags&0x1 != 0 {
		parts = append(parts, "UP")
	}
	if flags&0x2 != 0 {
		parts = append(parts, "BROADCAST")
	}
	if flags&0x8 != 0 {
		parts = append(parts, "LOOPBACK")
	}
	if flags&0x10 != 0 {
		parts = append(parts, "P2P")
	}
	if flags&0x40 != 0 {
		parts = append(parts, "RUNNING")
	}
	if flags&0x100 != 0 {
		parts = append(parts, "PROMISC")
	}
	if flags&0x1000 != 0 {
		parts = append(parts, "MULTICAST")
	}

	if len(parts) == 0 {
		return "-"
	}

	result := ""
	for i, p := range parts {
		if i > 0 {
			result += "|"
		}
		result += p
	}
	return result
}

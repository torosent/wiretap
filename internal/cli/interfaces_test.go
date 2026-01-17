package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestFormatInterfaceFlags_All(t *testing.T) {
	if got := formatInterfaceFlags(0); got != "-" {
		t.Fatalf("Expected '-', got %s", got)
	}

	flags := uint32(0x1 | 0x2 | 0x8 | 0x10 | 0x40 | 0x100 | 0x1000)
	got := formatInterfaceFlags(flags)
	expectedParts := []string{"UP", "BROADCAST", "LOOPBACK", "P2P", "RUNNING", "PROMISC", "MULTICAST"}
	for _, part := range expectedParts {
		if !strings.Contains(got, part) {
			t.Fatalf("Expected %s in %s", part, got)
		}
	}
}

func TestRunInterfaces_NoError(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().Bool("verbose", false, "")
	cmd.Flags().Bool("up", false, "")

	cmd.Flags().Set("verbose", "true")
	if err := runInterfaces(cmd, nil); err != nil {
		t.Fatalf("runInterfaces failed: %v", err)
	}
}

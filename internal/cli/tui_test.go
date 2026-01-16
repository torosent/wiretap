package cli

import (
	"testing"

	"github.com/spf13/cobra"
)

func newTUITestCommand() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("filter", "", "")
	cmd.Flags().String("interface", "", "")
	cmd.Flags().String("theme", "default", "")
	return cmd
}

func TestRunTUI_Args(t *testing.T) {
	orig := runTUIFn
	t.Cleanup(func() { runTUIFn = orig })

	called := false
	runTUIFn = func(pcapFile, iface, filter, theme string) error {
		called = true
		if pcapFile != "capture.pcap" {
			t.Errorf("pcapFile = %s", pcapFile)
		}
		if iface != "eth0" {
			t.Errorf("iface = %s", iface)
		}
		if filter != "tcp" {
			t.Errorf("filter = %s", filter)
		}
		if theme != "dark" {
			t.Errorf("theme = %s", theme)
		}
		return nil
	}

	cmd := newTUITestCommand()
	cmd.Flags().Set("filter", "tcp")
	cmd.Flags().Set("interface", "eth0")
	cmd.Flags().Set("theme", "dark")

	if err := runTUI(cmd, []string{"capture.pcap"}); err != nil {
		t.Fatalf("runTUI failed: %v", err)
	}
	if !called {
		t.Fatal("Expected runTUI to call runner")
	}
}

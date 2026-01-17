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
	cmd.Flags().String("plugin-dir", "", "")
	cmd.Flags().StringSlice("plugin", nil, "")
	cmd.Flags().StringSlice("proto-dir", nil, "")
	cmd.Flags().StringSlice("proto-file", nil, "")
	return cmd
}

func TestRunTUI_Args(t *testing.T) {
	orig := runTUIFn
	t.Cleanup(func() { runTUIFn = orig })

	called := false
	runTUIFn = func(pcapFile, iface, filter, theme, pluginDir string, pluginFiles []string) error {
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
		cfg := GetConfig()
		if pluginDir != cfg.Plugins.Directory {
			t.Errorf("pluginDir = %s", pluginDir)
		}
		if len(pluginFiles) != len(cfg.Plugins.Enabled) {
			t.Errorf("pluginFiles = %v", pluginFiles)
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

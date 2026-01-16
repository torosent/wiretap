package cli

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
)

func TestRootCmd(t *testing.T) {
	// Test that root command is properly configured
	if rootCmd.Use != "wiretap" {
		t.Errorf("Expected Use to be 'wiretap', got '%s'", rootCmd.Use)
	}

	if rootCmd.Short == "" {
		t.Error("Root command should have a short description")
	}

	if rootCmd.Long == "" {
		t.Error("Root command should have a long description")
	}
}

func TestRootCmd_HasSubcommands(t *testing.T) {
	// Ensure root command has expected subcommands
	expectedCommands := []string{"capture", "config", "read", "index", "interfaces", "export", "tui"}
	commands := rootCmd.Commands()

	for _, expected := range expectedCommands {
		// Check if the command or a variant exists
		found := false
		for _, cmd := range commands {
			if cmd.Use == expected || (len(cmd.Use) > len(expected) && cmd.Use[:len(expected)] == expected) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected subcommand '%s' not found", expected)
		}
	}
}

func TestRootCmd_PersistentFlags(t *testing.T) {
	// Test that persistent flags are registered
	flags := rootCmd.PersistentFlags()

	configFlag := flags.Lookup("config")
	if configFlag == nil {
		t.Error("Expected 'config' persistent flag")
	}

	verboseFlag := flags.Lookup("verbose")
	if verboseFlag == nil {
		t.Error("Expected 'verbose' persistent flag")
	}

	logLevelFlag := flags.Lookup("log-level")
	if logLevelFlag == nil {
		t.Error("Expected 'log-level' persistent flag")
	}
}

func TestGetConfig(t *testing.T) {
	// Test that GetConfig returns a valid config
	config := GetConfig()
	if config == nil {
		t.Error("GetConfig should not return nil")
	}
}

func TestCaptureCmd(t *testing.T) {
	// Test capture command configuration
	if captureCmd.Use != "capture" {
		t.Errorf("Expected Use to be 'capture', got '%s'", captureCmd.Use)
	}

	// Test flags exist
	flags := captureCmd.Flags()

	ifaceFlag := flags.Lookup("interface")
	if ifaceFlag == nil {
		t.Error("Expected 'interface' flag on capture command")
	}
	if ifaceFlag.Shorthand != "i" {
		t.Errorf("Expected 'interface' shorthand to be 'i', got '%s'", ifaceFlag.Shorthand)
	}

	filterFlag := flags.Lookup("filter")
	if filterFlag == nil {
		t.Error("Expected 'filter' flag on capture command")
	}

	writeFlag := flags.Lookup("write")
	if writeFlag == nil {
		t.Error("Expected 'write' flag on capture command")
	}

	countFlag := flags.Lookup("count")
	if countFlag == nil {
		t.Error("Expected 'count' flag on capture command")
	}
}

func TestReadCmd(t *testing.T) {
	// Test read command configuration
	if readCmd.Use != "read <file>" {
		t.Errorf("Expected Use to be 'read <file>', got '%s'", readCmd.Use)
	}

	// Test flags exist
	flags := readCmd.Flags()

	countFlag := flags.Lookup("count")
	if countFlag == nil {
		t.Error("Expected 'count' flag on read command")
	}
}

func TestIndexCmd(t *testing.T) {
	// Test index command has subcommands
	subcommands := indexCmd.Commands()

	expectedSubcmds := []string{"build", "info", "search"}

	for _, expected := range expectedSubcmds {
		found := false
		for _, cmd := range subcommands {
			if cmd.Use == expected || (len(cmd.Use) > len(expected) && cmd.Use[:len(expected)] == expected) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected subcommand '%s' not found in index command", expected)
		}
	}
}

func TestInterfacesCmd(t *testing.T) {
	// Test interfaces command
	if interfacesCmd.Use != "interfaces" {
		t.Errorf("Expected Use to be 'interfaces', got '%s'", interfacesCmd.Use)
	}

	// Test aliases
	if len(interfacesCmd.Aliases) == 0 {
		t.Error("Expected interfaces command to have aliases")
	}

	// Check for specific aliases
	aliasMap := make(map[string]bool)
	for _, a := range interfacesCmd.Aliases {
		aliasMap[a] = true
	}

	if !aliasMap["if"] {
		t.Error("Expected 'if' alias for interfaces command")
	}
}

func TestRunInterfaces(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().Bool("verbose", false, "")
	cmd.Flags().Bool("up", false, "")

	if err := runInterfaces(cmd, nil); err != nil {
		t.Fatalf("runInterfaces failed: %v", err)
	}
}

func TestExportCmd(t *testing.T) {
	// Test export command
	if exportCmd.Use != "export <pcap-file>" {
		t.Errorf("Expected Use to contain 'export', got '%s'", exportCmd.Use)
	}

	// Test flags
	flags := exportCmd.Flags()

	formatFlag := flags.Lookup("format")
	if formatFlag == nil {
		t.Error("Expected 'format' flag on export command")
	}

	outputFlag := flags.Lookup("output")
	if outputFlag == nil {
		t.Error("Expected 'output' flag on export command")
	}
}

func TestFormatInterfaceFlags(t *testing.T) {
	tests := []struct {
		name     string
		flags    uint32
		expected string
	}{
		{"No flags", 0, "-"},
		{"UP", 0x1, "UP"},
		{"UP|RUNNING", 0x41, "UP|RUNNING"},
		{"LOOPBACK", 0x8, "LOOPBACK"},
		{"UP|BROADCAST|MULTICAST", 0x1003, "UP|BROADCAST|MULTICAST"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatInterfaceFlags(tt.flags)
			if result != tt.expected {
				t.Errorf("formatInterfaceFlags(%d) = %s, expected %s", tt.flags, result, tt.expected)
			}
		})
	}
}

// TestCommandExecution tests that commands can be created and have proper structure
func TestCommandExecution(t *testing.T) {
	// Create a test command
	testCmd := &cobra.Command{
		Use:   "test",
		Short: "Test command",
		Run:   func(cmd *cobra.Command, args []string) {},
	}

	// Capture output
	buf := new(bytes.Buffer)
	testCmd.SetOut(buf)
	testCmd.SetErr(buf)

	// Execute with help flag
	testCmd.SetArgs([]string{"--help"})
	err := testCmd.Execute()
	if err != nil {
		t.Errorf("Command execution failed: %v", err)
	}

	// Check output contains usage
	output := buf.String()
	if output == "" {
		t.Error("Expected help output, got empty string")
	}
}

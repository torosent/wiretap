package cli

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/viper"
)

func resetRootGlobals() {
	cfgFile = ""
	cfg = nil
	viper.Reset()
	rootCmd.SetArgs(nil)
	rootCmd.SetOut(io.Discard)
	rootCmd.SetErr(io.Discard)
}

func TestInitConfig_DefaultOverrides(t *testing.T) {
	resetRootGlobals()
	t.Cleanup(resetRootGlobals)

	viper.Set("capture.snaplen", 1234)
	viper.Set("capture.promisc", false)
	viper.Set("capture.timeout", 2*time.Second)
	viper.Set("log_level", "debug")

	initConfig()

	if cfg == nil {
		t.Fatal("Expected cfg to be initialized")
	}
	if cfg.Capture.Snaplen != 1234 {
		t.Errorf("Snaplen = %d, want 1234", cfg.Capture.Snaplen)
	}
	if cfg.Capture.Promiscuous {
		t.Error("Promiscuous should be false")
	}
	if cfg.Capture.Timeout != 2*time.Second {
		t.Errorf("Timeout = %v, want 2s", cfg.Capture.Timeout)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("Log level = %s, want debug", cfg.Logging.Level)
	}
}

func TestInitConfig_LoadFromFile(t *testing.T) {
	resetRootGlobals()
	t.Cleanup(resetRootGlobals)

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	content := "logging:\n  level: warn\n"
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	cfgFile = configPath
	initConfig()

	if cfg == nil {
		t.Fatal("Expected cfg to be initialized")
	}
	if cfg.Logging.Level != "warn" {
		t.Errorf("Log level = %s, want warn", cfg.Logging.Level)
	}
}

func TestExecute_Help(t *testing.T) {
	resetRootGlobals()
	t.Cleanup(resetRootGlobals)

	rootCmd.SetArgs([]string{"--help"})
	Execute()
}

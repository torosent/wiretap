package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/wiretap/wiretap/internal/config"
)

func TestResolveConfigPath(t *testing.T) {
	origCfgFile := cfgFile
	t.Cleanup(func() { cfgFile = origCfgFile })

	cfgFile = ""
	if got := resolveConfigPath(""); !strings.HasSuffix(got, filepath.Join(".config", "wiretap", "config.yaml")) {
		t.Errorf("resolveConfigPath default = %s", got)
	}

	cfgFile = "/tmp/custom.yaml"
	if got := resolveConfigPath(""); got != "/tmp/custom.yaml" {
		t.Errorf("resolveConfigPath with cfgFile = %s", got)
	}

	if got := resolveConfigPath("/tmp/output.yaml"); got != "/tmp/output.yaml" {
		t.Errorf("resolveConfigPath with output = %s", got)
	}
}

func TestRunConfig_Path(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().Bool("path", false, "")
	cmd.Flags().Bool("init", false, "")
	cmd.Flags().Bool("force", false, "")
	cmd.Flags().String("output", "", "")

	buf := &bytes.Buffer{}
	cmd.SetOut(buf)

	if err := cmd.Flags().Set("path", "true"); err != nil {
		t.Fatalf("Set flag failed: %v", err)
	}

	if err := runConfig(cmd, nil); err != nil {
		t.Fatalf("runConfig failed: %v", err)
	}

	output := strings.TrimSpace(buf.String())
	if output == "" {
		t.Fatal("Expected path output")
	}
}

func TestRunConfig_Init(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")

	cmd := &cobra.Command{}
	cmd.Flags().Bool("path", false, "")
	cmd.Flags().Bool("init", false, "")
	cmd.Flags().Bool("force", false, "")
	cmd.Flags().String("output", "", "")

	buf := &bytes.Buffer{}
	cmd.SetOut(buf)

	cmd.Flags().Set("init", "true")
	cmd.Flags().Set("output", cfgPath)

	if err := runConfig(cmd, nil); err != nil {
		t.Fatalf("runConfig init failed: %v", err)
	}

	if _, err := os.Stat(cfgPath); err != nil {
		t.Fatalf("config file not created: %v", err)
	}
}

func TestRunConfig_PrintConfig(t *testing.T) {
	origCfg := cfg
	t.Cleanup(func() { cfg = origCfg })

	cfg = config.DefaultConfig()

	cmd := &cobra.Command{}
	cmd.Flags().Bool("path", false, "")
	cmd.Flags().Bool("init", false, "")
	cmd.Flags().Bool("force", false, "")
	cmd.Flags().String("output", "", "")

	buf := &bytes.Buffer{}
	cmd.SetOut(buf)

	if err := runConfig(cmd, nil); err != nil {
		t.Fatalf("runConfig failed: %v", err)
	}

	if !strings.Contains(buf.String(), "index:") {
		t.Error("Expected YAML config output")
	}
}

func TestWriteDefaultConfig_ExistingNoForce(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yaml")

	if err := os.WriteFile(path, []byte("existing"), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})

	if err := writeDefaultConfig(path, false, cmd); err == nil {
		t.Fatal("Expected error when config already exists without --force")
	}
}

func TestWriteDefaultConfig_ForceOverwrite(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "config.yaml")

	if err := os.WriteFile(path, []byte("existing"), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})

	if err := writeDefaultConfig(path, true, cmd); err != nil {
		t.Fatalf("writeDefaultConfig failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if strings.Contains(string(data), "existing") {
		t.Fatal("Expected config to be overwritten")
	}
}

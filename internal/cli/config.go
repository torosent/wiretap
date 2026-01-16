package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"

	"github.com/wiretap/wiretap/internal/config"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "View or initialize configuration",
	Long: `View or initialize Wiretap configuration.

Examples:
  # Print the resolved configuration
  wiretap config

  # Print the default config path
  wiretap config --path

  # Write a default config file
  wiretap config --init

  # Write a default config file to a custom path
  wiretap config --init --output ./config.yaml`,
	RunE: runConfig,
}

func init() {
	configCmd.Flags().Bool("init", false, "write a default config file")
	configCmd.Flags().Bool("force", false, "overwrite existing config file when using --init")
	configCmd.Flags().Bool("path", false, "print the default config file path")
	configCmd.Flags().StringP("output", "o", "", "output path for --init (defaults to config path)")
}

func runConfig(cmd *cobra.Command, args []string) error {
	showPath, _ := cmd.Flags().GetBool("path")
	initFile, _ := cmd.Flags().GetBool("init")
	force, _ := cmd.Flags().GetBool("force")
	output, _ := cmd.Flags().GetString("output")

	configPath := resolveConfigPath(output)
	if showPath {
		fmt.Fprintln(cmd.OutOrStdout(), configPath)
		return nil
	}

	if initFile {
		return writeDefaultConfig(configPath, force, cmd)
	}

	cfg := GetConfig()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	fmt.Fprintln(cmd.OutOrStdout(), string(data))
	return nil
}

func resolveConfigPath(output string) string {
	if output != "" {
		return output
	}
	if cfgFile != "" {
		return cfgFile
	}
	return config.DefaultConfigPath()
}

func writeDefaultConfig(path string, force bool, cmd *cobra.Command) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("config file already exists: %s (use --force to overwrite)", path)
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("failed to check config file: %w", err)
		}
	}

	cfg := config.DefaultConfig()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Wrote config to %s\n", path)
	return nil
}

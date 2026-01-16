// Package cli provides command-line interface for wiretap
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/wiretap/wiretap/internal/config"
)

var cfgFile string
var cfg *config.Config

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "wiretap",
	Short: "A network packet analyzer",
	Long: `Wiretap is a command-line network packet analyzer similar to Wireshark.

It can capture live network traffic, read pcap files, and display
detailed protocol information including HTTP/1.x, HTTP/2, TLS, and DNS.

Examples:
  # List available network interfaces
  wiretap interfaces

  # Capture packets from an interface
	wiretap capture -i en0 -w capture.pcap

  # Read and display packets from a pcap file
  wiretap read capture.pcap

  # Launch the interactive TUI
  wiretap tui capture.pcap`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Add subcommands
	rootCmd.AddCommand(captureCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(readCmd)
	rootCmd.AddCommand(indexCmd)
	rootCmd.AddCommand(interfacesCmd)
	rootCmd.AddCommand(exportCmd)
	rootCmd.AddCommand(tuiCmd)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.config/wiretap/config.yaml)")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "enable verbose output")
	rootCmd.PersistentFlags().String("log-level", "info", "log level (debug, info, warn, error)")

	// Bind flags to viper
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	viper.BindPFlag("log_level", rootCmd.PersistentFlags().Lookup("log-level"))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	var err error
	if cfgFile != "" {
		cfg, err = config.LoadFromFile(cfgFile)
	} else {
		cfg, err = config.Load()
	}
	if err != nil {
		// Use defaults if config load fails
		cfg = config.DefaultConfig()
	}

	// Override with viper values
	if viper.IsSet("capture.snaplen") {
		cfg.Capture.Snaplen = viper.GetInt("capture.snaplen")
	}
	if viper.IsSet("capture.promisc") {
		cfg.Capture.Promiscuous = viper.GetBool("capture.promisc")
	}
	if viper.IsSet("capture.timeout") {
		cfg.Capture.Timeout = viper.GetDuration("capture.timeout")
	}
	if viper.IsSet("log_level") {
		cfg.Logging.Level = viper.GetString("log_level")
	}
}

// GetConfig returns the loaded configuration
func GetConfig() *config.Config {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	return cfg
}

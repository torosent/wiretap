// Package config provides configuration management for wiretap.
// It uses Viper for loading configuration from files, environment variables,
// and command-line flags with sensible defaults.
package config

import (
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for wiretap.
type Config struct {
	Index     IndexConfig     `mapstructure:"index"`
	Capture   CaptureConfig   `mapstructure:"capture"`
	TUI       TUIConfig       `mapstructure:"tui"`
	Protocols ProtocolsConfig `mapstructure:"protocols"`
	Export    ExportConfig    `mapstructure:"export"`
	Logging   LoggingConfig   `mapstructure:"logging"`
}

// IndexConfig holds configuration for packet indexing.
type IndexConfig struct {
	// Directory where index files are stored
	Directory string `mapstructure:"directory"`
	// Auto-index files larger than this size (bytes)
	AutoIndexThreshold int64 `mapstructure:"auto_index_threshold"`
}

// CaptureConfig holds configuration for packet capture.
type CaptureConfig struct {
	// Maximum bytes to capture per packet
	Snaplen int `mapstructure:"snaplen"`
	// Enable promiscuous mode
	Promiscuous bool `mapstructure:"promiscuous"`
	// Packet buffer timeout
	Timeout time.Duration `mapstructure:"timeout"`
	// Default interface
	Interface string `mapstructure:"interface"`
}

// TUIConfig holds configuration for the terminal UI.
type TUIConfig struct {
	// Color theme: dark, light
	Theme string `mapstructure:"theme"`
	// Show hex view by default
	ShowHex bool `mapstructure:"show_hex"`
	// Show timestamps in local time
	LocalTime bool `mapstructure:"local_time"`
	// Time format: relative, absolute, epoch
	TimeFormat string `mapstructure:"time_format"`
	// Maximum packets to display (0 = unlimited)
	MaxDisplay int `mapstructure:"max_display"`
}

// ProtocolsConfig holds configuration for protocol parsers.
type ProtocolsConfig struct {
	HTTP HTTPProtocolConfig `mapstructure:"http"`
	TLS  TLSProtocolConfig  `mapstructure:"tls"`
	DNS  DNSProtocolConfig  `mapstructure:"dns"`
	GRPC GRPCProtocolConfig `mapstructure:"grpc"`
}

// HTTPProtocolConfig holds HTTP-specific settings.
type HTTPProtocolConfig struct {
	// Maximum body size to parse (bytes)
	MaxBodySize int64 `mapstructure:"max_body_size"`
	// Parse HTTP/2 cleartext (h2c)
	ParseH2C bool `mapstructure:"parse_h2c"`
}

// TLSProtocolConfig holds TLS-specific settings.
type TLSProtocolConfig struct {
	// Extract server certificates
	ParseCertificates bool `mapstructure:"parse_certificates"`
	// Compute JA3 fingerprints
	ComputeJA3 bool `mapstructure:"compute_ja3"`
	// Enable TLS decryption (requires keylog file)
	Decrypt bool `mapstructure:"decrypt"`
	// Path to NSS SSLKEYLOGFILE for TLS decryption
	KeyLogFile string `mapstructure:"keylog_file"`
}

// DNSProtocolConfig holds DNS-specific settings.
type DNSProtocolConfig struct {
	// Resolve PTR records for display
	ResolvePTR bool `mapstructure:"resolve_ptr"`
}

// GRPCProtocolConfig holds gRPC-specific settings.
type GRPCProtocolConfig struct {
	// Directories to search for .proto files (compiled descriptor sets)
	ProtoDirs []string `mapstructure:"proto_dirs"`
	// Individual .proto descriptor files
	ProtoFiles []string `mapstructure:"proto_files"`
}

// ExportConfig holds configuration for data export.
type ExportConfig struct {
	// Default export format: json, har
	DefaultFormat string `mapstructure:"default_format"`
	// Pretty print JSON output
	PrettyJSON bool `mapstructure:"pretty_json"`
}

// LoggingConfig holds configuration for logging.
type LoggingConfig struct {
	// Log level: debug, info, warn, error
	Level string `mapstructure:"level"`
	// Log file (empty = stderr only)
	File string `mapstructure:"file"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	homeDir, _ := os.UserHomeDir()
	return &Config{
		Index: IndexConfig{
			Directory:          filepath.Join(homeDir, ".cache", "wiretap"),
			AutoIndexThreshold: 10 * 1024 * 1024, // 10MB
		},
		Capture: CaptureConfig{
			Snaplen:     65535,
			Promiscuous: true,
			Timeout:     time.Second,
			Interface:   "",
		},
		TUI: TUIConfig{
			Theme:      "dark",
			ShowHex:    true,
			LocalTime:  true,
			TimeFormat: "relative",
			MaxDisplay: 0,
		},
		Protocols: ProtocolsConfig{
			HTTP: HTTPProtocolConfig{
				MaxBodySize: 1024 * 1024, // 1MB
				ParseH2C:    true,
			},
			TLS: TLSProtocolConfig{
				ParseCertificates: true,
				ComputeJA3:        true,
				Decrypt:           false,
				KeyLogFile:        "",
			},
			DNS: DNSProtocolConfig{
				ResolvePTR: false,
			},
			GRPC: GRPCProtocolConfig{
				ProtoDirs:  []string{},
				ProtoFiles: []string{},
			},
		},
		Export: ExportConfig{
			DefaultFormat: "json",
			PrettyJSON:    true,
		},
		Logging: LoggingConfig{
			Level: "info",
			File:  "",
		},
	}
}

// global holds the global configuration instance.
var global *Config

// Global returns the global configuration instance.
func Global() *Config {
	if global == nil {
		global = DefaultConfig()
	}
	return global
}

// SetGlobal sets the global configuration instance.
func SetGlobal(cfg *Config) {
	global = cfg
}

// Load loads configuration from file and environment variables.
func Load() (*Config, error) {
	v := viper.New()

	// Set defaults
	setDefaults(v)

	// Config file search paths
	v.SetConfigName("config")
	v.SetConfigType("yaml")

	// Search paths
	homeDir, _ := os.UserHomeDir()
	v.AddConfigPath(filepath.Join(homeDir, ".config", "wiretap"))
	v.AddConfigPath("/etc/wiretap")
	v.AddConfigPath(".")

	// Environment variable prefix
	v.SetEnvPrefix("WIRETAP")
	v.AutomaticEnv()

	// Read config file (ignore if not found)
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	// Unmarshal into config struct
	cfg := &Config{}
	if err := v.Unmarshal(cfg); err != nil {
		return nil, err
	}

	// Expand home directory in paths
	cfg.Index.Directory = expandPath(cfg.Index.Directory)
	if cfg.Logging.File != "" {
		cfg.Logging.File = expandPath(cfg.Logging.File)
	}

	// Set global config
	SetGlobal(cfg)

	return cfg, nil
}

// LoadFromFile loads configuration from a specific file.
func LoadFromFile(path string) (*Config, error) {
	v := viper.New()

	// Set defaults
	setDefaults(v)

	// Set specific config file
	v.SetConfigFile(path)

	// Read config file
	if err := v.ReadInConfig(); err != nil {
		return nil, err
	}

	// Unmarshal into config struct
	cfg := &Config{}
	if err := v.Unmarshal(cfg); err != nil {
		return nil, err
	}

	// Expand home directory in paths
	cfg.Index.Directory = expandPath(cfg.Index.Directory)
	if cfg.Logging.File != "" {
		cfg.Logging.File = expandPath(cfg.Logging.File)
	}

	// Set global config
	SetGlobal(cfg)

	return cfg, nil
}

// setDefaults sets default values in viper.
func setDefaults(v *viper.Viper) {
	homeDir, _ := os.UserHomeDir()

	// Index defaults
	v.SetDefault("index.directory", filepath.Join(homeDir, ".cache", "wiretap"))
	v.SetDefault("index.auto_index_threshold", 10*1024*1024)

	// Capture defaults
	v.SetDefault("capture.snaplen", 65535)
	v.SetDefault("capture.promiscuous", true)
	v.SetDefault("capture.timeout", time.Second)
	v.SetDefault("capture.interface", "")

	// TUI defaults
	v.SetDefault("tui.theme", "dark")
	v.SetDefault("tui.show_hex", true)
	v.SetDefault("tui.local_time", true)
	v.SetDefault("tui.time_format", "relative")
	v.SetDefault("tui.max_display", 0)

	// Protocol defaults
	v.SetDefault("protocols.http.max_body_size", 1024*1024)
	v.SetDefault("protocols.http.parse_h2c", true)
	v.SetDefault("protocols.tls.parse_certificates", true)
	v.SetDefault("protocols.tls.compute_ja3", true)
	v.SetDefault("protocols.tls.decrypt", false)
	v.SetDefault("protocols.tls.keylog_file", "")
	v.SetDefault("protocols.dns.resolve_ptr", false)
	v.SetDefault("protocols.grpc.proto_dirs", []string{})
	v.SetDefault("protocols.grpc.proto_files", []string{})

	// Export defaults
	v.SetDefault("export.default_format", "json")
	v.SetDefault("export.pretty_json", true)

	// Logging defaults
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.file", "")
}

// DefaultConfigPath returns the default configuration file path.
func DefaultConfigPath() string {
	homeDir, _ := os.UserHomeDir()
	return filepath.Join(homeDir, ".config", "wiretap", "config.yaml")
}

// expandPath expands ~ to the user's home directory.
func expandPath(path string) string {
	if len(path) == 0 {
		return path
	}
	if path[0] == '~' {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return path
		}
		return filepath.Join(homeDir, path[1:])
	}
	return path
}

// EnsureIndexDir ensures the index directory exists.
func (c *Config) EnsureIndexDir() error {
	return os.MkdirAll(c.Index.Directory, 0755)
}

// IndexPath returns the index file path for a given pcap file.
func (c *Config) IndexPath(pcapPath string) string {
	// Use the pcap filename with .idx extension
	base := filepath.Base(pcapPath)
	return filepath.Join(c.Index.Directory, base+".idx")
}

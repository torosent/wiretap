// Package crypto provides TLS decryption capabilities using SSLKEYLOGFILE.
// It supports the NSS key log format used by browsers and curl when
// SSLKEYLOGFILE environment variable is set.
package crypto

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// Key log label types as defined in NSS key log format.
// See: https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format
const (
	// TLS 1.2 and earlier
	LabelClientRandom = "CLIENT_RANDOM"

	// TLS 1.3 secrets
	LabelClientEarlyTrafficSecret     = "CLIENT_EARLY_TRAFFIC_SECRET"
	LabelClientHandshakeTrafficSecret = "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
	LabelServerHandshakeTrafficSecret = "SERVER_HANDSHAKE_TRAFFIC_SECRET"
	LabelClientTrafficSecret0         = "CLIENT_TRAFFIC_SECRET_0"
	LabelServerTrafficSecret0         = "SERVER_TRAFFIC_SECRET_0"
	LabelEarlyExporterSecret          = "EARLY_EXPORTER_SECRET"
	LabelExporterSecret               = "EXPORTER_SECRET"
)

// ErrKeyNotFound is returned when a key is not found in the key log.
var ErrKeyNotFound = errors.New("key not found in key log")

// ErrInvalidKeyLogFormat is returned when a key log line is malformed.
var ErrInvalidKeyLogFormat = errors.New("invalid key log format")

// KeyLogEntry represents a single entry from an SSLKEYLOGFILE.
type KeyLogEntry struct {
	// Label identifies the type of secret
	Label string

	// ClientRandom is the 32-byte client random from ClientHello
	// Used as the key to look up secrets
	ClientRandom [32]byte

	// Secret is the derived secret (master secret for TLS 1.2, or
	// traffic secret for TLS 1.3)
	Secret []byte
}

// KeyLog stores parsed key log entries and provides lookup by client random.
type KeyLog struct {
	mu      sync.RWMutex
	entries map[string]map[string][]byte // clientRandom (hex) -> label -> secret
}

// NewKeyLog creates a new empty key log.
func NewKeyLog() *KeyLog {
	return &KeyLog{
		entries: make(map[string]map[string][]byte),
	}
}

// LoadFromFile loads key log entries from an SSLKEYLOGFILE.
func LoadFromFile(path string) (*KeyLog, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open key log file: %w", err)
	}
	defer f.Close()

	return LoadFromReader(f)
}

// LoadFromReader loads key log entries from a reader.
func LoadFromReader(r io.Reader) (*KeyLog, error) {
	kl := NewKeyLog()

	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		entry, err := ParseKeyLogLine(line)
		if err != nil {
			// Log warning but continue parsing
			continue
		}

		kl.Add(entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read key log file: %w", err)
	}

	return kl, nil
}

// ParseKeyLogLine parses a single line from an SSLKEYLOGFILE.
// Format: <label> <client_random_hex> <secret_hex>
func ParseKeyLogLine(line string) (*KeyLogEntry, error) {
	// Split by whitespace
	parts := strings.Fields(line)
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: expected 3 fields, got %d", ErrInvalidKeyLogFormat, len(parts))
	}

	label := parts[0]
	clientRandomHex := parts[1]
	secretHex := parts[2]

	// Validate label
	if !isValidLabel(label) {
		return nil, fmt.Errorf("%w: unknown label %q", ErrInvalidKeyLogFormat, label)
	}

	// Parse client random (must be 32 bytes = 64 hex chars)
	if len(clientRandomHex) != 64 {
		return nil, fmt.Errorf("%w: client random must be 64 hex chars, got %d",
			ErrInvalidKeyLogFormat, len(clientRandomHex))
	}

	clientRandomBytes, err := hex.DecodeString(clientRandomHex)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid client random hex: %v", ErrInvalidKeyLogFormat, err)
	}

	var clientRandom [32]byte
	copy(clientRandom[:], clientRandomBytes)

	// Parse secret
	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid secret hex: %v", ErrInvalidKeyLogFormat, err)
	}

	// Validate secret length based on label
	if err := validateSecretLength(label, len(secret)); err != nil {
		return nil, err
	}

	return &KeyLogEntry{
		Label:        label,
		ClientRandom: clientRandom,
		Secret:       secret,
	}, nil
}

// isValidLabel checks if a label is a known key log label.
func isValidLabel(label string) bool {
	switch label {
	case LabelClientRandom,
		LabelClientEarlyTrafficSecret,
		LabelClientHandshakeTrafficSecret,
		LabelServerHandshakeTrafficSecret,
		LabelClientTrafficSecret0,
		LabelServerTrafficSecret0,
		LabelEarlyExporterSecret,
		LabelExporterSecret:
		return true
	default:
		return false
	}
}

// validateSecretLength validates the secret length for a given label.
func validateSecretLength(label string, length int) error {
	switch label {
	case LabelClientRandom:
		// Master secret is 48 bytes for TLS 1.2
		if length != 48 {
			return fmt.Errorf("%w: master secret must be 48 bytes, got %d",
				ErrInvalidKeyLogFormat, length)
		}
	default:
		// TLS 1.3 secrets are typically 32, 48, or 64 bytes depending on cipher
		if length < 32 || length > 64 {
			return fmt.Errorf("%w: secret length %d out of valid range [32, 64]",
				ErrInvalidKeyLogFormat, length)
		}
	}
	return nil
}

// Add adds a key log entry to the store.
func (kl *KeyLog) Add(entry *KeyLogEntry) {
	kl.mu.Lock()
	defer kl.mu.Unlock()

	key := hex.EncodeToString(entry.ClientRandom[:])

	if kl.entries[key] == nil {
		kl.entries[key] = make(map[string][]byte)
	}

	// Make a copy of the secret to avoid external modification
	secret := make([]byte, len(entry.Secret))
	copy(secret, entry.Secret)
	kl.entries[key][entry.Label] = secret
}

// Lookup finds a secret by client random and label.
func (kl *KeyLog) Lookup(clientRandom [32]byte, label string) ([]byte, error) {
	kl.mu.RLock()
	defer kl.mu.RUnlock()

	key := hex.EncodeToString(clientRandom[:])

	labels, ok := kl.entries[key]
	if !ok {
		return nil, ErrKeyNotFound
	}

	secret, ok := labels[label]
	if !ok {
		return nil, ErrKeyNotFound
	}

	// Return a copy to prevent external modification
	result := make([]byte, len(secret))
	copy(result, secret)
	return result, nil
}

// LookupMasterSecret looks up the TLS 1.2 master secret by client random.
func (kl *KeyLog) LookupMasterSecret(clientRandom [32]byte) ([]byte, error) {
	return kl.Lookup(clientRandom, LabelClientRandom)
}

// LookupTLS13Secrets looks up all TLS 1.3 traffic secrets by client random.
func (kl *KeyLog) LookupTLS13Secrets(clientRandom [32]byte) (*TLS13Secrets, error) {
	kl.mu.RLock()
	defer kl.mu.RUnlock()

	key := hex.EncodeToString(clientRandom[:])

	labels, ok := kl.entries[key]
	if !ok {
		return nil, ErrKeyNotFound
	}

	secrets := &TLS13Secrets{}

	// Copy each secret if present
	if s, ok := labels[LabelClientHandshakeTrafficSecret]; ok {
		secrets.ClientHandshakeTrafficSecret = make([]byte, len(s))
		copy(secrets.ClientHandshakeTrafficSecret, s)
	}
	if s, ok := labels[LabelServerHandshakeTrafficSecret]; ok {
		secrets.ServerHandshakeTrafficSecret = make([]byte, len(s))
		copy(secrets.ServerHandshakeTrafficSecret, s)
	}
	if s, ok := labels[LabelClientTrafficSecret0]; ok {
		secrets.ClientTrafficSecret0 = make([]byte, len(s))
		copy(secrets.ClientTrafficSecret0, s)
	}
	if s, ok := labels[LabelServerTrafficSecret0]; ok {
		secrets.ServerTrafficSecret0 = make([]byte, len(s))
		copy(secrets.ServerTrafficSecret0, s)
	}
	if s, ok := labels[LabelClientEarlyTrafficSecret]; ok {
		secrets.ClientEarlyTrafficSecret = make([]byte, len(s))
		copy(secrets.ClientEarlyTrafficSecret, s)
	}
	if s, ok := labels[LabelExporterSecret]; ok {
		secrets.ExporterSecret = make([]byte, len(s))
		copy(secrets.ExporterSecret, s)
	}

	// Check if we have at least the application traffic secrets
	if secrets.ClientTrafficSecret0 == nil && secrets.ServerTrafficSecret0 == nil {
		return nil, ErrKeyNotFound
	}

	return secrets, nil
}

// TLS13Secrets holds all TLS 1.3 secrets for a connection.
type TLS13Secrets struct {
	ClientEarlyTrafficSecret     []byte
	ClientHandshakeTrafficSecret []byte
	ServerHandshakeTrafficSecret []byte
	ClientTrafficSecret0         []byte
	ServerTrafficSecret0         []byte
	ExporterSecret               []byte
}

// HasHandshakeSecrets returns true if handshake traffic secrets are available.
func (s *TLS13Secrets) HasHandshakeSecrets() bool {
	return s.ClientHandshakeTrafficSecret != nil && s.ServerHandshakeTrafficSecret != nil
}

// HasApplicationSecrets returns true if application traffic secrets are available.
func (s *TLS13Secrets) HasApplicationSecrets() bool {
	return s.ClientTrafficSecret0 != nil && s.ServerTrafficSecret0 != nil
}

// Count returns the number of entries in the key log.
func (kl *KeyLog) Count() int {
	kl.mu.RLock()
	defer kl.mu.RUnlock()
	return len(kl.entries)
}

// HasKey returns true if the key log contains any secrets for the given client random.
func (kl *KeyLog) HasKey(clientRandom [32]byte) bool {
	kl.mu.RLock()
	defer kl.mu.RUnlock()

	key := hex.EncodeToString(clientRandom[:])
	_, ok := kl.entries[key]
	return ok
}

// Clear removes all entries from the key log.
// This should be called when secrets are no longer needed for security.
func (kl *KeyLog) Clear() {
	kl.mu.Lock()
	defer kl.mu.Unlock()

	// Overwrite secrets with zeros before clearing
	for _, labels := range kl.entries {
		for _, secret := range labels {
			for i := range secret {
				secret[i] = 0
			}
		}
	}

	kl.entries = make(map[string]map[string][]byte)
}

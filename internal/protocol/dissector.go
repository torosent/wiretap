// Package protocol provides protocol dissectors for network traffic analysis.
// Each dissector implements parsing logic for a specific application-layer protocol.
package protocol

import (
	"errors"

	"github.com/wiretap/wiretap/internal/crypto"
	"github.com/wiretap/wiretap/internal/model"
)

// Common errors returned by dissectors.
var (
	ErrInvalidProtocol   = errors.New("invalid protocol data")
	ErrIncompleteData    = errors.New("incomplete data for parsing")
	ErrUnsupportedMethod = errors.New("unsupported method")
)

// Dissector is the interface for protocol parsers.
type Dissector interface {
	// Name returns the protocol name.
	Name() string

	// Detect checks if the data belongs to this protocol.
	// It returns true if the protocol can parse the data.
	Detect(data []byte) bool

	// Parse attempts to parse the data and returns protocol-specific information.
	// The result is stored in the provided Packet's protocol-specific fields.
	Parse(data []byte, pkt *model.Packet) error
}

// DissectorRegistry manages registered protocol dissectors.
type DissectorRegistry struct {
	dissectors          []Dissector
	sessionManager      *crypto.SessionManager
	tlsDecryptDissector *TLSDecryptingDissector
}

// NewRegistry creates a new dissector registry with default dissectors.
func NewRegistry() *DissectorRegistry {
	r := &DissectorRegistry{
		dissectors: make([]Dissector, 0),
	}

	// Register default dissectors in order of detection priority
	r.Register(NewHTTP2Dissector())
	r.Register(NewHTTP1Dissector())
	r.Register(NewTLSDissector())
	r.Register(NewDNSDissector())

	return r
}

// NewDecryptingRegistry creates a dissector registry with TLS decryption enabled.
// The sessionManager provides TLS keys for decryption.
func NewDecryptingRegistry(sessionManager *crypto.SessionManager) *DissectorRegistry {
	r := &DissectorRegistry{
		dissectors:     make([]Dissector, 0),
		sessionManager: sessionManager,
	}

	// Create inner registry for parsing decrypted data (HTTP/2, HTTP/1)
	innerRegistry := &DissectorRegistry{
		dissectors: make([]Dissector, 0),
	}
	innerRegistry.Register(NewHTTP2Dissector())
	innerRegistry.Register(NewHTTP1Dissector())

	// Create TLS decrypting dissector with inner registry
	tlsDecrypt := NewTLSDecryptingDissector(sessionManager, innerRegistry)
	r.tlsDecryptDissector = tlsDecrypt

	// Register dissectors in order of detection priority
	// TLS must come before HTTP/2 because HTTP/2 frame detection is aggressive
	// and can match TLS records (0x16 0x03 0x01 looks like an HTTP/2 frame)
	r.Register(tlsDecrypt)
	r.Register(NewHTTP2Dissector())
	r.Register(NewHTTP1Dissector())
	r.Register(NewDNSDissector())

	return r
}

// TLSDecryptingDissector returns the TLS decrypting dissector if available.
func (r *DissectorRegistry) TLSDecryptingDissector() *TLSDecryptingDissector {
	return r.tlsDecryptDissector
}

// SessionManager returns the session manager if available.
func (r *DissectorRegistry) SessionManager() *crypto.SessionManager {
	return r.sessionManager
}

// Register adds a dissector to the registry.
func (r *DissectorRegistry) Register(d Dissector) {
	r.dissectors = append(r.dissectors, d)
}

// Detect finds the first matching dissector for the data.
func (r *DissectorRegistry) Detect(data []byte) Dissector {
	for _, d := range r.dissectors {
		if d.Detect(data) {
			return d
		}
	}
	return nil
}

// Parse tries all registered dissectors and returns the first successful parse.
func (r *DissectorRegistry) Parse(data []byte, pkt *model.Packet) error {
	d := r.Detect(data)
	if d == nil {
		return nil // No matching dissector
	}
	return d.Parse(data, pkt)
}

// Get returns a dissector by name.
func (r *DissectorRegistry) Get(name string) Dissector {
	for _, d := range r.dissectors {
		if d.Name() == name {
			return d
		}
	}
	return nil
}

// List returns all registered dissector names.
func (r *DissectorRegistry) List() []string {
	names := make([]string, len(r.dissectors))
	for i, d := range r.dissectors {
		names[i] = d.Name()
	}
	return names
}

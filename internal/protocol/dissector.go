// Package protocol provides protocol dissectors for network traffic analysis.
// Each dissector implements parsing logic for a specific application-layer protocol.
package protocol

import (
	"errors"

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
	dissectors []Dissector
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

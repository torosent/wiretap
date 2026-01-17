package protocol

import (
	"encoding/hex"
	"sync"

	"github.com/wiretap/wiretap/internal/crypto"
	"github.com/wiretap/wiretap/internal/model"
)

// TLSConnectionState tracks TLS handshake state across packets for a connection.
type TLSConnectionState struct {
	// ClientRandom from ClientHello (used to lookup keys)
	ClientRandom [32]byte
	// ServerRandom from ServerHello
	ServerRandom [32]byte
	// CipherSuite negotiated
	CipherSuite uint16
	// Version negotiated
	Version uint16
	// HasClientHello indicates ClientHello was seen
	HasClientHello bool
	// HasServerHello indicates ServerHello was seen
	HasServerHello bool
	// DecryptorInitialized indicates decryptor is ready
	DecryptorInitialized bool
	// SNI from ClientHello for debugging
	SNI string
}

// TLSConnectionTracker tracks TLS state across multiple packets by flow hash.
type TLSConnectionTracker struct {
	mu          sync.RWMutex
	connections map[uint64]*TLSConnectionState
}

// NewTLSConnectionTracker creates a new connection tracker.
func NewTLSConnectionTracker() *TLSConnectionTracker {
	return &TLSConnectionTracker{
		connections: make(map[uint64]*TLSConnectionState),
	}
}

// GetOrCreate retrieves or creates connection state for a flow.
func (t *TLSConnectionTracker) GetOrCreate(flowHash uint64) *TLSConnectionState {
	t.mu.Lock()
	defer t.mu.Unlock()

	if state, ok := t.connections[flowHash]; ok {
		return state
	}

	state := &TLSConnectionState{}
	t.connections[flowHash] = state
	return state
}

// Get retrieves connection state for a flow, or nil if not found.
func (t *TLSConnectionTracker) Get(flowHash uint64) *TLSConnectionState {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.connections[flowHash]
}

// Count returns the number of tracked connections.
func (t *TLSConnectionTracker) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.connections)
}

// Clear removes all tracked connections.
func (t *TLSConnectionTracker) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.connections = make(map[uint64]*TLSConnectionState)
}

// TLSDecryptingDissector wraps the TLS dissector to enable decryption
// and chained parsing of decrypted application data.
type TLSDecryptingDissector struct {
	tlsDissector      *TLSDissector
	sessionManager    *crypto.SessionManager
	innerRegistry     *DissectorRegistry
	connectionTracker *TLSConnectionTracker
}

// NewTLSDecryptingDissector creates a new TLS decrypting dissector.
// sessionManager: manages TLS sessions and keys
// innerRegistry: dissectors to try on decrypted data (e.g., HTTP/2, HTTP/1)
func NewTLSDecryptingDissector(sessionManager *crypto.SessionManager, innerRegistry *DissectorRegistry) *TLSDecryptingDissector {
	return &TLSDecryptingDissector{
		tlsDissector:      NewTLSDissector(),
		sessionManager:    sessionManager,
		innerRegistry:     innerRegistry,
		connectionTracker: NewTLSConnectionTracker(),
	}
}

// Name returns the dissector name.
func (d *TLSDecryptingDissector) Name() string {
	return "TLS+Decrypt"
}

// Detect checks if data looks like TLS traffic.
func (d *TLSDecryptingDissector) Detect(data []byte) bool {
	return d.tlsDissector.Detect(data)
}

// Parse parses TLS records, attempts decryption, and chains to inner dissectors.
func (d *TLSDecryptingDissector) Parse(data []byte, pkt *model.Packet) error {
	// First, let the TLS dissector extract metadata (handshake info, etc.)
	if err := d.tlsDissector.Parse(data, pkt); err != nil {
		// Continue even on error - partial parsing may have succeeded.
		_ = err
	}

	// Get or create connection state for this flow (always track, even without decryption)
	flowHash := pkt.FlowHash()
	connState := d.connectionTracker.GetOrCreate(flowHash)

	// Update connection state from TLSInfo
	if pkt.TLSInfo != nil {
		d.updateConnectionState(connState, pkt.TLSInfo)
	}

	// If no session manager, we can't decrypt - but we still tracked the connection.
	if d.sessionManager == nil {
		return nil
	}

	// Try to initialize decryptor if we have enough handshake data
	if connState.HasClientHello && !connState.DecryptorInitialized {
		if err := d.tryInitializeDecryptor(connState); err == nil {
			connState.DecryptorInitialized = true
		}
	}

	// Try to decrypt application data records using tracked connection state
	decrypted := d.tryDecryptRecordsWithState(data, pkt, connState)
	if len(decrypted) > 0 {
		pkt.DecryptedPayload = decrypted
		pkt.TLSDecrypted = true

		// Chain to inner dissectors for the decrypted data.
		if d.innerRegistry != nil {
			if err := d.innerRegistry.Parse(decrypted, pkt); err != nil {
				// Log but don't fail - we still have the decrypted data.
				_ = err
			}
		}
	}

	return nil
}

// updateConnectionState updates the connection state from TLS handshake info.
func (d *TLSDecryptingDissector) updateConnectionState(state *TLSConnectionState, tlsInfo *model.TLSInfo) {
	if tlsInfo.ClientHello != nil && !state.HasClientHello {
		state.ClientRandom = tlsInfo.ClientHello.Random
		state.HasClientHello = true
		state.SNI = tlsInfo.ClientHello.SNI
	}

	if tlsInfo.ServerHello != nil && !state.HasServerHello {
		state.ServerRandom = tlsInfo.ServerHello.Random
		state.CipherSuite = uint16(tlsInfo.ServerHello.CipherSuite)
		state.HasServerHello = true
	}

	if tlsInfo.Version != 0 {
		state.Version = uint16(tlsInfo.Version)
	}
}

// tryInitializeDecryptor attempts to initialize the decryptor for a connection.
func (d *TLSDecryptingDissector) tryInitializeDecryptor(state *TLSConnectionState) error {
	if !state.HasClientHello {
		return crypto.ErrKeyNotFound
	}

	clientRandom := state.ClientRandom[:]

	// Determine version - default to TLS 1.3 if not specified
	version := state.Version
	if version == 0 {
		version = 0x0304 // TLS 1.3
	}

	// Get cipher suite - needed for proper decryption
	cipherSuite := state.CipherSuite
	if cipherSuite == 0 && state.HasServerHello {
		// Already have it from ServerHello
	}

	return d.sessionManager.InitializeDecryptor(clientRandom, version, cipherSuite)
}

// tryInitializeSession attempts to initialize a TLS session for decryption.
// This is the legacy method that works with TLSInfo from a single packet.
func (d *TLSDecryptingDissector) tryInitializeSession(tlsInfo *model.TLSInfo) {
	// Get client random from ClientHello.
	var clientRandom []byte
	if tlsInfo.ClientHello != nil {
		clientRandom = tlsInfo.ClientHello.Random[:]
	}
	if len(clientRandom) != 32 {
		return
	}

	// Determine TLS version.
	version := uint16(tlsInfo.Version)
	if version == 0 {
		// Default to TLS 1.3 if not specified.
		version = 0x0304
	}

	// Get cipher suite from ServerHello.
	var cipherSuite uint16
	if tlsInfo.ServerHello != nil {
		cipherSuite = uint16(tlsInfo.ServerHello.CipherSuite)
	}
	if cipherSuite == 0 {
		// Can't initialize without cipher suite.
		return
	}

	// Try to initialize the decryptor.
	_ = d.sessionManager.InitializeDecryptor(clientRandom, version, cipherSuite)
}

// tryDecryptRecordsWithState attempts to decrypt TLS application data records
// using the tracked connection state (for cross-packet decryption).
func (d *TLSDecryptingDissector) tryDecryptRecordsWithState(data []byte, pkt *model.Packet, state *TLSConnectionState) []byte {
	// Need client random to look up keys
	if !state.HasClientHello {
		return nil
	}
	clientRandom := state.ClientRandom[:]

	var decrypted []byte
	offset := 0

	for offset < len(data) {
		// Check for TLS record header (5 bytes).
		if offset+5 > len(data) {
			break
		}

		recordType := data[offset]
		recordVersion := uint16(data[offset+1])<<8 | uint16(data[offset+2])
		recordLen := int(data[offset+3])<<8 | int(data[offset+4])

		// Validate record.
		if recordLen > 16384+256 { // Max TLS record size + overhead.
			break
		}
		if offset+5+recordLen > len(data) {
			break
		}

		// Only decrypt application data records (type 23).
		if recordType == 23 && recordVersion >= 0x0301 {
			record := data[offset : offset+5+recordLen]

			// Determine direction (client to server based on port heuristics).
			isClientToServer := d.determineDirection(pkt)

			plaintext, err := d.sessionManager.DecryptRecord(
				clientRandom,
				record,
				isClientToServer,
			)
			if err == nil && len(plaintext) > 0 {
				decrypted = append(decrypted, plaintext...)
			}
		}

		offset += 5 + recordLen
	}

	return decrypted
}

// determineDirection determines if the packet is client-to-server based on port heuristics.
func (d *TLSDecryptingDissector) determineDirection(pkt *model.Packet) bool {
	// Common TLS server ports
	serverPorts := map[uint16]bool{
		443:  true, // HTTPS
		8443: true, // HTTPS alt
		993:  true, // IMAPS
		995:  true, // POP3S
		465:  true, // SMTPS
		636:  true, // LDAPS
		853:  true, // DNS over TLS
		5061: true, // SIPS
	}

	// If destination port is a known server port, it's client-to-server
	if serverPorts[pkt.DstPort] {
		return true
	}
	// If source port is a known server port, it's server-to-client
	if serverPorts[pkt.SrcPort] {
		return false
	}

	// Default heuristic: lower port is usually the server
	return pkt.DstPort < pkt.SrcPort
}

// tryDecryptRecords attempts to decrypt TLS application data records.
// Deprecated: Use tryDecryptRecordsWithState for cross-packet decryption.
func (d *TLSDecryptingDissector) tryDecryptRecords(data []byte, pkt *model.Packet) []byte {
	// Get client random from TLSInfo.
	if pkt.TLSInfo == nil || pkt.TLSInfo.ClientHello == nil {
		return nil
	}
	clientRandom := pkt.TLSInfo.ClientHello.Random[:]

	var decrypted []byte
	offset := 0

	for offset < len(data) {
		// Check for TLS record header (5 bytes).
		if offset+5 > len(data) {
			break
		}

		recordType := data[offset]
		recordVersion := uint16(data[offset+1])<<8 | uint16(data[offset+2])
		recordLen := int(data[offset+3])<<8 | int(data[offset+4])

		// Validate record.
		if recordLen > 16384+256 { // Max TLS record size + overhead.
			break
		}
		if offset+5+recordLen > len(data) {
			break
		}

		// Only decrypt application data records (type 23).
		if recordType == 23 && recordVersion >= 0x0301 {
			record := data[offset : offset+5+recordLen]

			// Determine direction (client to server based on source port).
			isClientToServer := true
			if pkt.SrcPort > pkt.DstPort {
				isClientToServer = pkt.SrcPort < 1024 // Heuristic for server ports.
			}

			plaintext, err := d.sessionManager.DecryptRecord(
				clientRandom,
				record,
				isClientToServer,
			)
			if err == nil && len(plaintext) > 0 {
				decrypted = append(decrypted, plaintext...)
			}
		}

		offset += 5 + recordLen
	}

	return decrypted
}

// SessionManager returns the session manager used for decryption.
func (d *TLSDecryptingDissector) SessionManager() *crypto.SessionManager {
	return d.sessionManager
}

// SetSessionManager sets the session manager.
func (d *TLSDecryptingDissector) SetSessionManager(mgr *crypto.SessionManager) {
	d.sessionManager = mgr
}

// ConnectionTracker returns the connection tracker.
func (d *TLSDecryptingDissector) ConnectionTracker() *TLSConnectionTracker {
	return d.connectionTracker
}

// ConnectionStateByFlow returns the TLS connection state for a given flow hash.
func (d *TLSDecryptingDissector) ConnectionStateByFlow(flowHash uint64) *TLSConnectionState {
	return d.connectionTracker.Get(flowHash)
}

// ClientRandomHex returns the client random as a hex string for debugging.
func (s *TLSConnectionState) ClientRandomHex() string {
	return hex.EncodeToString(s.ClientRandom[:])
}

// ServerRandomHex returns the server random as a hex string for debugging.
func (s *TLSConnectionState) ServerRandomHex() string {
	return hex.EncodeToString(s.ServerRandom[:])
}

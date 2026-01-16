// Package crypto provides cryptographic utilities for TLS decryption.
package crypto

import (
	"sync"
)

// SessionManager manages TLS sessions for decryption.
// It tracks TLS connections and their associated decryptors.
type SessionManager struct {
	mu        sync.RWMutex
	keyLog    *KeyLog
	sessions  map[string]*TLSSession
}

// TLSSession represents a tracked TLS connection.
type TLSSession struct {
	// ClientRandom identifies the session.
	ClientRandom []byte
	// Version is the negotiated TLS version (0x0303=TLS1.2, 0x0304=TLS1.3).
	Version uint16
	// CipherSuite is the negotiated cipher suite.
	CipherSuite uint16
	// Decryptor handles decryption of records.
	Decryptor *Decryptor
	// DecryptedPayloads holds decrypted application data.
	DecryptedPayloads [][]byte
	// IsClientToServer indicates direction tracking.
	mu sync.Mutex
}

// NewSessionManager creates a session manager with the given keylog.
func NewSessionManager(keyLog *KeyLog) *SessionManager {
	return &SessionManager{
		keyLog:   keyLog,
		sessions: make(map[string]*TLSSession),
	}
}

// KeyLog returns the associated key log.
func (m *SessionManager) KeyLog() *KeyLog {
	return m.keyLog
}

// GetOrCreateSession retrieves or creates a TLS session by client random.
func (m *SessionManager) GetOrCreateSession(clientRandom []byte) *TLSSession {
	key := string(clientRandom)

	m.mu.RLock()
	session, exists := m.sessions[key]
	m.mu.RUnlock()

	if exists {
		return session
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock.
	if session, exists = m.sessions[key]; exists {
		return session
	}

	session = &TLSSession{
		ClientRandom:      clientRandom,
		DecryptedPayloads: make([][]byte, 0),
	}
	m.sessions[key] = session
	return session
}

// GetSession retrieves a TLS session by client random.
func (m *SessionManager) GetSession(clientRandom []byte) *TLSSession {
	key := string(clientRandom)
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[key]
}

// InitializeDecryptor sets up the decryptor for a session.
// Returns nil error on success, non-nil if keys are unavailable.
func (m *SessionManager) InitializeDecryptor(clientRandom []byte, version, cipherSuite uint16) error {
	session := m.GetOrCreateSession(clientRandom)

	session.mu.Lock()
	defer session.mu.Unlock()

	session.Version = version
	session.CipherSuite = cipherSuite

	// Convert clientRandom to fixed-size array.
	var cr [32]byte
	copy(cr[:], clientRandom)

	// Try to create decryptor based on version.
	if version == 0x0304 { // TLS 1.3
		secrets, err := m.keyLog.LookupTLS13Secrets(cr)
		if err != nil {
			return ErrKeyNotFound
		}
		dec, err := NewTLS13Decryptor(cipherSuite, secrets)
		if err != nil {
			return err
		}
		session.Decryptor = dec
	} else if version == 0x0303 { // TLS 1.2
		_, err := m.keyLog.LookupMasterSecret(cr)
		if err != nil {
			return ErrKeyNotFound
		}
		// For TLS 1.2, we need both client and server randoms.
		// This is typically extracted from handshake.
		// For now, create with just the master secret.
		// The actual decryptor init happens when we have both randoms.
	}

	return nil
}

// DecryptRecord decrypts a TLS record for the given session.
// isClientToServer indicates the direction of the traffic.
func (m *SessionManager) DecryptRecord(clientRandom []byte, record []byte, isClientToServer bool) ([]byte, error) {
	session := m.GetSession(clientRandom)
	if session == nil {
		return nil, ErrKeyNotFound
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	if session.Decryptor == nil {
		return nil, ErrKeyNotFound
	}

	plaintext, err := session.Decryptor.DecryptRecord(record, isClientToServer)
	if err != nil {
		return nil, err
	}

	session.DecryptedPayloads = append(session.DecryptedPayloads, plaintext)
	return plaintext, nil
}

// GetDecryptedPayloads returns all decrypted payloads for a session.
func (m *SessionManager) GetDecryptedPayloads(clientRandom []byte) [][]byte {
	session := m.GetSession(clientRandom)
	if session == nil {
		return nil
	}

	session.mu.Lock()
	defer session.mu.Unlock()

	result := make([][]byte, len(session.DecryptedPayloads))
	copy(result, session.DecryptedPayloads)
	return result
}

// SessionCount returns the number of tracked sessions.
func (m *SessionManager) SessionCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

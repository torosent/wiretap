package crypto

import (
	"bytes"
	"strings"
	"sync"
	"testing"
)

func TestNewSessionManager(t *testing.T) {
	keyLog := NewKeyLog()
	mgr := NewSessionManager(keyLog)

	if mgr == nil {
		t.Fatal("NewSessionManager returned nil")
	}
	if mgr.KeyLog() != keyLog {
		t.Error("KeyLog() returned wrong keylog")
	}
	if mgr.SessionCount() != 0 {
		t.Errorf("Expected 0 sessions, got %d", mgr.SessionCount())
	}
}

func TestSessionManager_GetOrCreateSession(t *testing.T) {
	keyLog := NewKeyLog()
	mgr := NewSessionManager(keyLog)

	clientRandom := make([]byte, 32)
	for i := range clientRandom {
		clientRandom[i] = byte(i)
	}

	// First call creates new session.
	session1 := mgr.GetOrCreateSession(clientRandom)
	if session1 == nil {
		t.Fatal("GetOrCreateSession returned nil")
	}
	if !bytes.Equal(session1.ClientRandom, clientRandom) {
		t.Error("Session has wrong ClientRandom")
	}
	if mgr.SessionCount() != 1 {
		t.Errorf("Expected 1 session, got %d", mgr.SessionCount())
	}

	// Second call returns same session.
	session2 := mgr.GetOrCreateSession(clientRandom)
	if session2 != session1 {
		t.Error("GetOrCreateSession returned different session for same clientRandom")
	}
	if mgr.SessionCount() != 1 {
		t.Errorf("Expected 1 session, got %d", mgr.SessionCount())
	}

	// Different clientRandom creates new session.
	clientRandom2 := make([]byte, 32)
	for i := range clientRandom2 {
		clientRandom2[i] = byte(i + 100)
	}
	session3 := mgr.GetOrCreateSession(clientRandom2)
	if session3 == session1 {
		t.Error("Different clientRandom should create new session")
	}
	if mgr.SessionCount() != 2 {
		t.Errorf("Expected 2 sessions, got %d", mgr.SessionCount())
	}
}

func TestSessionManager_GetSession(t *testing.T) {
	keyLog := NewKeyLog()
	mgr := NewSessionManager(keyLog)

	clientRandom := make([]byte, 32)

	// Get non-existent session returns nil.
	session := mgr.GetSession(clientRandom)
	if session != nil {
		t.Error("GetSession should return nil for non-existent session")
	}

	// Create session.
	created := mgr.GetOrCreateSession(clientRandom)

	// Now GetSession returns it.
	session = mgr.GetSession(clientRandom)
	if session != created {
		t.Error("GetSession should return the created session")
	}
}

func TestSessionManager_InitializeDecryptor_TLS13(t *testing.T) {
	clientRandom := make([]byte, 32)
	for i := range clientRandom {
		clientRandom[i] = byte(i)
	}
	serverTrafficSecret := make([]byte, 32)
	for i := range serverTrafficSecret {
		serverTrafficSecret[i] = byte(i + 50)
	}

	// Add TLS 1.3 keys first.
	keyLogData := "SERVER_TRAFFIC_SECRET_0 " +
		bytesToHex(clientRandom) + " " +
		bytesToHex(serverTrafficSecret)
	keyLog, err := LoadFromReader(strings.NewReader(keyLogData))
	if err != nil {
		t.Fatalf("LoadFromReader failed: %v", err)
	}

	mgr := NewSessionManager(keyLog)

	// Now initialization succeeds.
	err = mgr.InitializeDecryptor(clientRandom, 0x0304, TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Errorf("InitializeDecryptor failed: %v", err)
	}

	session := mgr.GetSession(clientRandom)
	if session == nil {
		t.Fatal("Session not found")
	}
	if session.Decryptor == nil {
		t.Error("Decryptor not initialized")
	}
	if session.Version != 0x0304 {
		t.Errorf("Expected version 0x0304, got 0x%04x", session.Version)
	}
	if session.CipherSuite != TLS_AES_128_GCM_SHA256 {
		t.Errorf("Expected cipher suite 0x1301, got 0x%04x", session.CipherSuite)
	}
}

func TestSessionManager_InitializeDecryptor_TLS13_NoKeys(t *testing.T) {
	keyLog := NewKeyLog()
	mgr := NewSessionManager(keyLog)

	clientRandom := make([]byte, 32)
	for i := range clientRandom {
		clientRandom[i] = byte(i)
	}

	// Without keys, initialization fails.
	err := mgr.InitializeDecryptor(clientRandom, 0x0304, TLS_AES_128_GCM_SHA256)
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

func TestSessionManager_InitializeDecryptor_TLS12(t *testing.T) {
	keyLog := NewKeyLog()
	mgr := NewSessionManager(keyLog)

	clientRandom := make([]byte, 32)
	for i := range clientRandom {
		clientRandom[i] = byte(i)
	}

	// TLS 1.2 without keys returns error.
	err := mgr.InitializeDecryptor(clientRandom, 0x0303, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
	// For TLS 1.2, we need master secret which isn't available.
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound for TLS 1.2 without keys, got %v", err)
	}
}

func TestSessionManager_DecryptRecord(t *testing.T) {
	keyLog := NewKeyLog()
	mgr := NewSessionManager(keyLog)

	clientRandom := make([]byte, 32)
	for i := range clientRandom {
		clientRandom[i] = byte(i)
	}

	// Decrypt without session fails.
	_, err := mgr.DecryptRecord(clientRandom, []byte{0x17, 0x03, 0x03, 0x00, 0x10}, false)
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}

	// Create session without decryptor.
	mgr.GetOrCreateSession(clientRandom)
	_, err = mgr.DecryptRecord(clientRandom, []byte{0x17, 0x03, 0x03, 0x00, 0x10}, false)
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound (no decryptor), got %v", err)
	}
}

func TestSessionManager_GetDecryptedPayloads(t *testing.T) {
	keyLog := NewKeyLog()
	mgr := NewSessionManager(keyLog)

	clientRandom := make([]byte, 32)

	// No session returns nil.
	payloads := mgr.GetDecryptedPayloads(clientRandom)
	if payloads != nil {
		t.Error("Expected nil for non-existent session")
	}

	// Create session.
	session := mgr.GetOrCreateSession(clientRandom)
	session.DecryptedPayloads = append(session.DecryptedPayloads, []byte("payload1"))
	session.DecryptedPayloads = append(session.DecryptedPayloads, []byte("payload2"))

	payloads = mgr.GetDecryptedPayloads(clientRandom)
	if len(payloads) != 2 {
		t.Errorf("Expected 2 payloads, got %d", len(payloads))
	}
	if string(payloads[0]) != "payload1" {
		t.Errorf("Expected 'payload1', got '%s'", string(payloads[0]))
	}
	if string(payloads[1]) != "payload2" {
		t.Errorf("Expected 'payload2', got '%s'", string(payloads[1]))
	}
}

func TestSessionManager_ConcurrentAccess(t *testing.T) {
	keyLog := NewKeyLog()
	mgr := NewSessionManager(keyLog)

	var wg sync.WaitGroup
	numGoroutines := 100

	// Concurrent GetOrCreateSession with same client random.
	clientRandom := make([]byte, 32)
	sessions := make([]*TLSSession, numGoroutines)

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			sessions[idx] = mgr.GetOrCreateSession(clientRandom)
		}(i)
	}
	wg.Wait()

	// All should return the same session.
	for i := 1; i < numGoroutines; i++ {
		if sessions[i] != sessions[0] {
			t.Error("Concurrent GetOrCreateSession returned different sessions")
			break
		}
	}
	if mgr.SessionCount() != 1 {
		t.Errorf("Expected 1 session, got %d", mgr.SessionCount())
	}
}

func TestTLSSession_AppendPayloads(t *testing.T) {
	session := &TLSSession{
		ClientRandom:      make([]byte, 32),
		DecryptedPayloads: make([][]byte, 0),
	}

	// Test concurrent payload appending.
	var wg sync.WaitGroup
	numGoroutines := 50

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			session.mu.Lock()
			session.DecryptedPayloads = append(session.DecryptedPayloads, []byte{byte(idx)})
			session.mu.Unlock()
		}(i)
	}
	wg.Wait()

	if len(session.DecryptedPayloads) != numGoroutines {
		t.Errorf("Expected %d payloads, got %d", numGoroutines, len(session.DecryptedPayloads))
	}
}

// bytesToHex converts bytes to hex string.
func bytesToHex(data []byte) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, len(data)*2)
	for i, b := range data {
		result[i*2] = hexChars[b>>4]
		result[i*2+1] = hexChars[b&0x0f]
	}
	return string(result)
}

package protocol

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/wiretap/wiretap/internal/crypto"
	"github.com/wiretap/wiretap/internal/model"
)

// ============================================
// TLSConnectionTracker Tests
// ============================================

func TestNewTLSConnectionTracker(t *testing.T) {
	tracker := NewTLSConnectionTracker()
	if tracker == nil {
		t.Fatal("NewTLSConnectionTracker returned nil")
	}
	if tracker.Count() != 0 {
		t.Errorf("expected empty tracker, got %d connections", tracker.Count())
	}
}

func TestTLSConnectionTracker_GetOrCreate(t *testing.T) {
	tracker := NewTLSConnectionTracker()

	// First call should create new state
	state1 := tracker.GetOrCreate(12345)
	if state1 == nil {
		t.Fatal("GetOrCreate returned nil")
	}
	if tracker.Count() != 1 {
		t.Errorf("expected 1 connection, got %d", tracker.Count())
	}

	// Second call with same hash should return same state
	state2 := tracker.GetOrCreate(12345)
	if state1 != state2 {
		t.Error("GetOrCreate should return same state for same hash")
	}
	if tracker.Count() != 1 {
		t.Errorf("expected 1 connection, got %d", tracker.Count())
	}

	// Different hash should create new state
	state3 := tracker.GetOrCreate(67890)
	if state1 == state3 {
		t.Error("GetOrCreate should return different state for different hash")
	}
	if tracker.Count() != 2 {
		t.Errorf("expected 2 connections, got %d", tracker.Count())
	}
}

func TestTLSConnectionTracker_Get(t *testing.T) {
	tracker := NewTLSConnectionTracker()

	// Get on non-existent hash should return nil
	if state := tracker.Get(12345); state != nil {
		t.Error("Get should return nil for non-existent hash")
	}

	// Create a state
	tracker.GetOrCreate(12345)

	// Now Get should return the state
	if state := tracker.Get(12345); state == nil {
		t.Error("Get should return state for existing hash")
	}
}

func TestTLSConnectionTracker_Clear(t *testing.T) {
	tracker := NewTLSConnectionTracker()
	tracker.GetOrCreate(12345)
	tracker.GetOrCreate(67890)

	if tracker.Count() != 2 {
		t.Fatalf("expected 2 connections, got %d", tracker.Count())
	}

	tracker.Clear()

	if tracker.Count() != 0 {
		t.Errorf("expected 0 connections after Clear, got %d", tracker.Count())
	}
}

func TestConcurrentConnectionTracking(t *testing.T) {
	tracker := NewTLSConnectionTracker()

	// Simulate concurrent access
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				hash := uint64(id*1000 + j)
				state := tracker.GetOrCreate(hash)
				state.HasClientHello = true
				_ = tracker.Get(hash)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should have 1000 connections
	if tracker.Count() != 1000 {
		t.Errorf("Expected 1000 connections, got %d", tracker.Count())
	}
}

// ============================================
// TLSConnectionState Tests
// ============================================

func TestTLSConnectionState_ClientRandomHex(t *testing.T) {
	state := &TLSConnectionState{
		ClientRandom: [32]byte{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
			0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
		},
	}

	hex := state.ClientRandomHex()
	expected := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	if hex != expected {
		t.Errorf("ClientRandomHex = %q, want %q", hex, expected)
	}
}

func TestTLSConnectionState_ServerRandomHex(t *testing.T) {
	state := &TLSConnectionState{
		ServerRandom: [32]byte{
			0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
			0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
			0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
			0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
		},
	}

	hex := state.ServerRandomHex()
	expected := "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	if hex != expected {
		t.Errorf("ServerRandomHex = %q, want %q", hex, expected)
	}
}

func TestTLSConnectionState_ZeroValues(t *testing.T) {
	state := &TLSConnectionState{}

	if state.HasClientHello {
		t.Error("HasClientHello should be false")
	}
	if state.HasServerHello {
		t.Error("HasServerHello should be false")
	}
	if state.DecryptorInitialized {
		t.Error("DecryptorInitialized should be false")
	}
	if state.CipherSuite != 0 {
		t.Error("CipherSuite should be 0")
	}
	if state.Version != 0 {
		t.Error("Version should be 0")
	}
	if state.SNI != "" {
		t.Error("SNI should be empty")
	}

	// Hex functions should still work
	clientHex := state.ClientRandomHex()
	if len(clientHex) != 64 {
		t.Errorf("ClientRandomHex length = %d, want 64", len(clientHex))
	}
}

func TestTLSConnectionState_FullHandshake(t *testing.T) {
	state := &TLSConnectionState{}

	// Simulate ClientHello
	state.ClientRandom = [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	state.SNI = "example.com"
	state.HasClientHello = true

	// Simulate ServerHello
	state.ServerRandom = [32]byte{32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	state.CipherSuite = 0x1301
	state.Version = 0x0304
	state.HasServerHello = true

	if !state.HasClientHello {
		t.Error("HasClientHello should be true")
	}
	if !state.HasServerHello {
		t.Error("HasServerHello should be true")
	}
	if state.CipherSuite != 0x1301 {
		t.Errorf("CipherSuite = %x, want %x", state.CipherSuite, 0x1301)
	}
	if state.Version != 0x0304 {
		t.Errorf("Version = %x, want %x", state.Version, 0x0304)
	}
	if state.SNI != "example.com" {
		t.Errorf("SNI = %q, want %q", state.SNI, "example.com")
	}
}

// ============================================
// TLSDecryptingDissector Tests
// ============================================

func TestNewTLSDecryptingDissector(t *testing.T) {
	keyLog := crypto.NewKeyLog()
	mgr := crypto.NewSessionManager(keyLog)
	innerReg := NewRegistry()

	dissector := NewTLSDecryptingDissector(mgr, innerReg)

	if dissector == nil {
		t.Fatal("NewTLSDecryptingDissector returned nil")
	}
	if dissector.Name() != "TLS+Decrypt" {
		t.Errorf("Expected name 'TLS+Decrypt', got '%s'", dissector.Name())
	}
	if dissector.SessionManager() != mgr {
		t.Error("SessionManager() returned wrong manager")
	}
	if dissector.connectionTracker == nil {
		t.Error("connectionTracker should not be nil")
	}
}

func TestNewTLSDecryptingDissector_NilSessionManager(t *testing.T) {
	d := NewTLSDecryptingDissector(nil, nil)
	if d == nil {
		t.Fatal("NewTLSDecryptingDissector returned nil")
	}
	if d.tlsDissector == nil {
		t.Error("tlsDissector should not be nil")
	}
	if d.connectionTracker == nil {
		t.Error("connectionTracker should not be nil")
	}
	if d.sessionManager != nil {
		t.Error("sessionManager should be nil when not provided")
	}
}

func TestTLSDecryptingDissector_Detect(t *testing.T) {
	dissector := NewTLSDecryptingDissector(nil, nil)

	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name: "TLS ClientHello",
			data: []byte{
				0x16, 0x03, 0x01, 0x00, 0x05,
				0x01, 0x00, 0x00, 0x01, 0x00,
			},
			expected: true,
		},
		{
			name: "TLS Application Data",
			data: []byte{
				0x17, 0x03, 0x03, 0x00, 0x10,
			},
			expected: true,
		},
		{
			name:     "HTTP data",
			data:     []byte("GET / HTTP/1.1\r\n"),
			expected: false,
		},
		{
			name:     "Empty",
			data:     []byte{},
			expected: false,
		},
		{
			name:     "Too short",
			data:     []byte{0x16, 0x03},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dissector.Detect(tt.data)
			if result != tt.expected {
				t.Errorf("Detect() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestTLSDecryptingDissector_ParseWithoutSessionManager(t *testing.T) {
	dissector := NewTLSDecryptingDissector(nil, nil)

	pkt := &model.Packet{
		Timestamp: time.Now(),
		SrcIP:     net.ParseIP("192.168.1.100"),
		DstIP:     net.ParseIP("93.184.216.34"),
		SrcPort:   54321,
		DstPort:   443,
	}

	// TLS application data record.
	tlsRecord := []byte{
		0x17,       // Application data
		0x03, 0x03, // TLS 1.2
		0x00, 0x10, // Length 16
	}
	tlsRecord = append(tlsRecord, make([]byte, 16)...)

	err := dissector.Parse(tlsRecord, pkt)
	if err != nil {
		t.Errorf("Parse() error = %v", err)
	}

	// Without session manager, no decryption should happen.
	if pkt.TLSDecrypted {
		t.Error("TLSDecrypted should be false without session manager")
	}
}

func TestTLSDecryptingDissector_Parse_UpdatesConnectionState(t *testing.T) {
	keyLog := crypto.NewKeyLog()
	sessionMgr := crypto.NewSessionManager(keyLog)
	d := NewTLSDecryptingDissector(sessionMgr, nil)

	data := buildClientHelloForDecrypt("test.example.com")
	pkt := &model.Packet{
		Timestamp: time.Now(),
		SrcIP:     net.ParseIP("10.0.0.1"),
		DstIP:     net.ParseIP("10.0.0.2"),
		SrcPort:   12345,
		DstPort:   443,
	}

	err := d.Parse(data, pkt)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	flowHash := pkt.FlowHash()
	state := d.ConnectionStateByFlow(flowHash)
	if state == nil {
		t.Fatal("ConnectionStateByFlow returned nil")
	}

	if !state.HasClientHello {
		t.Error("HasClientHello should be true after parsing ClientHello")
	}

	if state.SNI != "test.example.com" {
		t.Errorf("SNI = %q, want %q", state.SNI, "test.example.com")
	}

	emptyRandom := [32]byte{}
	if state.ClientRandom == emptyRandom {
		t.Error("ClientRandom should be set")
	}
}

func TestTLSDecryptingDissector_Parse_ServerHello(t *testing.T) {
	keyLog := crypto.NewKeyLog()
	sessionMgr := crypto.NewSessionManager(keyLog)
	d := NewTLSDecryptingDissector(sessionMgr, nil)

	// First send ClientHello
	clientHello := buildClientHelloForDecrypt("server.example.com")
	pkt1 := &model.Packet{
		Timestamp: time.Now(),
		SrcIP:     net.ParseIP("192.168.1.50"),
		DstIP:     net.ParseIP("203.0.113.50"),
		SrcPort:   55555,
		DstPort:   443,
	}
	d.Parse(clientHello, pkt1)

	// Then send ServerHello (same flow, reversed direction)
	serverHello := buildServerHelloForDecrypt()
	pkt2 := &model.Packet{
		Timestamp: time.Now().Add(time.Millisecond),
		SrcIP:     net.ParseIP("203.0.113.50"),
		DstIP:     net.ParseIP("192.168.1.50"),
		SrcPort:   443,
		DstPort:   55555,
	}
	d.Parse(serverHello, pkt2)

	// Both packets should have same flow hash (direction-independent)
	hash1 := pkt1.FlowHash()
	hash2 := pkt2.FlowHash()
	if hash1 != hash2 {
		t.Errorf("Flow hashes should match: %d vs %d", hash1, hash2)
	}

	state := d.ConnectionStateByFlow(hash1)
	if state == nil {
		t.Fatal("ConnectionStateByFlow returned nil")
	}

	if !state.HasClientHello {
		t.Error("HasClientHello should be true")
	}

	if !state.HasServerHello {
		t.Error("HasServerHello should be true")
	}

	if state.CipherSuite == 0 {
		t.Error("CipherSuite should be set from ServerHello")
	}
}

func TestTLSDecryptingDissector_SetSessionManager(t *testing.T) {
	dissector := NewTLSDecryptingDissector(nil, nil)

	if dissector.SessionManager() != nil {
		t.Error("SessionManager() should return nil initially")
	}

	keyLog := crypto.NewKeyLog()
	mgr := crypto.NewSessionManager(keyLog)
	dissector.SetSessionManager(mgr)

	if dissector.SessionManager() != mgr {
		t.Error("SessionManager() should return the set manager")
	}
}

func TestTLSDecryptingDissector_ConnectionTracker(t *testing.T) {
	d := NewTLSDecryptingDissector(nil, nil)

	tracker := d.ConnectionTracker()
	if tracker == nil {
		t.Fatal("ConnectionTracker() should not return nil")
	}

	pkt := &model.Packet{
		Timestamp: time.Now(),
		SrcIP:     net.ParseIP("1.2.3.4"),
		DstIP:     net.ParseIP("5.6.7.8"),
		SrcPort:   1234,
		DstPort:   443,
	}
	data := buildClientHelloForDecrypt("tracker.test.com")
	d.Parse(data, pkt)

	if tracker.Count() != 1 {
		t.Errorf("Tracker should have 1 connection, got %d", tracker.Count())
	}
}

func TestTLSDecryptingDissector_DetermineDirection(t *testing.T) {
	d := NewTLSDecryptingDissector(nil, nil)

	tests := []struct {
		name     string
		srcPort  uint16
		dstPort  uint16
		expected bool // true = client-to-server
	}{
		{
			name:     "Client to HTTPS server",
			srcPort:  54321,
			dstPort:  443,
			expected: true,
		},
		{
			name:     "Server to HTTPS client",
			srcPort:  443,
			dstPort:  54321,
			expected: false,
		},
		{
			name:     "Client to HTTPS alt server",
			srcPort:  54321,
			dstPort:  8443,
			expected: true,
		},
		{
			name:     "Client to IMAPS server",
			srcPort:  12345,
			dstPort:  993,
			expected: true,
		},
		{
			name:     "Unknown ports - lower dst",
			srcPort:  50000,
			dstPort:  1234,
			expected: true,
		},
		{
			name:     "Unknown ports - lower src",
			srcPort:  1234,
			dstPort:  50000,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := &model.Packet{
				SrcPort: tt.srcPort,
				DstPort: tt.dstPort,
			}
			result := d.determineDirection(pkt)
			if result != tt.expected {
				t.Errorf("determineDirection() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestTLSDecryptingDissector_TryInitializeSession(t *testing.T) {
	// Create keylog with TLS 1.3 secrets.
	clientRandom := make([]byte, 32)
	for i := range clientRandom {
		clientRandom[i] = byte(i)
	}
	serverTrafficSecret := make([]byte, 32)
	for i := range serverTrafficSecret {
		serverTrafficSecret[i] = byte(i + 50)
	}

	keyLogData := "SERVER_TRAFFIC_SECRET_0 " +
		bytesToHex(clientRandom) + " " +
		bytesToHex(serverTrafficSecret)
	keyLog, err := crypto.LoadFromReader(strings.NewReader(keyLogData))
	if err != nil {
		t.Fatalf("LoadFromReader failed: %v", err)
	}

	mgr := crypto.NewSessionManager(keyLog)
	dissector := NewTLSDecryptingDissector(mgr, nil)

	// Create TLSInfo with ClientHello and ServerHello.
	var random [32]byte
	copy(random[:], clientRandom)

	tlsInfo := &model.TLSInfo{
		Version: model.TLSVersion13,
		ClientHello: &model.TLSClientHello{
			Random: random,
		},
		ServerHello: &model.TLSServerHello{
			CipherSuite: model.TLS_AES_128_GCM_SHA256,
		},
	}

	dissector.tryInitializeSession(tlsInfo)

	session := mgr.GetSession(clientRandom)
	if session == nil {
		t.Error("Session was not created")
	}
	if session.Decryptor == nil {
		t.Error("Decryptor was not initialized")
	}
}

func TestTLSDecryptingDissector_TryInitializeSession_NoCipherSuite(t *testing.T) {
	keyLog := crypto.NewKeyLog()
	mgr := crypto.NewSessionManager(keyLog)
	dissector := NewTLSDecryptingDissector(mgr, nil)

	// TLSInfo without ServerHello (no cipher suite).
	tlsInfo := &model.TLSInfo{
		Version: model.TLSVersion13,
		ClientHello: &model.TLSClientHello{
			Random: [32]byte{1, 2, 3},
		},
	}

	dissector.tryInitializeSession(tlsInfo)

	session := mgr.GetSession([]byte{1, 2, 3})
	if session != nil && session.Decryptor != nil {
		t.Error("Decryptor should not be initialized without cipher suite")
	}
}

func TestTLSDecryptingDissector_TryDecryptRecords_NoClientHello(t *testing.T) {
	keyLog := crypto.NewKeyLog()
	mgr := crypto.NewSessionManager(keyLog)
	dissector := NewTLSDecryptingDissector(mgr, nil)

	pkt := &model.Packet{
		TLSInfo: &model.TLSInfo{}, // No ClientHello.
	}

	result := dissector.tryDecryptRecords([]byte{0x17, 0x03, 0x03, 0x00, 0x10}, pkt)
	if result != nil {
		t.Error("Should return nil when ClientHello is missing")
	}
}

func TestTLSDecryptingDissector_TryDecryptRecordsWithState_NoClientHello(t *testing.T) {
	keyLog := crypto.NewKeyLog()
	sessionMgr := crypto.NewSessionManager(keyLog)
	d := NewTLSDecryptingDissector(sessionMgr, nil)

	state := &TLSConnectionState{
		HasClientHello: false,
	}

	pkt := &model.Packet{
		SrcPort: 12345,
		DstPort: 443,
	}

	decrypted := d.tryDecryptRecordsWithState([]byte{0x17, 0x03, 0x03, 0x00, 0x10}, pkt, state)
	if decrypted != nil {
		t.Error("tryDecryptRecordsWithState should return nil without ClientHello")
	}
}

func TestTLSDecryptingDissector_TryDecryptRecords_InvalidRecords(t *testing.T) {
	keyLog := crypto.NewKeyLog()
	sessionMgr := crypto.NewSessionManager(keyLog)
	d := NewTLSDecryptingDissector(sessionMgr, nil)

	state := &TLSConnectionState{
		ClientRandom:   [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		HasClientHello: true,
	}

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "Too short header",
			data: []byte{0x17, 0x03, 0x03},
		},
		{
			name: "Record too large",
			data: []byte{
				0x17, 0x03, 0x03, 0xFF, 0xFF,
			},
		},
		{
			name: "Incomplete record",
			data: []byte{
				0x17, 0x03, 0x03, 0x00, 0x10,
				0x00, 0x01, 0x02,
			},
		},
		{
			name: "Non-application data",
			data: []byte{
				0x16, 0x03, 0x03, 0x00, 0x05,
				0x00, 0x01, 0x02, 0x03, 0x04,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := &model.Packet{
				SrcPort: 12345,
				DstPort: 443,
			}
			decrypted := d.tryDecryptRecordsWithState(tt.data, pkt, state)
			if decrypted != nil && len(decrypted) > 0 {
				t.Error("Expected no decryption for invalid record")
			}
		})
	}
}

func TestTLSDecryptingDissector_TryInitializeDecryptor_NoClientHello(t *testing.T) {
	keyLog := crypto.NewKeyLog()
	sessionMgr := crypto.NewSessionManager(keyLog)
	d := NewTLSDecryptingDissector(sessionMgr, nil)

	state := &TLSConnectionState{
		HasClientHello: false,
	}

	err := d.tryInitializeDecryptor(state)
	if err != crypto.ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

func TestTLSDecryptingDissector_EmptyPacket(t *testing.T) {
	d := NewTLSDecryptingDissector(nil, nil)

	pkt := &model.Packet{
		Timestamp: time.Now(),
		SrcIP:     net.ParseIP("1.1.1.1"),
		DstIP:     net.ParseIP("2.2.2.2"),
		SrcPort:   11111,
		DstPort:   443,
	}

	err := d.Parse([]byte{}, pkt)
	if err != nil {
		t.Errorf("Parse on empty data should not error: %v", err)
	}
}

func TestTLSDecryptingDissector_MultipleRecords(t *testing.T) {
	d := NewTLSDecryptingDissector(nil, nil)

	var data []byte
	clientHello := buildClientHelloForDecrypt("multi.example.com")
	data = append(data, clientHello...)

	pkt := &model.Packet{
		Timestamp: time.Now(),
		SrcIP:     net.ParseIP("1.1.1.1"),
		DstIP:     net.ParseIP("2.2.2.2"),
		SrcPort:   11111,
		DstPort:   443,
	}

	err := d.Parse(data, pkt)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if pkt.TLSInfo == nil {
		t.Error("TLSInfo should be set")
	}
}

// ============================================
// DecryptingRegistry Tests
// ============================================

func TestNewDecryptingRegistry(t *testing.T) {
	keyLog := crypto.NewKeyLog()
	sessionMgr := crypto.NewSessionManager(keyLog)

	registry := NewDecryptingRegistry(sessionMgr)
	if registry == nil {
		t.Fatal("NewDecryptingRegistry returned nil")
	}

	if registry.SessionManager() != sessionMgr {
		t.Error("SessionManager should be set")
	}

	tlsDecrypt := registry.TLSDecryptingDissector()
	if tlsDecrypt == nil {
		t.Error("TLSDecryptingDissector should be set")
	}

	names := registry.List()
	found := false
	for _, name := range names {
		if name == "TLS+Decrypt" {
			found = true
			break
		}
	}
	if !found {
		t.Error("TLS+Decrypt dissector should be in registry")
	}

	for _, name := range names {
		if name == "TLS" {
			t.Error("Regular TLS dissector should not be in decrypting registry")
		}
	}
}

func TestNewDecryptingRegistry_InnerRegistry(t *testing.T) {
	keyLog := crypto.NewKeyLog()
	sessionMgr := crypto.NewSessionManager(keyLog)
	registry := NewDecryptingRegistry(sessionMgr)

	tlsDecrypt := registry.TLSDecryptingDissector()
	if tlsDecrypt == nil {
		t.Fatal("TLSDecryptingDissector is nil")
	}

	if tlsDecrypt.innerRegistry == nil {
		t.Fatal("innerRegistry should not be nil")
	}

	innerNames := tlsDecrypt.innerRegistry.List()
	hasHTTP2 := false
	hasHTTP1 := false
	for _, name := range innerNames {
		if name == "HTTP/2" {
			hasHTTP2 = true
		}
		if name == "HTTP/1.x" {
			hasHTTP1 = true
		}
	}

	if !hasHTTP2 {
		t.Error("Inner registry should have HTTP/2 dissector")
	}
	if !hasHTTP1 {
		t.Error("Inner registry should have HTTP/1.x dissector")
	}
}

func TestDecryptingRegistry_DetectsTLS(t *testing.T) {
	keyLog := crypto.NewKeyLog()
	sessionMgr := crypto.NewSessionManager(keyLog)
	registry := NewDecryptingRegistry(sessionMgr)

	tlsData := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00}
	d := registry.Detect(tlsData)
	if d == nil {
		t.Fatal("Should detect TLS data")
	}
	if d.Name() != "TLS+Decrypt" {
		t.Errorf("Expected TLS+Decrypt, got %s", d.Name())
	}
}

func TestDecryptingRegistry_ParsesTLS(t *testing.T) {
	keyLog := crypto.NewKeyLog()
	sessionMgr := crypto.NewSessionManager(keyLog)
	registry := NewDecryptingRegistry(sessionMgr)

	data := buildClientHelloForDecrypt("registry.test.com")
	pkt := &model.Packet{
		Timestamp: time.Now(),
		SrcIP:     net.ParseIP("10.1.1.1"),
		DstIP:     net.ParseIP("10.2.2.2"),
		SrcPort:   11111,
		DstPort:   443,
	}

	err := registry.Parse(data, pkt)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if pkt.TLSInfo == nil {
		t.Error("TLSInfo should be set")
	}
	if pkt.TLSInfo.SNI() != "registry.test.com" {
		t.Errorf("SNI = %q, want %q", pkt.TLSInfo.SNI(), "registry.test.com")
	}
}

func TestDecryptingRegistryListDissectors(t *testing.T) {
	keyLog := crypto.NewKeyLog()
	sessionMgr := crypto.NewSessionManager(keyLog)
	registry := NewDecryptingRegistry(sessionMgr)

	names := registry.List()

	expectedDissectors := []string{"HTTP/2", "HTTP/1.x", "TLS+Decrypt", "DNS"}

	for _, expected := range expectedDissectors {
		found := false
		for _, name := range names {
			if name == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected dissector %q not found in list: %v", expected, names)
		}
	}
}

func TestDecryptingRegistry_NilSessionManager(t *testing.T) {
	registry := NewRegistry()

	if registry.SessionManager() != nil {
		t.Error("Standard registry should not have session manager")
	}

	if registry.TLSDecryptingDissector() != nil {
		t.Error("Standard registry should not have TLSDecryptingDissector")
	}
}

// ============================================
// Helper functions
// ============================================

func bytesToHex(data []byte) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, len(data)*2)
	for i, b := range data {
		result[i*2] = hexChars[b>>4]
		result[i*2+1] = hexChars[b&0x0f]
	}
	return string(result)
}

func buildClientHelloForDecrypt(sni string) []byte {
	var clientHello []byte

	// Version (TLS 1.2 in handshake)
	clientHello = append(clientHello, 0x03, 0x03)

	// Random (32 bytes) - non-zero for testing
	for i := 0; i < 32; i++ {
		clientHello = append(clientHello, byte(i+1))
	}

	// Session ID length (0)
	clientHello = append(clientHello, 0x00)

	// Cipher suites (2 suites)
	clientHello = append(clientHello, 0x00, 0x04)
	clientHello = append(clientHello, 0x13, 0x01) // TLS_AES_128_GCM_SHA256
	clientHello = append(clientHello, 0xC0, 0x2F) // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

	// Compression methods
	clientHello = append(clientHello, 0x01, 0x00)

	// Extensions
	extensions := buildSNIExtensionForDecrypt(sni)
	clientHello = append(clientHello, byte(len(extensions)>>8), byte(len(extensions)))
	clientHello = append(clientHello, extensions...)

	// Wrap in handshake message
	handshake := []byte{0x01}
	handshake = append(handshake, byte(len(clientHello)>>16), byte(len(clientHello)>>8), byte(len(clientHello)))
	handshake = append(handshake, clientHello...)

	// Wrap in TLS record
	record := []byte{0x16, 0x03, 0x01}
	record = append(record, byte(len(handshake)>>8), byte(len(handshake)))
	record = append(record, handshake...)

	return record
}

func buildSNIExtensionForDecrypt(name string) []byte {
	var ext []byte

	// Extension type (0x0000 = server_name)
	ext = append(ext, 0x00, 0x00)

	// Extension length
	nameLen := len(name)
	extDataLen := 5 + nameLen
	ext = append(ext, byte(extDataLen>>8), byte(extDataLen))

	// Server name list length
	listLen := 3 + nameLen
	ext = append(ext, byte(listLen>>8), byte(listLen))

	// Server name type (0 = hostname)
	ext = append(ext, 0x00)

	// Server name length and value
	ext = append(ext, byte(nameLen>>8), byte(nameLen))
	ext = append(ext, []byte(name)...)

	return ext
}

func buildServerHelloForDecrypt() []byte {
	var serverHello []byte

	// Version (TLS 1.2)
	serverHello = append(serverHello, 0x03, 0x03)

	// Random (32 bytes) - non-zero for testing
	for i := 0; i < 32; i++ {
		serverHello = append(serverHello, byte(i+0x80))
	}

	// Session ID length (0)
	serverHello = append(serverHello, 0x00)

	// Cipher suite
	serverHello = append(serverHello, 0x13, 0x01) // TLS_AES_128_GCM_SHA256

	// Compression method
	serverHello = append(serverHello, 0x00)

	// Extensions length (0)
	serverHello = append(serverHello, 0x00, 0x00)

	// Wrap in handshake message
	handshake := []byte{0x02}
	handshake = append(handshake, byte(len(serverHello)>>16), byte(len(serverHello)>>8), byte(len(serverHello)))
	handshake = append(handshake, serverHello...)

	// Wrap in TLS record
	record := []byte{0x16, 0x03, 0x03}
	record = append(record, byte(len(handshake)>>8), byte(len(handshake)))
	record = append(record, handshake...)

	return record
}

// ============================================
// Additional tests for high coverage
// ============================================

func TestTLSDecryptingDissector_Parse_WithSessionManager(t *testing.T) {
	keyLog := crypto.NewKeyLog()
	sessionMgr := crypto.NewSessionManager(keyLog)
	innerRegistry := NewRegistry()
	d := NewTLSDecryptingDissector(sessionMgr, innerRegistry)

	pkt := &model.Packet{
		Timestamp: time.Now(),
		SrcIP:     net.ParseIP("10.0.0.1"),
		DstIP:     net.ParseIP("10.0.0.2"),
		SrcPort:   54321,
		DstPort:   443,
	}

	// Build and parse ClientHello
	clientHello := buildClientHelloForDecrypt("session.test.com")
	err := d.Parse(clientHello, pkt)
	if err != nil {
		t.Fatalf("Parse ClientHello failed: %v", err)
	}

	// Verify connection state was created
	tracker := d.ConnectionTracker()
	if tracker.Count() != 1 {
		t.Errorf("Expected 1 connection, got %d", tracker.Count())
	}

	// Verify TLSInfo was populated
	if pkt.TLSInfo == nil {
		t.Fatal("TLSInfo should not be nil")
	}

	// Parse ServerHello on same connection
	pkt2 := &model.Packet{
		Timestamp: time.Now(),
		SrcIP:     net.ParseIP("10.0.0.2"),
		DstIP:     net.ParseIP("10.0.0.1"),
		SrcPort:   443,
		DstPort:   54321,
	}
	serverHello := buildServerHelloForDecrypt()
	err = d.Parse(serverHello, pkt2)
	if err != nil {
		t.Fatalf("Parse ServerHello failed: %v", err)
	}

	// Still 1 connection (bidirectional)
	if tracker.Count() != 1 {
		t.Errorf("Expected 1 connection after ServerHello, got %d", tracker.Count())
	}

	// Verify state has both hello messages
	state := d.ConnectionStateByFlow(pkt.FlowHash())
	if state == nil {
		t.Fatal("Connection state should exist")
	}
	if !state.HasClientHello {
		t.Error("State should have ClientHello")
	}
	if !state.HasServerHello {
		t.Error("State should have ServerHello")
	}
}

func TestTLSDecryptingDissector_Parse_ApplicationData(t *testing.T) {
	keyLog := crypto.NewKeyLog()
	sessionMgr := crypto.NewSessionManager(keyLog)
	d := NewTLSDecryptingDissector(sessionMgr, nil)

	pkt := &model.Packet{
		Timestamp: time.Now(),
		SrcIP:     net.ParseIP("192.168.1.1"),
		DstIP:     net.ParseIP("192.168.1.2"),
		SrcPort:   45678,
		DstPort:   443,
	}

	// Build TLS application data record (0x17)
	appData := []byte{
		0x17, 0x03, 0x03, 0x00, 0x10, // TLS application data, length 16
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	}

	err := d.Parse(appData, pkt)
	if err != nil {
		t.Fatalf("Parse application data failed: %v", err)
	}

	// Without keys, decryption should not succeed
	if pkt.TLSDecrypted {
		t.Error("Should not be marked as decrypted without keys")
	}
}

func TestTLSDecryptingDissector_Parse_MultipleConnections(t *testing.T) {
	keyLog := crypto.NewKeyLog()
	sessionMgr := crypto.NewSessionManager(keyLog)
	d := NewTLSDecryptingDissector(sessionMgr, nil)

	// Create 3 different connections
	connections := []struct {
		srcIP   string
		dstIP   string
		srcPort uint16
		dstPort uint16
		sni     string
	}{
		{"10.0.0.1", "10.0.0.100", 40001, 443, "conn1.test.com"},
		{"10.0.0.2", "10.0.0.100", 40002, 443, "conn2.test.com"},
		{"10.0.0.3", "10.0.0.100", 40003, 443, "conn3.test.com"},
	}

	for _, conn := range connections {
		pkt := &model.Packet{
			Timestamp: time.Now(),
			SrcIP:     net.ParseIP(conn.srcIP),
			DstIP:     net.ParseIP(conn.dstIP),
			SrcPort:   conn.srcPort,
			DstPort:   conn.dstPort,
		}
		clientHello := buildClientHelloForDecrypt(conn.sni)
		d.Parse(clientHello, pkt)
	}

	tracker := d.ConnectionTracker()
	if tracker.Count() != 3 {
		t.Errorf("Expected 3 connections, got %d", tracker.Count())
	}

	// Verify each connection has correct SNI
	for _, conn := range connections {
		pkt := &model.Packet{
			SrcIP:   net.ParseIP(conn.srcIP),
			DstIP:   net.ParseIP(conn.dstIP),
			SrcPort: conn.srcPort,
			DstPort: conn.dstPort,
		}
		state := d.ConnectionStateByFlow(pkt.FlowHash())
		if state == nil {
			t.Errorf("Connection %s should exist", conn.sni)
			continue
		}
		if state.SNI != conn.sni {
			t.Errorf("Expected SNI %s, got %s", conn.sni, state.SNI)
		}
	}
}

func TestTLSDecryptingDissector_Parse_InvalidData(t *testing.T) {
	d := NewTLSDecryptingDissector(nil, nil)

	pkt := &model.Packet{
		Timestamp: time.Now(),
		SrcIP:     net.ParseIP("1.2.3.4"),
		DstIP:     net.ParseIP("5.6.7.8"),
		SrcPort:   12345,
		DstPort:   443,
	}

	// Test with various invalid data
	testCases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"too short", []byte{0x16, 0x03}},
		{"invalid content type", []byte{0xFF, 0x03, 0x03, 0x00, 0x01, 0x00}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := d.Parse(tc.data, pkt)
			// Should not error (graceful handling)
			if err != nil {
				t.Errorf("Parse should handle %s gracefully, got: %v", tc.name, err)
			}
		})
	}
}

func TestTLSConnectionState_RandomHex(t *testing.T) {
	state := &TLSConnectionState{}

	// Initial state - should return empty hex strings
	if state.ClientRandomHex() != "0000000000000000000000000000000000000000000000000000000000000000" {
		t.Error("ClientRandomHex should return 64 zeros for zero array")
	}
	if state.ServerRandomHex() != "0000000000000000000000000000000000000000000000000000000000000000" {
		t.Error("ServerRandomHex should return 64 zeros for zero array")
	}

	// Set values
	for i := 0; i < 32; i++ {
		state.ClientRandom[i] = byte(i)
		state.ServerRandom[i] = byte(i + 0x80)
	}
	state.HasClientHello = true
	state.HasServerHello = true

	clientHex := state.ClientRandomHex()
	if len(clientHex) != 64 {
		t.Errorf("ClientRandomHex should be 64 chars, got %d", len(clientHex))
	}
	if clientHex[:4] != "0001" {
		t.Errorf("ClientRandomHex should start with 0001, got %s", clientHex[:4])
	}

	serverHex := state.ServerRandomHex()
	if len(serverHex) != 64 {
		t.Errorf("ServerRandomHex should be 64 chars, got %d", len(serverHex))
	}
	if serverHex[:4] != "8081" {
		t.Errorf("ServerRandomHex should start with 8081, got %s", serverHex[:4])
	}
}

func TestDissectorRegistry_Detect_NoMatch(t *testing.T) {
	registry := NewRegistry()

	// Data that doesn't match any dissector
	randomData := []byte{0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A}
	d := registry.Detect(randomData)
	if d != nil {
		t.Errorf("Should not match any dissector, but got: %s", d.Name())
	}
}

func TestDissectorRegistry_Parse_NoMatch(t *testing.T) {
	registry := NewRegistry()

	pkt := &model.Packet{
		Timestamp: time.Now(),
	}

	// Data that doesn't match any dissector
	randomData := []byte{0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A}
	err := registry.Parse(randomData, pkt)
	if err != nil {
		t.Errorf("Parse should return nil for no matching dissector, got: %v", err)
	}
}

func TestNewDecryptingRegistry_VerifyOrder(t *testing.T) {
	keyLog := crypto.NewKeyLog()
	sessionMgr := crypto.NewSessionManager(keyLog)
	registry := NewDecryptingRegistry(sessionMgr)

	// TLS+Decrypt should be first to avoid HTTP/2 false positives
	names := registry.List()
	if len(names) < 1 {
		t.Fatal("Registry should have dissectors")
	}
	if names[0] != "TLS+Decrypt" {
		t.Errorf("First dissector should be TLS+Decrypt, got %s", names[0])
	}
}

func TestTLSDecryptingDissector_ClearTracker(t *testing.T) {
	d := NewTLSDecryptingDissector(nil, nil)
	tracker := d.ConnectionTracker()

	// Add some connections
	for i := 0; i < 5; i++ {
		pkt := &model.Packet{
			SrcIP:   net.ParseIP("10.0.0.1"),
			DstIP:   net.ParseIP("10.0.0.2"),
			SrcPort: uint16(10000 + i),
			DstPort: 443,
		}
		tracker.GetOrCreate(pkt.FlowHash())
	}

	if tracker.Count() != 5 {
		t.Errorf("Expected 5 connections, got %d", tracker.Count())
	}

	// Clear and verify
	tracker.Clear()
	if tracker.Count() != 0 {
		t.Errorf("Expected 0 connections after clear, got %d", tracker.Count())
	}
}

func TestTLSDecryptingDissector_UpdateStateIdempotent(t *testing.T) {
	d := NewTLSDecryptingDissector(nil, nil)

	pkt := &model.Packet{
		Timestamp: time.Now(),
		SrcIP:     net.ParseIP("172.16.0.1"),
		DstIP:     net.ParseIP("172.16.0.2"),
		SrcPort:   55555,
		DstPort:   443,
	}

	clientHello := buildClientHelloForDecrypt("idempotent.test.com")

	// Parse same ClientHello multiple times
	for i := 0; i < 3; i++ {
		d.Parse(clientHello, pkt)
	}

	// Should still be 1 connection with correct state
	tracker := d.ConnectionTracker()
	if tracker.Count() != 1 {
		t.Errorf("Expected 1 connection, got %d", tracker.Count())
	}

	state := d.ConnectionStateByFlow(pkt.FlowHash())
	if state == nil {
		t.Fatal("State should exist")
	}
	if state.SNI != "idempotent.test.com" {
		t.Errorf("SNI should be idempotent.test.com, got %s", state.SNI)
	}
}

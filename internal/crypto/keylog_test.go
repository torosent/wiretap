package crypto

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestParseKeyLogLine(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		wantLabel   string
		wantRandom  string
		wantSecret  string
		wantErr     bool
		errContains string
	}{
		{
			name:       "valid CLIENT_RANDOM",
			line:       "CLIENT_RANDOM 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef " + strings.Repeat("ab", 48),
			wantLabel:  LabelClientRandom,
			wantRandom: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			wantSecret: strings.Repeat("ab", 48),
			wantErr:    false,
		},
		{
			name:       "valid CLIENT_TRAFFIC_SECRET_0",
			line:       "CLIENT_TRAFFIC_SECRET_0 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef " + strings.Repeat("cd", 32),
			wantLabel:  LabelClientTrafficSecret0,
			wantRandom: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			wantSecret: strings.Repeat("cd", 32),
			wantErr:    false,
		},
		{
			name:       "valid SERVER_TRAFFIC_SECRET_0",
			line:       "SERVER_TRAFFIC_SECRET_0 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef " + strings.Repeat("ef", 48),
			wantLabel:  LabelServerTrafficSecret0,
			wantRandom: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			wantSecret: strings.Repeat("ef", 48),
			wantErr:    false,
		},
		{
			name:        "invalid - too few fields",
			line:        "CLIENT_RANDOM 0123456789abcdef",
			wantErr:     true,
			errContains: "expected 3 fields",
		},
		{
			name:        "invalid - too many fields",
			line:        "CLIENT_RANDOM a b c d",
			wantErr:     true,
			errContains: "expected 3 fields",
		},
		{
			name:        "invalid - unknown label",
			line:        "UNKNOWN_LABEL 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef " + strings.Repeat("ab", 48),
			wantErr:     true,
			errContains: "unknown label",
		},
		{
			name:        "invalid - client random too short",
			line:        "CLIENT_RANDOM 0123456789abcdef " + strings.Repeat("ab", 48),
			wantErr:     true,
			errContains: "client random must be 64 hex chars",
		},
		{
			name:        "invalid - client random not hex",
			line:        "CLIENT_RANDOM gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg " + strings.Repeat("ab", 48),
			wantErr:     true,
			errContains: "invalid client random hex",
		},
		{
			name:        "invalid - secret not hex",
			line:        "CLIENT_RANDOM 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef gggg",
			wantErr:     true,
			errContains: "invalid secret hex",
		},
		{
			name:        "invalid - master secret wrong length",
			line:        "CLIENT_RANDOM 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef " + strings.Repeat("ab", 32),
			wantErr:     true,
			errContains: "master secret must be 48 bytes",
		},
		{
			name:        "invalid - TLS 1.3 secret too short",
			line:        "CLIENT_TRAFFIC_SECRET_0 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef " + strings.Repeat("ab", 16),
			wantErr:     true,
			errContains: "out of valid range",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, err := ParseKeyLogLine(tt.line)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseKeyLogLine() expected error containing %q, got nil", tt.errContains)
					return
				}
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ParseKeyLogLine() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("ParseKeyLogLine() unexpected error = %v", err)
				return
			}

			if entry.Label != tt.wantLabel {
				t.Errorf("ParseKeyLogLine() label = %v, want %v", entry.Label, tt.wantLabel)
			}

			gotRandom := hex.EncodeToString(entry.ClientRandom[:])
			if gotRandom != tt.wantRandom {
				t.Errorf("ParseKeyLogLine() clientRandom = %v, want %v", gotRandom, tt.wantRandom)
			}

			gotSecret := hex.EncodeToString(entry.Secret)
			if gotSecret != tt.wantSecret {
				t.Errorf("ParseKeyLogLine() secret = %v, want %v", gotSecret, tt.wantSecret)
			}
		})
	}
}

func TestLoadFromReader(t *testing.T) {
	keyLogContent := `# This is a comment
CLIENT_RANDOM 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef ` + strings.Repeat("ab", 48) + `

# Another comment
CLIENT_TRAFFIC_SECRET_0 fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 ` + strings.Repeat("cd", 32) + `
SERVER_TRAFFIC_SECRET_0 fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 ` + strings.Repeat("ef", 32) + `

# Invalid line that should be skipped
INVALID_LINE
`

	kl, err := LoadFromReader(strings.NewReader(keyLogContent))
	if err != nil {
		t.Fatalf("LoadFromReader() error = %v", err)
	}

	if kl.Count() != 2 {
		t.Errorf("LoadFromReader() count = %d, want 2", kl.Count())
	}

	// Test lookup for TLS 1.2 master secret
	clientRandom1, _ := hex.DecodeString("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	var cr1 [32]byte
	copy(cr1[:], clientRandom1)

	masterSecret, err := kl.LookupMasterSecret(cr1)
	if err != nil {
		t.Errorf("LookupMasterSecret() error = %v", err)
	}
	expectedMasterSecret, _ := hex.DecodeString(strings.Repeat("ab", 48))
	if !bytes.Equal(masterSecret, expectedMasterSecret) {
		t.Errorf("LookupMasterSecret() = %x, want %x", masterSecret, expectedMasterSecret)
	}

	// Test lookup for TLS 1.3 secrets
	clientRandom2, _ := hex.DecodeString("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")
	var cr2 [32]byte
	copy(cr2[:], clientRandom2)

	secrets, err := kl.LookupTLS13Secrets(cr2)
	if err != nil {
		t.Errorf("LookupTLS13Secrets() error = %v", err)
	}

	expectedClientSecret, _ := hex.DecodeString(strings.Repeat("cd", 32))
	if !bytes.Equal(secrets.ClientTrafficSecret0, expectedClientSecret) {
		t.Errorf("ClientTrafficSecret0 = %x, want %x", secrets.ClientTrafficSecret0, expectedClientSecret)
	}

	expectedServerSecret, _ := hex.DecodeString(strings.Repeat("ef", 32))
	if !bytes.Equal(secrets.ServerTrafficSecret0, expectedServerSecret) {
		t.Errorf("ServerTrafficSecret0 = %x, want %x", secrets.ServerTrafficSecret0, expectedServerSecret)
	}
}

func TestKeyLog_Add_And_Lookup(t *testing.T) {
	kl := NewKeyLog()

	clientRandom := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	secret := make([]byte, 48)
	for i := range secret {
		secret[i] = byte(i)
	}

	entry := &KeyLogEntry{
		Label:        LabelClientRandom,
		ClientRandom: clientRandom,
		Secret:       secret,
	}

	kl.Add(entry)

	if kl.Count() != 1 {
		t.Errorf("Count() = %d, want 1", kl.Count())
	}

	if !kl.HasKey(clientRandom) {
		t.Error("HasKey() = false, want true")
	}

	// Lookup should return a copy
	result, err := kl.Lookup(clientRandom, LabelClientRandom)
	if err != nil {
		t.Errorf("Lookup() error = %v", err)
	}

	if !bytes.Equal(result, secret) {
		t.Errorf("Lookup() = %v, want %v", result, secret)
	}

	// Modifying the result should not affect stored secret
	result[0] = 0xff
	stored, _ := kl.Lookup(clientRandom, LabelClientRandom)
	if stored[0] == 0xff {
		t.Error("Lookup() returned reference to stored secret, should return copy")
	}
}

func TestKeyLog_Lookup_NotFound(t *testing.T) {
	kl := NewKeyLog()

	clientRandom := [32]byte{1, 2, 3}

	_, err := kl.Lookup(clientRandom, LabelClientRandom)
	if err != ErrKeyNotFound {
		t.Errorf("Lookup() error = %v, want ErrKeyNotFound", err)
	}

	_, err = kl.LookupMasterSecret(clientRandom)
	if err != ErrKeyNotFound {
		t.Errorf("LookupMasterSecret() error = %v, want ErrKeyNotFound", err)
	}

	_, err = kl.LookupTLS13Secrets(clientRandom)
	if err != ErrKeyNotFound {
		t.Errorf("LookupTLS13Secrets() error = %v, want ErrKeyNotFound", err)
	}
}

func TestKeyLog_Clear(t *testing.T) {
	kl := NewKeyLog()

	clientRandom := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	secret := make([]byte, 48)

	kl.Add(&KeyLogEntry{
		Label:        LabelClientRandom,
		ClientRandom: clientRandom,
		Secret:       secret,
	})

	if kl.Count() != 1 {
		t.Errorf("Count() before Clear() = %d, want 1", kl.Count())
	}

	kl.Clear()

	if kl.Count() != 0 {
		t.Errorf("Count() after Clear() = %d, want 0", kl.Count())
	}

	if kl.HasKey(clientRandom) {
		t.Error("HasKey() after Clear() = true, want false")
	}
}

func TestTLS13Secrets_Methods(t *testing.T) {
	t.Run("empty secrets", func(t *testing.T) {
		s := &TLS13Secrets{}
		if s.HasHandshakeSecrets() {
			t.Error("HasHandshakeSecrets() = true, want false")
		}
		if s.HasApplicationSecrets() {
			t.Error("HasApplicationSecrets() = true, want false")
		}
	})

	t.Run("handshake secrets only", func(t *testing.T) {
		s := &TLS13Secrets{
			ClientHandshakeTrafficSecret: []byte{1, 2, 3},
			ServerHandshakeTrafficSecret: []byte{4, 5, 6},
		}
		if !s.HasHandshakeSecrets() {
			t.Error("HasHandshakeSecrets() = false, want true")
		}
		if s.HasApplicationSecrets() {
			t.Error("HasApplicationSecrets() = true, want false")
		}
	})

	t.Run("application secrets only", func(t *testing.T) {
		s := &TLS13Secrets{
			ClientTrafficSecret0: []byte{1, 2, 3},
			ServerTrafficSecret0: []byte{4, 5, 6},
		}
		if s.HasHandshakeSecrets() {
			t.Error("HasHandshakeSecrets() = true, want false")
		}
		if !s.HasApplicationSecrets() {
			t.Error("HasApplicationSecrets() = false, want true")
		}
	})

	t.Run("all secrets", func(t *testing.T) {
		s := &TLS13Secrets{
			ClientHandshakeTrafficSecret: []byte{1, 2, 3},
			ServerHandshakeTrafficSecret: []byte{4, 5, 6},
			ClientTrafficSecret0:         []byte{7, 8, 9},
			ServerTrafficSecret0:         []byte{10, 11, 12},
		}
		if !s.HasHandshakeSecrets() {
			t.Error("HasHandshakeSecrets() = false, want true")
		}
		if !s.HasApplicationSecrets() {
			t.Error("HasApplicationSecrets() = false, want true")
		}
	})
}

func TestIsValidLabel(t *testing.T) {
	validLabels := []string{
		LabelClientRandom,
		LabelClientEarlyTrafficSecret,
		LabelClientHandshakeTrafficSecret,
		LabelServerHandshakeTrafficSecret,
		LabelClientTrafficSecret0,
		LabelServerTrafficSecret0,
		LabelEarlyExporterSecret,
		LabelExporterSecret,
	}

	for _, label := range validLabels {
		if !isValidLabel(label) {
			t.Errorf("isValidLabel(%q) = false, want true", label)
		}
	}

	invalidLabels := []string{
		"INVALID",
		"CLIENT_SECRET",
		"",
		"client_random",
	}

	for _, label := range invalidLabels {
		if isValidLabel(label) {
			t.Errorf("isValidLabel(%q) = true, want false", label)
		}
	}
}

func TestKeyLog_ConcurrentAccess(t *testing.T) {
	kl := NewKeyLog()
	done := make(chan struct{})

	// Writer goroutine
	go func() {
		for i := 0; i < 100; i++ {
			var cr [32]byte
			cr[0] = byte(i)
			kl.Add(&KeyLogEntry{
				Label:        LabelClientRandom,
				ClientRandom: cr,
				Secret:       make([]byte, 48),
			})
		}
		done <- struct{}{}
	}()

	// Reader goroutine
	go func() {
		for i := 0; i < 100; i++ {
			var cr [32]byte
			cr[0] = byte(i)
			kl.HasKey(cr)
			kl.Lookup(cr, LabelClientRandom)
		}
		done <- struct{}{}
	}()

	<-done
	<-done
}

func TestKeyLog_LookupWrongLabel(t *testing.T) {
	kl := NewKeyLog()

	clientRandom := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

	kl.Add(&KeyLogEntry{
		Label:        LabelClientRandom,
		ClientRandom: clientRandom,
		Secret:       make([]byte, 48),
	})

	// Try to lookup with different label
	_, err := kl.Lookup(clientRandom, LabelClientTrafficSecret0)
	if err != ErrKeyNotFound {
		t.Errorf("Lookup() with wrong label error = %v, want ErrKeyNotFound", err)
	}
}

func TestKeyLog_MultipleLabels(t *testing.T) {
	kl := NewKeyLog()

	clientRandom := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

	clientSecret := make([]byte, 32)
	for i := range clientSecret {
		clientSecret[i] = byte(i)
	}

	serverSecret := make([]byte, 32)
	for i := range serverSecret {
		serverSecret[i] = byte(i + 100)
	}

	kl.Add(&KeyLogEntry{
		Label:        LabelClientTrafficSecret0,
		ClientRandom: clientRandom,
		Secret:       clientSecret,
	})

	kl.Add(&KeyLogEntry{
		Label:        LabelServerTrafficSecret0,
		ClientRandom: clientRandom,
		Secret:       serverSecret,
	})

	// Should only count as one entry (same client random)
	if kl.Count() != 1 {
		t.Errorf("Count() = %d, want 1", kl.Count())
	}

	// Should be able to lookup both secrets
	gotClient, err := kl.Lookup(clientRandom, LabelClientTrafficSecret0)
	if err != nil {
		t.Errorf("Lookup(ClientTrafficSecret0) error = %v", err)
	}
	if !bytes.Equal(gotClient, clientSecret) {
		t.Errorf("Lookup(ClientTrafficSecret0) = %v, want %v", gotClient, clientSecret)
	}

	gotServer, err := kl.Lookup(clientRandom, LabelServerTrafficSecret0)
	if err != nil {
		t.Errorf("Lookup(ServerTrafficSecret0) error = %v", err)
	}
	if !bytes.Equal(gotServer, serverSecret) {
		t.Errorf("Lookup(ServerTrafficSecret0) = %v, want %v", gotServer, serverSecret)
	}
}

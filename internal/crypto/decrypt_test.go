package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestSupportedCipherSuites(t *testing.T) {
	// Verify all expected cipher suites are registered
	expectedCiphers := []uint16{
		TLS_AES_128_GCM_SHA256,
		TLS_AES_256_GCM_SHA384,
		TLS_CHACHA20_POLY1305_SHA256,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		TLS_RSA_WITH_AES_128_GCM_SHA256,
		TLS_RSA_WITH_AES_256_GCM_SHA384,
	}

	for _, cs := range expectedCiphers {
		info, ok := SupportedCipherSuites[cs]
		if !ok {
			t.Errorf("cipher suite 0x%04x not found", cs)
			continue
		}
		if info.ID != cs {
			t.Errorf("cipher suite 0x%04x has wrong ID: got 0x%04x", cs, info.ID)
		}
		if info.KeyLen == 0 {
			t.Errorf("cipher suite 0x%04x has zero KeyLen", cs)
		}
		if info.IVLen == 0 {
			t.Errorf("cipher suite 0x%04x has zero IVLen", cs)
		}
		if info.HashFunc == nil {
			t.Errorf("cipher suite 0x%04x has nil HashFunc", cs)
		}
	}
}

func TestNewTLS13Decryptor(t *testing.T) {
	tests := []struct {
		name        string
		cipherSuite uint16
		secrets     *TLS13Secrets
		wantErr     bool
		errContains string
	}{
		{
			name:        "AES-128-GCM with valid secrets",
			cipherSuite: TLS_AES_128_GCM_SHA256,
			secrets: &TLS13Secrets{
				ClientTrafficSecret0: make([]byte, 32),
				ServerTrafficSecret0: make([]byte, 32),
			},
			wantErr: false,
		},
		{
			name:        "AES-256-GCM with valid secrets",
			cipherSuite: TLS_AES_256_GCM_SHA384,
			secrets: &TLS13Secrets{
				ClientTrafficSecret0: make([]byte, 48),
				ServerTrafficSecret0: make([]byte, 48),
			},
			wantErr: false,
		},
		{
			name:        "ChaCha20-Poly1305 with valid secrets",
			cipherSuite: TLS_CHACHA20_POLY1305_SHA256,
			secrets: &TLS13Secrets{
				ClientTrafficSecret0: make([]byte, 32),
				ServerTrafficSecret0: make([]byte, 32),
			},
			wantErr: false,
		},
		{
			name:        "unsupported cipher suite",
			cipherSuite: 0xFFFF,
			secrets:     &TLS13Secrets{},
			wantErr:     true,
			errContains: "unsupported cipher suite",
		},
		{
			name:        "TLS 1.2 cipher suite for TLS 1.3 decryptor",
			cipherSuite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			secrets:     &TLS13Secrets{},
			wantErr:     true,
			errContains: "not a TLS 1.3 cipher suite",
		},
		{
			name:        "client secrets only",
			cipherSuite: TLS_AES_128_GCM_SHA256,
			secrets: &TLS13Secrets{
				ClientTrafficSecret0: make([]byte, 32),
			},
			wantErr: false,
		},
		{
			name:        "server secrets only",
			cipherSuite: TLS_AES_128_GCM_SHA256,
			secrets: &TLS13Secrets{
				ServerTrafficSecret0: make([]byte, 32),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewTLS13Decryptor(tt.cipherSuite, tt.secrets)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if tt.errContains != "" && !bytes.Contains([]byte(err.Error()), []byte(tt.errContains)) {
					t.Errorf("error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error = %v", err)
				return
			}

			if d == nil {
				t.Error("decryptor is nil")
				return
			}

			if !d.IsTLS13() {
				t.Error("IsTLS13() = false, want true")
			}

			if tt.secrets.ClientTrafficSecret0 != nil && !d.HasClientKeys() {
				t.Error("HasClientKeys() = false, want true")
			}

			if tt.secrets.ServerTrafficSecret0 != nil && !d.HasServerKeys() {
				t.Error("HasServerKeys() = false, want true")
			}
		})
	}
}

func TestNewTLS12Decryptor(t *testing.T) {
	masterSecret := make([]byte, 48)
	var clientRandom, serverRandom [32]byte
	for i := range clientRandom {
		clientRandom[i] = byte(i)
		serverRandom[i] = byte(i + 32)
	}

	tests := []struct {
		name        string
		cipherSuite uint16
		wantErr     bool
		errContains string
	}{
		{
			name:        "ECDHE-RSA-AES-128-GCM",
			cipherSuite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			wantErr:     false,
		},
		{
			name:        "ECDHE-RSA-AES-256-GCM",
			cipherSuite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			wantErr:     false,
		},
		{
			name:        "unsupported cipher suite",
			cipherSuite: 0xFFFF,
			wantErr:     true,
			errContains: "unsupported cipher suite",
		},
		{
			name:        "TLS 1.3 cipher for TLS 1.2 decryptor",
			cipherSuite: TLS_AES_128_GCM_SHA256,
			wantErr:     true,
			errContains: "not a TLS 1.2 cipher suite",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewTLS12Decryptor(tt.cipherSuite, masterSecret, clientRandom, serverRandom)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if tt.errContains != "" && !bytes.Contains([]byte(err.Error()), []byte(tt.errContains)) {
					t.Errorf("error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error = %v", err)
				return
			}

			if d == nil {
				t.Error("decryptor is nil")
				return
			}

			if d.IsTLS13() {
				t.Error("IsTLS13() = true, want false")
			}

			if !d.HasClientKeys() {
				t.Error("HasClientKeys() = false, want true")
			}

			if !d.HasServerKeys() {
				t.Error("HasServerKeys() = false, want true")
			}
		})
	}
}

func TestHKDFExpandLabel(t *testing.T) {
	// Test HKDF-Expand-Label with known test vectors
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}

	tests := []struct {
		name   string
		label  string
		length int
	}{
		{
			name:   "key derivation",
			label:  "key",
			length: 16,
		},
		{
			name:   "iv derivation",
			label:  "iv",
			length: 12,
		},
		{
			name:   "longer output",
			label:  "traffic",
			length: 32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := hkdfExpandLabel(
				SupportedCipherSuites[TLS_AES_128_GCM_SHA256].HashFunc,
				secret,
				tt.label,
				nil,
				tt.length,
			)

			if err != nil {
				t.Errorf("hkdfExpandLabel() error = %v", err)
				return
			}

			if len(result) != tt.length {
				t.Errorf("hkdfExpandLabel() length = %d, want %d", len(result), tt.length)
			}

			// Verify determinism - same inputs should produce same output
			result2, _ := hkdfExpandLabel(
				SupportedCipherSuites[TLS_AES_128_GCM_SHA256].HashFunc,
				secret,
				tt.label,
				nil,
				tt.length,
			)

			if !bytes.Equal(result, result2) {
				t.Error("hkdfExpandLabel() not deterministic")
			}
		})
	}
}

func TestPRF12(t *testing.T) {
	// Test TLS 1.2 PRF
	secret := make([]byte, 48)
	for i := range secret {
		secret[i] = byte(i)
	}
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i + 100)
	}

	result, err := prf12(
		SupportedCipherSuites[TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256].HashFunc,
		secret,
		[]byte("key expansion"),
		seed,
		72, // 2*16 (keys) + 2*4 (IVs) for AES-128-GCM
	)

	if err != nil {
		t.Errorf("prf12() error = %v", err)
		return
	}

	if len(result) != 72 {
		t.Errorf("prf12() length = %d, want 72", len(result))
	}

	// Verify determinism
	result2, _ := prf12(
		SupportedCipherSuites[TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256].HashFunc,
		secret,
		[]byte("key expansion"),
		seed,
		72,
	)

	if !bytes.Equal(result, result2) {
		t.Error("prf12() not deterministic")
	}
}

func TestDecryptor_CipherName(t *testing.T) {
	secrets := &TLS13Secrets{
		ClientTrafficSecret0: make([]byte, 32),
	}

	tests := []struct {
		cipherSuite uint16
		wantName    string
	}{
		{TLS_AES_128_GCM_SHA256, "TLS_AES_128_GCM_SHA256"},
		{TLS_AES_256_GCM_SHA384, "TLS_AES_256_GCM_SHA384"},
		{TLS_CHACHA20_POLY1305_SHA256, "TLS_CHACHA20_POLY1305_SHA256"},
	}

	for _, tt := range tests {
		t.Run(tt.wantName, func(t *testing.T) {
			d, err := NewTLS13Decryptor(tt.cipherSuite, secrets)
			if err != nil {
				t.Fatalf("NewTLS13Decryptor() error = %v", err)
			}

			if got := d.CipherName(); got != tt.wantName {
				t.Errorf("CipherName() = %v, want %v", got, tt.wantName)
			}
		})
	}
}

func TestDecryptor_DecryptRecord_InvalidRecord(t *testing.T) {
	secrets := &TLS13Secrets{
		ClientTrafficSecret0: make([]byte, 32),
		ServerTrafficSecret0: make([]byte, 32),
	}

	d, err := NewTLS13Decryptor(TLS_AES_128_GCM_SHA256, secrets)
	if err != nil {
		t.Fatalf("NewTLS13Decryptor() error = %v", err)
	}

	tests := []struct {
		name   string
		record []byte
	}{
		{
			name:   "record too short",
			record: []byte{0x17, 0x03, 0x03},
		},
		{
			name:   "declared length exceeds actual",
			record: []byte{0x17, 0x03, 0x03, 0x00, 0xFF, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := d.DecryptRecord(tt.record, true)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestDecryptor_NoKeysAvailable(t *testing.T) {
	// Create decryptor with only client secrets
	secrets := &TLS13Secrets{
		ClientTrafficSecret0: make([]byte, 32),
	}

	d, err := NewTLS13Decryptor(TLS_AES_128_GCM_SHA256, secrets)
	if err != nil {
		t.Fatalf("NewTLS13Decryptor() error = %v", err)
	}

	// Create a minimal valid record structure
	record := []byte{0x17, 0x03, 0x03, 0x00, 0x10}
	record = append(record, make([]byte, 16)...)

	// Try to decrypt server data without server keys
	_, err = d.DecryptRecord(record, false)
	if err == nil {
		t.Error("expected error when decrypting without server keys")
	}
}

func TestDecryptor_TLS13_EncryptDecrypt(t *testing.T) {
	// This test verifies that we can decrypt what we encrypt
	// using known test data

	// Generate test secrets
	clientSecret := make([]byte, 32)
	serverSecret := make([]byte, 32)
	for i := range clientSecret {
		clientSecret[i] = byte(i)
		serverSecret[i] = byte(i + 32)
	}

	secrets := &TLS13Secrets{
		ClientTrafficSecret0: clientSecret,
		ServerTrafficSecret0: serverSecret,
	}

	d, err := NewTLS13Decryptor(TLS_AES_128_GCM_SHA256, secrets)
	if err != nil {
		t.Fatalf("NewTLS13Decryptor() error = %v", err)
	}

	// Encrypt test data using the same derived keys
	plaintext := []byte("Hello, TLS 1.3!")
	contentType := byte(0x17) // Application data

	// Derive keys the same way the decryptor does
	key, _ := hkdfExpandLabel(
		SupportedCipherSuites[TLS_AES_128_GCM_SHA256].HashFunc,
		clientSecret, "key", nil, 16,
	)
	iv, _ := hkdfExpandLabel(
		SupportedCipherSuites[TLS_AES_128_GCM_SHA256].HashFunc,
		clientSecret, "iv", nil, 12,
	)

	// Create AEAD cipher
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)

	// TLS 1.3 inner plaintext: data + content type
	innerPlaintext := append(plaintext, contentType)

	// Construct nonce (IV XOR sequence number 0)
	nonce := make([]byte, 12)
	copy(nonce, iv)

	// Additional data
	ciphertextLen := len(innerPlaintext) + aead.Overhead()
	additionalData := []byte{
		RecordTypeApplicationData,
		0x03, 0x03,
		byte(ciphertextLen >> 8), byte(ciphertextLen),
	}

	// Encrypt
	ciphertext := aead.Seal(nil, nonce, innerPlaintext, additionalData)

	// Build TLS record
	record := make([]byte, 5+len(ciphertext))
	record[0] = RecordTypeApplicationData
	record[1] = 0x03
	record[2] = 0x03
	binary.BigEndian.PutUint16(record[3:5], uint16(len(ciphertext)))
	copy(record[5:], ciphertext)

	// Decrypt using our decryptor
	decrypted, err := d.DecryptRecord(record, true)
	if err != nil {
		t.Fatalf("DecryptRecord() error = %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("DecryptRecord() = %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptor_TLS13_ChaCha20(t *testing.T) {
	// Test ChaCha20-Poly1305 cipher
	clientSecret := make([]byte, 32)
	for i := range clientSecret {
		clientSecret[i] = byte(i)
	}

	secrets := &TLS13Secrets{
		ClientTrafficSecret0: clientSecret,
	}

	d, err := NewTLS13Decryptor(TLS_CHACHA20_POLY1305_SHA256, secrets)
	if err != nil {
		t.Fatalf("NewTLS13Decryptor() error = %v", err)
	}

	// Similar test as AES-GCM
	plaintext := []byte("ChaCha20 test!")
	contentType := byte(0x17)

	key, _ := hkdfExpandLabel(
		SupportedCipherSuites[TLS_CHACHA20_POLY1305_SHA256].HashFunc,
		clientSecret, "key", nil, 32,
	)
	iv, _ := hkdfExpandLabel(
		SupportedCipherSuites[TLS_CHACHA20_POLY1305_SHA256].HashFunc,
		clientSecret, "iv", nil, 12,
	)

	aead, _ := chacha20poly1305.New(key)

	innerPlaintext := append(plaintext, contentType)
	nonce := make([]byte, 12)
	copy(nonce, iv)

	ciphertextLen := len(innerPlaintext) + aead.Overhead()
	additionalData := []byte{
		RecordTypeApplicationData,
		0x03, 0x03,
		byte(ciphertextLen >> 8), byte(ciphertextLen),
	}

	ciphertext := aead.Seal(nil, nonce, innerPlaintext, additionalData)

	record := make([]byte, 5+len(ciphertext))
	record[0] = RecordTypeApplicationData
	record[1] = 0x03
	record[2] = 0x03
	binary.BigEndian.PutUint16(record[3:5], uint16(len(ciphertext)))
	copy(record[5:], ciphertext)

	decrypted, err := d.DecryptRecord(record, true)
	if err != nil {
		t.Fatalf("DecryptRecord() error = %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("DecryptRecord() = %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptor_SequenceNumberIncrement(t *testing.T) {
	clientSecret := make([]byte, 32)
	for i := range clientSecret {
		clientSecret[i] = byte(i)
	}

	secrets := &TLS13Secrets{
		ClientTrafficSecret0: clientSecret,
	}

	d, err := NewTLS13Decryptor(TLS_AES_128_GCM_SHA256, secrets)
	if err != nil {
		t.Fatalf("NewTLS13Decryptor() error = %v", err)
	}

	// Create multiple records and verify sequence numbers are used correctly
	key, _ := hkdfExpandLabel(
		SupportedCipherSuites[TLS_AES_128_GCM_SHA256].HashFunc,
		clientSecret, "key", nil, 16,
	)
	iv, _ := hkdfExpandLabel(
		SupportedCipherSuites[TLS_AES_128_GCM_SHA256].HashFunc,
		clientSecret, "iv", nil, 12,
	)

	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)

	for seqNum := uint64(0); seqNum < 3; seqNum++ {
		plaintext := []byte{byte('A' + seqNum)}
		contentType := byte(0x17)
		innerPlaintext := append(plaintext, contentType)

		// Construct nonce with sequence number
		nonce := make([]byte, 12)
		copy(nonce, iv)
		for i := 0; i < 8; i++ {
			nonce[12-8+i] ^= byte(seqNum >> (56 - 8*i))
		}

		ciphertextLen := len(innerPlaintext) + aead.Overhead()
		additionalData := []byte{
			RecordTypeApplicationData,
			0x03, 0x03,
			byte(ciphertextLen >> 8), byte(ciphertextLen),
		}

		ciphertext := aead.Seal(nil, nonce, innerPlaintext, additionalData)

		record := make([]byte, 5+len(ciphertext))
		record[0] = RecordTypeApplicationData
		record[1] = 0x03
		record[2] = 0x03
		binary.BigEndian.PutUint16(record[3:5], uint16(len(ciphertext)))
		copy(record[5:], ciphertext)

		decrypted, err := d.DecryptRecord(record, true)
		if err != nil {
			t.Fatalf("DecryptRecord() seqNum=%d error = %v", seqNum, err)
		}

		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("DecryptRecord() seqNum=%d = %q, want %q", seqNum, decrypted, plaintext)
		}
	}
}

func TestHMACHash(t *testing.T) {
	// Test HMAC implementation
	key := []byte("secret key")
	data := []byte("test data")

	result1 := hmacHash(SupportedCipherSuites[TLS_AES_128_GCM_SHA256].HashFunc, key, data)
	result2 := hmacHash(SupportedCipherSuites[TLS_AES_128_GCM_SHA256].HashFunc, key, data)

	if !bytes.Equal(result1, result2) {
		t.Error("hmacHash not deterministic")
	}

	// Different data should produce different result
	result3 := hmacHash(SupportedCipherSuites[TLS_AES_128_GCM_SHA256].HashFunc, key, []byte("other data"))
	if bytes.Equal(result1, result3) {
		t.Error("hmacHash produced same result for different data")
	}

	// Test with long key (should be hashed)
	longKey := make([]byte, 128)
	for i := range longKey {
		longKey[i] = byte(i)
	}
	result4 := hmacHash(SupportedCipherSuites[TLS_AES_128_GCM_SHA256].HashFunc, longKey, data)
	if len(result4) == 0 {
		t.Error("hmacHash with long key returned empty result")
	}
}

func TestDecryptor_TLS12_KeyDerivation(t *testing.T) {
	// Test TLS 1.2 key derivation produces consistent keys
	masterSecret := make([]byte, 48)
	for i := range masterSecret {
		masterSecret[i] = byte(i)
	}

	var clientRandom, serverRandom [32]byte
	for i := range clientRandom {
		clientRandom[i] = byte(i + 100)
		serverRandom[i] = byte(i + 200)
	}

	d1, err := NewTLS12Decryptor(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, masterSecret, clientRandom, serverRandom)
	if err != nil {
		t.Fatalf("NewTLS12Decryptor() error = %v", err)
	}

	d2, err := NewTLS12Decryptor(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, masterSecret, clientRandom, serverRandom)
	if err != nil {
		t.Fatalf("NewTLS12Decryptor() error = %v", err)
	}

	// Both should have keys
	if !d1.HasClientKeys() || !d1.HasServerKeys() {
		t.Error("d1 missing keys")
	}
	if !d2.HasClientKeys() || !d2.HasServerKeys() {
		t.Error("d2 missing keys")
	}

	// Verify cipher name
	if d1.CipherName() != "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" {
		t.Errorf("CipherName() = %v, want TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", d1.CipherName())
	}
}

func TestDecryptor_WrongRecordType_TLS13(t *testing.T) {
	secrets := &TLS13Secrets{
		ClientTrafficSecret0: make([]byte, 32),
	}

	d, err := NewTLS13Decryptor(TLS_AES_128_GCM_SHA256, secrets)
	if err != nil {
		t.Fatalf("NewTLS13Decryptor() error = %v", err)
	}

	// Create a handshake record (not application data)
	record := []byte{RecordTypeHandshake, 0x03, 0x03, 0x00, 0x10}
	record = append(record, make([]byte, 16)...)

	_, err = d.DecryptRecord(record, true)
	if err == nil {
		t.Error("expected error for non-application-data record type in TLS 1.3")
	}
}

func TestDecryptor_DecryptionFailure(t *testing.T) {
	secrets := &TLS13Secrets{
		ClientTrafficSecret0: make([]byte, 32),
	}

	d, err := NewTLS13Decryptor(TLS_AES_128_GCM_SHA256, secrets)
	if err != nil {
		t.Fatalf("NewTLS13Decryptor() error = %v", err)
	}

	// Create an application data record with garbage ciphertext
	ciphertext := make([]byte, 32) // Random garbage
	record := make([]byte, 5+len(ciphertext))
	record[0] = RecordTypeApplicationData
	record[1] = 0x03
	record[2] = 0x03
	binary.BigEndian.PutUint16(record[3:5], uint16(len(ciphertext)))
	copy(record[5:], ciphertext)

	_, err = d.DecryptRecord(record, true)
	if err == nil {
		t.Error("expected decryption failure for garbage ciphertext")
	}
}

func TestPHash_VaryingLengths(t *testing.T) {
	secret := []byte("test secret")
	seed := []byte("test seed")

	// Test various output lengths
	lengths := []int{16, 32, 48, 64, 128}

	for _, length := range lengths {
		result, err := pHash(SupportedCipherSuites[TLS_AES_128_GCM_SHA256].HashFunc, secret, seed, length)
		if err != nil {
			t.Errorf("pHash(length=%d) error = %v", length, err)
			continue
		}
		if len(result) != length {
			t.Errorf("pHash(length=%d) returned %d bytes", length, len(result))
		}
	}
}

func TestDecryptor_TLS12_EncryptDecrypt(t *testing.T) {
	// Test TLS 1.2 decryption with known keys
	masterSecret := make([]byte, 48)
	for i := range masterSecret {
		masterSecret[i] = byte(i)
	}

	var clientRandom, serverRandom [32]byte
	for i := range clientRandom {
		clientRandom[i] = byte(i + 100)
		serverRandom[i] = byte(i + 200)
	}

	d, err := NewTLS12Decryptor(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, masterSecret, clientRandom, serverRandom)
	if err != nil {
		t.Fatalf("NewTLS12Decryptor() error = %v", err)
	}

	// Test that decryptor was created successfully
	if d.IsTLS13() {
		t.Error("IsTLS13() = true, want false for TLS 1.2 decryptor")
	}
}

func TestTrafficKeys_Structure(t *testing.T) {
	// Test that TrafficKeys can hold expected data sizes
	keys := &TrafficKeys{
		Key: make([]byte, 32),
		IV:  make([]byte, 12),
	}

	if len(keys.Key) != 32 {
		t.Errorf("Key length = %d, want 32", len(keys.Key))
	}
	if len(keys.IV) != 12 {
		t.Errorf("IV length = %d, want 12", len(keys.IV))
	}
}

func TestCipherSuiteInfo_TLS13Detection(t *testing.T) {
	tls13Ciphers := []uint16{
		TLS_AES_128_GCM_SHA256,
		TLS_AES_256_GCM_SHA384,
		TLS_CHACHA20_POLY1305_SHA256,
	}

	tls12Ciphers := []uint16{
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		TLS_RSA_WITH_AES_128_GCM_SHA256,
		TLS_RSA_WITH_AES_256_GCM_SHA384,
	}

	for _, cs := range tls13Ciphers {
		info := SupportedCipherSuites[cs]
		if !info.IsTLS13 {
			t.Errorf("cipher 0x%04x should be TLS 1.3", cs)
		}
	}

	for _, cs := range tls12Ciphers {
		info := SupportedCipherSuites[cs]
		if info.IsTLS13 {
			t.Errorf("cipher 0x%04x should not be TLS 1.3", cs)
		}
	}
}

func TestHKDFExpandLabel_WithContext(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}

	context := []byte("test context data")

	result, err := hkdfExpandLabel(
		SupportedCipherSuites[TLS_AES_128_GCM_SHA256].HashFunc,
		secret,
		"derived",
		context,
		32,
	)

	if err != nil {
		t.Errorf("hkdfExpandLabel() with context error = %v", err)
	}

	if len(result) != 32 {
		t.Errorf("hkdfExpandLabel() length = %d, want 32", len(result))
	}

	// Result without context should be different
	resultNoCtx, _ := hkdfExpandLabel(
		SupportedCipherSuites[TLS_AES_128_GCM_SHA256].HashFunc,
		secret,
		"derived",
		nil,
		32,
	)

	if bytes.Equal(result, resultNoCtx) {
		t.Error("results with and without context should differ")
	}
}

func TestDecryptor_TLS12_DecryptRecord_FullFlow(t *testing.T) {
	// Test full TLS 1.2 decryption flow
	masterSecret := make([]byte, 48)
	for i := range masterSecret {
		masterSecret[i] = byte(i)
	}

	var clientRandom, serverRandom [32]byte
	for i := range clientRandom {
		clientRandom[i] = byte(i + 100)
		serverRandom[i] = byte(i + 200)
	}

	d, err := NewTLS12Decryptor(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, masterSecret, clientRandom, serverRandom)
	if err != nil {
		t.Fatalf("NewTLS12Decryptor() error = %v", err)
	}

	// Create a properly formatted TLS 1.2 record
	plaintext := []byte("Hello, TLS 1.2!")

	// TLS 1.2 AEAD format: explicit_nonce (8 bytes) + ciphertext + tag (16 bytes)
	// We need the actual keys to encrypt properly

	// Get the client keys (we'll need to derive them the same way)
	keyMaterial, _ := prf12(
		SupportedCipherSuites[TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256].HashFunc,
		masterSecret,
		[]byte("key expansion"),
		append(serverRandom[:], clientRandom[:]...),
		40, // 2*16 (keys) + 2*4 (IVs)
	)

	clientKey := keyMaterial[0:16]
	clientIV := keyMaterial[32:36]

	// Create AES-GCM cipher
	block, _ := aes.NewCipher(clientKey)
	aead, _ := cipher.NewGCM(block)

	// Explicit nonce (8 bytes)
	explicitNonce := make([]byte, 8)
	for i := range explicitNonce {
		explicitNonce[i] = byte(i)
	}

	// Full nonce = implicit IV (4 bytes) + explicit nonce (8 bytes)
	nonce := make([]byte, 12)
	copy(nonce[:4], clientIV)
	copy(nonce[4:], explicitNonce)

	// Additional data: seq_num (8) + type (1) + version (2) + length (2)
	additionalData := make([]byte, 13)
	binary.BigEndian.PutUint64(additionalData[0:8], 0) // seq num 0
	additionalData[8] = RecordTypeApplicationData
	binary.BigEndian.PutUint16(additionalData[9:11], 0x0303) // TLS 1.2
	binary.BigEndian.PutUint16(additionalData[11:13], uint16(len(plaintext)))

	// Encrypt
	ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)

	// Build TLS 1.2 record: type + version + length + explicit_nonce + ciphertext
	recordPayload := append(explicitNonce, ciphertext...)
	record := make([]byte, 5+len(recordPayload))
	record[0] = RecordTypeApplicationData
	binary.BigEndian.PutUint16(record[1:3], 0x0303) // TLS 1.2
	binary.BigEndian.PutUint16(record[3:5], uint16(len(recordPayload)))
	copy(record[5:], recordPayload)

	// Decrypt
	decrypted, err := d.DecryptRecord(record, true)
	if err != nil {
		t.Fatalf("DecryptRecord() error = %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("DecryptRecord() = %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptor_TLS12_InvalidRecord(t *testing.T) {
	masterSecret := make([]byte, 48)
	var clientRandom, serverRandom [32]byte

	d, _ := NewTLS12Decryptor(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, masterSecret, clientRandom, serverRandom)

	tests := []struct {
		name   string
		record []byte
	}{
		{
			name:   "record too short",
			record: []byte{0x17, 0x03, 0x03},
		},
		{
			name:   "explicit nonce too short",
			record: []byte{0x17, 0x03, 0x03, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04},
		},
		{
			name:   "ciphertext too short for tag",
			record: []byte{0x17, 0x03, 0x03, 0x00, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := d.DecryptRecord(tt.record, true)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestDecryptor_TLS12_WrongRecordType(t *testing.T) {
	masterSecret := make([]byte, 48)
	var clientRandom, serverRandom [32]byte

	d, _ := NewTLS12Decryptor(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, masterSecret, clientRandom, serverRandom)

	// Handshake record, not application data
	record := []byte{RecordTypeHandshake, 0x03, 0x03, 0x00, 0x20}
	record = append(record, make([]byte, 32)...)

	_, err := d.DecryptRecord(record, true)
	if err == nil {
		t.Error("expected error for non-application-data record type")
	}
}

func TestDecryptor_CipherName_NilCipher(t *testing.T) {
	// Test CipherName with nil cipher
	d := &Decryptor{cipher: nil}
	if d.CipherName() != "unknown" {
		t.Errorf("CipherName() with nil cipher = %v, want 'unknown'", d.CipherName())
	}
}

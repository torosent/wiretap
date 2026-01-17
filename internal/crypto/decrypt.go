package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// TLS record types
const (
	RecordTypeChangeCipherSpec = 20
	RecordTypeAlert            = 21
	RecordTypeHandshake        = 22
	RecordTypeApplicationData  = 23
)

// TLS cipher suite identifiers
const (
	TLS_AES_128_GCM_SHA256       uint16 = 0x1301
	TLS_AES_256_GCM_SHA384       uint16 = 0x1302
	TLS_CHACHA20_POLY1305_SHA256 uint16 = 0x1303

	// TLS 1.2 cipher suites
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   uint16 = 0xc02f
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   uint16 = 0xc030
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 uint16 = 0xc02b
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 uint16 = 0xc02c
	TLS_RSA_WITH_AES_128_GCM_SHA256         uint16 = 0x009c
	TLS_RSA_WITH_AES_256_GCM_SHA384         uint16 = 0x009d
)

// Common errors
var (
	ErrUnsupportedCipher = errors.New("unsupported cipher suite")
	ErrDecryptionFailed  = errors.New("decryption failed")
	ErrInvalidRecord     = errors.New("invalid TLS record")
	ErrInvalidMAC        = errors.New("invalid MAC")
)

// CipherSuiteInfo contains information about a cipher suite.
type CipherSuiteInfo struct {
	ID       uint16
	Name     string
	KeyLen   int
	IVLen    int
	TagLen   int
	HashFunc func() hash.Hash
	IsTLS13  bool
	IsAEAD   bool
	IsChaCha bool
}

// SupportedCipherSuites maps cipher suite IDs to their info.
var SupportedCipherSuites = map[uint16]*CipherSuiteInfo{
	// TLS 1.3 cipher suites
	TLS_AES_128_GCM_SHA256: {
		ID:       TLS_AES_128_GCM_SHA256,
		Name:     "TLS_AES_128_GCM_SHA256",
		KeyLen:   16,
		IVLen:    12,
		TagLen:   16,
		HashFunc: sha256.New,
		IsTLS13:  true,
		IsAEAD:   true,
	},
	TLS_AES_256_GCM_SHA384: {
		ID:       TLS_AES_256_GCM_SHA384,
		Name:     "TLS_AES_256_GCM_SHA384",
		KeyLen:   32,
		IVLen:    12,
		TagLen:   16,
		HashFunc: sha512.New384,
		IsTLS13:  true,
		IsAEAD:   true,
	},
	TLS_CHACHA20_POLY1305_SHA256: {
		ID:       TLS_CHACHA20_POLY1305_SHA256,
		Name:     "TLS_CHACHA20_POLY1305_SHA256",
		KeyLen:   32,
		IVLen:    12,
		TagLen:   16,
		HashFunc: sha256.New,
		IsTLS13:  true,
		IsAEAD:   true,
		IsChaCha: true,
	},
	// TLS 1.2 AEAD cipher suites
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: {
		ID:       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		Name:     "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		KeyLen:   16,
		IVLen:    4, // TLS 1.2 uses 4-byte implicit + 8-byte explicit nonce
		TagLen:   16,
		HashFunc: sha256.New,
		IsTLS13:  false,
		IsAEAD:   true,
	},
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: {
		ID:       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		Name:     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		KeyLen:   32,
		IVLen:    4,
		TagLen:   16,
		HashFunc: sha512.New384,
		IsTLS13:  false,
		IsAEAD:   true,
	},
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: {
		ID:       TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		Name:     "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		KeyLen:   16,
		IVLen:    4,
		TagLen:   16,
		HashFunc: sha256.New,
		IsTLS13:  false,
		IsAEAD:   true,
	},
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: {
		ID:       TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		Name:     "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		KeyLen:   32,
		IVLen:    4,
		TagLen:   16,
		HashFunc: sha512.New384,
		IsTLS13:  false,
		IsAEAD:   true,
	},
	TLS_RSA_WITH_AES_128_GCM_SHA256: {
		ID:       TLS_RSA_WITH_AES_128_GCM_SHA256,
		Name:     "TLS_RSA_WITH_AES_128_GCM_SHA256",
		KeyLen:   16,
		IVLen:    4,
		TagLen:   16,
		HashFunc: sha256.New,
		IsTLS13:  false,
		IsAEAD:   true,
	},
	TLS_RSA_WITH_AES_256_GCM_SHA384: {
		ID:       TLS_RSA_WITH_AES_256_GCM_SHA384,
		Name:     "TLS_RSA_WITH_AES_256_GCM_SHA384",
		KeyLen:   32,
		IVLen:    4,
		TagLen:   16,
		HashFunc: sha512.New384,
		IsTLS13:  false,
		IsAEAD:   true,
	},
}

// TrafficKeys holds the derived keys for encryption/decryption.
type TrafficKeys struct {
	Key []byte
	IV  []byte
}

// Decryptor handles TLS record decryption.
type Decryptor struct {
	cipher       *CipherSuiteInfo
	clientKeys   *TrafficKeys
	serverKeys   *TrafficKeys
	clientSeqNum uint64
	serverSeqNum uint64
	isTLS13      bool
}

// NewTLS13Decryptor creates a decryptor for TLS 1.3 traffic.
func NewTLS13Decryptor(cipherSuite uint16, secrets *TLS13Secrets) (*Decryptor, error) {
	info, ok := SupportedCipherSuites[cipherSuite]
	if !ok {
		return nil, fmt.Errorf("%w: 0x%04x", ErrUnsupportedCipher, cipherSuite)
	}

	if !info.IsTLS13 {
		return nil, fmt.Errorf("%w: not a TLS 1.3 cipher suite", ErrUnsupportedCipher)
	}

	d := &Decryptor{
		cipher:  info,
		isTLS13: true,
	}

	// Derive traffic keys from secrets
	if secrets.ClientTrafficSecret0 != nil {
		clientKeys, err := d.deriveTrafficKeysTLS13(secrets.ClientTrafficSecret0)
		if err != nil {
			return nil, fmt.Errorf("derive client keys: %w", err)
		}
		d.clientKeys = clientKeys
	}

	if secrets.ServerTrafficSecret0 != nil {
		serverKeys, err := d.deriveTrafficKeysTLS13(secrets.ServerTrafficSecret0)
		if err != nil {
			return nil, fmt.Errorf("derive server keys: %w", err)
		}
		d.serverKeys = serverKeys
	}

	return d, nil
}

// NewTLS12Decryptor creates a decryptor for TLS 1.2 traffic.
func NewTLS12Decryptor(cipherSuite uint16, masterSecret []byte, clientRandom, serverRandom [32]byte) (*Decryptor, error) {
	info, ok := SupportedCipherSuites[cipherSuite]
	if !ok {
		return nil, fmt.Errorf("%w: 0x%04x", ErrUnsupportedCipher, cipherSuite)
	}

	if info.IsTLS13 {
		return nil, fmt.Errorf("%w: not a TLS 1.2 cipher suite", ErrUnsupportedCipher)
	}

	if !info.IsAEAD {
		return nil, fmt.Errorf("%w: only AEAD cipher suites supported", ErrUnsupportedCipher)
	}

	d := &Decryptor{
		cipher:  info,
		isTLS13: false,
	}

	// Derive key material using PRF
	keyMaterial, err := d.deriveKeyMaterialTLS12(masterSecret, clientRandom, serverRandom)
	if err != nil {
		return nil, fmt.Errorf("derive key material: %w", err)
	}

	// Extract keys from key material
	// For AEAD: client_write_key, server_write_key, client_write_IV, server_write_IV
	keyLen := info.KeyLen
	ivLen := info.IVLen

	offset := 0
	d.clientKeys = &TrafficKeys{
		Key: keyMaterial[offset : offset+keyLen],
	}
	offset += keyLen

	d.serverKeys = &TrafficKeys{
		Key: keyMaterial[offset : offset+keyLen],
	}
	offset += keyLen

	d.clientKeys.IV = keyMaterial[offset : offset+ivLen]
	offset += ivLen

	d.serverKeys.IV = keyMaterial[offset : offset+ivLen]

	return d, nil
}

// deriveTrafficKeysTLS13 derives traffic keys from a TLS 1.3 traffic secret.
func (d *Decryptor) deriveTrafficKeysTLS13(trafficSecret []byte) (*TrafficKeys, error) {
	hashFunc := d.cipher.HashFunc

	// Derive key using HKDF-Expand-Label
	key, err := hkdfExpandLabel(hashFunc, trafficSecret, "key", nil, d.cipher.KeyLen)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}

	// Derive IV using HKDF-Expand-Label
	iv, err := hkdfExpandLabel(hashFunc, trafficSecret, "iv", nil, d.cipher.IVLen)
	if err != nil {
		return nil, fmt.Errorf("derive iv: %w", err)
	}

	return &TrafficKeys{
		Key: key,
		IV:  iv,
	}, nil
}

// deriveKeyMaterialTLS12 derives key material for TLS 1.2 using PRF.
func (d *Decryptor) deriveKeyMaterialTLS12(masterSecret []byte, clientRandom, serverRandom [32]byte) ([]byte, error) {
	// key_block = PRF(master_secret, "key expansion", server_random + client_random)
	seed := make([]byte, 64)
	copy(seed[0:32], serverRandom[:])
	copy(seed[32:64], clientRandom[:])

	// Need: 2*key_len + 2*iv_len bytes
	keyBlockLen := 2*d.cipher.KeyLen + 2*d.cipher.IVLen

	return prf12(d.cipher.HashFunc, masterSecret, []byte("key expansion"), seed, keyBlockLen)
}

// hkdfExpandLabel implements HKDF-Expand-Label for TLS 1.3.
func hkdfExpandLabel(hashFunc func() hash.Hash, secret []byte, label string, context []byte, length int) ([]byte, error) {
	// HkdfLabel struct:
	// uint16 length
	// opaque label<7..255> = "tls13 " + Label
	// opaque context<0..255>

	fullLabel := "tls13 " + label
	labelLen := len(fullLabel)
	contextLen := len(context)

	hkdfLabel := make([]byte, 2+1+labelLen+1+contextLen)
	binary.BigEndian.PutUint16(hkdfLabel[0:2], uint16(length))
	hkdfLabel[2] = byte(labelLen)
	copy(hkdfLabel[3:3+labelLen], fullLabel)
	hkdfLabel[3+labelLen] = byte(contextLen)
	if contextLen > 0 {
		copy(hkdfLabel[4+labelLen:], context)
	}

	reader := hkdf.Expand(hashFunc, secret, hkdfLabel)
	out := make([]byte, length)
	if _, err := io.ReadFull(reader, out); err != nil {
		return nil, err
	}

	return out, nil
}

// prf12 implements the TLS 1.2 PRF using P_SHA256 or P_SHA384.
func prf12(hashFunc func() hash.Hash, secret, label, seed []byte, length int) ([]byte, error) {
	labelSeed := make([]byte, len(label)+len(seed))
	copy(labelSeed, label)
	copy(labelSeed[len(label):], seed)

	return pHash(hashFunc, secret, labelSeed, length)
}

// pHash implements P_hash for TLS PRF.
func pHash(hashFunc func() hash.Hash, secret, seed []byte, length int) ([]byte, error) {
	result := make([]byte, length)
	h := hashFunc()
	hashSize := h.Size()

	// A(0) = seed
	// A(i) = HMAC_hash(secret, A(i-1))
	a := seed

	offset := 0
	for offset < length {
		// A(i) = HMAC_hash(secret, A(i-1))
		a = hmacHash(hashFunc, secret, a)

		// P_hash = HMAC_hash(secret, A(1) + seed) + HMAC_hash(secret, A(2) + seed) + ...
		input := make([]byte, len(a)+len(seed))
		copy(input, a)
		copy(input[len(a):], seed)

		output := hmacHash(hashFunc, secret, input)

		remaining := length - offset
		if remaining > hashSize {
			remaining = hashSize
		}
		copy(result[offset:offset+remaining], output[:remaining])
		offset += remaining
	}

	return result, nil
}

// hmacHash computes HMAC using the given hash function.
func hmacHash(hashFunc func() hash.Hash, key, data []byte) []byte {
	h := hashFunc()
	blockSize := h.BlockSize()

	// If key is longer than block size, hash it
	if len(key) > blockSize {
		h.Write(key)
		key = h.Sum(nil)
		h.Reset()
	}

	// Pad key to block size
	paddedKey := make([]byte, blockSize)
	copy(paddedKey, key)

	// Inner padding
	ipad := make([]byte, blockSize)
	for i := range ipad {
		ipad[i] = paddedKey[i] ^ 0x36
	}

	// Outer padding
	opad := make([]byte, blockSize)
	for i := range opad {
		opad[i] = paddedKey[i] ^ 0x5c
	}

	// Inner hash: H(ipad || data)
	h.Reset()
	h.Write(ipad)
	h.Write(data)
	innerHash := h.Sum(nil)

	// Outer hash: H(opad || innerHash)
	h.Reset()
	h.Write(opad)
	h.Write(innerHash)
	return h.Sum(nil)
}

// DecryptRecord decrypts a TLS record.
// isFromClient indicates if the record is from the client (true) or server (false).
func (d *Decryptor) DecryptRecord(record []byte, isFromClient bool) ([]byte, error) {
	if len(record) < 5 {
		return nil, ErrInvalidRecord
	}

	recordType := record[0]
	recordLen := binary.BigEndian.Uint16(record[3:5])

	if len(record) < 5+int(recordLen) {
		return nil, ErrInvalidRecord
	}

	// Only decrypt application data records
	if d.isTLS13 {
		// In TLS 1.3, all records after handshake look like application data
		if recordType != RecordTypeApplicationData {
			return nil, fmt.Errorf("unexpected record type for TLS 1.3: %d", recordType)
		}
		return d.decryptTLS13Record(record[5:5+int(recordLen)], isFromClient)
	}

	// TLS 1.2
	if recordType != RecordTypeApplicationData {
		return nil, fmt.Errorf("unexpected record type: %d", recordType)
	}
	return d.decryptTLS12Record(record, isFromClient)
}

// decryptTLS13Record decrypts a TLS 1.3 record payload.
func (d *Decryptor) decryptTLS13Record(ciphertext []byte, isFromClient bool) ([]byte, error) {
	var keys *TrafficKeys
	var seqNum *uint64

	if isFromClient {
		keys = d.clientKeys
		seqNum = &d.clientSeqNum
	} else {
		keys = d.serverKeys
		seqNum = &d.serverSeqNum
	}

	if keys == nil {
		return nil, errors.New("no keys available for decryption")
	}

	// Construct nonce: XOR IV with sequence number
	nonce := make([]byte, d.cipher.IVLen)
	copy(nonce, keys.IV)

	for i := 0; i < 8; i++ {
		nonce[d.cipher.IVLen-8+i] ^= byte(*seqNum >> (56 - 8*i))
	}

	// Increment sequence number
	*seqNum++

	// Additional data for AEAD is the record header
	// TLS 1.3: type (1) + legacy_version (2) + length (2)
	additionalData := []byte{
		RecordTypeApplicationData,
		0x03, 0x03, // TLS 1.2 version in record layer
		byte(len(ciphertext) >> 8), byte(len(ciphertext)),
	}

	// Decrypt
	plaintext, err := d.aeadDecrypt(keys.Key, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	// Remove content type byte at the end (TLS 1.3 encrypted record format)
	if len(plaintext) == 0 {
		return nil, errors.New("empty plaintext")
	}

	// Strip padding zeros and get actual content type
	for len(plaintext) > 0 && plaintext[len(plaintext)-1] == 0 {
		plaintext = plaintext[:len(plaintext)-1]
	}

	if len(plaintext) == 0 {
		return nil, errors.New("empty plaintext after removing padding")
	}

	// Last byte is the actual content type
	// actualContentType := plaintext[len(plaintext)-1]
	plaintext = plaintext[:len(plaintext)-1]

	return plaintext, nil
}

// decryptTLS12Record decrypts a TLS 1.2 AEAD record.
func (d *Decryptor) decryptTLS12Record(record []byte, isFromClient bool) ([]byte, error) {
	if len(record) < 5 {
		return nil, ErrInvalidRecord
	}

	var keys *TrafficKeys
	var seqNum *uint64

	if isFromClient {
		keys = d.clientKeys
		seqNum = &d.clientSeqNum
	} else {
		keys = d.serverKeys
		seqNum = &d.serverSeqNum
	}

	if keys == nil {
		return nil, errors.New("no keys available for decryption")
	}

	recordType := record[0]
	version := binary.BigEndian.Uint16(record[1:3])
	recordLen := binary.BigEndian.Uint16(record[3:5])
	payload := record[5 : 5+int(recordLen)]

	// TLS 1.2 AEAD: explicit nonce (8 bytes) + ciphertext + tag
	if len(payload) < 8 {
		return nil, ErrInvalidRecord
	}

	explicitNonce := payload[:8]
	ciphertext := payload[8:]

	// Construct nonce: implicit IV (4 bytes) + explicit nonce (8 bytes)
	nonce := make([]byte, 12)
	copy(nonce[:4], keys.IV)
	copy(nonce[4:], explicitNonce)

	// Additional data: seq_num (8) + type (1) + version (2) + length (2)
	// Length is the plaintext length = ciphertext length - tag length
	plaintextLen := len(ciphertext) - d.cipher.TagLen
	if plaintextLen < 0 {
		return nil, ErrInvalidRecord
	}

	additionalData := make([]byte, 13)
	binary.BigEndian.PutUint64(additionalData[0:8], *seqNum)
	additionalData[8] = recordType
	binary.BigEndian.PutUint16(additionalData[9:11], version)
	binary.BigEndian.PutUint16(additionalData[11:13], uint16(plaintextLen))

	// Increment sequence number
	*seqNum++

	// Decrypt
	plaintext, err := d.aeadDecrypt(keys.Key, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	return plaintext, nil
}

// aeadDecrypt decrypts using the configured AEAD cipher.
func (d *Decryptor) aeadDecrypt(key, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	var aead cipher.AEAD
	var err error

	if d.cipher.IsChaCha {
		aead, err = chacha20poly1305.New(key)
	} else {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aead, err = cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
	}

	if err != nil {
		return nil, err
	}

	return aead.Open(nil, nonce, ciphertext, additionalData)
}

// HasClientKeys returns true if client decryption keys are available.
func (d *Decryptor) HasClientKeys() bool {
	return d.clientKeys != nil
}

// HasServerKeys returns true if server decryption keys are available.
func (d *Decryptor) HasServerKeys() bool {
	return d.serverKeys != nil
}

// CipherName returns the name of the cipher suite.
func (d *Decryptor) CipherName() string {
	if d.cipher == nil {
		return "unknown"
	}
	return d.cipher.Name
}

// IsTLS13 returns true if this is a TLS 1.3 decryptor.
func (d *Decryptor) IsTLS13() bool {
	return d.isTLS13
}

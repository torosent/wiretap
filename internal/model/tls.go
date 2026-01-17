// Package model defines TLS-related types.
package model

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"time"
)

// TLSVersion represents TLS/SSL protocol versions.
type TLSVersion uint16

// TLS version constants.
const (
	TLSVersionSSL30 TLSVersion = 0x0300
	TLSVersion10    TLSVersion = 0x0301
	TLSVersion11    TLSVersion = 0x0302
	TLSVersion12    TLSVersion = 0x0303
	TLSVersion13    TLSVersion = 0x0304
)

// String returns the version string.
func (v TLSVersion) String() string {
	switch v {
	case TLSVersionSSL30:
		return "SSL 3.0"
	case TLSVersion10:
		return "TLS 1.0"
	case TLSVersion11:
		return "TLS 1.1"
	case TLSVersion12:
		return "TLS 1.2"
	case TLSVersion13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", uint16(v))
	}
}

// TLSContentType represents TLS record content types.
type TLSContentType uint8

// TLS content types.
const (
	TLSContentTypeChangeCipherSpec TLSContentType = 20
	TLSContentTypeAlert            TLSContentType = 21
	TLSContentTypeHandshake        TLSContentType = 22
	TLSContentTypeApplicationData  TLSContentType = 23
)

// String returns the content type name.
func (t TLSContentType) String() string {
	switch t {
	case TLSContentTypeChangeCipherSpec:
		return "ChangeCipherSpec"
	case TLSContentTypeAlert:
		return "Alert"
	case TLSContentTypeHandshake:
		return "Handshake"
	case TLSContentTypeApplicationData:
		return "ApplicationData"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(t))
	}
}

// TLSHandshakeType represents TLS handshake message types.
type TLSHandshakeType uint8

// TLS handshake types.
const (
	TLSHandshakeClientHello        TLSHandshakeType = 1
	TLSHandshakeServerHello        TLSHandshakeType = 2
	TLSHandshakeCertificate        TLSHandshakeType = 11
	TLSHandshakeServerKeyExchange  TLSHandshakeType = 12
	TLSHandshakeCertificateRequest TLSHandshakeType = 13
	TLSHandshakeServerHelloDone    TLSHandshakeType = 14
	TLSHandshakeCertificateVerify  TLSHandshakeType = 15
	TLSHandshakeClientKeyExchange  TLSHandshakeType = 16
	TLSHandshakeFinished           TLSHandshakeType = 20
)

// String returns the handshake type name.
func (t TLSHandshakeType) String() string {
	switch t {
	case TLSHandshakeClientHello:
		return "ClientHello"
	case TLSHandshakeServerHello:
		return "ServerHello"
	case TLSHandshakeCertificate:
		return "Certificate"
	case TLSHandshakeServerKeyExchange:
		return "ServerKeyExchange"
	case TLSHandshakeCertificateRequest:
		return "CertificateRequest"
	case TLSHandshakeServerHelloDone:
		return "ServerHelloDone"
	case TLSHandshakeCertificateVerify:
		return "CertificateVerify"
	case TLSHandshakeClientKeyExchange:
		return "ClientKeyExchange"
	case TLSHandshakeFinished:
		return "Finished"
	default:
		return fmt.Sprintf("Unknown(%d)", uint8(t))
	}
}

// TLSInfo contains TLS connection information.
type TLSInfo struct {
	// Version negotiated
	Version TLSVersion

	// Record version (from TLS record layer)
	RecordVersion TLSVersion

	// Client info
	ClientHello *TLSClientHello

	// Server info
	ServerHello *TLSServerHello

	// Certificates
	Certificates []*TLSCertificateInfo

	// JA3 fingerprint
	JA3       string
	JA3Digest string

	// JA3S fingerprint (server)
	JA3S       string
	JA3SDigest string

	// Connection is encrypted (post-handshake)
	Encrypted bool

	// ALPN negotiated protocol (e.g., "h2", "http/1.1")
	ALPN string

	// Timestamp
	Timestamp time.Time

	// Flags for what was seen
	IsClientHello      bool
	IsServerHello      bool
	HasApplicationData bool

	// Alert info
	AlertLevel       uint8
	AlertDescription uint8
}

// SNI returns the Server Name Indication, or empty string if not present.
func (t *TLSInfo) SNI() string {
	if t.ClientHello != nil {
		return t.ClientHello.SNI
	}
	return ""
}

// TLSClientHello contains ClientHello message details.
type TLSClientHello struct {
	// Version in ClientHello (may differ from negotiated)
	Version TLSVersion

	// Random value (32 bytes)
	Random [32]byte

	// Session ID
	SessionID []byte

	// Cipher suites offered
	CipherSuites []TLSCipherSuite

	// Compression methods offered
	CompressionMethods []uint8

	// Server Name Indication
	SNI string

	// Supported versions (TLS 1.3+)
	SupportedVersions []TLSVersion

	// Signature algorithms
	SignatureAlgorithms []uint16

	// Elliptic curves / supported groups
	EllipticCurves  []uint16
	SupportedGroups []uint16

	// EC point formats
	ECPointFormats []uint8

	// ALPN protocols
	ALPN          []string
	ALPNProtocols []string

	// Extension type IDs
	Extensions []uint16

	// JA3 fingerprint
	JA3     string
	JA3Hash string
}

// TLSServerHello contains ServerHello message details.
type TLSServerHello struct {
	// Version selected
	Version TLSVersion

	// Random value (32 bytes)
	Random [32]byte

	// Session ID
	SessionID []byte

	// Cipher suite selected
	CipherSuite TLSCipherSuite

	// Compression method selected
	CompressionMethod uint8

	// ALPN protocol selected
	ALPN string

	// Extension type IDs
	Extensions []uint16

	// JA3S fingerprint
	JA3S     string
	JA3SHash string
}

// TLSExtension represents a TLS extension.
type TLSExtension struct {
	Type uint16
	Data []byte
}

// TLS extension types.
const (
	TLSExtServerName          uint16 = 0
	TLSExtSupportedVersions   uint16 = 43
	TLSExtSignatureAlgorithms uint16 = 13
	TLSExtSupportedGroups     uint16 = 10
	TLSExtECPointFormats      uint16 = 11
	TLSExtALPN                uint16 = 16
)

// TLSCipherSuite represents a TLS cipher suite.
type TLSCipherSuite uint16

// Common cipher suites.
const (
	TLS_RSA_WITH_AES_128_CBC_SHA            TLSCipherSuite = 0x002f
	TLS_RSA_WITH_AES_256_CBC_SHA            TLSCipherSuite = 0x0035
	TLS_RSA_WITH_AES_128_GCM_SHA256         TLSCipherSuite = 0x009c
	TLS_RSA_WITH_AES_256_GCM_SHA384         TLSCipherSuite = 0x009d
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA      TLSCipherSuite = 0xc013
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA      TLSCipherSuite = 0xc014
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   TLSCipherSuite = 0xc02f
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384   TLSCipherSuite = 0xc030
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 TLSCipherSuite = 0xc02b
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 TLSCipherSuite = 0xc02c
	TLS_AES_128_GCM_SHA256                  TLSCipherSuite = 0x1301
	TLS_AES_256_GCM_SHA384                  TLSCipherSuite = 0x1302
	TLS_CHACHA20_POLY1305_SHA256            TLSCipherSuite = 0x1303
)

// String returns the cipher suite name.
func (c TLSCipherSuite) String() string {
	names := map[TLSCipherSuite]string{
		TLS_RSA_WITH_AES_128_CBC_SHA:            "TLS_RSA_WITH_AES_128_CBC_SHA",
		TLS_RSA_WITH_AES_256_CBC_SHA:            "TLS_RSA_WITH_AES_256_CBC_SHA",
		TLS_RSA_WITH_AES_128_GCM_SHA256:         "TLS_RSA_WITH_AES_128_GCM_SHA256",
		TLS_RSA_WITH_AES_256_GCM_SHA384:         "TLS_RSA_WITH_AES_256_GCM_SHA384",
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		TLS_AES_128_GCM_SHA256:                  "TLS_AES_128_GCM_SHA256",
		TLS_AES_256_GCM_SHA384:                  "TLS_AES_256_GCM_SHA384",
		TLS_CHACHA20_POLY1305_SHA256:            "TLS_CHACHA20_POLY1305_SHA256",
	}

	if name, ok := names[c]; ok {
		return name
	}
	return fmt.Sprintf("0x%04x", uint16(c))
}

// TLSCertificateInfo contains parsed certificate information.
type TLSCertificateInfo struct {
	// Subject common name
	CommonName string

	// Full subject string
	Subject string

	// Subject organization
	Organization string

	// Subject alternative names
	SANs        []string
	DNSNames    []string
	IPAddresses []string

	// Issuer common name
	IssuerCN string

	// Full issuer string
	Issuer string

	// Issuer organization
	IssuerOrg string

	// Validity
	NotBefore time.Time
	NotAfter  time.Time

	// Key info
	PublicKeyAlgorithm string
	SignatureAlgorithm string

	// Fingerprints
	SHA1Fingerprint   string
	SHA256Fingerprint string

	// Is CA certificate
	IsCA bool

	// Serial number
	SerialNumber string

	// Validity flags
	IsExpired     bool
	IsNotYetValid bool
	IsSelfSigned  bool
}

// NewTLSCertificateInfo creates a TLSCertificateInfo from an x509.Certificate.
func NewTLSCertificateInfo(cert *x509.Certificate) *TLSCertificateInfo {
	if cert == nil {
		return nil
	}

	now := time.Now()

	// Extract organization from subject
	org := ""
	if len(cert.Subject.Organization) > 0 {
		org = cert.Subject.Organization[0]
	}

	// Extract issuer organization
	issuerOrg := ""
	if len(cert.Issuer.Organization) > 0 {
		issuerOrg = cert.Issuer.Organization[0]
	}

	// Build SANs from DNS names and IP addresses
	sans := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses))
	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}

	// Build IP addresses as strings
	ipAddrs := make([]string, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		ipAddrs = append(ipAddrs, ip.String())
	}

	// Calculate fingerprints
	sha1Sum := sha1.Sum(cert.Raw)
	sha256Sum := sha256.Sum256(cert.Raw)

	// Check self-signed (issuer equals subject)
	isSelfSigned := cert.Subject.String() == cert.Issuer.String()

	return &TLSCertificateInfo{
		CommonName:         cert.Subject.CommonName,
		Subject:            cert.Subject.String(),
		Organization:       org,
		SANs:               sans,
		DNSNames:           cert.DNSNames,
		IPAddresses:        ipAddrs,
		IssuerCN:           cert.Issuer.CommonName,
		Issuer:             cert.Issuer.String(),
		IssuerOrg:          issuerOrg,
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		SHA1Fingerprint:    fmt.Sprintf("%X", sha1Sum[:]),
		SHA256Fingerprint:  fmt.Sprintf("%X", sha256Sum[:]),
		IsCA:               cert.IsCA,
		SerialNumber:       cert.SerialNumber.String(),
		IsExpired:          now.After(cert.NotAfter),
		IsNotYetValid:      now.Before(cert.NotBefore),
		IsSelfSigned:       isSelfSigned,
	}
}

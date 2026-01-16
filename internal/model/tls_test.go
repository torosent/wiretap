package model

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestTLSVersionString(t *testing.T) {
	tests := []struct {
		version  TLSVersion
		expected string
	}{
		{TLSVersionSSL30, "SSL 3.0"},
		{TLSVersion10, "TLS 1.0"},
		{TLSVersion11, "TLS 1.1"},
		{TLSVersion12, "TLS 1.2"},
		{TLSVersion13, "TLS 1.3"},
		{TLSVersion(0x0999), "Unknown (0x0999)"},
	}

	for _, tt := range tests {
		result := tt.version.String()
		if result != tt.expected {
			t.Errorf("TLSVersion(0x%04x).String() = %q, expected %q", tt.version, result, tt.expected)
		}
	}
}

func TestTLSContentTypeString(t *testing.T) {
	tests := []struct {
		contentType TLSContentType
		expected    string
	}{
		{TLSContentTypeChangeCipherSpec, "ChangeCipherSpec"},
		{TLSContentTypeAlert, "Alert"},
		{TLSContentTypeHandshake, "Handshake"},
		{TLSContentTypeApplicationData, "ApplicationData"},
		{TLSContentType(99), "Unknown(99)"},
	}

	for _, tt := range tests {
		result := tt.contentType.String()
		if result != tt.expected {
			t.Errorf("TLSContentType(%d).String() = %q, expected %q", tt.contentType, result, tt.expected)
		}
	}
}

func TestTLSHandshakeTypeString(t *testing.T) {
	tests := []struct {
		hsType   TLSHandshakeType
		expected string
	}{
		{TLSHandshakeClientHello, "ClientHello"},
		{TLSHandshakeServerHello, "ServerHello"},
		{TLSHandshakeCertificate, "Certificate"},
		{TLSHandshakeFinished, "Finished"},
		{TLSHandshakeType(99), "Unknown(99)"},
	}

	for _, tt := range tests {
		result := tt.hsType.String()
		if result != tt.expected {
			t.Errorf("TLSHandshakeType(%d).String() = %q, expected %q", tt.hsType, result, tt.expected)
		}
	}
}

func TestTLSInfoSNI(t *testing.T) {
	// Without ClientHello
	info1 := &TLSInfo{}
	if sni := info1.SNI(); sni != "" {
		t.Errorf("expected empty SNI, got %q", sni)
	}

	// With ClientHello
	info2 := &TLSInfo{
		ClientHello: &TLSClientHello{
			SNI: "example.com",
		},
	}
	if sni := info2.SNI(); sni != "example.com" {
		t.Errorf("expected 'example.com', got %q", sni)
	}
}

func TestTLSCipherSuiteString(t *testing.T) {
	tests := []struct {
		suite    TLSCipherSuite
		expected string
	}{
		{TLS_AES_128_GCM_SHA256, "TLS_AES_128_GCM_SHA256"},
		{TLS_AES_256_GCM_SHA384, "TLS_AES_256_GCM_SHA384"},
		{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		{TLSCipherSuite(0x9999), "0x9999"},
	}

	for _, tt := range tests {
		result := tt.suite.String()
		if result != tt.expected {
			t.Errorf("TLSCipherSuite(0x%04x).String() = %q, expected %q", tt.suite, result, tt.expected)
		}
	}
}

func TestNewTLSCertificateInfo(t *testing.T) {
	// Create a mock certificate
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   "example.com",
			Organization: []string{"Example Inc"},
		},
		Issuer: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test CA Org"},
		},
		NotBefore:          time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:           time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		SerialNumber:       big.NewInt(12345),
		PublicKeyAlgorithm: x509.RSA,
		SignatureAlgorithm: x509.SHA256WithRSA,
		IsCA:               false,
		DNSNames:           []string{"example.com", "www.example.com"},
	}

	info := NewTLSCertificateInfo(cert)

	if info.CommonName != "example.com" {
		t.Errorf("expected CommonName 'example.com', got %q", info.CommonName)
	}

	if info.Organization != "Example Inc" {
		t.Errorf("expected Organization 'Example Inc', got %q", info.Organization)
	}

	if info.IssuerCN != "Test CA" {
		t.Errorf("expected IssuerCN 'Test CA', got %q", info.IssuerCN)
	}

	if info.IssuerOrg != "Test CA Org" {
		t.Errorf("expected IssuerOrg 'Test CA Org', got %q", info.IssuerOrg)
	}

	if info.IsCA != false {
		t.Error("expected IsCA to be false")
	}

	if len(info.SANs) != 2 {
		t.Errorf("expected 2 SANs, got %d", len(info.SANs))
	}

	if info.SerialNumber != "12345" {
		t.Errorf("expected SerialNumber '12345', got %q", info.SerialNumber)
	}
}

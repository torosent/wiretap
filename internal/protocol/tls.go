package protocol

import (
	"bytes"
	"crypto/md5"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wiretap/wiretap/internal/model"
)

// TLS record types
const (
	tlsRecordTypeChangeCipherSpec = 20
	tlsRecordTypeAlert            = 21
	tlsRecordTypeHandshake        = 22
	tlsRecordTypeApplicationData  = 23
)

// TLS handshake types
const (
	tlsHandshakeClientHello        = 1
	tlsHandshakeServerHello        = 2
	tlsHandshakeCertificate        = 11
	tlsHandshakeServerKeyExchange  = 12
	tlsHandshakeCertificateRequest = 13
	tlsHandshakeServerHelloDone    = 14
	tlsHandshakeCertificateVerify  = 15
	tlsHandshakeClientKeyExchange  = 16
	tlsHandshakeFinished           = 20
	tlsHandshakeEncryptedExtensions = 8  // TLS 1.3
)

// TLS extension types
const (
	tlsExtServerName          = 0
	tlsExtStatusRequest       = 5
	tlsExtSupportedGroups     = 10
	tlsExtECPointFormats      = 11
	tlsExtSignatureAlgorithms = 13
	tlsExtHeartbeat           = 15
	tlsExtALPN                = 16
	tlsExtPadding             = 21
	tlsExtSessionTicket       = 35
	tlsExtSupportedVersions   = 43
	tlsExtPSKKeyExchangeModes = 45
	tlsExtKeyShare            = 51
)

// TLSDissector parses TLS protocol traffic.
type TLSDissector struct{}

// NewTLSDissector creates a new TLS dissector.
func NewTLSDissector() *TLSDissector {
	return &TLSDissector{}
}

// Name returns the dissector name.
func (d *TLSDissector) Name() string {
	return "TLS"
}

// Detect checks if data looks like TLS traffic.
func (d *TLSDissector) Detect(data []byte) bool {
	if len(data) < 5 {
		return false
	}

	// Check record type
	recordType := data[0]
	if recordType < tlsRecordTypeChangeCipherSpec || recordType > tlsRecordTypeApplicationData {
		return false
	}

	// Check version (0x0301=TLS1.0, 0x0302=TLS1.1, 0x0303=TLS1.2/1.3)
	version := binary.BigEndian.Uint16(data[1:3])
	if version < 0x0300 || version > 0x0304 {
		// Also accept SSLv3 (0x0300) but not lower
		return false
	}

	// Check record length is reasonable
	length := binary.BigEndian.Uint16(data[3:5])
	if length > 16384+2048 { // Max TLS record + overhead
		return false
	}

	return true
}

// Parse extracts TLS information from the data.
func (d *TLSDissector) Parse(data []byte, pkt *model.Packet) error {
	if len(data) < 5 {
		return ErrIncompleteData
	}

	info := &model.TLSInfo{
		Timestamp: pkt.Timestamp,
	}

	// Parse TLS records
	offset := 0
	for offset < len(data) {
		if offset+5 > len(data) {
			break
		}

		recordType := data[offset]
		version := binary.BigEndian.Uint16(data[offset+1 : offset+3])
		length := binary.BigEndian.Uint16(data[offset+3 : offset+5])

		// Set record version
		info.RecordVersion = model.TLSVersion(version)

		if offset+5+int(length) > len(data) {
			break // Incomplete record
		}

		payload := data[offset+5 : offset+5+int(length)]

		switch recordType {
		case tlsRecordTypeHandshake:
			d.parseHandshake(payload, info)
		case tlsRecordTypeAlert:
			d.parseAlert(payload, info)
		case tlsRecordTypeApplicationData:
			info.HasApplicationData = true
		}

		offset += 5 + int(length)
	}

	pkt.ApplicationProtocol = "TLS"
	pkt.TLSInfo = info

	return nil
}

// parseHandshake parses TLS handshake messages.
func (d *TLSDissector) parseHandshake(data []byte, info *model.TLSInfo) {
	offset := 0

	for offset+4 <= len(data) {
		hsType := data[offset]
		hsLen := int(data[offset+1])<<16 | int(data[offset+2])<<8 | int(data[offset+3])

		if offset+4+hsLen > len(data) {
			break
		}

		hsData := data[offset+4 : offset+4+hsLen]

		switch hsType {
		case tlsHandshakeClientHello:
			info.ClientHello = d.parseClientHello(hsData)
			info.IsClientHello = true
		case tlsHandshakeServerHello:
			info.ServerHello = d.parseServerHello(hsData)
			info.IsServerHello = true
		case tlsHandshakeCertificate:
			certs := d.parseCertificates(hsData)
			info.Certificates = certs
		}

		offset += 4 + hsLen
	}
}

// parseClientHello extracts Client Hello details.
func (d *TLSDissector) parseClientHello(data []byte) *model.TLSClientHello {
	if len(data) < 34 {
		return nil
	}

	ch := &model.TLSClientHello{}

	// Client version
	ch.Version = model.TLSVersion(binary.BigEndian.Uint16(data[0:2]))

	// Random (32 bytes)
	copy(ch.Random[:], data[2:34])

	offset := 34

	// Session ID
	if offset >= len(data) {
		return ch
	}
	sessionIDLen := int(data[offset])
	offset++
	if offset+sessionIDLen > len(data) {
		return ch
	}
	ch.SessionID = data[offset : offset+sessionIDLen]
	offset += sessionIDLen

	// Cipher suites
	if offset+2 > len(data) {
		return ch
	}
	cipherLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	if offset+cipherLen > len(data) {
		return ch
	}

	for i := 0; i < cipherLen; i += 2 {
		suite := binary.BigEndian.Uint16(data[offset+i : offset+i+2])
		ch.CipherSuites = append(ch.CipherSuites, model.TLSCipherSuite(suite))
	}
	offset += cipherLen

	// Compression methods
	if offset >= len(data) {
		return ch
	}
	compLen := int(data[offset])
	offset++
	if offset+compLen > len(data) {
		return ch
	}
	ch.CompressionMethods = data[offset : offset+compLen]
	offset += compLen

	// Extensions
	if offset+2 > len(data) {
		return ch
	}
	extLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	d.parseExtensions(data[offset:offset+extLen], ch, nil)

	// Calculate JA3 fingerprint
	ch.JA3 = d.calculateJA3(ch)
	ch.JA3Hash = fmt.Sprintf("%x", md5.Sum([]byte(ch.JA3)))

	return ch
}

// parseServerHello extracts Server Hello details.
func (d *TLSDissector) parseServerHello(data []byte) *model.TLSServerHello {
	if len(data) < 34 {
		return nil
	}

	sh := &model.TLSServerHello{}

	// Server version
	sh.Version = model.TLSVersion(binary.BigEndian.Uint16(data[0:2]))

	// Random (32 bytes)
	copy(sh.Random[:], data[2:34])

	offset := 34

	// Session ID
	if offset >= len(data) {
		return sh
	}
	sessionIDLen := int(data[offset])
	offset++
	if offset+sessionIDLen > len(data) {
		return sh
	}
	sh.SessionID = data[offset : offset+sessionIDLen]
	offset += sessionIDLen

	// Cipher suite
	if offset+2 > len(data) {
		return sh
	}
	sh.CipherSuite = model.TLSCipherSuite(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	// Compression method
	if offset >= len(data) {
		return sh
	}
	sh.CompressionMethod = data[offset]
	offset++

	// Extensions
	if offset+2 > len(data) {
		return sh
	}
	extLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	if offset+extLen <= len(data) {
		d.parseExtensions(data[offset:offset+extLen], nil, sh)
	}

	// Calculate JA3S fingerprint
	sh.JA3S = d.calculateJA3S(sh)
	sh.JA3SHash = fmt.Sprintf("%x", md5.Sum([]byte(sh.JA3S)))

	return sh
}

// parseExtensions parses TLS extensions.
func (d *TLSDissector) parseExtensions(data []byte, ch *model.TLSClientHello, sh *model.TLSServerHello) {
	offset := 0

	var extTypes []uint16
	var ellipticCurves []uint16
	var ecPointFormats []uint8

	for offset+4 <= len(data) {
		extType := binary.BigEndian.Uint16(data[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4

		if offset+extLen > len(data) {
			break
		}

		extData := data[offset : offset+extLen]
		extTypes = append(extTypes, extType)

		switch extType {
		case tlsExtServerName:
			if ch != nil && len(extData) > 5 {
				// SNI format: list length (2) + type (1) + name length (2) + name
				nameLen := int(binary.BigEndian.Uint16(extData[3:5]))
				if 5+nameLen <= len(extData) {
					ch.SNI = string(extData[5 : 5+nameLen])
				}
			}

		case tlsExtSupportedVersions:
			if sh != nil && len(extData) >= 2 {
				// Server Hello: selected version (2 bytes)
				sh.Version = model.TLSVersion(binary.BigEndian.Uint16(extData[0:2]))
			} else if ch != nil && len(extData) > 1 {
				// Client Hello: versions list
				listLen := int(extData[0])
				for i := 1; i <= listLen-1 && i+1 < len(extData); i += 2 {
					ver := binary.BigEndian.Uint16(extData[i : i+2])
					ch.SupportedVersions = append(ch.SupportedVersions, model.TLSVersion(ver))
				}
			}

		case tlsExtSupportedGroups:
			if len(extData) >= 2 {
				listLen := int(binary.BigEndian.Uint16(extData[0:2]))
				for i := 2; i < 2+listLen && i+1 < len(extData); i += 2 {
					curve := binary.BigEndian.Uint16(extData[i : i+2])
					ellipticCurves = append(ellipticCurves, curve)
				}
			}

		case tlsExtECPointFormats:
			if len(extData) >= 1 {
				listLen := int(extData[0])
				for i := 1; i <= listLen && i < len(extData); i++ {
					ecPointFormats = append(ecPointFormats, extData[i])
				}
			}

		case tlsExtALPN:
			if len(extData) >= 2 {
				// Parse ALPN protocols
				listLen := int(binary.BigEndian.Uint16(extData[0:2]))
				pos := 2
				for pos < 2+listLen && pos < len(extData) {
					protoLen := int(extData[pos])
					pos++
					if pos+protoLen <= len(extData) {
						proto := string(extData[pos : pos+protoLen])
						if ch != nil {
							ch.ALPN = append(ch.ALPN, proto)
						}
						if sh != nil {
							sh.ALPN = proto
						}
						pos += protoLen
					}
				}
			}
		}

		offset += extLen
	}

	if ch != nil {
		ch.Extensions = extTypes
		ch.EllipticCurves = ellipticCurves
		ch.ECPointFormats = ecPointFormats
	}
	if sh != nil {
		sh.Extensions = extTypes
	}
}

// parseCertificates parses the Certificate message.
func (d *TLSDissector) parseCertificates(data []byte) []*model.TLSCertificateInfo {
	if len(data) < 3 {
		return nil
	}

	totalLen := int(data[0])<<16 | int(data[1])<<8 | int(data[2])
	if totalLen+3 > len(data) {
		totalLen = len(data) - 3
	}

	var certs []*model.TLSCertificateInfo
	offset := 3

	for offset < 3+totalLen {
		if offset+3 > len(data) {
			break
		}

		certLen := int(data[offset])<<16 | int(data[offset+1])<<8 | int(data[offset+2])
		offset += 3

		if offset+certLen > len(data) {
			break
		}

		certData := data[offset : offset+certLen]
		offset += certLen

		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			continue
		}

		certInfo := &model.TLSCertificateInfo{
			Subject:            cert.Subject.String(),
			Issuer:             cert.Issuer.String(),
			SerialNumber:       cert.SerialNumber.String(),
			NotBefore:          cert.NotBefore,
			NotAfter:           cert.NotAfter,
			SignatureAlgorithm: cert.SignatureAlgorithm.String(),
			PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		}

		// Extract SANs
		certInfo.DNSNames = cert.DNSNames
		for _, ip := range cert.IPAddresses {
			certInfo.IPAddresses = append(certInfo.IPAddresses, ip.String())
		}

		// Check validity
		now := time.Now()
		certInfo.IsExpired = now.After(cert.NotAfter)
		certInfo.IsNotYetValid = now.Before(cert.NotBefore)

		// Check if self-signed
		if bytes.Equal(cert.RawSubject, cert.RawIssuer) {
			certInfo.IsSelfSigned = true
		}

		certs = append(certs, certInfo)
	}

	return certs
}

// parseAlert parses TLS alert messages.
func (d *TLSDissector) parseAlert(data []byte, info *model.TLSInfo) {
	if len(data) < 2 {
		return
	}

	info.AlertLevel = data[0]
	info.AlertDescription = data[1]
}

// calculateJA3 computes the JA3 fingerprint string.
func (d *TLSDissector) calculateJA3(ch *model.TLSClientHello) string {
	// JA3 format: version,ciphers,extensions,elliptic_curves,ec_point_formats
	var parts []string

	// Version
	parts = append(parts, fmt.Sprintf("%d", uint16(ch.Version)))

	// Cipher suites (excluding GREASE values)
	var ciphers []string
	for _, c := range ch.CipherSuites {
		if !isGREASE(uint16(c)) {
			ciphers = append(ciphers, fmt.Sprintf("%d", uint16(c)))
		}
	}
	parts = append(parts, strings.Join(ciphers, "-"))

	// Extensions (excluding GREASE values)
	var exts []string
	for _, e := range ch.Extensions {
		if !isGREASE(e) {
			exts = append(exts, fmt.Sprintf("%d", e))
		}
	}
	parts = append(parts, strings.Join(exts, "-"))

	// Elliptic curves (excluding GREASE values)
	var curves []string
	for _, c := range ch.EllipticCurves {
		if !isGREASE(c) {
			curves = append(curves, fmt.Sprintf("%d", c))
		}
	}
	parts = append(parts, strings.Join(curves, "-"))

	// EC point formats
	var formats []string
	for _, f := range ch.ECPointFormats {
		formats = append(formats, fmt.Sprintf("%d", f))
	}
	parts = append(parts, strings.Join(formats, "-"))

	return strings.Join(parts, ",")
}

// calculateJA3S computes the JA3S fingerprint string.
func (d *TLSDissector) calculateJA3S(sh *model.TLSServerHello) string {
	// JA3S format: version,cipher,extensions
	var parts []string

	// Version
	parts = append(parts, fmt.Sprintf("%d", uint16(sh.Version)))

	// Cipher suite
	parts = append(parts, fmt.Sprintf("%d", uint16(sh.CipherSuite)))

	// Extensions (excluding GREASE values)
	var exts []string
	for _, e := range sh.Extensions {
		if !isGREASE(e) {
			exts = append(exts, fmt.Sprintf("%d", e))
		}
	}
	parts = append(parts, strings.Join(exts, "-"))

	return strings.Join(parts, ",")
}

// isGREASE checks if a value is a GREASE value.
// GREASE values are used to prevent extension intolerance.
func isGREASE(v uint16) bool {
	// GREASE values: 0x0a0a, 0x1a1a, 0x2a2a, etc.
	return (v & 0x0F0F) == 0x0A0A
}

// TLSCipherSuiteName returns the name of a cipher suite.
func TLSCipherSuiteName(suite model.TLSCipherSuite) string {
	names := map[model.TLSCipherSuite]string{
		0x0000: "TLS_NULL_WITH_NULL_NULL",
		0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
		0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
		0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
		0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
		0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		0x1301: "TLS_AES_128_GCM_SHA256",
		0x1302: "TLS_AES_256_GCM_SHA384",
		0x1303: "TLS_CHACHA20_POLY1305_SHA256",
		0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	}

	if name, ok := names[suite]; ok {
		return name
	}
	return fmt.Sprintf("Unknown (0x%04X)", uint16(suite))
}

// TLSVersionName returns the name of a TLS version.
func TLSVersionName(ver model.TLSVersion) string {
	names := map[model.TLSVersion]string{
		model.TLSVersionSSL30: "SSL 3.0",
		model.TLSVersion10:    "TLS 1.0",
		model.TLSVersion11:    "TLS 1.1",
		model.TLSVersion12:    "TLS 1.2",
		model.TLSVersion13:    "TLS 1.3",
	}

	if name, ok := names[ver]; ok {
		return name
	}
	return fmt.Sprintf("Unknown (0x%04X)", uint16(ver))
}

// TLSAlertName returns the name of a TLS alert.
func TLSAlertName(desc uint8) string {
	names := map[uint8]string{
		0:   "close_notify",
		10:  "unexpected_message",
		20:  "bad_record_mac",
		21:  "decryption_failed",
		22:  "record_overflow",
		30:  "decompression_failure",
		40:  "handshake_failure",
		42:  "bad_certificate",
		43:  "unsupported_certificate",
		44:  "certificate_revoked",
		45:  "certificate_expired",
		46:  "certificate_unknown",
		47:  "illegal_parameter",
		48:  "unknown_ca",
		49:  "access_denied",
		50:  "decode_error",
		51:  "decrypt_error",
		70:  "protocol_version",
		71:  "insufficient_security",
		80:  "internal_error",
		86:  "inappropriate_fallback",
		90:  "user_canceled",
		100: "no_renegotiation",
		112: "missing_extension",
		116: "certificate_required",
	}

	if name, ok := names[desc]; ok {
		return name
	}
	return fmt.Sprintf("unknown_alert_%d", desc)
}

// FormatJA3 returns a formatted JA3 string for display.
func FormatJA3(ja3 string) string {
	parts := strings.Split(ja3, ",")
	if len(parts) != 5 {
		return ja3
	}

	var lines []string
	lines = append(lines, fmt.Sprintf("Version: %s", parts[0]))
	lines = append(lines, fmt.Sprintf("Ciphers: %s", formatList(parts[1])))
	lines = append(lines, fmt.Sprintf("Extensions: %s", formatList(parts[2])))
	lines = append(lines, fmt.Sprintf("Curves: %s", formatList(parts[3])))
	lines = append(lines, fmt.Sprintf("Point Formats: %s", parts[4]))

	return strings.Join(lines, "\n")
}

func formatList(s string) string {
	if s == "" {
		return "(none)"
	}
	parts := strings.Split(s, "-")
	if len(parts) > 10 {
		return fmt.Sprintf("%s... (%d total)", strings.Join(parts[:10], "-"), len(parts))
	}
	return s
}

// ParseCipherSuites parses a list of cipher suites from a string.
func ParseCipherSuites(s string) []model.TLSCipherSuite {
	parts := strings.Split(s, "-")
	var suites []model.TLSCipherSuite

	for _, p := range parts {
		if v, err := strconv.ParseUint(p, 10, 16); err == nil {
			suites = append(suites, model.TLSCipherSuite(v))
		}
	}

	return suites
}

// SortCipherSuites sorts cipher suites by preference.
func SortCipherSuites(suites []model.TLSCipherSuite) {
	// Sort by security strength (AEAD ciphers first, then by key size)
	sort.Slice(suites, func(i, j int) bool {
		return uint16(suites[i]) < uint16(suites[j])
	})
}

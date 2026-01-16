package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/wiretap/wiretap/internal/model"
)

// DNS constants
const (
	dnsHeaderSize = 12
	dnsPort       = 53
	dnsMaxNameLen = 255
)

// DNS opcodes
const (
	dnsOpcodeQuery  = 0
	dnsOpcodeIQuery = 1
	dnsOpcodeStatus = 2
	dnsOpcodeNotify = 4
	dnsOpcodeUpdate = 5
)

// DNS response codes
const (
	dnsRcodeNoError        = 0
	dnsRcodeFormatError    = 1
	dnsRcodeServerFailure  = 2
	dnsRcodeNameError      = 3 // NXDOMAIN
	dnsRcodeNotImplemented = 4
	dnsRcodeRefused        = 5
)

// DNS record types
const (
	dnsTypeA     = 1
	dnsTypeNS    = 2
	dnsTypeCNAME = 5
	dnsTypeSOA   = 6
	dnsTypePTR   = 12
	dnsTypeMX    = 15
	dnsTypeTXT   = 16
	dnsTypeAAAA  = 28
	dnsTypeSRV   = 33
)

// DNSDissector parses DNS protocol traffic.
type DNSDissector struct{}

// NewDNSDissector creates a new DNS dissector.
func NewDNSDissector() *DNSDissector {
	return &DNSDissector{}
}

// Name returns the dissector name.
func (d *DNSDissector) Name() string {
	return "DNS"
}

// Detect checks if data looks like DNS traffic.
func (d *DNSDissector) Detect(data []byte) bool {
	if len(data) < dnsHeaderSize {
		return false
	}

	// Check flags for valid opcode
	flags := binary.BigEndian.Uint16(data[2:4])
	opcode := (flags >> 11) & 0x0F

	if opcode > dnsOpcodeUpdate {
		return false
	}

	// Check question count is reasonable
	qdCount := binary.BigEndian.Uint16(data[4:6])
	if qdCount > 100 {
		return false
	}

	// For queries, check that we have at least one question
	isResponse := flags&0x8000 != 0
	if !isResponse && qdCount == 0 {
		return false
	}

	return true
}

// Parse extracts DNS information from the data.
func (d *DNSDissector) Parse(data []byte, pkt *model.Packet) error {
	if len(data) < dnsHeaderSize {
		return ErrIncompleteData
	}

	dns := &model.DNSInfo{}

	// Parse header
	dns.TransactionID = binary.BigEndian.Uint16(data[0:2])
	flags := binary.BigEndian.Uint16(data[2:4])

	dns.IsResponse = flags&0x8000 != 0
	dns.Opcode = uint8((flags >> 11) & 0x0F)
	dns.Authoritative = flags&0x0400 != 0
	dns.Truncated = flags&0x0200 != 0
	dns.RecursionDesired = flags&0x0100 != 0
	dns.RecursionAvailable = flags&0x0080 != 0
	dns.ResponseCode = uint8(flags & 0x000F)

	qdCount := binary.BigEndian.Uint16(data[4:6])
	anCount := binary.BigEndian.Uint16(data[6:8])
	nsCount := binary.BigEndian.Uint16(data[8:10])
	arCount := binary.BigEndian.Uint16(data[10:12])

	offset := dnsHeaderSize

	// Parse questions
	for i := uint16(0); i < qdCount && offset < len(data); i++ {
		q, newOffset, err := d.parseQuestion(data, offset)
		if err != nil {
			break
		}
		dns.Questions = append(dns.Questions, q)
		offset = newOffset
	}

	// Parse answers
	for i := uint16(0); i < anCount && offset < len(data); i++ {
		rr, newOffset, err := d.parseResourceRecord(data, offset)
		if err != nil {
			break
		}
		dns.Answers = append(dns.Answers, rr)
		offset = newOffset
	}

	// Parse authority records
	for i := uint16(0); i < nsCount && offset < len(data); i++ {
		rr, newOffset, err := d.parseResourceRecord(data, offset)
		if err != nil {
			break
		}
		dns.Authority = append(dns.Authority, rr)
		offset = newOffset
	}

	// Parse additional records
	for i := uint16(0); i < arCount && offset < len(data); i++ {
		rr, newOffset, err := d.parseResourceRecord(data, offset)
		if err != nil {
			break
		}
		dns.Additional = append(dns.Additional, rr)
		offset = newOffset
	}

	pkt.ApplicationProtocol = "DNS"
	pkt.DNSInfo = dns

	return nil
}

// parseQuestion parses a DNS question section.
func (d *DNSDissector) parseQuestion(data []byte, offset int) (*model.DNSQuestion, int, error) {
	name, newOffset, err := d.parseName(data, offset)
	if err != nil {
		return nil, offset, err
	}

	if newOffset+4 > len(data) {
		return nil, offset, ErrIncompleteData
	}

	q := &model.DNSQuestion{
		Name:  name,
		Type:  binary.BigEndian.Uint16(data[newOffset : newOffset+2]),
		Class: binary.BigEndian.Uint16(data[newOffset+2 : newOffset+4]),
	}

	return q, newOffset + 4, nil
}

// parseResourceRecord parses a DNS resource record.
func (d *DNSDissector) parseResourceRecord(data []byte, offset int) (*model.DNSResourceRecord, int, error) {
	name, newOffset, err := d.parseName(data, offset)
	if err != nil {
		return nil, offset, err
	}

	if newOffset+10 > len(data) {
		return nil, offset, ErrIncompleteData
	}

	rr := &model.DNSResourceRecord{
		Name:  name,
		Type:  binary.BigEndian.Uint16(data[newOffset : newOffset+2]),
		Class: binary.BigEndian.Uint16(data[newOffset+2 : newOffset+4]),
		TTL:   binary.BigEndian.Uint32(data[newOffset+4 : newOffset+8]),
	}

	rdLen := binary.BigEndian.Uint16(data[newOffset+8 : newOffset+10])
	newOffset += 10

	if newOffset+int(rdLen) > len(data) {
		return nil, offset, ErrIncompleteData
	}

	rr.Data = data[newOffset : newOffset+int(rdLen)]
	rr.DataString = d.formatRData(rr.Type, data, newOffset, int(rdLen))

	return rr, newOffset + int(rdLen), nil
}

// parseName parses a DNS name with compression support.
func (d *DNSDissector) parseName(data []byte, offset int) (string, int, error) {
	var name bytes.Buffer
	visited := make(map[int]bool)
	finalOffset := offset

	for {
		if offset >= len(data) {
			return "", finalOffset, ErrIncompleteData
		}

		length := int(data[offset])

		// Check for pointer (compression)
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				return "", finalOffset, ErrIncompleteData
			}

			// Get pointer offset
			ptr := int(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3FFF)

			// Prevent infinite loops
			if visited[ptr] {
				return "", finalOffset, ErrInvalidProtocol
			}
			visited[ptr] = true

			// First pointer sets the final offset
			if finalOffset == offset {
				finalOffset = offset + 2
			}

			offset = ptr
			continue
		}

		// Check for end of name
		if length == 0 {
			if finalOffset == offset {
				finalOffset = offset + 1
			}
			break
		}

		// Safety check
		if length > 63 || offset+1+length > len(data) {
			return "", finalOffset, ErrInvalidProtocol
		}

		// Add label
		if name.Len() > 0 {
			name.WriteByte('.')
		}
		name.Write(data[offset+1 : offset+1+length])

		offset += 1 + length
		if finalOffset < offset {
			finalOffset = offset
		}
	}

	return name.String(), finalOffset, nil
}

// formatRData formats resource record data for display.
func (d *DNSDissector) formatRData(rrType uint16, data []byte, offset, length int) string {
	if offset+length > len(data) {
		return fmt.Sprintf("(invalid data, len=%d)", length)
	}

	rdata := data[offset : offset+length]

	switch rrType {
	case dnsTypeA:
		if length == 4 {
			return net.IP(rdata).String()
		}
	case dnsTypeAAAA:
		if length == 16 {
			return net.IP(rdata).String()
		}
	case dnsTypeCNAME, dnsTypeNS, dnsTypePTR:
		name, _, err := d.parseName(data, offset)
		if err == nil {
			return name
		}
	case dnsTypeMX:
		if length >= 2 {
			pref := binary.BigEndian.Uint16(rdata[:2])
			name, _, err := d.parseName(data, offset+2)
			if err == nil {
				return fmt.Sprintf("%d %s", pref, name)
			}
		}
	case dnsTypeTXT:
		var parts []string
		pos := 0
		for pos < length {
			txtLen := int(rdata[pos])
			pos++
			if pos+txtLen <= length {
				parts = append(parts, string(rdata[pos:pos+txtLen]))
				pos += txtLen
			} else {
				break
			}
		}
		return strings.Join(parts, " ")
	case dnsTypeSRV:
		if length >= 6 {
			priority := binary.BigEndian.Uint16(rdata[0:2])
			weight := binary.BigEndian.Uint16(rdata[2:4])
			port := binary.BigEndian.Uint16(rdata[4:6])
			name, _, err := d.parseName(data, offset+6)
			if err == nil {
				return fmt.Sprintf("%d %d %d %s", priority, weight, port, name)
			}
		}
	}

	// Default: hex dump
	return fmt.Sprintf("% x", rdata)
}

// DNSTypeName returns the name of a DNS record type.
func DNSTypeName(t uint16) string {
	names := map[uint16]string{
		dnsTypeA:     "A",
		dnsTypeNS:    "NS",
		dnsTypeCNAME: "CNAME",
		dnsTypeSOA:   "SOA",
		dnsTypePTR:   "PTR",
		dnsTypeMX:    "MX",
		dnsTypeTXT:   "TXT",
		dnsTypeAAAA:  "AAAA",
		dnsTypeSRV:   "SRV",
	}

	if name, ok := names[t]; ok {
		return name
	}
	return fmt.Sprintf("TYPE%d", t)
}

// DNSClassName returns the name of a DNS class.
func DNSClassName(c uint16) string {
	switch c {
	case 1:
		return "IN"
	case 3:
		return "CH"
	case 4:
		return "HS"
	case 255:
		return "ANY"
	default:
		return fmt.Sprintf("CLASS%d", c)
	}
}

// DNSRcodeName returns the name of a DNS response code.
func DNSRcodeName(rcode uint8) string {
	names := map[uint8]string{
		dnsRcodeNoError:        "NOERROR",
		dnsRcodeFormatError:    "FORMERR",
		dnsRcodeServerFailure:  "SERVFAIL",
		dnsRcodeNameError:      "NXDOMAIN",
		dnsRcodeNotImplemented: "NOTIMP",
		dnsRcodeRefused:        "REFUSED",
	}

	if name, ok := names[rcode]; ok {
		return name
	}
	return fmt.Sprintf("RCODE%d", rcode)
}

// FormatDNSQuery formats a DNS query for display.
func FormatDNSQuery(dns *model.DNSInfo) string {
	if len(dns.Questions) == 0 {
		return "DNS Query (no questions)"
	}

	q := dns.Questions[0]
	return fmt.Sprintf("DNS Query: %s %s", q.Name, DNSTypeName(q.Type))
}

// FormatDNSResponse formats a DNS response for display.
func FormatDNSResponse(dns *model.DNSInfo) string {
	var parts []string

	status := DNSRcodeName(dns.ResponseCode)
	parts = append(parts, fmt.Sprintf("DNS Response: %s", status))

	for _, a := range dns.Answers {
		parts = append(parts, fmt.Sprintf("  %s %s %s", a.Name, DNSTypeName(a.Type), a.DataString))
	}

	return strings.Join(parts, "\n")
}

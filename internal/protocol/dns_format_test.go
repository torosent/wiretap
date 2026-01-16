package protocol

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/wiretap/wiretap/internal/model"
)

func TestDNSNamesAndFormatting(t *testing.T) {
	if DNSTypeName(1) != "A" {
		t.Errorf("DNSTypeName(1) = %s", DNSTypeName(1))
	}
	if DNSTypeName(999) != "TYPE999" {
		t.Errorf("DNSTypeName(999) = %s", DNSTypeName(999))
	}

	if DNSClassName(1) != "IN" {
		t.Errorf("DNSClassName(1) = %s", DNSClassName(1))
	}
	if DNSClassName(99) != "CLASS99" {
		t.Errorf("DNSClassName(99) = %s", DNSClassName(99))
	}

	if DNSRcodeName(3) != "NXDOMAIN" {
		t.Errorf("DNSRcodeName(3) = %s", DNSRcodeName(3))
	}
	if DNSRcodeName(9) != "RCODE9" {
		t.Errorf("DNSRcodeName(9) = %s", DNSRcodeName(9))
	}

	dns := &model.DNSInfo{Questions: []*model.DNSQuestion{{Name: "example.com", Type: dnsTypeA}}}
	if query := FormatDNSQuery(dns); !strings.Contains(query, "example.com") {
		t.Errorf("FormatDNSQuery = %s", query)
	}

	empty := &model.DNSInfo{}
	if query := FormatDNSQuery(empty); query != "DNS Query (no questions)" {
		t.Errorf("FormatDNSQuery empty = %s", query)
	}

	resp := &model.DNSInfo{
		ResponseCode: dnsRcodeNoError,
		Answers:      []*model.DNSResourceRecord{{Name: "example.com", Type: dnsTypeA, DataString: "1.2.3.4"}},
	}
	formatted := FormatDNSResponse(resp)
	if !strings.Contains(formatted, "DNS Response: NOERROR") {
		t.Errorf("FormatDNSResponse = %s", formatted)
	}
	if !strings.Contains(formatted, "example.com") {
		t.Errorf("Expected answer in response, got %s", formatted)
	}
}

func TestDNSDissector_Basics(t *testing.T) {
	d := NewDNSDissector()
	if d.Name() != "DNS" {
		t.Errorf("Name = %s", d.Name())
	}

	data := make([]byte, 12)
	binary.BigEndian.PutUint16(data[4:6], 1)
	if !d.Detect(data) {
		t.Error("Expected Detect to return true for basic query")
	}

	invalid := make([]byte, 11)
	if d.Detect(invalid) {
		t.Error("Expected Detect to reject short data")
	}
}

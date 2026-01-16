package filter

import (
	"net"
	"strings"
	"testing"
)

func TestDomainFilter_ExactMatch(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		mode     Mode
		domain   string
		want     bool
	}{
		{
			name:     "exact match include",
			patterns: []string{"example.com"},
			mode:     Include,
			domain:   "example.com",
			want:     true,
		},
		{
			name:     "exact match no match",
			patterns: []string{"example.com"},
			mode:     Include,
			domain:   "other.com",
			want:     false,
		},
		{
			name:     "exact match exclude",
			patterns: []string{"example.com"},
			mode:     Exclude,
			domain:   "example.com",
			want:     false,
		},
		{
			name:     "exact match exclude no match",
			patterns: []string{"example.com"},
			mode:     Exclude,
			domain:   "other.com",
			want:     true,
		},
		{
			name:     "case insensitive",
			patterns: []string{"Example.COM"},
			mode:     Include,
			domain:   "example.com",
			want:     true,
		},
		{
			name:     "multiple patterns",
			patterns: []string{"example.com", "test.org"},
			mode:     Include,
			domain:   "test.org",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewDomainFilter(tt.patterns, tt.mode)
			if err != nil {
				t.Fatalf("NewDomainFilter() error = %v", err)
			}
			if got := f.Match(tt.domain, nil, 0); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDomainFilter_WildcardMatch(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		mode     Mode
		domain   string
		want     bool
	}{
		{
			name:     "wildcard subdomain match",
			patterns: []string{"*.example.com"},
			mode:     Include,
			domain:   "www.example.com",
			want:     true,
		},
		{
			name:     "wildcard deep subdomain",
			patterns: []string{"*.example.com"},
			mode:     Include,
			domain:   "api.v2.example.com",
			want:     true,
		},
		{
			name:     "wildcard exact domain match",
			patterns: []string{"*.example.com"},
			mode:     Include,
			domain:   "example.com",
			want:     true,
		},
		{
			name:     "wildcard no match different domain",
			patterns: []string{"*.example.com"},
			mode:     Include,
			domain:   "example.org",
			want:     false,
		},
		{
			name:     "wildcard exclude",
			patterns: []string{"*.internal.com"},
			mode:     Exclude,
			domain:   "api.internal.com",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewDomainFilter(tt.patterns, tt.mode)
			if err != nil {
				t.Fatalf("NewDomainFilter() error = %v", err)
			}
			if got := f.Match(tt.domain, nil, 0); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDomainFilter_RegexMatch(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		mode     Mode
		domain   string
		want     bool
	}{
		{
			name:     "regex match",
			patterns: []string{"/.*\\.example\\.com/"},
			mode:     Include,
			domain:   "www.example.com",
			want:     true,
		},
		{
			name:     "regex no match",
			patterns: []string{"/^api\\./"},
			mode:     Include,
			domain:   "www.example.com",
			want:     false,
		},
		{
			name:     "regex prefix match",
			patterns: []string{"/^api\\./"},
			mode:     Include,
			domain:   "api.example.com",
			want:     true,
		},
		{
			name:     "regex exclude",
			patterns: []string{"/test/"},
			mode:     Exclude,
			domain:   "test.example.com",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewDomainFilter(tt.patterns, tt.mode)
			if err != nil {
				t.Fatalf("NewDomainFilter() error = %v", err)
			}
			if got := f.Match(tt.domain, nil, 0); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDomainFilter_InvalidRegex(t *testing.T) {
	_, err := NewDomainFilter([]string{"/[invalid/"}, Include)
	if err == nil {
		t.Error("NewDomainFilter() expected error for invalid regex")
	}
}

func TestDomainFilter_EmptyDomain(t *testing.T) {
	f, _ := NewDomainFilter([]string{"example.com"}, Include)
	if got := f.Match("", nil, 0); got != false {
		t.Errorf("Match() empty domain include = %v, want false", got)
	}

	f, _ = NewDomainFilter([]string{"example.com"}, Exclude)
	if got := f.Match("", nil, 0); got != true {
		t.Errorf("Match() empty domain exclude = %v, want true", got)
	}
}

func TestDomainFilter_String(t *testing.T) {
	f, _ := NewDomainFilter([]string{"example.com", "*.test.org"}, Include)
	s := f.String()
	if s == "" {
		t.Error("String() returned empty string")
	}
	if !strings.Contains(s, "DomainFilter") || !strings.Contains(s, "include") {
		t.Errorf("String() = %v, missing expected content", s)
	}
}

func TestIPFilter_SingleIP(t *testing.T) {
	tests := []struct {
		name      string
		addresses []string
		mode      Mode
		ip        net.IP
		want      bool
	}{
		{
			name:      "IPv4 match",
			addresses: []string{"192.168.1.1"},
			mode:      Include,
			ip:        net.ParseIP("192.168.1.1"),
			want:      true,
		},
		{
			name:      "IPv4 no match",
			addresses: []string{"192.168.1.1"},
			mode:      Include,
			ip:        net.ParseIP("192.168.1.2"),
			want:      false,
		},
		{
			name:      "IPv6 match",
			addresses: []string{"::1"},
			mode:      Include,
			ip:        net.ParseIP("::1"),
			want:      true,
		},
		{
			name:      "IPv4 exclude",
			addresses: []string{"10.0.0.1"},
			mode:      Exclude,
			ip:        net.ParseIP("10.0.0.1"),
			want:      false,
		},
		{
			name:      "IPv4 exclude no match",
			addresses: []string{"10.0.0.1"},
			mode:      Exclude,
			ip:        net.ParseIP("10.0.0.2"),
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewIPFilter(tt.addresses, tt.mode)
			if err != nil {
				t.Fatalf("NewIPFilter() error = %v", err)
			}
			if got := f.Match("", tt.ip, 0); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIPFilter_CIDR(t *testing.T) {
	tests := []struct {
		name      string
		addresses []string
		mode      Mode
		ip        net.IP
		want      bool
	}{
		{
			name:      "CIDR /24 match",
			addresses: []string{"192.168.1.0/24"},
			mode:      Include,
			ip:        net.ParseIP("192.168.1.100"),
			want:      true,
		},
		{
			name:      "CIDR /24 no match",
			addresses: []string{"192.168.1.0/24"},
			mode:      Include,
			ip:        net.ParseIP("192.168.2.1"),
			want:      false,
		},
		{
			name:      "CIDR /8 match",
			addresses: []string{"10.0.0.0/8"},
			mode:      Include,
			ip:        net.ParseIP("10.255.255.255"),
			want:      true,
		},
		{
			name:      "IPv6 CIDR match",
			addresses: []string{"fe80::/10"},
			mode:      Include,
			ip:        net.ParseIP("fe80::1"),
			want:      true,
		},
		{
			name:      "CIDR exclude",
			addresses: []string{"172.16.0.0/12"},
			mode:      Exclude,
			ip:        net.ParseIP("172.20.1.1"),
			want:      false,
		},
		{
			name:      "multiple CIDRs",
			addresses: []string{"10.0.0.0/8", "172.16.0.0/12"},
			mode:      Include,
			ip:        net.ParseIP("172.20.1.1"),
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewIPFilter(tt.addresses, tt.mode)
			if err != nil {
				t.Fatalf("NewIPFilter() error = %v", err)
			}
			if got := f.Match("", tt.ip, 0); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIPFilter_Invalid(t *testing.T) {
	tests := []struct {
		name      string
		addresses []string
	}{
		{name: "invalid IP", addresses: []string{"not-an-ip"}},
		{name: "invalid CIDR", addresses: []string{"192.168.1.0/33"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewIPFilter(tt.addresses, Include)
			if err == nil {
				t.Error("NewIPFilter() expected error")
			}
		})
	}
}

func TestIPFilter_NilIP(t *testing.T) {
	f, _ := NewIPFilter([]string{"192.168.1.1"}, Include)
	if got := f.Match("", nil, 0); got != false {
		t.Errorf("Match() nil IP include = %v, want false", got)
	}

	f, _ = NewIPFilter([]string{"192.168.1.1"}, Exclude)
	if got := f.Match("", nil, 0); got != true {
		t.Errorf("Match() nil IP exclude = %v, want true", got)
	}
}

func TestIPFilter_String(t *testing.T) {
	f, _ := NewIPFilter([]string{"192.168.1.1", "10.0.0.0/8"}, Include)
	s := f.String()
	if s == "" {
		t.Error("String() returned empty string")
	}
	if !strings.Contains(s, "IPFilter") || !strings.Contains(s, "include") {
		t.Errorf("String() = %v, missing expected content", s)
	}
}

func TestPortFilter_SinglePort(t *testing.T) {
	tests := []struct {
		name  string
		ports []string
		mode  Mode
		port  uint16
		want  bool
	}{
		{
			name:  "port match",
			ports: []string{"80"},
			mode:  Include,
			port:  80,
			want:  true,
		},
		{
			name:  "port no match",
			ports: []string{"80"},
			mode:  Include,
			port:  443,
			want:  false,
		},
		{
			name:  "port exclude",
			ports: []string{"22"},
			mode:  Exclude,
			port:  22,
			want:  false,
		},
		{
			name:  "port exclude no match",
			ports: []string{"22"},
			mode:  Exclude,
			port:  80,
			want:  true,
		},
		{
			name:  "multiple ports",
			ports: []string{"80", "443", "8080"},
			mode:  Include,
			port:  443,
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewPortFilter(tt.ports, tt.mode)
			if err != nil {
				t.Fatalf("NewPortFilter() error = %v", err)
			}
			if got := f.Match("", nil, tt.port); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPortFilter_Range(t *testing.T) {
	tests := []struct {
		name  string
		ports []string
		mode  Mode
		port  uint16
		want  bool
	}{
		{
			name:  "range match start",
			ports: []string{"8000-8080"},
			mode:  Include,
			port:  8000,
			want:  true,
		},
		{
			name:  "range match end",
			ports: []string{"8000-8080"},
			mode:  Include,
			port:  8080,
			want:  true,
		},
		{
			name:  "range match middle",
			ports: []string{"8000-8080"},
			mode:  Include,
			port:  8040,
			want:  true,
		},
		{
			name:  "range no match below",
			ports: []string{"8000-8080"},
			mode:  Include,
			port:  7999,
			want:  false,
		},
		{
			name:  "range no match above",
			ports: []string{"8000-8080"},
			mode:  Include,
			port:  8081,
			want:  false,
		},
		{
			name:  "range exclude",
			ports: []string{"1-1024"},
			mode:  Exclude,
			port:  22,
			want:  false,
		},
		{
			name:  "mixed port and range",
			ports: []string{"80", "8000-8080"},
			mode:  Include,
			port:  8040,
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewPortFilter(tt.ports, tt.mode)
			if err != nil {
				t.Fatalf("NewPortFilter() error = %v", err)
			}
			if got := f.Match("", nil, tt.port); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPortFilter_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		ports []string
	}{
		{name: "not a number", ports: []string{"http"}},
		{name: "port too large", ports: []string{"65536"}},
		{name: "port zero", ports: []string{"0"}},
		{name: "invalid range start", ports: []string{"abc-100"}},
		{name: "invalid range end", ports: []string{"100-xyz"}},
		{name: "reversed range", ports: []string{"100-50"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewPortFilter(tt.ports, Include)
			if err == nil {
				t.Error("NewPortFilter() expected error")
			}
		})
	}
}

func TestPortFilter_ZeroPort(t *testing.T) {
	f, _ := NewPortFilter([]string{"80"}, Include)
	if got := f.Match("", nil, 0); got != false {
		t.Errorf("Match() zero port include = %v, want false", got)
	}

	f, _ = NewPortFilter([]string{"80"}, Exclude)
	if got := f.Match("", nil, 0); got != true {
		t.Errorf("Match() zero port exclude = %v, want true", got)
	}
}

func TestPortFilter_String(t *testing.T) {
	f, _ := NewPortFilter([]string{"80", "8000-8080"}, Include)
	s := f.String()
	if s == "" {
		t.Error("String() returned empty string")
	}
	if !strings.Contains(s, "PortFilter") || !strings.Contains(s, "include") {
		t.Errorf("String() = %v, missing expected content", s)
	}
}

func TestCompositeFilter_And(t *testing.T) {
	domainFilter, _ := NewDomainFilter([]string{"example.com"}, Include)
	portFilter, _ := NewPortFilter([]string{"443"}, Include)

	f := NewCompositeFilter([]Filter{domainFilter, portFilter}, And)

	tests := []struct {
		name   string
		domain string
		ip     net.IP
		port   uint16
		want   bool
	}{
		{
			name:   "both match",
			domain: "example.com",
			port:   443,
			want:   true,
		},
		{
			name:   "domain match only",
			domain: "example.com",
			port:   80,
			want:   false,
		},
		{
			name:   "port match only",
			domain: "other.com",
			port:   443,
			want:   false,
		},
		{
			name:   "neither match",
			domain: "other.com",
			port:   80,
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := f.Match(tt.domain, tt.ip, tt.port); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCompositeFilter_Or(t *testing.T) {
	domainFilter, _ := NewDomainFilter([]string{"example.com"}, Include)
	portFilter, _ := NewPortFilter([]string{"443"}, Include)

	f := NewCompositeFilter([]Filter{domainFilter, portFilter}, Or)

	tests := []struct {
		name   string
		domain string
		ip     net.IP
		port   uint16
		want   bool
	}{
		{
			name:   "both match",
			domain: "example.com",
			port:   443,
			want:   true,
		},
		{
			name:   "domain match only",
			domain: "example.com",
			port:   80,
			want:   true,
		},
		{
			name:   "port match only",
			domain: "other.com",
			port:   443,
			want:   true,
		},
		{
			name:   "neither match",
			domain: "other.com",
			port:   80,
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := f.Match(tt.domain, tt.ip, tt.port); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCompositeFilter_Empty(t *testing.T) {
	f := NewCompositeFilter([]Filter{}, And)
	if got := f.Match("anything", nil, 80); got != true {
		t.Errorf("Match() empty AND = %v, want true", got)
	}

	f = NewCompositeFilter([]Filter{}, Or)
	if got := f.Match("anything", nil, 80); got != true {
		t.Errorf("Match() empty OR = %v, want true", got)
	}
}

func TestCompositeFilter_String(t *testing.T) {
	domainFilter, _ := NewDomainFilter([]string{"example.com"}, Include)
	f := NewCompositeFilter([]Filter{domainFilter}, And)
	s := f.String()
	if s == "" {
		t.Error("String() returned empty string")
	}
	if !strings.Contains(s, "CompositeFilter") || !strings.Contains(s, "AND") {
		t.Errorf("String() = %v, missing expected content", s)
	}
}

func TestBuildFilter_EmptyConfig(t *testing.T) {
	f, err := BuildFilter(nil)
	if err != nil {
		t.Errorf("BuildFilter(nil) error = %v", err)
	}
	if f != nil {
		t.Errorf("BuildFilter(nil) = %v, want nil", f)
	}

	f, err = BuildFilter(&FilterConfig{})
	if err != nil {
		t.Errorf("BuildFilter(empty) error = %v", err)
	}
	if f != nil {
		t.Errorf("BuildFilter(empty) = %v, want nil", f)
	}
}

func TestBuildFilter_SingleFilter(t *testing.T) {
	cfg := &FilterConfig{
		IncludeDomains: []string{"example.com"},
	}

	f, err := BuildFilter(cfg)
	if err != nil {
		t.Fatalf("BuildFilter() error = %v", err)
	}
	if f == nil {
		t.Fatal("BuildFilter() returned nil")
	}

	// Should be a DomainFilter, not a CompositeFilter
	if _, ok := f.(*DomainFilter); !ok {
		t.Errorf("BuildFilter() returned %T, want *DomainFilter", f)
	}
}

func TestBuildFilter_MultipleFilters(t *testing.T) {
	cfg := &FilterConfig{
		IncludeDomains: []string{"example.com"},
		ExcludeIPs:     []string{"10.0.0.0/8"},
		IncludePorts:   []string{"443"},
	}

	f, err := BuildFilter(cfg)
	if err != nil {
		t.Fatalf("BuildFilter() error = %v", err)
	}
	if f == nil {
		t.Fatal("BuildFilter() returned nil")
	}

	// Should be a CompositeFilter
	cf, ok := f.(*CompositeFilter)
	if !ok {
		t.Fatalf("BuildFilter() returned %T, want *CompositeFilter", f)
	}

	// Test the composite filter
	if got := cf.Match("example.com", net.ParseIP("192.168.1.1"), 443); got != true {
		t.Errorf("Match() = %v, want true", got)
	}
	if got := cf.Match("example.com", net.ParseIP("10.1.1.1"), 443); got != false {
		t.Errorf("Match() excluded IP = %v, want false", got)
	}
}

func TestBuildFilter_InvalidDomain(t *testing.T) {
	cfg := &FilterConfig{
		IncludeDomains: []string{"/[invalid/"},
	}

	_, err := BuildFilter(cfg)
	if err == nil {
		t.Error("BuildFilter() expected error for invalid domain pattern")
	}
}

func TestBuildFilter_InvalidExcludeDomain(t *testing.T) {
	cfg := &FilterConfig{
		ExcludeDomains: []string{"/[invalid/"},
	}

	_, err := BuildFilter(cfg)
	if err == nil {
		t.Error("BuildFilter() expected error for invalid exclude domain pattern")
	}
}

func TestBuildFilter_InvalidIP(t *testing.T) {
	cfg := &FilterConfig{
		IncludeIPs: []string{"not-an-ip"},
	}

	_, err := BuildFilter(cfg)
	if err == nil {
		t.Error("BuildFilter() expected error for invalid IP")
	}
}

func TestBuildFilter_InvalidExcludeIP(t *testing.T) {
	cfg := &FilterConfig{
		ExcludeIPs: []string{"not-an-ip"},
	}

	_, err := BuildFilter(cfg)
	if err == nil {
		t.Error("BuildFilter() expected error for invalid exclude IP")
	}
}

func TestBuildFilter_InvalidPort(t *testing.T) {
	cfg := &FilterConfig{
		IncludePorts: []string{"invalid"},
	}

	_, err := BuildFilter(cfg)
	if err == nil {
		t.Error("BuildFilter() expected error for invalid port")
	}
}

func TestBuildFilter_InvalidExcludePort(t *testing.T) {
	cfg := &FilterConfig{
		ExcludePorts: []string{"invalid"},
	}

	_, err := BuildFilter(cfg)
	if err == nil {
		t.Error("BuildFilter() expected error for invalid exclude port")
	}
}

func TestBuildFilter_AllFilterTypes(t *testing.T) {
	cfg := &FilterConfig{
		IncludeDomains: []string{"*.example.com"},
		ExcludeDomains: []string{"internal.example.com"},
		IncludeIPs:     []string{"192.168.0.0/16"},
		ExcludeIPs:     []string{"192.168.1.1"},
		IncludePorts:   []string{"80", "443"},
		ExcludePorts:   []string{"8080"},
	}

	f, err := BuildFilter(cfg)
	if err != nil {
		t.Fatalf("BuildFilter() error = %v", err)
	}
	if f == nil {
		t.Fatal("BuildFilter() returned nil")
	}

	// All conditions must match (AND)
	tests := []struct {
		name   string
		domain string
		ip     net.IP
		port   uint16
		want   bool
	}{
		{
			name:   "all match",
			domain: "api.example.com",
			ip:     net.ParseIP("192.168.2.1"),
			port:   443,
			want:   true,
		},
		{
			name:   "excluded domain",
			domain: "internal.example.com",
			ip:     net.ParseIP("192.168.2.1"),
			port:   443,
			want:   false,
		},
		{
			name:   "excluded IP",
			domain: "api.example.com",
			ip:     net.ParseIP("192.168.1.1"),
			port:   443,
			want:   false,
		},
		{
			name:   "excluded port",
			domain: "api.example.com",
			ip:     net.ParseIP("192.168.2.1"),
			port:   8080,
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := f.Match(tt.domain, tt.ip, tt.port); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

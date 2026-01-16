// Package filter provides domain, IP, and port filtering for network packets.
package filter

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Filter is the interface for all packet filters.
type Filter interface {
	// Match returns true if the filter matches the given parameters.
	Match(domain string, ip net.IP, port uint16) bool
	// String returns a human-readable description of the filter.
	String() string
}

// Mode determines whether a filter includes or excludes matches.
type Mode int

const (
	// Include means matching items should be included.
	Include Mode = iota
	// Exclude means matching items should be excluded.
	Exclude
)

// DomainFilter filters traffic by domain name patterns.
type DomainFilter struct {
	patterns []*domainPattern
	mode     Mode
}

type domainPattern struct {
	original string
	regex    *regexp.Regexp
	exact    string
	suffix   string // for wildcard patterns like *.example.com
}

// NewDomainFilter creates a new domain filter with the given patterns.
// Pattern formats:
//   - "example.com" - exact match
//   - "*.example.com" - matches any subdomain of example.com
//   - "/regex/" - regular expression match
func NewDomainFilter(patterns []string, mode Mode) (*DomainFilter, error) {
	df := &DomainFilter{
		patterns: make([]*domainPattern, 0, len(patterns)),
		mode:     mode,
	}

	for _, p := range patterns {
		dp, err := parseDomainPattern(p)
		if err != nil {
			return nil, fmt.Errorf("invalid domain pattern %q: %w", p, err)
		}
		df.patterns = append(df.patterns, dp)
	}

	return df, nil
}

func parseDomainPattern(pattern string) (*domainPattern, error) {
	dp := &domainPattern{original: pattern}

	// Check for regex pattern
	if strings.HasPrefix(pattern, "/") && strings.HasSuffix(pattern, "/") && len(pattern) > 2 {
		regexStr := pattern[1 : len(pattern)-1]
		re, err := regexp.Compile(regexStr)
		if err != nil {
			return nil, fmt.Errorf("invalid regex: %w", err)
		}
		dp.regex = re
		return dp, nil
	}

	// Check for wildcard pattern
	if strings.HasPrefix(pattern, "*.") {
		dp.suffix = strings.ToLower(pattern[1:]) // Keep the dot: .example.com
		return dp, nil
	}

	// Exact match
	dp.exact = strings.ToLower(pattern)
	return dp, nil
}

// Match returns true if the domain matches any pattern in the filter.
func (f *DomainFilter) Match(domain string, _ net.IP, _ uint16) bool {
	if domain == "" {
		return f.mode == Exclude // If no domain, don't filter by domain
	}

	domain = strings.ToLower(domain)
	matched := false

	for _, p := range f.patterns {
		if p.matches(domain) {
			matched = true
			break
		}
	}

	if f.mode == Include {
		return matched
	}
	return !matched
}

func (p *domainPattern) matches(domain string) bool {
	if p.regex != nil {
		return p.regex.MatchString(domain)
	}
	if p.suffix != "" {
		// Match exact domain or any subdomain
		return strings.HasSuffix(domain, p.suffix) || domain == p.suffix[1:]
	}
	return domain == p.exact
}

func (f *DomainFilter) String() string {
	patterns := make([]string, len(f.patterns))
	for i, p := range f.patterns {
		patterns[i] = p.original
	}
	mode := "include"
	if f.mode == Exclude {
		mode = "exclude"
	}
	return fmt.Sprintf("DomainFilter(%s: %v)", mode, patterns)
}

// IPFilter filters traffic by IP address or CIDR range.
type IPFilter struct {
	networks []*net.IPNet
	ips      []net.IP
	mode     Mode
}

// NewIPFilter creates a new IP filter with the given addresses/ranges.
// Formats:
//   - "192.168.1.1" - single IP address
//   - "192.168.1.0/24" - CIDR range
//   - "10.0.0.0/8" - larger CIDR range
//   - "::1" - IPv6 address
//   - "fe80::/10" - IPv6 CIDR range
func NewIPFilter(addresses []string, mode Mode) (*IPFilter, error) {
	f := &IPFilter{
		networks: make([]*net.IPNet, 0),
		ips:      make([]net.IP, 0),
		mode:     mode,
	}

	for _, addr := range addresses {
		if strings.Contains(addr, "/") {
			_, network, err := net.ParseCIDR(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", addr, err)
			}
			f.networks = append(f.networks, network)
		} else {
			ip := net.ParseIP(addr)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP address %q", addr)
			}
			f.ips = append(f.ips, ip)
		}
	}

	return f, nil
}

// Match returns true if the IP matches any address or range in the filter.
func (f *IPFilter) Match(_ string, ip net.IP, _ uint16) bool {
	if ip == nil {
		return f.mode == Exclude
	}

	matched := false

	// Check exact IPs
	for _, filterIP := range f.ips {
		if filterIP.Equal(ip) {
			matched = true
			break
		}
	}

	// Check CIDR ranges
	if !matched {
		for _, network := range f.networks {
			if network.Contains(ip) {
				matched = true
				break
			}
		}
	}

	if f.mode == Include {
		return matched
	}
	return !matched
}

func (f *IPFilter) String() string {
	parts := make([]string, 0, len(f.ips)+len(f.networks))
	for _, ip := range f.ips {
		parts = append(parts, ip.String())
	}
	for _, network := range f.networks {
		parts = append(parts, network.String())
	}
	mode := "include"
	if f.mode == Exclude {
		mode = "exclude"
	}
	return fmt.Sprintf("IPFilter(%s: %v)", mode, parts)
}

// PortFilter filters traffic by port number or port range.
type PortFilter struct {
	ports  []uint16
	ranges []portRange
	mode   Mode
}

type portRange struct {
	start uint16
	end   uint16
}

// NewPortFilter creates a new port filter with the given ports/ranges.
// Formats:
//   - "80" - single port
//   - "443" - single port
//   - "8000-8080" - port range (inclusive)
func NewPortFilter(ports []string, mode Mode) (*PortFilter, error) {
	f := &PortFilter{
		ports:  make([]uint16, 0),
		ranges: make([]portRange, 0),
		mode:   mode,
	}

	for _, p := range ports {
		if strings.Contains(p, "-") {
			parts := strings.SplitN(p, "-", 2)
			start, err := parsePort(parts[0])
			if err != nil {
				return nil, fmt.Errorf("invalid port range start %q: %w", parts[0], err)
			}
			end, err := parsePort(parts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid port range end %q: %w", parts[1], err)
			}
			if start > end {
				return nil, fmt.Errorf("invalid port range: start %d > end %d", start, end)
			}
			f.ranges = append(f.ranges, portRange{start: start, end: end})
		} else {
			port, err := parsePort(p)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q: %w", p, err)
			}
			f.ports = append(f.ports, port)
		}
	}

	return f, nil
}

func parsePort(s string) (uint16, error) {
	s = strings.TrimSpace(s)
	port, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, err
	}
	if port == 0 {
		return 0, fmt.Errorf("port cannot be 0")
	}
	return uint16(port), nil
}

// Match returns true if the port matches any port or range in the filter.
func (f *PortFilter) Match(_ string, _ net.IP, port uint16) bool {
	if port == 0 {
		return f.mode == Exclude
	}

	matched := false

	// Check exact ports
	for _, p := range f.ports {
		if p == port {
			matched = true
			break
		}
	}

	// Check port ranges
	if !matched {
		for _, r := range f.ranges {
			if port >= r.start && port <= r.end {
				matched = true
				break
			}
		}
	}

	if f.mode == Include {
		return matched
	}
	return !matched
}

func (f *PortFilter) String() string {
	parts := make([]string, 0, len(f.ports)+len(f.ranges))
	for _, p := range f.ports {
		parts = append(parts, strconv.Itoa(int(p)))
	}
	for _, r := range f.ranges {
		parts = append(parts, fmt.Sprintf("%d-%d", r.start, r.end))
	}
	mode := "include"
	if f.mode == Exclude {
		mode = "exclude"
	}
	return fmt.Sprintf("PortFilter(%s: %v)", mode, parts)
}

// CompositeFilter combines multiple filters with AND or OR logic.
type CompositeFilter struct {
	filters []Filter
	op      Operator
}

// Operator determines how composite filter combines sub-filters.
type Operator int

const (
	// And requires all sub-filters to match.
	And Operator = iota
	// Or requires at least one sub-filter to match.
	Or
)

// NewCompositeFilter creates a new composite filter.
func NewCompositeFilter(filters []Filter, op Operator) *CompositeFilter {
	return &CompositeFilter{
		filters: filters,
		op:      op,
	}
}

// Match returns true based on the operator:
//   - And: all filters must match
//   - Or: at least one filter must match
func (f *CompositeFilter) Match(domain string, ip net.IP, port uint16) bool {
	if len(f.filters) == 0 {
		return true
	}

	if f.op == And {
		for _, filter := range f.filters {
			if !filter.Match(domain, ip, port) {
				return false
			}
		}
		return true
	}

	// Or
	for _, filter := range f.filters {
		if filter.Match(domain, ip, port) {
			return true
		}
	}
	return false
}

func (f *CompositeFilter) String() string {
	parts := make([]string, len(f.filters))
	for i, filter := range f.filters {
		parts[i] = filter.String()
	}
	op := "AND"
	if f.op == Or {
		op = "OR"
	}
	return fmt.Sprintf("CompositeFilter(%s: [%s])", op, strings.Join(parts, ", "))
}

// FilterConfig holds filter configuration from config file or CLI.
type FilterConfig struct {
	// Domain patterns to include (empty means all)
	IncludeDomains []string
	// Domain patterns to exclude
	ExcludeDomains []string
	// IP addresses/ranges to include (empty means all)
	IncludeIPs []string
	// IP addresses/ranges to exclude
	ExcludeIPs []string
	// Ports to include (empty means all)
	IncludePorts []string
	// Ports to exclude
	ExcludePorts []string
}

// BuildFilter creates a composite filter from the configuration.
func BuildFilter(cfg *FilterConfig) (Filter, error) {
	if cfg == nil {
		return nil, nil
	}

	var filters []Filter

	// Domain filters
	if len(cfg.IncludeDomains) > 0 {
		f, err := NewDomainFilter(cfg.IncludeDomains, Include)
		if err != nil {
			return nil, fmt.Errorf("include domain filter: %w", err)
		}
		filters = append(filters, f)
	}
	if len(cfg.ExcludeDomains) > 0 {
		f, err := NewDomainFilter(cfg.ExcludeDomains, Exclude)
		if err != nil {
			return nil, fmt.Errorf("exclude domain filter: %w", err)
		}
		filters = append(filters, f)
	}

	// IP filters
	if len(cfg.IncludeIPs) > 0 {
		f, err := NewIPFilter(cfg.IncludeIPs, Include)
		if err != nil {
			return nil, fmt.Errorf("include IP filter: %w", err)
		}
		filters = append(filters, f)
	}
	if len(cfg.ExcludeIPs) > 0 {
		f, err := NewIPFilter(cfg.ExcludeIPs, Exclude)
		if err != nil {
			return nil, fmt.Errorf("exclude IP filter: %w", err)
		}
		filters = append(filters, f)
	}

	// Port filters
	if len(cfg.IncludePorts) > 0 {
		f, err := NewPortFilter(cfg.IncludePorts, Include)
		if err != nil {
			return nil, fmt.Errorf("include port filter: %w", err)
		}
		filters = append(filters, f)
	}
	if len(cfg.ExcludePorts) > 0 {
		f, err := NewPortFilter(cfg.ExcludePorts, Exclude)
		if err != nil {
			return nil, fmt.Errorf("exclude port filter: %w", err)
		}
		filters = append(filters, f)
	}

	if len(filters) == 0 {
		return nil, nil
	}

	if len(filters) == 1 {
		return filters[0], nil
	}

	// All filters must match (AND logic)
	return NewCompositeFilter(filters, And), nil
}

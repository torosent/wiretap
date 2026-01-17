package cli

import (
	"strings"

	"github.com/wiretap/wiretap/internal/filter"
	"github.com/wiretap/wiretap/internal/model"
)

type packetFilter struct {
	domainInclude *filter.DomainFilter
	domainExclude *filter.DomainFilter
	ipInclude     *filter.IPFilter
	ipExclude     *filter.IPFilter
	portInclude   *filter.PortFilter
	portExclude   *filter.PortFilter
}

func newPacketFilter(cfg *filter.FilterConfig) (*packetFilter, error) {
	if cfg == nil {
		return nil, nil
	}

	pf := &packetFilter{}
	var err error

	if len(cfg.IncludeDomains) > 0 {
		pf.domainInclude, err = filter.NewDomainFilter(cfg.IncludeDomains, filter.Include)
		if err != nil {
			return nil, err
		}
	}
	if len(cfg.ExcludeDomains) > 0 {
		pf.domainExclude, err = filter.NewDomainFilter(cfg.ExcludeDomains, filter.Exclude)
		if err != nil {
			return nil, err
		}
	}

	if len(cfg.IncludeIPs) > 0 {
		pf.ipInclude, err = filter.NewIPFilter(cfg.IncludeIPs, filter.Include)
		if err != nil {
			return nil, err
		}
	}
	if len(cfg.ExcludeIPs) > 0 {
		pf.ipExclude, err = filter.NewIPFilter(cfg.ExcludeIPs, filter.Exclude)
		if err != nil {
			return nil, err
		}
	}

	if len(cfg.IncludePorts) > 0 {
		pf.portInclude, err = filter.NewPortFilter(cfg.IncludePorts, filter.Include)
		if err != nil {
			return nil, err
		}
	}
	if len(cfg.ExcludePorts) > 0 {
		pf.portExclude, err = filter.NewPortFilter(cfg.ExcludePorts, filter.Exclude)
		if err != nil {
			return nil, err
		}
	}

	if pf.domainInclude == nil && pf.domainExclude == nil && pf.ipInclude == nil && pf.ipExclude == nil && pf.portInclude == nil && pf.portExclude == nil {
		return nil, nil
	}

	return pf, nil
}

func (f *packetFilter) needsDomain() bool {
	return f != nil && (f.domainInclude != nil || f.domainExclude != nil)
}

func (f *packetFilter) matches(pkt *model.Packet, domain string) bool {
	if f == nil || pkt == nil {
		return true
	}

	// Domain filters (single value)
	if f.domainInclude != nil && !f.domainInclude.Match(domain, nil, 0) {
		return false
	}
	if f.domainExclude != nil && !f.domainExclude.Match(domain, nil, 0) {
		return false
	}

	// IP filters (match either side for include, both sides for exclude)
	if f.ipInclude != nil {
		if !f.ipInclude.Match("", pkt.SrcIP, 0) && !f.ipInclude.Match("", pkt.DstIP, 0) {
			return false
		}
	}
	if f.ipExclude != nil {
		if !f.ipExclude.Match("", pkt.SrcIP, 0) || !f.ipExclude.Match("", pkt.DstIP, 0) {
			return false
		}
	}

	// Port filters (match either side for include, both sides for exclude)
	if f.portInclude != nil {
		if !f.portInclude.Match("", nil, pkt.SrcPort) && !f.portInclude.Match("", nil, pkt.DstPort) {
			return false
		}
	}
	if f.portExclude != nil {
		if !f.portExclude.Match("", nil, pkt.SrcPort) || !f.portExclude.Match("", nil, pkt.DstPort) {
			return false
		}
	}

	return true
}

func extractPacketDomain(pkt *model.Packet) string {
	if pkt == nil {
		return ""
	}

	if pkt.HTTPInfo != nil && pkt.HTTPInfo.Request != nil {
		if host := strings.TrimSpace(pkt.HTTPInfo.Request.Host); host != "" {
			return host
		}
	}
	if pkt.TLSInfo != nil {
		if sni := strings.TrimSpace(pkt.TLSInfo.SNI()); sni != "" {
			return sni
		}
	}
	if pkt.DNSInfo != nil && len(pkt.DNSInfo.Questions) > 0 {
		return strings.TrimSpace(pkt.DNSInfo.Questions[0].Name)
	}

	return ""
}

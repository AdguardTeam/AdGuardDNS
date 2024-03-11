package access

import (
	"net/netip"
	"slices"

	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/miekg/dns"
)

// Profile is the profile access manager interface.
type Profile interface {
	// Config returns profile access configuration.
	Config() (conf *ProfileConfig)

	// IsBlocked returns true if the req should be blocked.  req must not be
	// nil, and req.Question must have one item.
	IsBlocked(req *dns.Msg, rAddr netip.AddrPort, l *geoip.Location) (blocked bool)
}

// EmptyProfile is an empty profile implementation that does nothing.
type EmptyProfile struct{}

// type check
var _ Profile = EmptyProfile{}

// Config implements the [Profile] interface for EmptyProfile.  It always
// returns nil.
func (EmptyProfile) Config() (conf *ProfileConfig) { return nil }

// IsBlocked implements the [Profile] interface for EmptyProfile.  It always
// returns false.
func (EmptyProfile) IsBlocked(_ *dns.Msg, _ netip.AddrPort, _ *geoip.Location) (blocked bool) {
	return false
}

// ProfileConfig is a profile specific access configuration.
//
// NOTE: Do not change fields of this structure without incrementing
// [internal/profiledb/internal.FileCacheVersion].
type ProfileConfig struct {
	// AllowedNets is slice of CIDRs to be allowed.
	AllowedNets []netip.Prefix

	// BlockedNets is slice of CIDRs to be blocked.
	BlockedNets []netip.Prefix

	// AllowedNets is slice of location ASNs to be allowed.
	AllowedASN []geoip.ASN

	// BlockedASN is slice of location ASNs to be blocked.
	BlockedASN []geoip.ASN

	// BlocklistDomainRules is slice of rules to match requests.
	BlocklistDomainRules []string
}

// DefaultProfile controls profile specific IP and client blocking that take
// place before all other processing.  DefaultProfile is safe for concurrent
// use.
type DefaultProfile struct {
	blockedHostsEng *blockedHostEngine

	allowedNets []netip.Prefix
	blockedNets []netip.Prefix

	// TODO(d.kolyshev): Change to map[geoip.ASN]unit to improve performance.
	allowedASN []geoip.ASN
	blockedASN []geoip.ASN

	blocklistDomainRules []string
}

// NewDefaultProfile creates a new *DefaultProfile.  conf is assumed to be
// valid.
func NewDefaultProfile(conf *ProfileConfig) (p *DefaultProfile) {
	return &DefaultProfile{
		allowedNets:          conf.AllowedNets,
		blockedNets:          conf.BlockedNets,
		allowedASN:           conf.AllowedASN,
		blockedASN:           conf.BlockedASN,
		blocklistDomainRules: conf.BlocklistDomainRules,
		blockedHostsEng:      newBlockedHostEngine(conf.BlocklistDomainRules),
	}
}

// type check
var _ Profile = (*DefaultProfile)(nil)

// Config implements the [Profile] interface for *DefaultProfile.
func (p *DefaultProfile) Config() (conf *ProfileConfig) {
	return &ProfileConfig{
		AllowedNets:          slices.Clone(p.allowedNets),
		BlockedNets:          slices.Clone(p.blockedNets),
		AllowedASN:           slices.Clone(p.allowedASN),
		BlockedASN:           slices.Clone(p.blockedASN),
		BlocklistDomainRules: slices.Clone(p.blocklistDomainRules),
	}
}

// IsBlocked implements the [Profile] interface for *DefaultProfile.
func (p *DefaultProfile) IsBlocked(req *dns.Msg, rAddr netip.AddrPort, l *geoip.Location) (blocked bool) {
	ip := rAddr.Addr()

	return p.isBlockedByNets(ip, l) || p.isBlockedByHostsEng(req)
}

// isBlockedByNets returns true if ip or l is blocked by current profile.
func (p *DefaultProfile) isBlockedByNets(ip netip.Addr, l *geoip.Location) (blocked bool) {
	if matchASNs(p.allowedASN, l) || matchNets(p.allowedNets, ip) {
		return false
	}

	return matchASNs(p.blockedASN, l) || matchNets(p.blockedNets, ip)
}

// matchNets returns true if ip is contained by any of the subnets.
func matchNets(nets []netip.Prefix, ip netip.Addr) (ok bool) {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}

	return false
}

// matchASNs returns true if l is not nil and its asn is included in asns.
func matchASNs(asns []geoip.ASN, l *geoip.Location) (ok bool) {
	return l != nil && slices.Contains(asns, l.ASN)
}

// isBlockedByHostsEng returns true if the req is blocked by
// BlocklistDomainRules.  req must have exactly one question.
func (p *DefaultProfile) isBlockedByHostsEng(req *dns.Msg) (blocked bool) {
	return p.blockedHostsEng.isBlocked(req)
}

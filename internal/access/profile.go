package access

import (
	"context"
	"net/netip"
	"slices"

	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/miekg/dns"
)

// Profile is the profile access manager interface.
type Profile interface {
	// Config returns the profile access configuration.
	Config() (conf *ProfileConfig)

	// IsBlocked returns true if the req should be blocked.  req must not be
	// nil, and req.Question must have one item.
	IsBlocked(
		ctx context.Context,
		req *dns.Msg,
		rAddr netip.AddrPort,
		l *geoip.Location,
	) (blocked bool)
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
func (EmptyProfile) IsBlocked(
	_ context.Context,
	_ *dns.Msg,
	_ netip.AddrPort,
	_ *geoip.Location,
) (blocked bool) {
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

// defaultProfileConfig is the configuration for the default access for
// profiles.
type defaultProfileConfig struct {
	// conf is the configuration to use for the access manager.  It must not be
	// nil and must be valid.
	conf *ProfileConfig

	// metrics is used for the collection of the profile access engine
	// statistics.  It must not be nil.
	metrics ProfileMetrics
}

// newDefaultProfile creates a new *DefaultProfile.  conf is assumed to be
// valid.  mtrc must not be nil.
func newDefaultProfile(c *defaultProfileConfig) (p *DefaultProfile) {
	return &DefaultProfile{
		allowedNets:          c.conf.AllowedNets,
		blockedNets:          c.conf.BlockedNets,
		allowedASN:           c.conf.AllowedASN,
		blockedASN:           c.conf.BlockedASN,
		blocklistDomainRules: c.conf.BlocklistDomainRules,
		blockedHostsEng:      newBlockedHostEngine(c.metrics, c.conf.BlocklistDomainRules),
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
func (p *DefaultProfile) IsBlocked(
	ctx context.Context,
	req *dns.Msg,
	rAddr netip.AddrPort,
	l *geoip.Location,
) (blocked bool) {
	ip := rAddr.Addr()

	return p.isBlockedByNets(ip, l) || p.isBlockedByHostsEng(ctx, req)
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
func (p *DefaultProfile) isBlockedByHostsEng(ctx context.Context, req *dns.Msg) (blocked bool) {
	return p.blockedHostsEng.isBlocked(ctx, req)
}

// ProfileConstructor creates default access managers for profiles.
//
// TODO(a.garipov):  Add global standard rules for profile access managers here
// as well.
type ProfileConstructor struct {
	metrics ProfileMetrics
}

// NewProfileConstructor returns a properly initialized *ProfileConstructor.
// mtrc must not be nil.
func NewProfileConstructor(mtrc ProfileMetrics) (c *ProfileConstructor) {
	return &ProfileConstructor{
		metrics: mtrc,
	}
}

// New creates a new access manager for a profile based on the configuration.
// conf must not be nil and must be valid.
func (c *ProfileConstructor) New(conf *ProfileConfig) (p *DefaultProfile) {
	return newDefaultProfile(&defaultProfileConfig{
		conf:    conf,
		metrics: c.metrics,
	})
}

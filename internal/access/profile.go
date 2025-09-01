package access

import (
	"context"
	"net/netip"
	"slices"

	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/AdguardTeam/urlfilter"
	"github.com/miekg/dns"
)

// Profile is the profile access manager interface.
type Profile interface {
	// Config returns the profile access configuration.
	Config() (conf *ProfileConfig)

	Blocker
}

// EmptyProfile is an empty [Profile] implementation that does nothing.
type EmptyProfile struct {
	EmptyBlocker
}

// type check
var _ Profile = EmptyProfile{}

// Config implements the [Profile] interface for EmptyProfile.  It always
// returns nil.
func (EmptyProfile) Config() (conf *ProfileConfig) { return nil }

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

	// StandardEnabled controls whether the profile should also apply standard
	// access settings.
	StandardEnabled bool
}

// DefaultProfile controls profile specific IP and client blocking that take
// place before all other processing.  DefaultProfile is safe for concurrent
// use.
type DefaultProfile struct {
	standard Blocker

	blockedHostsEng *blockedHostEngine

	reqPool *syncutil.Pool[urlfilter.DNSRequest]
	resPool *syncutil.Pool[urlfilter.DNSResult]

	allowedNets []netip.Prefix
	blockedNets []netip.Prefix

	// TODO(d.kolyshev): Change to map[geoip.ASN]unit to improve performance.
	allowedASN []geoip.ASN
	blockedASN []geoip.ASN

	blocklistDomainRules []string

	standardEnabled bool
}

// defaultProfileConfig is the configuration for the default access for
// profiles.
type defaultProfileConfig struct {
	// conf is the configuration to use for the access manager.  It must not be
	// nil and must be valid.
	conf *ProfileConfig

	// reqPool is the pool of URLFilter request data to use and reuse during
	// filtering.  It must not be nil.
	reqPool *syncutil.Pool[urlfilter.DNSRequest]

	// resPool is the pool of URLFilter result data to use and reuse during
	// filtering.  It must not be nil.
	resPool *syncutil.Pool[urlfilter.DNSResult]

	// metrics is used for the collection of the profile access engine
	// statistics.  It must not be nil.
	metrics ProfileMetrics

	// standard is the standard access blocker to use.
	standard Blocker
}

// newDefaultProfile creates a new *DefaultProfile.  conf is assumed to be
// valid.  mtrc must not be nil.
func newDefaultProfile(c *defaultProfileConfig) (p *DefaultProfile) {
	return &DefaultProfile{
		standard: c.standard,

		blockedHostsEng: newBlockedHostEngine(c.metrics, c.conf.BlocklistDomainRules),

		reqPool: c.reqPool,
		resPool: c.resPool,

		allowedNets: c.conf.AllowedNets,
		blockedNets: c.conf.BlockedNets,

		allowedASN: c.conf.AllowedASN,
		blockedASN: c.conf.BlockedASN,

		blocklistDomainRules: c.conf.BlocklistDomainRules,

		standardEnabled: c.conf.StandardEnabled,
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
		StandardEnabled:      p.standardEnabled,
	}
}

// type check
var _ Blocker = (*DefaultProfile)(nil)

// IsBlocked implements the [Blocker] interface for *DefaultProfile.
func (p *DefaultProfile) IsBlocked(
	ctx context.Context,
	req *dns.Msg,
	rAddr netip.AddrPort,
	l *geoip.Location,
) (blocked bool) {
	ip := rAddr.Addr()

	return p.isBlockedByNets(ip, l) ||
		p.isBlockedByHostsEng(ctx, req) ||
		p.standard.IsBlocked(ctx, req, rAddr, l)
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

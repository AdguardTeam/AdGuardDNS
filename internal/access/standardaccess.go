package access

import (
	"context"
	"net/netip"
	"slices"
	"sync"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdurlflt"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/miekg/dns"
)

// StandardSetter is the interface for setting the standard access blocker
// configuration.
type StandardSetter interface {
	// SetConfig sets the configuration for the standard access blocker.  conf
	// must not be nil.  Fields of conf must not be modified after calling this
	// method.  It must be safe for concurrent use.
	SetConfig(conf *StandardBlockerConfig)
}

// EmptyStandard is an empty [StandardSetter] implementation that does nothing.
type EmptyStandard struct{}

// type check
var _ StandardSetter = EmptyStandard{}

// SetConfig implements the [StandardSetter] interface for EmptyStandard.  It
// always returns false.
func (EmptyStandard) SetConfig(_ *StandardBlockerConfig) {}

// StandardBlockerConfig is the configuration structure for the standard access
// blocker.
type StandardBlockerConfig struct {
	// AllowedNets are the networks allowed for DNS resolution.  If empty or
	// nil, all networks are allowed, except those blocked by BlockedNets.
	AllowedNets []netip.Prefix

	// BlockedNets are the networks blocked for DNS resolution.  If empty or
	// nil, all networks are allowed, except those allowed by AllowedNets.
	BlockedNets []netip.Prefix

	// AllowedASN are the ASNs allowed for DNS resolution.  If empty or nil, all
	// ASNs are allowed, except those blocked by BlockedASN.
	AllowedASN []geoip.ASN

	// BlockedASN are the ASNs blocked for DNS resolution.  If empty or nil, all
	// ASNs are allowed, except those allowed by AllowedASN.
	BlockedASN []geoip.ASN

	// BlocklistDomainRules are the rules blocking the domains.  If empty or
	// nil, no domains are blocked.
	BlocklistDomainRules []string
}

// StandardBlocker is the dynamic [Blocker] implementation with standard
// access settings.
type StandardBlocker struct {
	reqPool *syncutil.Pool[urlfilter.DNSRequest]
	resPool *syncutil.Pool[urlfilter.DNSResult]

	// mu protects all fields below.
	mu *sync.RWMutex

	blockedHostsEng *urlfilter.DNSEngine

	allowedNets []netip.Prefix
	blockedNets []netip.Prefix

	// TODO(d.kolyshev): Change to map[geoip.ASN]unit to improve performance.
	allowedASN []geoip.ASN
	blockedASN []geoip.ASN
}

// NewStandardBlocker creates a new StandardBlocker instance.  conf must not be
// nil.
func NewStandardBlocker(conf *StandardBlockerConfig) (s *StandardBlocker) {
	s = &StandardBlocker{
		reqPool: syncutil.NewPool(func() (req *urlfilter.DNSRequest) {
			return &urlfilter.DNSRequest{}
		}),
		resPool: syncutil.NewPool(func() (v *urlfilter.DNSResult) {
			return &urlfilter.DNSResult{}
		}),

		mu: &sync.RWMutex{},
	}

	s.SetConfig(conf)

	return s
}

// type check
var _ StandardSetter = (*StandardBlocker)(nil)

// SetConfig implements the [StandardSetter] interface for *StandardBlocker.
func (b *StandardBlocker) SetConfig(c *StandardBlockerConfig) {
	lists := []filterlist.Interface{
		filterlist.NewBytes(&filterlist.BytesConfig{
			ID:             blocklistFilterID,
			RulesText:      agdurlflt.RulesToBytesLower(c.BlocklistDomainRules),
			IgnoreCosmetic: true,
		}),
	}

	// Should never panic, since the storage has only one list.
	rulesStrg := errors.Must(filterlist.NewRuleStorage(lists))
	eng := urlfilter.NewDNSEngine(rulesStrg)

	b.mu.Lock()
	defer b.mu.Unlock()

	b.blockedHostsEng = eng
	b.allowedNets = c.AllowedNets
	b.blockedNets = c.BlockedNets
	b.allowedASN = c.AllowedASN
	b.blockedASN = c.BlockedASN
}

// type check
var _ Blocker = (*StandardBlocker)(nil)

// IsBlocked implements the [Blocker] interface for *StandardBlocker.
func (b *StandardBlocker) IsBlocked(
	_ context.Context,
	req *dns.Msg,
	rAddr netip.AddrPort,
	l *geoip.Location,
) (blocked bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	ip := rAddr.Addr()

	return b.isBlockedByNets(ip, l) || b.isBlockedByHostsEng(req)
}

// isBlockedByNets returns true if ip or l is blocked by current configuration.
func (b *StandardBlocker) isBlockedByNets(ip netip.Addr, l *geoip.Location) (blocked bool) {
	if matchASNs(b.allowedASN, l) || matchNets(b.allowedNets, ip) {
		return false
	}

	return matchASNs(b.blockedASN, l) || matchNets(b.blockedNets, ip)
}

// isBlockedByHostsEng returns true if the req is blocked by blocklist domain
// rules.  req must have exactly one question.
func (b *StandardBlocker) isBlockedByHostsEng(req *dns.Msg) (blocked bool) {
	q := req.Question[0]

	host := agdnet.NormalizeQueryDomain(q.Name)

	return matchBlocked(host, q.Qtype, b.blockedHostsEng, b.reqPool, b.resPool)
}

// Equal returns true if c and other are equal.  nil is only equal to other nil.
func (c *StandardBlockerConfig) Equal(other *StandardBlockerConfig) (ok bool) {
	if c == nil {
		return other == nil
	} else if other == nil {
		return false
	}

	switch {
	case
		!slices.Equal(c.AllowedNets, other.AllowedNets),
		!slices.Equal(c.BlockedNets, other.BlockedNets),
		!slices.Equal(c.AllowedASN, other.AllowedASN),
		!slices.Equal(c.BlockedASN, other.BlockedASN),
		!slices.Equal(c.BlocklistDomainRules, other.BlocklistDomainRules):
		return false
	default:
		return true
	}
}

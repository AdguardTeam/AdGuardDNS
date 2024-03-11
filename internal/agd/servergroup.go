package agd

import (
	"crypto/tls"
	"fmt"
	"math"
	"net/netip"

	"github.com/AdguardTeam/golibs/stringutil"
	"github.com/miekg/dns"
)

// ServerGroup is a group of DNS servers all of which use the same filtering
// settings.
type ServerGroup struct {
	// BlockPageRedirect is the configuration for the server group's block page.
	// BlockPageRedirect is never nil.
	//
	// TODO(a.garipov): Use.
	BlockPageRedirect *BlockPageRedirect

	// DDR is the configuration for the server group's Discovery Of Designated
	// Resolvers (DDR) handlers.  DDR is never nil.
	DDR *DDR

	// TLS are the TLS settings for this server group.  If Servers contains at
	// least one server with a non-plain protocol (see [Protocol.IsPlain]), TLS
	// must not be nil.
	TLS *TLS

	// Name is the unique name of the server group.
	Name ServerGroupName

	// FilteringGroup is the ID of the filtering group for this server.
	FilteringGroup FilteringGroupID

	// Servers are the settings for servers.  Each element must be non-nil.
	Servers []*Server
}

// ServerGroupName is the name of a server group.
type ServerGroupName string

// TLS is the TLS configuration of a DNS server group.
type TLS struct {
	// Conf is the server's TLS configuration.
	Conf *tls.Config

	// DeviceIDWildcards are the domain wildcards used to detect device IDs from
	// clients' server names.
	DeviceIDWildcards []string

	// SessionKeys are paths to files containing the TLS session keys for this
	// server.
	SessionKeys []string
}

// DDR is the configuration for the server group's Discovery Of Designated
// Resolvers (DDR) handlers.
type DDR struct {
	// DeviceTargets is the set of all domain names, subdomains of which should
	// be checked for DDR queries with device IDs.
	DeviceTargets *stringutil.Set

	// PublicTargets is the set of all public domain names, DDR queries for
	// which should be processed.
	PublicTargets *stringutil.Set

	// DeviceRecordTemplates are used to respond to DDR queries from recognized
	// devices.
	DeviceRecordTemplates []*dns.SVCB

	// PubilcRecordTemplates are used to respond to DDR queries from
	// unrecognized devices.
	PublicRecordTemplates []*dns.SVCB

	// Enabled shows if DDR queries are processed.  If it is false, DDR domain
	// name queries receive an NXDOMAIN response.
	Enabled bool
}

// BlockPageRedirect is the configuration for a [ServerGroup]'s block page.
type BlockPageRedirect struct {
	// Apply defines request parameters based on which the block page is shown
	// always.  If a request matches Apply, both [BlockPageRedirect.Skip] and
	// [BlockPageRedirect.Probability] are ignored.
	//
	// If [BlockPageRedirect.Enabled] is true, Apply must not be nil.
	Apply *BlockPageRedirectApply

	// Skip defines request parameters based on which the block page is not
	// shown, regardless of [BlockPageRedirect.Probability].
	//
	// If [BlockPageRedirect.Enabled] is true, Skip must not be nil.
	Skip *BlockPageRedirectSkip

	// IPv4 are the IPv4 addresses of the block page, used to respond to A
	// queries.
	//
	// If [BlockPageRedirect.Enabled] is true, IPv4, [BlockPageRedirect.IPv6],
	// or both must be filled.
	IPv4 []netip.Addr

	// IPv6 are the IPv6 addresses of the block page, used to respond to AAAA
	// queries.
	//
	// If [BlockPageRedirect.Enabled] is true, [BlockPageRedirect.IPv4], IPv6,
	// or both must be filled.
	IPv6 []netip.Addr

	// Probability defines the probability of responding with the block page IPs
	// based on remote address.  Probability must be between 0.0 and 1.0.
	Probability Probability

	// Enabled defines whether the block-page feature is enabled.
	Enabled bool
}

// Probability is a type for probabilities ranging from 0.0 to 1.0.
type Probability float64

// NewProbability returns a properly converted Probability or an error.
func NewProbability(f float64) (prob Probability, err error) {
	if math.IsNaN(f) || f < 0.0 || f > 1.0 {
		return 0, fmt.Errorf("probability must be between 0.0 and 1.0; got %v", f)
	}

	return Probability(f), nil
}

// MustNewProbability returns a properly converted Probability or panics with an
// error.
func MustNewProbability(f float64) (prob Probability) {
	prob, err := NewProbability(f)
	if err != nil {
		panic(err)
	}

	return prob
}

// BlockPageRedirectApply defines the conditions for applying the block-page
// logic for a particular request.
type BlockPageRedirectApply struct {
	// ClientSubnets are the subnets for which block page is always enabled.
	ClientSubnets []netip.Prefix
}

// BlockPageRedirectSkip defines the conditions for skipping the block page
// logic for a particular request.
type BlockPageRedirectSkip struct {
	// ClientSubnets are the subnets for which block page is always disabled.
	ClientSubnets []netip.Prefix

	// QuestionDomains are the domain names for which block page is always
	// disabled.
	QuestionDomains []string
}

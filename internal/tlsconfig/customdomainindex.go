package tlsconfig

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtime"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/logutil/optslog"
)

// customDomainIndex optimizes the search for custom-domain data.
type customDomainIndex struct {
	// changed is the set of names of certificates that need updating.
	changed *container.SortedSliceSet[agd.CertificateName]

	// retries contains the data for retrying refreshes of custom-domain data.
	retries map[agd.CertificateName]*customDomainRetry

	// data is the mapping of custom domain or wildcard suffix to records that
	// relate to it.  The key must be a valid domain name, not a wildcard.
	// Items must not be nil.
	data map[string][]*customDomainIndexItem

	// accountIPPrefixes is the mapping of certificate names to a set of account
	// IP prefixes related to this certificate.  All elements must be full
	// prefixes.
	accountIPPrefixes map[agd.CertificateName]*prefixSet
}

// newCustomDomainIndex returns a new properly initialized *customDomainIndex.
func newCustomDomainIndex() (idx *customDomainIndex) {
	return &customDomainIndex{
		changed:           container.NewSortedSliceSet[agd.CertificateName](),
		retries:           map[agd.CertificateName]*customDomainRetry{},
		data:              map[string][]*customDomainIndexItem{},
		accountIPPrefixes: map[agd.CertificateName]*prefixSet{},
	}
}

// customDomainIndexItem contains data about a single custom domain.
type customDomainIndexItem struct {
	// accountIP is the destination IP for which certificate must be served.
	accountIP netip.Addr

	// notBefore is the time before which the certificate is not valid.  It must
	// not be empty and must be strictly before notAfter.
	notBefore time.Time

	// notAfter is the time after which the certificate is not valid.  It must
	// not be empty and must be strictly after notBefore.
	notAfter time.Time

	// certName is the unique name for fetching the actual certificate data.  It
	// must not be empty.
	certName agd.CertificateName

	// domain is the original domain name or wildcard from which the domain
	// pattern has been derived.  It must be a valid domain name or wildcard.
	domain string

	// accountID is the ID of the account to which this certificate belongs.
	accountID agd.AccountID
}

// customDomainRetry defines when a failed refresh of a certificate should be
// retried.
type customDomainRetry struct {
	// sched is the schedule that updates next.  It must not be nil.
	sched *agdtime.ExponentialSchedule

	// next is the next point in time after which the certificate refresh should
	// be retried.
	next time.Time
}

// match checks if the item matches the client data and the current time.
// matches is true if the client data match the item; isWC is true if the item
// is a wildcard domain.  isWC is never true if matches is false.
func (item *customDomainIndexItem) match(cliSrvName string, now time.Time) (matches, isWC bool) {
	if now.After(item.notAfter) || now.Before(item.notBefore) {
		return false, false
	}

	if item.domain == cliSrvName {
		return true, false
	} else if strings.HasPrefix(item.domain, "*.") && item.domain[len("*."):] == cliSrvName {
		return true, true
	}

	return false, false
}

// sameID returns true if item has the same identifiers as other.  item and
// other may be nil.
func (item *customDomainIndexItem) sameID(other *customDomainIndexItem) (ok bool) {
	if item == nil || other == nil {
		return item == other
	}

	return item.certName == other.certName &&
		item.domain == other.domain &&
		item.accountID == other.accountID &&
		item.accountIP == other.accountIP
}

// add saves the data about domains to the index.  l and state must not be nil.
// domains must contain only valid domain names and wildcards.
func (idx *customDomainIndex) add(
	ctx context.Context,
	l *slog.Logger,
	accID agd.AccountID,
	domains []string,
	state *agd.CustomDomainStateCurrent,
	accIP netip.Addr,
) {
	certName := state.CertName
	changed := false

	idx.addAccountIPPrefix(accIP, certName)
	for _, domain := range domains {
		added := idx.addItem(&customDomainIndexItem{
			notAfter:  state.NotAfter,
			notBefore: state.NotBefore,
			accountID: accID,
			certName:  certName,
			domain:    domain,
			accountIP: accIP,
		})

		// NOTE:  Do not merge this with the addItem call, since that will
		// short-circuit the logical operator and prevent the method call.
		changed = changed || added
	}

	if changed {
		idx.changed.Add(certName)

		l.DebugContext(ctx, "cert data changed")
	}
}

// addAccountIPPrefix adds a prefix for the given account IP to the set.  If
// accIP is not valid, it does nothing.
func (idx *customDomainIndex) addAccountIPPrefix(
	accIP netip.Addr,
	certName agd.CertificateName,
) {
	if !accIP.IsValid() {
		return
	}

	prefix := netip.PrefixFrom(accIP, accIP.BitLen())
	_, ok := idx.accountIPPrefixes[certName]
	if !ok {
		idx.accountIPPrefixes[certName] = &prefixSet{}
	}

	idx.accountIPPrefixes[certName].add(prefix)
}

// addItem adds a new item if it isn't already in the index.  changed is true if
// item has been added and false if it has already been in the index.
func (idx *customDomainIndex) addItem(item *customDomainIndexItem) (changed bool) {
	domainSuffix := strings.TrimPrefix(item.domain, "*.")
	prev := idx.data[domainSuffix]
	if len(prev) == 0 {
		idx.data[domainSuffix] = []*customDomainIndexItem{item}

		return true
	}

	for _, prevItem := range prev {
		if prevItem.sameID(item) {
			return false
		}
	}

	idx.data[domainSuffix] = append(prev, item)

	return true
}

// match returns the domain name or wildcard that matches the client-sent server
// name.  l must not be nil.
func (idx *customDomainIndex) match(
	ctx context.Context,
	l *slog.Logger,
	cliSrvName string,
	now time.Time,
) (matchedDomain string, accID agd.AccountID, accIP netip.Addr) {
	// First, check the domain itself.
	matched := idx.data[cliSrvName]
	for _, item := range matched {
		matches, isWC := item.match(cliSrvName, now)
		if matches && !isWC {
			optslog.Trace1(ctx, l, "matched custom domain", "domain", item.domain)

			return cliSrvName, item.accountID, item.accountIP
		}
	}

	// If nothing matched, check the domain without the supposed DeviceID
	// against the wildcards.
	_, suf, ok := strings.Cut(cliSrvName, ".")
	if !ok {
		return "", 0, netip.Addr{}
	}

	matched = idx.data[suf]
	for _, item := range matched {
		matches, isWC := item.match(suf, now)
		if matches && isWC {
			optslog.Trace1(ctx, l, "matched custom domain wildcard", "wildcard", item.domain)

			return item.domain, item.accountID, item.accountIP
		}
	}

	return "", 0, netip.Addr{}
}

// remove deletes the data about domains from the index.  l must not be nil.
// certName must not be empty.  domains must contain only valid domain names and
// wildcards.
func (idx *customDomainIndex) remove(
	ctx context.Context,
	l *slog.Logger,
	certName agd.CertificateName,
	accID agd.AccountID,
	accIP netip.Addr,
	domains []string,
) {
	idx.deleteAccountIPPrefix(accIP, certName)

	for _, domain := range domains {
		item := &customDomainIndexItem{
			// Do not set notAfter, notBefore, as they are unnecessary for
			// sameID.
			certName:  certName,
			domain:    domain,
			accountID: accID,
			accountIP: accIP,
		}

		domainSuffix := strings.TrimPrefix(item.domain, "*.")
		prev := idx.data[domainSuffix]
		if len(prev) == 0 {
			continue
		}

		idx.data[domainSuffix] = slices.DeleteFunc(prev, item.sameID)

		l.DebugContext(ctx, "cert data deleted")
	}

	idx.changed.Delete(certName)

	delete(idx.retries, certName)
}

// deleteAccountIPPrefix removes the prefix for the given account IP from the
// set.  If accIP is not valid, it does nothing.
func (idx *customDomainIndex) deleteAccountIPPrefix(
	accIP netip.Addr,
	certName agd.CertificateName,
) {
	if !accIP.IsValid() {
		return
	}

	prefix := netip.PrefixFrom(accIP, accIP.BitLen())
	prefixes, ok := idx.accountIPPrefixes[certName]
	if ok {
		prefixes.delete(prefix)
		if prefixes.len() == 0 {
			delete(idx.accountIPPrefixes, certName)
		}
	}
}

// currentCount returns the current number of custom-domain items in the index.
func (idx *customDomainIndex) currentCount() (n uint) {
	for _, domains := range idx.data {
		n += uint(len(domains))
	}

	return n
}

// collectCertNames returns a sorted set with all unique certificates names of
// the index.
func (idx *customDomainIndex) collectCertNames() (
	certNames *container.SortedSliceSet[agd.CertificateName],
) {
	names := make([]agd.CertificateName, 0, idx.currentCount())
	for _, items := range idx.data {
		for _, it := range items {
			names = append(names, it.certName)
		}
	}

	return container.NewSortedSliceSet(names...)
}

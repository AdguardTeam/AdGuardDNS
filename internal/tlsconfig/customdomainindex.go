package tlsconfig

import (
	"context"
	"log/slog"
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
}

// newCustomDomainIndex returns a new properly initialized *customDomainIndex.
func newCustomDomainIndex() (idx *customDomainIndex) {
	return &customDomainIndex{
		changed: container.NewSortedSliceSet[agd.CertificateName](),
		retries: map[agd.CertificateName]*customDomainRetry{},
		data:    map[string][]*customDomainIndexItem{},
	}
}

// customDomainIndexItem contains data about a single custom domain.
type customDomainIndexItem struct {
	// notBefore is the time before which the certificate is not valid.  It must
	// not be empty and must be strictly before notAfter.
	notBefore time.Time

	// notAfter is the time after which the certificate is not valid.  It must
	// not be empty and must be strictly after notBefore.
	notAfter time.Time

	// profileID is the ID of the profile to which this certificate belongs.  It
	// must not be empty.
	profileID agd.ProfileID

	// certName is the unique name for fetching the actual certificate data.  It
	// must not be empty.
	certName agd.CertificateName

	// domain is the original domain name or wildcard from which the domain
	// pattern has been derived.  It must be a valid domain name or wildcard.
	domain string
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
		item.profileID == other.profileID
}

// add saves the data about domains to the index.  l and state must not be nil.
// profID must not be empty.  domains must contain only valid domain names and
// wildcards.
func (idx *customDomainIndex) add(
	ctx context.Context,
	l *slog.Logger,
	profID agd.ProfileID,
	domains []string,
	state *agd.CustomDomainStateCurrent,
) {
	certName := state.CertName
	changed := false

	for _, domain := range domains {
		added := idx.addItem(&customDomainIndexItem{
			notAfter:  state.NotAfter,
			notBefore: state.NotBefore,
			profileID: profID,
			certName:  certName,
			domain:    domain,
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
) (matchedDomain string, profIDs []agd.ProfileID) {
	// First, check the domain itself.
	matched := idx.data[cliSrvName]
	for _, item := range matched {
		matches, isWC := item.match(cliSrvName, now)
		if matches && !isWC {
			optslog.Trace1(ctx, l, "matched custom domain", "domain", item.domain)

			profIDs = append(profIDs, item.profileID)
		}
	}

	if len(profIDs) > 0 {
		return cliSrvName, profIDs
	}

	// If nothing matched, check the domain without the supposed DeviceID
	// against the wildcards.
	_, suf, ok := strings.Cut(cliSrvName, ".")
	if !ok {
		return "", nil
	}

	matched = idx.data[suf]
	for _, item := range matched {
		matches, isWC := item.match(suf, now)
		if matches && isWC {
			optslog.Trace1(ctx, l, "matched custom domain wildcard", "wildcard", item.domain)

			matchedDomain = item.domain
			profIDs = append(profIDs, item.profileID)
		}
	}

	return matchedDomain, profIDs
}

// remove deletes the data about domains from the index.  l must not be nil.
// certName must not be empty.  domains must contain only valid domain names and
// wildcards.
func (idx *customDomainIndex) remove(
	ctx context.Context,
	l *slog.Logger,
	certName agd.CertificateName,
	profID agd.ProfileID,
	domains []string,
) {
	for _, domain := range domains {
		item := &customDomainIndexItem{
			// Do not set notAfter, notBefore, as they are unnecessary for
			// sameID.
			certName:  certName,
			domain:    domain,
			profileID: profID,
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

// currentCount returns the current number of custom-domain items in the index.
func (idx *customDomainIndex) currentCount() (n uint) {
	for _, domains := range idx.data {
		n += uint(len(domains))
	}

	return n
}

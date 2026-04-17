package dnspb

import (
	"fmt"
	"net/http/cookiejar"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/filterindex"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/validate"
)

// ToInternal converts a typosquatting-filter index from a backend protobuf
// response to an AdGuard DNS index.  list must not be nil.
func (x *TyposquattingFilterIndex) ToInternal(
	list cookiejar.PublicSuffixList,
) (idx *filterindex.Typosquatting, err error) {
	if err = validate.NotNil("index", x); err != nil {
		return nil, err
	}

	var errs []error
	domains, errs := protectedDomainsToInternal(x.GetDomains(), list, errs)

	pbExceptions := x.GetExceptions()
	exceptions := make([]*filterindex.TyposquattingException, 0, len(pbExceptions))
	for i, pbe := range pbExceptions {
		d := pbe.GetDomain()
		err = validateETLDPlus1(d, list)
		if err != nil {
			errs = append(errs, fmt.Errorf("exceptions: at index %d: domain: %w", i, err))

			continue
		}

		exceptions = append(exceptions, &filterindex.TyposquattingException{
			Domain: d,
		})
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	return &filterindex.Typosquatting{
		Domains:    domains,
		Exceptions: exceptions,
	}, nil
}

// validateETLDPlus1 returns an error if domain is not a valid eTLD+1 domain.
// list must not be nil.
func validateETLDPlus1(domain string, list cookiejar.PublicSuffixList) (err error) {
	etld, err := agdnet.EffectiveTLDPlusOne(list, domain)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	if domain != etld {
		return errors.Error("not an etld+1 domain")
	}

	return nil
}

// protectedDomainsToInternal converts the protected domains from protobuf to
// AdGuard DNS entities.  It appends all errors to errs and returns it.  list
// must not be nil.
func protectedDomainsToInternal(
	pbDomains []*TyposquattingFilterIndex_ProtectedDomain,
	list cookiejar.PublicSuffixList,
	errs []error,
) (domains []*filterindex.TyposquattingProtectedDomain, resErrs []error) {
	resErrs = errs

	domains = make([]*filterindex.TyposquattingProtectedDomain, 0, len(pbDomains))
	for i, pbd := range pbDomains {
		d := pbd.GetDomain()
		err := validateETLDPlus1(d, list)
		if err != nil {
			resErrs = append(resErrs, fmt.Errorf("domains: at index %d: domain: %w", i, err))
		}

		dist := pbd.GetDistance()
		err = validate.Positive("distance", dist)
		if err != nil {
			resErrs = append(resErrs, fmt.Errorf("domains: at index %d: %w", i, err))
		}

		domains = append(domains, &filterindex.TyposquattingProtectedDomain{
			Domain:   d,
			Distance: uint(dist),
		})
	}

	return domains, resErrs
}

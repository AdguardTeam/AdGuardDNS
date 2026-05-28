package dnspb

import (
	"fmt"
	"net/http/cookiejar"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/filterindex"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
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
	domains, errs := typosquattingDomainsToInternal(x.GetDomains(), list, errs)

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

// typosquattingDomainsToInternal converts the domains protected by the
// typosquatting filter from protobuf to AdGuard DNS entities.  It appends all
// errors to errs and returns it.  list must not be nil.
func typosquattingDomainsToInternal(
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

			continue
		}

		dist := pbd.GetDistance()
		err = validate.InRange("distance", dist, 1, netutil.MaxDomainNameLen)
		if err != nil {
			resErrs = append(resErrs, fmt.Errorf("domains: at index %d: %w", i, err))

			continue
		}

		domains = append(domains, &filterindex.TyposquattingProtectedDomain{
			Domain:   d,
			Distance: uint(dist),
		})
	}

	return domains, resErrs
}

// ToInternal converts a homoglyph-filter index from a backend protobuf response
// to an AdGuard DNS index.  list must not be nil.
func (x *HomoglyphFilterIndex) ToInternal(
	list cookiejar.PublicSuffixList,
) (idx *filterindex.Homoglyph, err error) {
	if err = validate.NotNil("index", x); err != nil {
		return nil, err
	}

	var errs []error
	domains, errs := homoglyphDomainsToInternal(x.GetDomains(), list, errs)

	pbExceptions := x.GetExceptions()
	exceptions := make([]*filterindex.HomoglyphException, 0, len(pbExceptions))
	for i, pbe := range pbExceptions {
		d := pbe.GetDomain()
		err = validateETLDPlus1(d, list)
		if err != nil {
			errs = append(errs, fmt.Errorf("exceptions: at index %d: domain: %w", i, err))

			continue
		}

		exceptions = append(exceptions, &filterindex.HomoglyphException{
			Domain: d,
		})
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	return &filterindex.Homoglyph{
		Domains:    domains,
		Exceptions: exceptions,
	}, nil
}

// homoglyphDomainsToInternal converts the domains protected by the homoglyph
// filter from protobuf to AdGuard DNS entities.  It appends all errors to errs
// and returns it.  list must not be nil.
func homoglyphDomainsToInternal(
	pbDomains []*HomoglyphFilterIndex_ProtectedDomain,
	list cookiejar.PublicSuffixList,
	errs []error,
) (domains []*filterindex.HomoglyphProtectedDomain, resErrs []error) {
	resErrs = errs

	domains = make([]*filterindex.HomoglyphProtectedDomain, 0, len(pbDomains))
	for i, pbd := range pbDomains {
		d := pbd.GetDomain()
		err := validateETLDPlus1(d, list)
		if err != nil {
			resErrs = append(resErrs, fmt.Errorf("domains: at index %d: domain: %w", i, err))

			continue
		}

		domains = append(domains, &filterindex.HomoglyphProtectedDomain{
			Domain: d,
		})
	}

	return domains, resErrs
}

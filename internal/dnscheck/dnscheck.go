// Package dnscheck contains types and utilities for checking if a particular
// client uses the DNS server.
package dnscheck

import (
	"context"
	"fmt"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

// Interface is the DNS checker interface.  All methods must be safe for
// concurrent use.
type Interface interface {
	// Check saves the information about a client's request and returns the
	// appropriate response.  If req is not the right type of request or not
	// a request for the appropriate check domain, both resp and err are nil.
	//
	// All arguments must be non-nil.  req must contain one question, which
	// should be either an A or an AAAA one.
	Check(ctx context.Context, req *dns.Msg, ri *agd.RequestInfo) (resp *dns.Msg, err error)
}

// randomIDFromDomain returns a random ID from name using one of the suf as
// the domain name suffix.  If matched is false, this is not a DNS check request.
func randomIDFromDomain(name string, suf []string) (id string, matched bool, err error) {
	for _, s := range suf {
		if name == s {
			return "", true, nil
		}

		id, matched = extractRandomID(name, s)
		if matched {
			if err = validateRandomID(id); err != nil {
				return "", true, err
			}

			return id, true, nil
		}
	}

	return "", false, nil
}

// extractRandomID returns a random ID extracted from name using suf as the
// domain name suffix.  If matched is false, the name does not match the suf.
func extractRandomID(name, suf string) (id string, matched bool) {
	if !strings.HasSuffix(name, suf) {
		return "", false
	}

	hyphenIdx := len(name) - len(suf) - 1
	if name[hyphenIdx] != '-' {
		// A weird request that only looks like a DNS check one but without
		// a hyphen.  Assume that this is not a real DNS check request.
		return "", false
	}

	id = name[:hyphenIdx]
	if strings.IndexByte(id, '.') != -1 {
		// Must be a request for a level below the expected.  Assume that this
		// is not a real DNS check request.
		return "", false
	}

	return id, true
}

// validateRandomID validates the random ID sent in the request.
func validateRandomID(id string) (err error) {
	defer func() { err = errors.Annotate(err, "id %q: %w", id) }()

	const (
		max = netutil.MaxDomainLabelLen
		min = 4
	)

	if err = agd.ValidateInclusion(len(id), max, min, agd.UnitByte); err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	if i := strings.IndexFunc(id, isInvalidRandomIDRune); i >= 0 {
		return fmt.Errorf("bad id: bad char %q at index %d", id[i], i)
	}

	return nil
}

// isInvalidRandomIDRune returns true if r is not a valid random ID rune.
func isInvalidRandomIDRune(r rune) (ok bool) {
	return !isValidRandomIDRune(r)
}

// isValidRandomIDRune returns true if r is a valid random ID rune.
func isValidRandomIDRune(r rune) (ok bool) {
	switch {
	case
		r >= 'a' && r <= 'z',
		r >= 'A' && r <= 'Z',
		r >= '0' && r <= '9',
		r == '-':
		return true
	default:
		return false
	}
}

package dnsmsg

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"unicode"

	"github.com/AdguardTeam/golibs/errors"
)

// StructuredDNSErrorsConfig is the configuration structure for the experimental
// Structured DNS Errors feature.
//
// See https://www.ietf.org/archive/id/draft-ietf-dnsop-structured-dns-error-09.html.
//
// TODO(a.garipov):  Add sub-error?
type StructuredDNSErrorsConfig struct {
	// Justification for this particular DNS filtering.  It must not be empty.
	Justification string

	// Organization is an optional description of the organization.
	Organization string

	// Contact information for the DNS service.  It must not be empty.  All
	// items must not be nil and must be valid mailto, sips, or tel URLs.
	Contact []*url.URL

	// Enabled, if true, enables the experimental Structured DNS Errors feature.
	Enabled bool
}

// iJSON returns the I-JSON representation of this configuration.  c must be
// valid.
func (c *StructuredDNSErrorsConfig) iJSON() (s string) {
	data := &structuredDNSErrorData{
		Justification: c.Justification,
		Organization:  c.Organization,
	}

	for _, cont := range c.Contact {
		data.Contact = append(data.Contact, cont.String())
	}

	// The only error that could be returned here is a type error from JSON
	// encoding, and these should never happen.
	b := errors.Must(json.Marshal(data))

	return string(b)
}

// structuredDNSErrorData is the structure for the JSON representation of the
// SDE data.
//
// TODO(a.garipov):  Add sub-error?
type structuredDNSErrorData struct {
	Justification string   `json:"j"`
	Organization  string   `json:"o,omitempty"`
	Contact       []string `json:"c"`
}

// forbiddenRanges contains the ranges of forbidden code points for structured
// DNS errors according to the I-JSON specification.
//
// See https://datatracker.ietf.org/doc/html/rfc7493#section-2.1.
var forbiddenRanges = []*unicode.RangeTable{unicode.Cs, unicode.Noncharacter_Code_Point}

// isSurrogateOrNonCharacter returns true if r is a surrogate or a non-character
// code point.
func isSurrogateOrNonCharacter(r rune) (ok bool) {
	return unicode.IsOneOf(forbiddenRanges, r)
}

// validateSDEString returns an error if s contains a surrogate or a
// non-character code point.  It always returns nil for an empty string.
func validateSDEString(s string) (err error) {
	if i := strings.IndexFunc(s, isSurrogateOrNonCharacter); i >= 0 {
		return fmt.Errorf("bad code point at index %d", i)
	}

	return nil
}

// validate checks the configuration for errors.
func (c *StructuredDNSErrorsConfig) validate(edeEnabled bool) (err error) {
	if c == nil {
		return errors.ErrNoValue
	}

	if !c.Enabled {
		return nil
	} else if !edeEnabled {
		return errors.Error("ede must be enabled to enable sde")
	}

	var errs []error
	if len(c.Contact) == 0 {
		err = fmt.Errorf("contact data: %w", errors.ErrEmptyValue)
		errs = append(errs, err)
	}

	for i, cont := range c.Contact {
		err = validateSDEContactURL(cont)
		if err != nil {
			err = fmt.Errorf("contact data: at index %d: %w", i, err)
			errs = append(errs, err)
		}
	}

	if c.Justification == "" {
		err = fmt.Errorf("justification: %w", errors.ErrEmptyValue)
		errs = append(errs, err)
	} else if err = validateSDEString(c.Justification); err != nil {
		err = fmt.Errorf("justification: %w", err)
		errs = append(errs, err)
	}

	if err = validateSDEString(c.Organization); err != nil {
		err = fmt.Errorf("organization: %w", err)
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// validateSDEContactURL returns an error if u is not a valid SDE contact URL.
// It doesn't check for bad code points in the URL since [url.URL.String]
// escapes them.
func validateSDEContactURL(u *url.URL) (err error) {
	if u == nil {
		return errors.ErrNoValue
	}

	switch strings.ToLower(u.Scheme) {
	case "mailto", "sips", "tel":
		// TODO(a.garipov):  Consider more thorough validations for each scheme.
	default:
		return fmt.Errorf("scheme: %w: %q", errors.ErrBadEnumValue, u.Scheme)
	}

	return nil
}

package agd

import (
	"bytes"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/syncutil"
)

// HumanID is a more human-readable identifier of a device.
type HumanID string

const (
	// MaxHumanIDLen is the maximum length of a human-readable device ID.
	MaxHumanIDLen = netutil.MaxDomainLabelLen

	// MinHumanIDLen is the minimum length of a human-readable device ID.
	MinHumanIDLen = 1
)

// NewHumanID converts a simple string into a HumanID and makes sure that it's
// valid.  This should be preferred to a simple type conversion.
//
// TODO(a.garipov):  Remove if it remains unused.
func NewHumanID(s string) (id HumanID, err error) {
	// Do not use [errors.Annotate] here, because it allocates even when the
	// error is nil.
	defer func() {
		if err != nil {
			err = fmt.Errorf("bad human id %q: %w", s, err)
		}
	}()

	return newHumanID(s)
}

// newHumanID converts a simple string into a HumanID and makes sure that it's
// valid.  It does not wrap the error to be used in places where that could
// create additional allocations.
func newHumanID(s string) (id HumanID, err error) {
	err = ValidateInclusion(len(s), MaxHumanIDLen, MinHumanIDLen, UnitByte)
	if err != nil {
		// Don't wrap the error, because the caller should do that.
		return "", err
	}

	// TODO(a.garipov):  Add boolean versions to netutil to avoid allocations of
	// errors that aren't used.
	err = netutil.ValidateHostnameLabel(s)
	if err != nil {
		// Don't wrap the error, because the caller should do that.
		return "", err
	}

	if i := strings.Index(s, "---"); i >= 0 {
		return "", fmt.Errorf("at index %d: max 2 consecutive hyphens are allowed", i)
	}

	return HumanID(s), nil
}

// HumanIDLower is the type for [HumanID] values that must be lowercase.
type HumanIDLower string

// NewHumanIDLower converts a simple string into a HumanIDLower and makes sure
// that it's valid and lowercased.  This should be preferred to a simple type
// conversion.
func NewHumanIDLower(s string) (id HumanIDLower, err error) {
	// Do not use [errors.Annotate] here, because it allocates even when the
	// error is nil.

	humanID, err := newHumanID(s)
	if err != nil {
		return "", fmt.Errorf("bad lowercase human id %q: %w", s, err)
	}

	for i, r := range humanID {
		if r >= 'A' && r <= 'Z' {
			return "", fmt.Errorf(
				"bad lowercase human id %q: at index %d: %q is not lowercase",
				s,
				i,
				r,
			)
		}
	}

	return HumanIDLower(s), nil
}

// HumanIDToLower returns a lowercase version of id.
func HumanIDToLower(id HumanID) (lower HumanIDLower) {
	return HumanIDLower(strings.ToLower(string(id)))
}

// HumanIDParser normalizes and parses a HumanID from a string.
type HumanIDParser struct {
	pool *syncutil.Pool[bytes.Buffer]
}

// NewHumanIDParser creates a new HumanIDParser.
func NewHumanIDParser() (p *HumanIDParser) {
	return &HumanIDParser{
		pool: syncutil.NewPool(func() (buf *bytes.Buffer) {
			return bytes.NewBuffer(make([]byte, 0, netutil.MaxDomainNameLen))
		}),
	}
}

// ParseNormalized normalizes and parses a HumanID from a string that may have
// issues, such as extra symbols that aren't supported.  The normalization is
// best-effort and may still fail, in which case id is empty and err is not nil.
func (p *HumanIDParser) ParseNormalized(s string) (id HumanID, err error) {
	id, err = newHumanID(s)
	if err == nil {
		return id, nil
	}

	// Do not use [errors.Annotate] here, because it allocates even when the
	// error is nil.
	original := s
	defer func() {
		if err != nil {
			err = fmt.Errorf("bad non-normalized human id %q: %w", original, err)
		}
	}()

	// Immediately validate it against the upper DNS hostname-length limit.
	err = ValidateInclusion(len(s), netutil.MaxDomainNameLen, MinHumanIDLen, UnitByte)
	if err != nil {
		// Don't wrap the error, because there is already a deferred wrap, and
		// the error is informative enough as is.
		return "", err
	}

	buf := p.pool.Get()
	defer func() { p.pool.Put(buf) }()

	buf.Reset()
	n := humanIDNormalizer{
		buf: buf,
	}

	for s != "" {
		r, sz := utf8.DecodeRuneInString(s)
		s = s[sz:]

		n.next(r)
	}

	s = n.result()
	if s == "" || s == "-" {
		return "", errors.Error("cannot normalize")
	}

	id, err = newHumanID(s)
	if err != nil {
		return "", err
	}

	return id, nil
}

// humanIDNormalizer is a stateful normalizer of human-readable device
// identifiers.
type humanIDNormalizer struct {
	buf          *bytes.Buffer
	state        uint8
	prevRune     rune
	prevPrevRune rune
}

// [humanIDNormalizer] states.
const (
	humanIDNormStateInitial uint8 = iota
	humanIDNormStateInvalid
	humanIDNormStateValid
)

// next writes r to the buffer, if it is valid.
func (p *humanIDNormalizer) next(r rune) {
	switch p.state {
	case humanIDNormStateInitial:
		p.nextInitial(r)
	case humanIDNormStateValid:
		p.nextValid(r)
	case humanIDNormStateInvalid:
		p.nextInvalid(r)
	default:
		panic(fmt.Errorf("bad humanIDNormalizer state %d", p.state))
	}
}

// nextInitial processes the initial state of the normalizer.
func (p *humanIDNormalizer) nextInitial(r rune) {
	if !netutil.IsValidHostOuterRune(r) {
		return
	}

	p.state = humanIDNormStateValid
	p.write(r)
}

// nextValid processes the valid state of the normalizer.
func (p *humanIDNormalizer) nextValid(r rune) {
	if r == '-' {
		if p.prevPrevRune == '-' && p.prevRune == '-' {
			p.buf.Truncate(p.buf.Len() - 2)
			p.prevPrevRune = utf8.RuneError
			p.prevRune = utf8.RuneError
			p.state = humanIDNormStateInvalid

			return
		}

		p.write(r)

		return
	}

	if !netutil.IsValidHostOuterRune(r) {
		p.truncateHyphens()
		p.state = humanIDNormStateInvalid

		return
	}

	p.write(r)
}

// truncateHyphens removes the unnecessary hyphens from the buffer if necessary.
func (p *humanIDNormalizer) truncateHyphens() {
	if p.prevRune != '-' {
		return
	}

	if p.prevPrevRune == '-' {
		p.buf.Truncate(p.buf.Len() - 2)
		p.prevPrevRune = utf8.RuneError
	} else {
		p.buf.Truncate(p.buf.Len() - 1)
	}

	p.prevRune = utf8.RuneError
}

// nextInvalid processes the invalid state of the normalizer.
func (p *humanIDNormalizer) nextInvalid(r rune) {
	if !netutil.IsValidHostOuterRune(r) {
		return
	}

	p.state = humanIDNormStateValid
	if p.prevRune != '-' {
		p.write('-')
	}

	p.write(r)
}

// write writes r to the buffer while also updating the previous runes.
func (p *humanIDNormalizer) write(r rune) {
	_, _ = p.buf.WriteRune(r)
	p.prevPrevRune = p.prevRune
	p.prevRune = r
}

// result returns the result of the normalization.
func (p *humanIDNormalizer) result() (s string) {
	b := p.buf.Bytes()
	b = b[:min(len(b), MaxHumanIDLen)]
	b = bytes.TrimRight(b, "-")

	return string(b)
}

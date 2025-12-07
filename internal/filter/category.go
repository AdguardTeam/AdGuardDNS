package filter

import (
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdvalidate"
	"github.com/AdguardTeam/golibs/errors"
)

// CategoryID is the ID of a category filter.  It is an opaque string.  It must
// be a valid FilterID.
type CategoryID string

// The maximum and minimum lengths of a CategoryID.
const (
	MaxCategoryIDLen = 128
	MinCategoryIDLen = 1
)

// CategoryIDNone is a zero value for category filter.
const CategoryIDNone CategoryID = ""

// NewCategoryID converts a simple string into a CategoryID and makes sure that
// it's valid.  This should be preferred to a simple type conversion.
func NewCategoryID(s string) (id CategoryID, err error) {
	defer func() { err = errors.Annotate(err, "bad category id %q: %w", s) }()

	err = agdvalidate.Inclusion(len(s), MinCategoryIDLen, MaxCategoryIDLen, agdvalidate.UnitByte)
	if err != nil {
		return CategoryIDNone, err
	}

	// Allow only the printable, non-whitespace ASCII characters.  Technically
	// we only need to exclude carriage return, line feed, and slash characters,
	// but let's be more strict just in case.
	if i, r := agdvalidate.FirstNonIDRune(s, true); i != -1 {
		return CategoryIDNone, fmt.Errorf("bad rune %q at index %d", r, i)
	}

	return CategoryID(s), nil
}

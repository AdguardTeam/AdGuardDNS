package agd

import (
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdvalidate"
)

// AccountID is the ID of an account containing multiple profiles (a.k.a. DNS
// servers).  It is an opaque string.
type AccountID string

// NewAccountID converts a simple string into an AccountID and makes sure that
// it's valid.  This should be preferred to a simple type conversion.
func NewAccountID(s string) (id AccountID, err error) {
	// For now, allow only the printable, non-whitespace ASCII characters.
	// Technically we only need to exclude carriage return and line feed
	// characters, but let's be more strict just in case.
	if i, r := agdvalidate.FirstNonIDRune(s, false); i != -1 {
		return "", fmt.Errorf("bad account id: bad char %q at index %d", r, i)
	}

	return AccountID(s), nil
}

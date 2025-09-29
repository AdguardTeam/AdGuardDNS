package agd

import (
	"fmt"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/validate"
)

// maxCertificateNameLen is the maximum length of a [CertificateName].
const maxCertificateNameLen = 32

// CertificateName is the unique name identifying the TLS certificate.
type CertificateName string

// NewCertificateName creates a new CertificateName from the given string.
func NewCertificateName(str string) (name CertificateName, err error) {
	if str == "" {
		return "", errors.ErrEmptyValue
	}

	err = validate.InRange("length", len(str), 1, maxCertificateNameLen)
	if err != nil {
		// Don't wrap the error, since it's informative enough as is.
		return "", err
	}

	for i, r := range str {
		// Don't use [agdvalidate.FirstNonIDRune] as it allows invalid symbols
		// for file names.
		if !isValidCertNameRune(r) {
			return "", fmt.Errorf("at index %d: bad symbol: %q", i, r)
		}
	}

	return CertificateName(str), nil
}

// isValidCertNameRune returns true if the given rune is valid to be used in a
// [CertificateName].  It essentially allows alphanumeric symbols, underscores,
// and hyphens.
func isValidCertNameRune(r rune) (ok bool) {
	switch {
	case
		r >= 'a' && r <= 'z',
		r >= 'A' && r <= 'Z',
		r >= '0' && r <= '9',
		r == '_', r == '-':
		return true
	default:
		return false
	}
}

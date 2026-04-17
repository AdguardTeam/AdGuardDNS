package agd

import (
	"fmt"
	"strconv"

	"github.com/AdguardTeam/golibs/validate"
)

// AccountID is the ID of an account containing multiple profiles (a.k.a. DNS
// servers).
type AccountID int32

// AccountIDEmpty is a value for empty account ID.
const AccountIDEmpty AccountID = 0

// NewAccountID converts int32 into an AccountID and makes sure that it is
// valid.  This should be preferred to a simple type conversion.
func NewAccountID(i int32) (id AccountID, err error) {
	err = validate.Positive("i", i)
	if err != nil {
		// Don't wrap the error, since it's informative enough as is.
		return AccountIDEmpty, err
	}

	return AccountID(i), nil
}

// NewAccountIDFromString converts a simple string into an AccountID and makes
// sure that it's valid.  This should be preferred to a simple type conversion.
//
// TODO(f.setrakov): Remove after migrating to int account ID.
func NewAccountIDFromString(s string) (id AccountID, err error) {
	var id64 int64
	id64, err = strconv.ParseInt(s, 10, 32)
	if err != nil {
		return AccountIDEmpty, fmt.Errorf("bad account id: %w", err)
	}

	err = validate.Positive("account id", id64)
	if err != nil {
		// Don't wrap the error, since it's informative enough as is.
		return AccountIDEmpty, err
	}

	return AccountID(id64), nil
}

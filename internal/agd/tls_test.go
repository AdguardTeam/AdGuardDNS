package agd_test

import (
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/golibs/testutil"
)

func TestNewCertificateName(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		value      string
		wantErrMsg string
	}{{
		name:       "empty",
		value:      "",
		wantErrMsg: "empty value",
	}, {
		name:       "bad_symbol",
		value:      "not valid",
		wantErrMsg: "at index 3: bad symbol: ' '",
	}, {
		name:       "bad_base_name",
		value:      "bad/base_name",
		wantErrMsg: "at index 3: bad symbol: '/'",
	}, {
		name:       "too_long",
		value:      "this_is_a_very_long_certificate_name_which_should_be_64_symbols_long",
		wantErrMsg: "length: out of range: must be no greater than 64, got 68",
	}, {
		name:       "ok",
		value:      "ok_cert_name",
		wantErrMsg: "",
	}, {
		name:       "ok_numeric",
		value:      "1234567890",
		wantErrMsg: "",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := agd.NewCertificateName(tc.value)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}

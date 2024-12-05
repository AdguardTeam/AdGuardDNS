package agd_test

import (
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
)

func TestNewDeviceName(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		in         string
		wantErrMsg string
	}{{
		name:       "empty",
		in:         "",
		wantErrMsg: "",
	}, {
		name:       "normal",
		in:         "Normal name",
		wantErrMsg: "",
	}, {
		name:       "normal_unicode",
		in:         "Нормальное имя",
		wantErrMsg: "",
	}, {
		name:       "too_long",
		in:         testLongStr,
		wantErrMsg: `bad device name "` + testLongStr + `": too long: got 200 runes, max 128`,
	}, {
		name: "too_long_unicode",
		in:   testLongStrUnicode,
		wantErrMsg: `bad device name "` + testLongStrUnicode +
			`": too long: got 200 runes, max 128`,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			n, err := agd.NewDeviceName(tc.in)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
			if tc.wantErrMsg == "" && tc.in != "" {
				assert.NotEmpty(t, n)
			} else {
				assert.Empty(t, n)
			}
		})
	}
}

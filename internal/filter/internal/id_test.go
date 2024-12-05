package internal_test

import (
	"strings"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
)

func TestNewID(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		in         string
		wantErrMsg string
	}{{
		name:       "normal",
		in:         "adguard_default_list",
		wantErrMsg: "",
	}, {
		name:       "too_short",
		in:         "",
		wantErrMsg: `bad filter id "": too short: got 0 bytes, min 1`,
	}, {
		name:       "too_long",
		in:         testLongStr,
		wantErrMsg: `bad filter id "` + testLongStr + `": too long: got 200 bytes, max 128`,
	}, {
		name:       "bad",
		in:         "bad/name",
		wantErrMsg: `bad filter id "bad/name": bad rune '/' at index 3`,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			id, err := internal.NewID(tc.in)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
			if tc.wantErrMsg == "" && tc.in != "" {
				assert.NotEmpty(t, id)
			} else {
				assert.Empty(t, id)
			}
		})
	}
}

func TestNewRuleText(t *testing.T) {
	t.Parallel()

	tooLong := strings.Repeat("a", internal.MaxRuleTextRuneLen+1)
	tooLongUnicode := strings.Repeat("ы", internal.MaxRuleTextRuneLen+1)

	testCases := []struct {
		name       string
		in         string
		wantErrMsg string
	}{{
		name:       "normal",
		in:         "||example.com^",
		wantErrMsg: "",
	}, {
		name:       "normal_unicode",
		in:         "||пример.рф",
		wantErrMsg: "",
	}, {
		name:       "empty",
		in:         "",
		wantErrMsg: "",
	}, {
		name:       "too_long",
		in:         tooLong,
		wantErrMsg: `bad filter rule text "` + tooLong + `": too long: got 1025 runes, max 1024`,
	}, {
		name: "too_long_unicode",
		in:   tooLongUnicode,
		wantErrMsg: `bad filter rule text "` + tooLongUnicode + `": too long: ` +
			`got 1025 runes, max 1024`,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			txt, err := internal.NewRuleText(tc.in)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
			if tc.wantErrMsg == "" && tc.in != "" {
				assert.NotEmpty(t, txt)
			} else {
				assert.Empty(t, txt)
			}
		})
	}
}

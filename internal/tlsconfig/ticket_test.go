package tlsconfig_test

import (
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/tlsconfig"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
)

func TestNewSessionTicket(t *testing.T) {
	t.Parallel()

	goodSessionTicket := tlsconfig.SessionTicket{
		31: 0x01,
	}

	testCases := []struct {
		name       string
		wantErrMsg string
		in         []byte
		want       tlsconfig.SessionTicket
	}{{
		name:       "success",
		wantErrMsg: "",
		in:         goodSessionTicket[:],
		want:       goodSessionTicket,
	}, {
		name:       "too_long",
		wantErrMsg: "",
		in:         append(goodSessionTicket[:], 0x02),
		want:       goodSessionTicket,
	}, {
		name:       "too_short",
		wantErrMsg: "length: out of range: must be no less than 32, got 31",
		in:         goodSessionTicket[:len(goodSessionTicket)-1],
		want:       tlsconfig.SessionTicket{},
	}, {
		name:       "nil",
		wantErrMsg: "length: out of range: must be no less than 32, got 0",
		in:         nil,
		want:       tlsconfig.SessionTicket{},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ticket, err := tlsconfig.NewSessionTicket(tc.in)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
			assert.Equal(t, tc.want, ticket)
		})
	}
}

func TestNewSessionTicketName(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		in         string
		wantErrMsg string
	}{{
		name:       "success",
		in:         "foo",
		wantErrMsg: "",
	}, {
		name:       "empty",
		in:         "",
		wantErrMsg: "str: empty value",
	}, {
		name:       "bad_filepath",
		in:         "foo/bar",
		wantErrMsg: "str: at index 3: bad rune '/'",
	}, {
		name:       "bad_label",
		in:         "a\xc5z",
		wantErrMsg: `str: not a valid label value: "a\xc5z"`,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := tlsconfig.NewSessionTicketName(tc.in)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}

package agdpasswd_test

import (
	"context"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdpasswd"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

func TestPasswordHashBcrypt_Authenticate(t *testing.T) {
	t.Parallel()

	const passwd = "mypassword"

	hash, err := bcrypt.GenerateFromPassword([]byte(passwd), 0)
	require.NoError(t, err)

	authenticator := agdpasswd.NewPasswordHashBcrypt(hash)

	testCases := []struct {
		want assert.BoolAssertionFunc
		name string
		pass string
	}{{
		want: assert.True,
		name: "success",
		pass: passwd,
	}, {
		want: assert.False,
		name: "fail",
		pass: "an-other-passwd",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tc.want(t, authenticator.Authenticate(context.Background(), []byte(tc.pass)))
		})
	}
}

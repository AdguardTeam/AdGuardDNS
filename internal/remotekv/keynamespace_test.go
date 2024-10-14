package remotekv_test

import (
	"context"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/remotekv"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKeyNamespace(t *testing.T) {
	const (
		testKey    = "key"
		testPrefix = "test"
	)

	kv := &agdtest.RemoteKV{
		OnSet: func(_ context.Context, key string, _ []byte) (_ error) {
			require.Equal(t, testPrefix+testKey, key)

			return assert.AnError
		},
		OnGet: func(_ context.Context, key string) (_ []byte, _ bool, _ error) {
			require.Equal(t, testPrefix+testKey, key)

			return nil, false, assert.AnError
		},
	}

	n := remotekv.NewKeyNamespace(&remotekv.KeyNamespaceConfig{
		KV:     kv,
		Prefix: testPrefix,
	})

	assert.NotPanics(t, func() {
		ctx := testutil.ContextWithTimeout(t, testTimeout)
		err := n.Set(ctx, testKey, nil)
		assert.ErrorIs(t, err, assert.AnError)

		_, _, err = n.Get(ctx, testKey)
		assert.ErrorIs(t, err, assert.AnError)
	})
}

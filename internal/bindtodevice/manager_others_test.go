//go:build !linux

package bindtodevice_test

import (
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/bindtodevice"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManager(t *testing.T) {
	t.Parallel()

	m := bindtodevice.NewManager(nil)

	t.Run("add", func(t *testing.T) {
		t.Parallel()

		wantErrMsg := "bindtodevice: add: " + errors.ErrUnsupported.Error() +
			"; only supported on linux"
		err := m.Add("", "", 0, nil, nil)
		testutil.AssertErrorMsg(t, wantErrMsg, err)
	})

	t.Run("listen_config", func(t *testing.T) {
		t.Parallel()

		wantErrMsg := "bindtodevice: listenconfig: " + errors.ErrUnsupported.Error() +
			"; only supported on linux"
		lc, err := m.ListenConfig("", netip.Prefix{})
		assert.Nil(t, lc)
		testutil.AssertErrorMsg(t, wantErrMsg, err)
	})

	t.Run("start", func(t *testing.T) {
		t.Parallel()

		ctx := testutil.ContextWithTimeout(t, testTimeout)

		wantErrMsg := "bindtodevice: starting: " + errors.ErrUnsupported.Error() +
			"; only supported on linux"
		err := m.Start(ctx)
		testutil.AssertErrorMsg(t, wantErrMsg, err)

		err = (*bindtodevice.Manager)(nil).Start(ctx)
		require.NoError(t, err)
	})

	t.Run("shutdown", func(t *testing.T) {
		t.Parallel()

		ctx := testutil.ContextWithTimeout(t, testTimeout)

		wantErrMsg := "bindtodevice: shutting down: " + errors.ErrUnsupported.Error() +
			"; only supported on linux"
		err := m.Shutdown(ctx)
		testutil.AssertErrorMsg(t, wantErrMsg, err)

		err = (*bindtodevice.Manager)(nil).Shutdown(ctx)
		require.NoError(t, err)
	})
}

package agd_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/stretchr/testify/require"
)

func TestRequestInfoFromContext(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	_, ok := agd.RequestInfoFromContext(ctx)
	require.False(t, ok)

	want := &agd.RequestInfo{
		DeviceResult: &agd.DeviceResultOK{
			Device:  &agd.Device{ID: "dev-id"},
			Profile: &agd.Profile{ID: "prof-id"},
		},
		Messages: agdtest.NewConstructor(t),
	}
	ctx = agd.ContextWithRequestInfo(ctx, want)

	got, ok := agd.RequestInfoFromContext(ctx)
	require.True(t, ok)
	require.Equal(t, want, got)
}

func TestMustRequestInfoFromContext(t *testing.T) {
	t.Parallel()

	require.Panics(t, func() {
		ctx := context.Background()
		_ = agd.MustRequestInfoFromContext(ctx)
	})
}

func TestLocalAddressFromContext(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	_, ok := agd.LocalAddressFromContext(ctx)
	require.False(t, ok)

	want := netip.MustParseAddr("192.0.2.0")
	ctx = agd.ContextWithLocalAddress(ctx, want)

	got, ok := agd.LocalAddressFromContext(ctx)
	require.True(t, ok)
	require.Equal(t, want, got)
}

func TestMustLocalAddressFromContext(t *testing.T) {
	t.Parallel()

	require.Panics(t, func() {
		ctx := context.Background()
		_ = agd.MustLocalAddressFromContext(ctx)
	})
}

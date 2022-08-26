package consul_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/consul"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/ratelimit"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	agdtest.DiscardLogOutput(m)
}

// handleWithURL starts the test server with h, finishes it on cleanup, and
// returns it's URL.
//
// TODO(e.burkov):  Move into one of the utility packages.
func handleWithURL(t *testing.T, h http.Handler) (u *url.URL) {
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)

	return u
}

// TODO(e.burkov):  Enhance with actual IP networks.
func TestNewAllowlistRefresher(t *testing.T) {
	al := ratelimit.NewDynamicAllowlist([]netip.Prefix{}, []netip.Prefix{})

	testIPs := []netip.Addr{
		0: netip.MustParseAddr("127.0.0.1"),
		1: netip.MustParseAddr("127.0.0.2"),
		2: netip.MustParseAddr("127.0.0.3"),
	}

	testCases := []struct {
		name         string
		resp         string
		wantAllow    []netip.Addr
		wantNotAllow []netip.Addr
	}{{
		name:         "empty",
		resp:         `[]`,
		wantAllow:    nil,
		wantNotAllow: testIPs,
	}, {
		name:         "single",
		resp:         `[{"Address":"127.0.0.1"}]`,
		wantAllow:    []netip.Addr{testIPs[0]},
		wantNotAllow: []netip.Addr{testIPs[1], testIPs[2]},
	}, {
		name:         "several",
		resp:         `[{"Address":"127.0.0.1"},{"Address":"127.0.0.2"},{"Address":"127.0.0.3"}]`,
		wantAllow:    testIPs,
		wantNotAllow: nil,
	}}

	for i, tc := range testCases {
		u := handleWithURL(t, http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
			pt := testutil.PanicT{}

			_, err := rw.Write([]byte(testCases[i].resp))
			require.NoError(pt, err)
		}))

		t.Run(tc.name, func(t *testing.T) {
			_, err := consul.NewAllowlistRefresher(al, u)
			require.NoError(t, err)

			for _, ip := range tc.wantAllow {
				var ok bool
				ok, err = al.IsAllowed(context.Background(), ip)
				require.NoError(t, err)

				assert.True(t, ok)
			}

			for _, ip := range tc.wantNotAllow {
				var ok bool
				ok, err = al.IsAllowed(context.Background(), ip)
				require.NoError(t, err)

				assert.False(t, ok)
			}
		})
	}

	t.Run("not_ok", func(t *testing.T) {
		const status = http.StatusInternalServerError

		u := handleWithURL(t, http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
			rw.WriteHeader(status)
		}))
		wantErr := &agdhttp.StatusError{}

		_, err := consul.NewAllowlistRefresher(al, u)
		require.ErrorAs(t, err, &wantErr)

		assert.Equal(t, wantErr.Got, status)
	})
}

func TestAllowlistRefresher_Refresh_deadline(t *testing.T) {
	al := ratelimit.NewDynamicAllowlist([]netip.Prefix{}, []netip.Prefix{})
	u := handleWithURL(t, http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		pt := testutil.PanicT{}

		_, err := rw.Write([]byte(`[]`))
		require.NoError(pt, err)
	}))

	c, err := consul.NewAllowlistRefresher(al, u)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = c.Refresh(ctx)
	assert.ErrorIs(t, err, context.Canceled)
}

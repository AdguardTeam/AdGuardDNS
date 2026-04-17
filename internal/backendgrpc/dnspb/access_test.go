package dnspb_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/dnspb"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/internal/backendtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
)

func TestAccessSettings_ToStandardConfig(t *testing.T) {
	t.Parallel()

	l := slogutil.NewDiscardLogger()
	ctx := testutil.ContextWithTimeout(t, backendtest.Timeout)
	addr := netutil.IPv4Localhost()

	validSettings := &dnspb.AccessSettings{
		AllowlistCidr: []*dnspb.CidrRange{{
			Address: addr.AsSlice(),
			Prefix:  8,
		}},
		BlocklistCidr: []*dnspb.CidrRange{{
			Address: addr.AsSlice(),
			Prefix:  16,
		}},
		AllowlistAsn: []uint32{
			backendtest.ASNAllowed,
		},
		BlocklistAsn: []uint32{
			backendtest.ASNBlocked,
		},
		BlocklistDomainRules: []string{
			backendtest.BlocklistDomainRule,
		},
		Enabled: true,
	}

	testCases := []struct {
		settings   *dnspb.AccessSettings
		want       *access.StandardBlockerConfig
		name       string
		wantErrMsg string
	}{{
		name:     "success",
		settings: validSettings,
		want: &access.StandardBlockerConfig{
			AllowedNets: []netip.Prefix{
				netip.PrefixFrom(addr, 8),
			},
			BlockedNets: []netip.Prefix{
				netip.PrefixFrom(addr, 16),
			},
			AllowedASN: []geoip.ASN{
				backendtest.ASNAllowed,
			},
			BlockedASN: []geoip.ASN{
				backendtest.ASNBlocked,
			},
			BlocklistDomainRules: []string{
				backendtest.BlocklistDomainRule,
			},
		},
		wantErrMsg: "",
	}, {
		name: "invalid_addr",
		settings: &dnspb.AccessSettings{
			AllowlistCidr: []*dnspb.CidrRange{{
				Address: []byte("127.1"),
				Prefix:  8,
			}},
			Enabled: true,
		},
		want:       &access.StandardBlockerConfig{},
		wantErrMsg: "converting cidrs: bad cidr at index 0: [49 50 55 46 49]",
	}, {
		name: "empty_settings_enabled",
		settings: &dnspb.AccessSettings{
			Enabled: true,
		},
		want:       &access.StandardBlockerConfig{},
		wantErrMsg: "",
	}, {
		name: "settings_disabled",
		settings: &dnspb.AccessSettings{
			Enabled: false,
		},
		want:       nil,
		wantErrMsg: "",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			errColl := &agdtest.ErrorCollector{}
			errColl.OnCollect = func(_ context.Context, err error) {
				testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
			}

			got := tc.settings.ToStandardConfig(ctx, l, errColl)
			assert.Equal(t, tc.want, got)
		})
	}
}

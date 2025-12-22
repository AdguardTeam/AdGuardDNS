package devicefinder_test

import (
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/devicefinder"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/dnssvctest"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
)

func TestDefault_Find_humanID(t *testing.T) {
	testCases := []struct {
		wantRes agd.DeviceResult
		name    string
		in      string
	}{{
		wantRes: &agd.DeviceResultError{
			Err: errors.Error(
				`extracting device data: tls server name device id check: ` +
					`parsing "!!!-abcd1234-My-Device-X--10": bad device type "!!!": ` +
					`unknown device type`,
			),
		},
		name: "bad_type",
		in:   "!!!-abcd1234-My-Device-X--10",
	}, {
		wantRes: &agd.DeviceResultError{
			Err: errors.Error(
				`extracting device data: tls server name device id check: ` +
					`parsing "otr-\x00-My-Device-X--10": bad profile id: ` +
					`bad char '\x00' at index 0`,
			),
		},
		name: "bad_profile_id",
		in:   "otr-\x00-My-Device-X--10",
	}, {
		wantRes: &agd.DeviceResultError{
			Err: errors.Error(
				`extracting device data: tls server name device id check: ` +
					`parsing "otr-abcd1234-!!!": bad non-normalized human id "!!!": ` +
					`cannot normalize`,
			),
		},
		name: "bad_human_id",
		in:   "otr-abcd1234-!!!",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			df := newDefault(t, &devicefinder.Config{
				Server:        srvDoT,
				DeviceDomains: []string{dnssvctest.DomainForDevices},
			})

			ctx := testutil.ContextWithTimeout(t, dnssvctest.Timeout)
			ctx = dnsserver.ContextWithRequestInfo(ctx, dnssvctest.NewRequestInfo(
				tc.in+"."+dnssvctest.DomainForDevices,
			))

			got := df.Find(ctx, reqNormal, dnssvctest.ClientAddrPort, dnssvctest.ServerAddrPort)
			assertEqualResult(t, tc.wantRes, got)
		})
	}
}

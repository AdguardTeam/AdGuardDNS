package debugsvc_test

import (
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/debugsvc"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestService_Start_geoIPAPI(t *testing.T) {
	t.Parallel()

	const (
		geoIPReqIP = "192.0.2.1"
		asn        = 42
	)

	geoIPLoc := &geoip.Location{
		Country:        geoip.CountryAD,
		Continent:      geoip.ContinentEU,
		TopSubdivision: "TopSubdivision",
		ASN:            asn,
	}

	geoIPSubnetStr := "198.51.100.0/24"
	geoIPSubnet := netip.MustParsePrefix(geoIPSubnetStr)

	geoIP := agdtest.NewGeoIP()
	geoIP.OnData = func(
		_ context.Context,
		host string,
		addr netip.Addr,
	) (l *geoip.Location, err error) {
		pt := testutil.NewPanicT(t)

		require.Empty(pt, host)
		require.Equal(pt, geoIPReqIP, addr.String())

		return geoIPLoc, nil
	}
	geoIP.OnSubnetByLocation = func(
		_ context.Context,
		l *geoip.Location,
		fam netutil.AddrFamily,
	) (n netip.Prefix, err error) {
		pt := testutil.NewPanicT(t)

		require.Equal(pt, geoIPLoc, l)

		if fam == netutil.AddrFamilyIPv4 {
			return geoIPSubnet, nil
		}

		return netip.Prefix{}, nil
	}

	c := &debugsvc.Config{
		APIAddr: localhostAnyPort,
		GeoIP:   geoIP,
	}

	svc := newTestDebugService(t, c)
	servicetest.RequireRun(t, svc, testTimeout)

	srvAddr := requireHandlerGroupAddr(t, svc, debugsvc.HandlerGroupAPI)

	client := &http.Client{
		Timeout: testTimeout,
	}

	srvURL := &url.URL{
		Scheme: urlutil.SchemeHTTP,
		Host:   srvAddr.String(),
	}

	// First check health-check service URL.  As the service could not be ready
	// yet, check for it in periodically.
	eventuallyCheckHealth(t, client, srvURL)

	geoIPQuery := url.Values{}
	geoIPQuery.Add(debugsvc.QueryKeyGeoIP, geoIPReqIP)

	geoIPURL := srvURL.JoinPath(debugsvc.PathPatternDebugAPIGeoIP)
	geoIPURL.RawQuery = geoIPQuery.Encode()

	resp, err := client.Get(geoIPURL.String())
	require.NoError(t, err)

	wantGeoIPResp := `
		{
		  "data": {
			"` + geoIPReqIP + `": {
			  "asn": ` + strconv.Itoa(asn) + `,
			  "continent": "` + string(geoip.ContinentEU) + `",
			  "country": "` + string(geoip.CountryAD) + `",
			  "top_subdivision": "` + geoIPLoc.TopSubdivision + `",
			  "replacement_subnets": {
				"ipv4": "` + geoIPSubnetStr + `"
			  }
			}
		  }
		}`

	respBody := readRespBody(t, resp)
	assert.JSONEq(t, wantGeoIPResp, respBody)
}

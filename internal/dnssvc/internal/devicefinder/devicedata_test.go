package devicefinder_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/netip"
	"net/url"
	"path"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/devicefinder"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/dnssvctest"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
)

func TestDefault_Find_DoHAuth(t *testing.T) {
	t.Parallel()

	var (
		devAuthSuccess = newDevAuth(false, true)
		devAuthFail    = newDevAuth(false, false)
	)

	testCases := []struct {
		wantRes   agd.DeviceResult
		profDBDev *agd.Device
		reqURL    *url.URL
		name      string
	}{{
		wantRes: &agd.DeviceResultOK{
			Device:  devAuthSuccess,
			Profile: testProfNormal,
		},
		profDBDev: devAuthSuccess,
		reqURL: &url.URL{
			Path: dnsserver.PathDoH,
			User: url.UserPassword(dnssvctest.DeviceIDStr, testPassword),
		},
		name: "success",
	}, {
		wantRes: &agd.DeviceResultAuthenticationFailure{
			Err: devicefinder.ErrAuthenticationFailed,
		},
		profDBDev: devAuthFail,
		reqURL: &url.URL{
			Path: dnsserver.PathDoH,
			User: url.UserPassword(dnssvctest.DeviceIDStr, testPassword),
		},
		name: "passwd_fail",
	}, {
		wantRes: &agd.DeviceResultAuthenticationFailure{
			Err: devicefinder.ErrNoPassword,
		},
		profDBDev: devAuthSuccess,
		reqURL: &url.URL{
			Path: dnsserver.PathDoH,
			User: url.User(dnssvctest.DeviceIDStr),
		},
		name: "no_passwd",
	}, {
		wantRes:   nil,
		profDBDev: devAuthSuccess,
		reqURL: &url.URL{
			Path: dnsserver.PathDoH,
			User: nil,
		},
		name: "no_userinfo",
	}, {
		wantRes: &agd.DeviceResultError{
			Err: errors.Error(
				`extracting device data: basic auth device id check: bad device id "!!!": ` +
					`bad hostname label rune '!'`,
			),
		},
		profDBDev: devAuthSuccess,
		reqURL: &url.URL{
			Path: dnsserver.PathDoH,
			User: url.UserPassword("!!!", testPassword),
		},
		name: "bad_id",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			profDB := agdtest.NewProfileDB()
			profDB.OnProfileByDeviceID = func(
				_ context.Context,
				devID agd.DeviceID,
			) (p *agd.Profile, d *agd.Device, err error) {
				if tc.profDBDev != nil {
					return testProfNormal, tc.profDBDev, nil
				}

				return nil, nil, profiledb.ErrDeviceNotFound
			}

			df := newDefault(t, &devicefinder.Config{
				ProfileDB: profDB,
			})

			tlsConnState := &tls.ConnectionState{
				ServerName: dnssvctest.DomainForDevices,
			}

			ctx := testutil.ContextWithTimeout(t, dnssvctest.Timeout)
			ctx = dnsserver.ContextWithRequestInfo(ctx, &dnsserver.RequestInfo{
				TLS:      tlsConnState,
				URL:      tc.reqURL,
				Userinfo: tc.reqURL.User,
			})

			got := df.Find(ctx, reqNormal, dnssvctest.ClientAddrPort, dnssvctest.ServerAddrPort)
			assertEqualResult(t, tc.wantRes, got)
		})
	}
}

func TestDefault_Find_DoHAuthOnly(t *testing.T) {
	t.Parallel()

	var (
		devAuthSuccess = newDevAuth(true, true)
		devAuthFail    = newDevAuth(true, false)
	)

	testCases := []struct {
		wantRes    agd.DeviceResult
		profDBDev  *agd.Device
		srv        *agd.Server
		reqURL     *url.URL
		cliSrvName string
		name       string
	}{{
		wantRes: &agd.DeviceResultOK{
			Device:  devAuthSuccess,
			Profile: testProfNormal,
		},
		profDBDev: devAuthSuccess,
		srv:       srvDoH,
		reqURL: &url.URL{
			Path: dnsserver.PathDoH,
			User: url.UserPassword(dnssvctest.DeviceIDStr, testPassword),
		},
		cliSrvName: dnssvctest.DomainForDevices,
		name:       "success",
	}, {
		wantRes: &agd.DeviceResultAuthenticationFailure{
			Err: devicefinder.ErrAuthenticationFailed,
		},
		profDBDev: devAuthFail,
		srv:       srvDoH,
		reqURL: &url.URL{
			Path: dnsserver.PathDoH,
			User: url.UserPassword(dnssvctest.DeviceIDStr, testPassword),
		},
		cliSrvName: dnssvctest.DomainForDevices,
		name:       "passwd_fail",
	}, {
		wantRes: &agd.DeviceResultAuthenticationFailure{
			Err: devicefinder.ErrNotDoH,
		},
		profDBDev:  devAuthSuccess,
		srv:        srvDoT,
		reqURL:     nil,
		cliSrvName: dnssvctest.DeviceIDSrvName,
		name:       "not_doh",
	}, {
		wantRes: &agd.DeviceResultAuthenticationFailure{
			Err: devicefinder.ErrNoUserInfo,
		},
		profDBDev: devAuthSuccess,
		srv:       srvDoH,
		reqURL: &url.URL{
			Path: dnsserver.PathDoH,
			User: nil,
		},
		cliSrvName: dnssvctest.DeviceIDSrvName,
		name:       "no_userinfo",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			profDB := agdtest.NewProfileDB()
			profDB.OnProfileByDeviceID = func(
				_ context.Context,
				devID agd.DeviceID,
			) (p *agd.Profile, d *agd.Device, err error) {
				return testProfNormal, tc.profDBDev, nil
			}

			df := newDefault(t, &devicefinder.Config{
				Server:        tc.srv,
				ProfileDB:     profDB,
				DeviceDomains: []string{dnssvctest.DomainForDevices},
			})

			tlsConnState := &tls.ConnectionState{
				ServerName: tc.cliSrvName,
			}
			srvReqInfo := &dnsserver.RequestInfo{
				TLS: tlsConnState,
				URL: tc.reqURL,
			}
			if tc.reqURL != nil {
				srvReqInfo.Userinfo = tc.reqURL.User
			}

			ctx := testutil.ContextWithTimeout(t, dnssvctest.Timeout)
			ctx = dnsserver.ContextWithRequestInfo(ctx, srvReqInfo)
			got := df.Find(ctx, reqNormal, dnssvctest.ClientAddrPort, dnssvctest.ServerAddrPort)
			assertEqualResult(t, tc.wantRes, got)
		})
	}
}

func TestDefault_Find_DoH(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		wantRes agd.DeviceResult
		reqURL  *url.URL
		name    string
	}{{
		wantRes: testResNormal,
		reqURL: &url.URL{
			Path: path.Join(dnsserver.PathDoH, dnssvctest.DeviceIDStr),
		},
		name: "id_path_match",
	}, {
		wantRes: &agd.DeviceResultError{
			Err: errors.Error(
				`extracting device data: http url path device id check: bad path "/dns-query/` +
					dnssvctest.DeviceIDStr + `/extra": ` + `1 extra path elems`,
			),
		},
		reqURL: &url.URL{
			Path: path.Join(dnsserver.PathDoH, dnssvctest.DeviceIDStr, "extra"),
		},
		name: "extra_elems",
	}, {
		wantRes: &agd.DeviceResultError{
			Err: errors.Error(
				`extracting device data: http url path device id check: bad device id "!!!": ` +
					`bad hostname label rune '!'`,
			),
		},
		reqURL: &url.URL{
			Path: path.Join(dnsserver.PathDoH, "!!!"),
		},
		name: "bad_id",
	}, {
		wantRes: nil,
		reqURL: &url.URL{
			Path: dnsserver.PathDoH,
		},
		name: "no_id",
	}, {
		wantRes: &agd.DeviceResultError{
			Err: errors.Error(
				`extracting device data: http url path device id check: bad path "/": ` +
					`path elems: no value`,
			),
		},
		reqURL: &url.URL{
			Path: "/",
		},
		name: "empty_path",
	}, {
		wantRes: &agd.DeviceResultError{
			Err: errors.Error(
				`extracting device data: http url path device id check: bad path "/other": ` +
					`not a dns path`,
			),
		},
		reqURL: &url.URL{
			Path: "/other",
		},
		name: "not_dns_path",
	}, {
		wantRes: resAuto,
		reqURL: &url.URL{
			Path: path.Join(dnsserver.PathDoH, dnssvctest.HumanIDPath),
		},
		name: "human_id_path_match",
	}}

	profDB := agdtest.NewProfileDB()
	profDB.OnProfileByDeviceID = newOnProfileByDeviceID(dnssvctest.DeviceID)
	profDB.OnProfileByHumanID = newOnProfileByHumanID(dnssvctest.ProfileID, dnssvctest.HumanIDLower)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			df := newDefault(t, &devicefinder.Config{
				ProfileDB: profDB,
			})

			tlsConnState := &tls.ConnectionState{
				ServerName: dnssvctest.DomainForDevices,
			}
			ctx := testutil.ContextWithTimeout(t, dnssvctest.Timeout)
			ctx = dnsserver.ContextWithRequestInfo(ctx, &dnsserver.RequestInfo{
				TLS: tlsConnState,
				URL: tc.reqURL,
			})

			got := df.Find(ctx, reqNormal, dnssvctest.ClientAddrPort, dnssvctest.ServerAddrPort)
			assertEqualResult(t, tc.wantRes, got)
		})
	}
}

func TestDefault_Find_stdEncrypted(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		wantRes       agd.DeviceResult
		cliSrvName    string
		name          string
		deviceDomains []string
	}{{
		cliSrvName:    "",
		name:          "no_id",
		deviceDomains: nil,
	}, {
		wantRes:       nil,
		cliSrvName:    dnssvctest.DeviceIDSrvName,
		name:          "no_dev_domains",
		deviceDomains: nil,
	}, {
		wantRes:       nil,
		cliSrvName:    "",
		name:          "no_cli_srvname",
		deviceDomains: []string{dnssvctest.DomainForDevices},
	}, {
		wantRes:       testResNormal,
		cliSrvName:    dnssvctest.DeviceIDSrvName,
		name:          "id_match",
		deviceDomains: []string{dnssvctest.DomainForDevices},
	}, {
		wantRes: &agd.DeviceResultError{
			Err: errors.Error(
				`extracting device data: tls server name device id check: bad device id "!!!": ` +
					`bad hostname label rune '!'`,
			),
		},
		cliSrvName:    "!!!.d.dns.example",
		name:          "bad_id",
		deviceDomains: []string{dnssvctest.DomainForDevices},
	}, {
		wantRes:       resAuto,
		cliSrvName:    dnssvctest.HumanIDSrvName,
		name:          "human_id_match",
		deviceDomains: []string{dnssvctest.DomainForDevices},
	}}

	profDB := agdtest.NewProfileDB()
	profDB.OnProfileByDeviceID = newOnProfileByDeviceID(dnssvctest.DeviceID)
	profDB.OnProfileByHumanID = newOnProfileByHumanID(dnssvctest.ProfileID, dnssvctest.HumanIDLower)

	srvData := []struct {
		srv    *agd.Server
		reqURL *url.URL
		name   string
	}{{
		srv: srvDoH,
		reqURL: &url.URL{
			Path: dnsserver.PathDoH,
		},
		name: "doh",
	}, {
		srv:    srvDoQ,
		reqURL: nil,
		name:   "doq",
	}, {
		srv:    srvDoT,
		reqURL: nil,
		name:   "dot",
	}}

	for _, tc := range testCases {
		for _, sd := range srvData {
			t.Run(sd.name+"_"+tc.name, func(t *testing.T) {
				t.Parallel()

				df := newDefault(t, &devicefinder.Config{
					Server:        sd.srv,
					ProfileDB:     profDB,
					DeviceDomains: tc.deviceDomains,
				})

				tlsConnState := &tls.ConnectionState{
					ServerName: tc.cliSrvName,
				}

				ctx := testutil.ContextWithTimeout(t, dnssvctest.Timeout)
				ctx = dnsserver.ContextWithRequestInfo(ctx, &dnsserver.RequestInfo{
					TLS: tlsConnState,
					URL: sd.reqURL,
				})

				got := df.Find(ctx, reqNormal, dnssvctest.ClientAddrPort, dnssvctest.ServerAddrPort)
				assertEqualResult(t, tc.wantRes, got)
			})
		}
	}
}

// testCustomDomainDB is a [devicefinder.CustomDomainDB] for tests.
type testCustomDomainDB struct {
	onMatch func(
		ctx context.Context,
		cliSrvName string,
	) (matchedDomain string, accID agd.AccountID, accIP netip.Addr)
}

// type check
var _ devicefinder.CustomDomainDB = (*testCustomDomainDB)(nil)

// Match implements the [devicefinder.CustomDomainDB] interface for
// *testCustomDomainDB.
func (db *testCustomDomainDB) Match(
	ctx context.Context,
	cliSrvName string,
) (matchedDomain string, accID agd.AccountID, accIP netip.Addr) {
	return db.onMatch(ctx, cliSrvName)
}

// newTestCustomDomainDB returns a *testCustomDomainDB that returns the given
// data.
func newTestCustomDomainDB(
	domain string,
	accID agd.AccountID,
	accIP netip.Addr,
) (db *testCustomDomainDB) {
	return &testCustomDomainDB{
		onMatch: func(
			_ context.Context,
			_ string,
		) (matchedDomain string, accountID agd.AccountID, accountIP netip.Addr) {
			return domain, accID, accIP
		},
	}
}

// TODO(a.garipov):  Add tests for DoH.
func TestDefault_Find_customDomainDoT(t *testing.T) {
	t.Parallel()

	addr := netip.Addr{}
	var (
		customDBMatch   = newTestCustomDomainDB(testCustomDomain, dnssvctest.AccountID, addr)
		customDBMatchWk = newTestCustomDomainDB("*."+testCustomDomain, dnssvctest.AccountID, addr)
		customDBNoMatch = newTestCustomDomainDB("", 0, addr)
	)

	profDBDefault := agdtest.NewProfileDB()
	profDBFoundDevID := agdtest.NewProfileDB()
	profDBFoundDevID.OnProfileByDeviceID = newOnProfileByDeviceID(dnssvctest.DeviceID)

	profDBFoundHumanID := agdtest.NewProfileDB()
	profDBFoundHumanID.OnProfileByHumanID = newOnProfileByHumanID(
		dnssvctest.ProfileID,
		dnssvctest.HumanIDLower,
	)
	profDBFoundHumanID.OnProfileByID = newOnProfileByID(dnssvctest.ProfileID)

	profDBFoundOtherHumanID := agdtest.NewProfileDB()
	profDBFoundOtherHumanID.OnProfileByHumanID = func(
		ctx context.Context,
		id agd.ProfileID,
		humanID agd.HumanIDLower,
	) (p *agd.Profile, d *agd.Device, err error) {
		return testProfOther, testDevNormal, err
	}

	profDBFoundOtherHumanID.OnProfileByID = func(
		ctx context.Context,
		id agd.ProfileID,
	) (p *agd.Profile, err error) {
		return testProfOther, err
	}

	profDBFoundOtherDevID := agdtest.NewProfileDB()
	profDBFoundOtherDevID.OnProfileByDeviceID = func(
		ctx context.Context,
		id agd.DeviceID,
	) (p *agd.Profile, d *agd.Device, err error) {
		return testProfOther, testDevNormal, err
	}

	profDBFoundSameAccDevID := agdtest.NewProfileDB()
	profDBFoundSameAccDevID.OnProfileByDeviceID = func(
		ctx context.Context,
		id agd.DeviceID,
	) (p *agd.Profile, d *agd.Device, err error) {
		return testProfSameAcc, testDevSameAcc, err
	}

	const devIDOtherStr = "dev5678"

	profDBNotFoundDevID := agdtest.NewProfileDB()
	profDBNotFoundDevID.OnProfileByDeviceID = newOnProfileByDeviceID(devIDOtherStr)

	testCases := []struct {
		customDB   devicefinder.CustomDomainDB
		profDB     profiledb.Interface
		wantRes    agd.DeviceResult
		cliSrvName string
		name       string
	}{{
		customDB:   customDBMatchWk,
		profDB:     profDBFoundDevID,
		wantRes:    testResNormal,
		cliSrvName: testCliSrvNameDev,
		name:       "match",
	}, {
		customDB:   customDBNoMatch,
		profDB:     profDBDefault,
		wantRes:    nil,
		cliSrvName: testCliSrvNameDev,
		name:       "domain_mismatch",
	}, {
		customDB:   customDBMatch,
		profDB:     profDBDefault,
		wantRes:    &agd.DeviceResultPartialData{},
		cliSrvName: testCliSrvNameDev,
		name:       "domain_not_wk",
	}, {
		customDB:   customDBMatchWk,
		profDB:     profDBFoundOtherDevID,
		wantRes:    nil,
		cliSrvName: testCliSrvNameDev,
		name:       "device_mismatch",
	}, {
		customDB: customDBMatchWk,
		profDB:   profDBFoundSameAccDevID,
		wantRes: &agd.DeviceResultOK{
			Device:  testDevSameAcc,
			Profile: testProfSameAcc,
		},
		cliSrvName: testDevIDSameAccStr + "." + testCustomDomain,
		name:       "same_account_different_device",
	}, {
		customDB:   customDBMatchWk,
		profDB:     profDBNotFoundDevID,
		wantRes:    nil,
		cliSrvName: testCliSrvNameDev,
		name:       "not_found",
	}, {
		customDB:   customDBMatch,
		profDB:     agdtest.NewProfileDB(),
		wantRes:    &agd.DeviceResultPartialData{},
		cliSrvName: testCustomDomain,
		name:       "empty",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			testFindCustomDomain(
				t,
				tc.customDB,
				tc.profDB,
				tc.cliSrvName,
				tc.wantRes,
				dnssvctest.ClientAddrPort,
				dnssvctest.ServerAddrPort,
			)
		})
	}
}

func TestDefault_Find_accountIP(t *testing.T) {
	t.Parallel()

	addr := netip.MustParseAddr("192.0.2.0")

	profDB := agdtest.NewProfileDB()
	profDB.OnProfileByDeviceID = newOnProfileByDeviceID(dnssvctest.DeviceID)

	customDomainDB := newTestCustomDomainDB("*."+testCustomDomain, dnssvctest.AccountID, addr)

	t.Run("match", func(t *testing.T) {
		t.Parallel()

		laddr := netip.AddrPortFrom(addr, 853)
		testFindCustomDomain(
			t,
			customDomainDB,
			profDB,
			testCliSrvNameDev,
			testResNormal,
			dnssvctest.ClientAddrPort,
			laddr,
		)
	})

	t.Run("mismatch", func(t *testing.T) {
		t.Parallel()

		laddr := netip.MustParseAddrPort("192.0.2.1:853")

		errMsg := fmt.Sprintf(
			"custom domain device id check: custom domain destination ip mismatch: got %s, want %s",
			laddr.Addr(),
			addr,
		)
		wantRes := &agd.DeviceResultError{
			Err: errors.Error(errMsg),
		}

		testFindCustomDomain(
			t,
			customDomainDB,
			profDB,
			testCliSrvNameDev,
			wantRes,
			dnssvctest.ClientAddrPort,
			laddr,
		)
	})
}

// testFindCustomDomain ensures that [devicefinder.Default.Find] works correctly
// for custom domains.
func testFindCustomDomain(
	tb testing.TB,
	customDB devicefinder.CustomDomainDB,
	profDB profiledb.Interface,
	cliSrvName string,
	wantRes agd.DeviceResult,
	raddr netip.AddrPort,
	laddr netip.AddrPort,
) {
	df := newDefault(tb, &devicefinder.Config{
		Server:         srvDoT,
		CustomDomainDB: customDB,
		ProfileDB:      profDB,
	})

	ctx := testutil.ContextWithTimeout(tb, dnssvctest.Timeout)
	ctx = dnsserver.ContextWithRequestInfo(ctx, dnssvctest.NewRequestInfo(cliSrvName))

	got := df.Find(ctx, reqNormal, raddr, laddr)
	assertEqualResult(tb, wantRes, got)
}

func TestDefault_Find_customDomainDoTHumanID(t *testing.T) {
	t.Parallel()

	customDB := newTestCustomDomainDB("*."+testCustomDomain, dnssvctest.AccountID, netip.Addr{})

	profDBFoundDevID := agdtest.NewProfileDB()
	profDBFoundDevID.OnProfileByDeviceID = newOnProfileByDeviceID(dnssvctest.DeviceID)

	profDBFoundHumanID := agdtest.NewProfileDB()
	profDBFoundHumanID.OnProfileByHumanID = newOnProfileByHumanID(
		dnssvctest.ProfileID,
		dnssvctest.HumanIDLower,
	)
	profDBFoundHumanID.OnProfileByID = newOnProfileByID(dnssvctest.ProfileID)

	profDBFoundOtherHumanID := agdtest.NewProfileDB()
	profDBFoundOtherHumanID.OnProfileByHumanID = func(
		ctx context.Context,
		id agd.ProfileID,
		humanID agd.HumanIDLower,
	) (p *agd.Profile, d *agd.Device, err error) {
		return testProfOther, testDevNormal, err
	}

	profDBFoundOtherHumanID.OnProfileByID = func(
		ctx context.Context,
		id agd.ProfileID,
	) (p *agd.Profile, err error) {
		return testProfOther, err
	}

	profDBFoundOtherDevID := agdtest.NewProfileDB()
	profDBFoundOtherDevID.OnProfileByDeviceID = func(
		ctx context.Context,
		id agd.DeviceID,
	) (p *agd.Profile, d *agd.Device, err error) {
		return testProfOther, testDevNormal, err
	}

	const devIDOtherStr = "dev5678"

	profDBNotFoundDevID := agdtest.NewProfileDB()
	profDBNotFoundDevID.OnProfileByDeviceID = newOnProfileByDeviceID(devIDOtherStr)

	deviceMismatchErr := errors.Error(
		fmt.Sprintf(
			"wrapping custom domains: custom domain device id check: "+
				"custom domain account id and ext id mismatch: got %d, want %d",
			testProfOther.AccountID,
			testProfNormal.AccountID,
		),
	)

	raddr, laddr := dnssvctest.ClientAddrPort, dnssvctest.ServerAddrPort

	testCases := []struct {
		profDB     profiledb.Interface
		wantRes    agd.DeviceResult
		cliSrvName string
		name       string
	}{{
		profDB:     profDBFoundHumanID,
		wantRes:    resAuto,
		cliSrvName: dnssvctest.HumanIDPath + "." + testCustomDomain,
		name:       "match",
	}, {
		profDB:  profDBFoundHumanID,
		wantRes: nil,
		cliSrvName: "otr-" + testProfIDOtherStr + "-" + dnssvctest.HumanIDStr +
			"." + testCustomDomain,
		name: "profile_device_not_found",
	}, {
		profDB: profDBFoundOtherHumanID,
		wantRes: &agd.DeviceResultError{
			Err: deviceMismatchErr,
		},
		cliSrvName: "otr-" + testProfIDOtherStr + "-" + dnssvctest.HumanIDStr +
			"." + testCustomDomain,
		name: "profile_mismatch",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			testFindCustomDomain(t, customDB, tc.profDB, tc.cliSrvName, tc.wantRes, raddr, laddr)
		})
	}
}

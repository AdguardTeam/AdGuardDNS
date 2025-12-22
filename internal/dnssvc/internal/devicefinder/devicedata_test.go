package devicefinder_test

import (
	"context"
	"crypto/tls"
	"net/url"
	"path"
	"slices"
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
			Profile: profNormal,
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
					return profNormal, tc.profDBDev, nil
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
			Profile: profNormal,
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
				return profNormal, tc.profDBDev, nil
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
		wantRes: resNormal,
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
		wantRes:       resNormal,
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

// testCustomDomainDB is an [CustomDomainDB] for tests.
type testCustomDomainDB struct {
	onMatch func(
		ctx context.Context,
		cliSrvName string,
	) (matchedDomain string, profIDs []agd.ProfileID)
}

// type check
var _ devicefinder.CustomDomainDB = (*testCustomDomainDB)(nil)

// Match implements the [CustomDomainDB] interface for *testCustomDomainDB.
func (db *testCustomDomainDB) Match(
	ctx context.Context,
	cliSrvName string,
) (matchedDomain string, profIDs []agd.ProfileID) {
	return db.onMatch(ctx, cliSrvName)
}

// newTestCustomDomainDB returns a *testCustomDomainDB that returns the given
// data.
func newTestCustomDomainDB(domain string, ids []agd.ProfileID) (db *testCustomDomainDB) {
	return &testCustomDomainDB{
		onMatch: func(_ context.Context, _ string) (matchedDomain string, profIDs []agd.ProfileID) {
			return domain, slices.Clone(ids)
		},
	}
}

// TODO(a.garipov):  Add tests for DoH.
func TestDefault_Find_customDomainDoT(t *testing.T) {
	t.Parallel()

	const customDomain = "custom.example"

	const profIDOtherStr = "prof5678"
	profOther := &agd.Profile{}
	*profOther = *profNormal
	profOther.ID = agd.ProfileID(profIDOtherStr)

	var (
		customDBMatch = newTestCustomDomainDB(customDomain, []agd.ProfileID{
			dnssvctest.ProfileID,
		})
		customDBMatchWkSeveral = newTestCustomDomainDB("*."+customDomain, []agd.ProfileID{
			dnssvctest.ProfileID,
			profIDOtherStr,
		})
		customDBMatchWk = newTestCustomDomainDB("*."+customDomain, []agd.ProfileID{
			dnssvctest.ProfileID,
		})
		customDBNoMatch = newTestCustomDomainDB("", nil)
	)

	profDBDefault := agdtest.NewProfileDB()

	profDBFoundDevID := agdtest.NewProfileDB()
	profDBFoundDevID.OnProfileByDeviceID = newOnProfileByDeviceID(dnssvctest.DeviceID)

	profDBFoundHumanID := agdtest.NewProfileDB()
	profDBFoundHumanID.OnProfileByHumanID = newOnProfileByHumanID(
		dnssvctest.ProfileID,
		dnssvctest.HumanIDLower,
	)

	profDBFoundOtherDevID := agdtest.NewProfileDB()
	profDBFoundOtherDevID.OnProfileByDeviceID = func(
		ctx context.Context,
		id agd.DeviceID,
	) (p *agd.Profile, d *agd.Device, err error) {
		return profOther, devNormal, err
	}

	const devIDOtherStr = "dev5678"

	profDBNotFoundDevID := agdtest.NewProfileDB()
	profDBNotFoundDevID.OnProfileByDeviceID = newOnProfileByDeviceID(devIDOtherStr)

	const cliSrvNameDev = dnssvctest.DeviceIDStr + "." + customDomain

	const errStrMismatch errors.Error = `wrapping custom domains: custom domain device id check: ` +
		`profile id in ext id: ` + profIDOtherStr + `: not contained by expected values`

	testCases := []struct {
		customDB   devicefinder.CustomDomainDB
		profDB     profiledb.Interface
		wantRes    agd.DeviceResult
		cliSrvName string
		name       string
	}{{
		customDB:   customDBMatchWk,
		profDB:     profDBFoundDevID,
		wantRes:    resNormal,
		cliSrvName: cliSrvNameDev,
		name:       "custom_device_match",
	}, {
		customDB:   customDBMatchWkSeveral,
		profDB:     profDBFoundDevID,
		wantRes:    resNormal,
		cliSrvName: cliSrvNameDev,
		name:       "custom_device_match_several",
	}, {
		customDB:   customDBNoMatch,
		profDB:     profDBDefault,
		wantRes:    nil,
		cliSrvName: cliSrvNameDev,
		name:       "custom_device_domain_mismatch",
	}, {
		customDB:   customDBMatch,
		profDB:     profDBDefault,
		wantRes:    nil,
		cliSrvName: cliSrvNameDev,
		name:       "custom_device_domain_not_wk",
	}, {
		customDB:   customDBMatchWk,
		profDB:     profDBFoundOtherDevID,
		wantRes:    nil,
		cliSrvName: cliSrvNameDev,
		name:       "custom_device_device_mismatch",
	}, {
		customDB:   customDBMatchWk,
		profDB:     profDBNotFoundDevID,
		wantRes:    nil,
		cliSrvName: cliSrvNameDev,
		name:       "custom_device_not_found",
	}, {
		customDB:   customDBMatchWk,
		profDB:     profDBFoundHumanID,
		wantRes:    resAuto,
		cliSrvName: dnssvctest.HumanIDPath + "." + customDomain,
		name:       "custom_human_match",
	}, {
		customDB: customDBMatchWk,
		profDB:   profDBFoundHumanID,
		wantRes: &agd.DeviceResultError{
			Err: errors.Error(errStrMismatch),
		},
		cliSrvName: "otr-" + profIDOtherStr + "-" + dnssvctest.HumanIDStr + "." + customDomain,
		name:       "custom_human_profile_mismatch",
	}, {
		name:       "custom_empty",
		cliSrvName: customDomain,
		customDB:   customDBMatch,
		profDB:     agdtest.NewProfileDB(),
		wantRes:    nil,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			df := newDefault(t, &devicefinder.Config{
				Server:         srvDoT,
				CustomDomainDB: tc.customDB,
				ProfileDB:      tc.profDB,
			})

			ctx := testutil.ContextWithTimeout(t, dnssvctest.Timeout)
			ctx = dnsserver.ContextWithRequestInfo(ctx, dnssvctest.NewRequestInfo(tc.cliSrvName))

			got := df.Find(ctx, reqNormal, dnssvctest.ClientAddrPort, dnssvctest.ServerAddrPort)
			assertEqualResult(t, tc.wantRes, got)
		})
	}
}

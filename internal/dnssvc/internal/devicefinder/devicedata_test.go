package devicefinder_test

import (
	"context"
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
	"github.com/AdguardTeam/golibs/logutil/slogutil"
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
				`basic auth device id check: bad device id "!!!": bad hostname label rune '!'`,
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

			df := devicefinder.NewDefault(&devicefinder.Config{
				Logger:        slogutil.NewDiscardLogger(),
				ProfileDB:     profDB,
				HumanIDParser: agd.NewHumanIDParser(),
				Server:        srvDoH,
				DeviceDomains: []string{},
			})

			ctx := testutil.ContextWithTimeout(t, dnssvctest.Timeout)
			ctx = dnsserver.ContextWithRequestInfo(ctx, &dnsserver.RequestInfo{
				TLSServerName: dnssvctest.DomainForDevices,
				URL:           tc.reqURL,
				Userinfo:      tc.reqURL.User,
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

			df := devicefinder.NewDefault(&devicefinder.Config{
				Logger:        slogutil.NewDiscardLogger(),
				ProfileDB:     profDB,
				HumanIDParser: agd.NewHumanIDParser(),
				Server:        tc.srv,
				DeviceDomains: []string{dnssvctest.DomainForDevices},
			})

			srvReqInfo := &dnsserver.RequestInfo{
				TLSServerName: tc.cliSrvName,
				URL:           tc.reqURL,
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
				`http url path device id check: bad path "/dns-query/` +
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
				`http url path device id check: bad device id "!!!": bad hostname label rune '!'`,
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
			Err: errors.Error(`http url path device id check: bad path "/": path elems: no value`),
		},
		reqURL: &url.URL{
			Path: "/",
		},
		name: "empty_path",
	}, {
		wantRes: &agd.DeviceResultError{
			Err: errors.Error(`http url path device id check: bad path "/other": not a dns path`),
		},
		reqURL: &url.URL{
			Path: "/other",
		},
		name: "not_dns_path",
	}, {
		wantRes: &agd.DeviceResultOK{
			Device:  devAuto,
			Profile: profNormal,
		},
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

			df := devicefinder.NewDefault(&devicefinder.Config{
				Logger:        slogutil.NewDiscardLogger(),
				ProfileDB:     profDB,
				HumanIDParser: agd.NewHumanIDParser(),
				Server:        srvDoH,
				DeviceDomains: []string{},
			})

			ctx := testutil.ContextWithTimeout(t, dnssvctest.Timeout)
			ctx = dnsserver.ContextWithRequestInfo(ctx, &dnsserver.RequestInfo{
				TLSServerName: dnssvctest.DomainForDevices,
				URL:           tc.reqURL,
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
				`tls server name device id check: bad device id "!!!": bad hostname label rune '!'`,
			),
		},
		cliSrvName:    "!!!.d.dns.example",
		name:          "bad_id",
		deviceDomains: []string{dnssvctest.DomainForDevices},
	}, {
		wantRes: &agd.DeviceResultOK{
			Device:  devAuto,
			Profile: profNormal,
		},
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

				df := devicefinder.NewDefault(&devicefinder.Config{
					Logger:        slogutil.NewDiscardLogger(),
					ProfileDB:     profDB,
					HumanIDParser: agd.NewHumanIDParser(),
					Server:        sd.srv,
					DeviceDomains: tc.deviceDomains,
				})

				ctx := testutil.ContextWithTimeout(t, dnssvctest.Timeout)
				ctx = dnsserver.ContextWithRequestInfo(ctx, &dnsserver.RequestInfo{
					TLSServerName: tc.cliSrvName,
					URL:           sd.reqURL,
				})

				got := df.Find(ctx, reqNormal, dnssvctest.ClientAddrPort, dnssvctest.ServerAddrPort)
				assertEqualResult(t, tc.wantRes, got)
			})
		}
	}
}

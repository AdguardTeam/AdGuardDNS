package devicesetter_test

import (
	"context"
	"net/netip"
	"net/url"
	"path"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/devicesetter"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/dnssvctest"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
)

func TestDefault_SetDevice_DoHAuth(t *testing.T) {
	t.Parallel()

	var (
		devAuthSuccess = newDevAuth(false, true)
		devAuthFail    = newDevAuth(false, false)
	)

	testCases := []struct {
		wantProf   *agd.Profile
		wantDev    *agd.Device
		profDBDev  *agd.Device
		reqURL     *url.URL
		wantErrMsg string
		name       string
	}{{
		wantProf:  profNormal,
		wantDev:   devAuthSuccess,
		profDBDev: devAuthSuccess,
		reqURL: &url.URL{
			Path: dnsserver.PathDoH,
			User: url.UserPassword(dnssvctest.DeviceIDStr, testPassword),
		},
		wantErrMsg: "",
		name:       "success",
	}, {
		wantProf:  nil,
		wantDev:   nil,
		profDBDev: devAuthFail,
		reqURL: &url.URL{
			Path: dnsserver.PathDoH,
			User: url.UserPassword(dnssvctest.DeviceIDStr, testPassword),
		},
		wantErrMsg: "",
		name:       "passwd_fail",
	}, {
		wantProf:  nil,
		wantDev:   nil,
		profDBDev: devAuthSuccess,
		reqURL: &url.URL{
			Path: dnsserver.PathDoH,
			User: url.User(dnssvctest.DeviceIDStr),
		},
		wantErrMsg: "",
		name:       "no_passwd",
	}, {
		wantProf:  nil,
		wantDev:   nil,
		profDBDev: nil,
		reqURL: &url.URL{
			Path: dnsserver.PathDoH,
			User: nil,
		},
		wantErrMsg: "",
		name:       "no_userinfo",
	}, {
		wantProf:  nil,
		wantDev:   nil,
		profDBDev: devAuthSuccess,
		reqURL: &url.URL{
			Path: dnsserver.PathDoH,
			User: url.UserPassword("!!!", testPassword),
		},
		wantErrMsg: `basic auth device id check: bad device id "!!!": bad hostname label rune '!'`,
		name:       "bad_id",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			profDB := &agdtest.ProfileDB{
				OnProfileByDedicatedIP: func(
					_ context.Context,
					_ netip.Addr,
				) (p *agd.Profile, d *agd.Device, err error) {
					panic("not implemented")
				},
				OnProfileByDeviceID: func(
					_ context.Context,
					devID agd.DeviceID,
				) (p *agd.Profile, d *agd.Device, err error) {
					if tc.profDBDev != nil {
						return profNormal, tc.profDBDev, nil
					}

					return nil, nil, profiledb.ErrDeviceNotFound
				},
				OnProfileByLinkedIP: func(
					_ context.Context,
					_ netip.Addr,
				) (p *agd.Profile, d *agd.Device, err error) {
					panic("not implemented")
				},
			}

			df := devicesetter.NewDefault(&devicesetter.Config{
				ProfileDB:         profDB,
				Server:            srvDoH,
				DeviceIDWildcards: []string{},
			})

			ctx := dnsserver.ContextWithRequestInfo(context.Background(), &dnsserver.RequestInfo{
				TLSServerName: dnssvctest.DomainForDevices,
				URL:           tc.reqURL,
				Userinfo:      tc.reqURL.User,
			})
			ri := &agd.RequestInfo{
				RemoteIP: dnssvctest.ClientAddr,
			}

			err := df.SetDevice(ctx, reqNormal, ri, dnssvctest.ServerAddrPort)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
			assert.Equal(t, tc.wantProf, ri.Profile)
			assert.Equal(t, tc.wantDev, ri.Device)
		})
	}
}

func TestDefault_SetDevice_DoHAuthOnly(t *testing.T) {
	t.Parallel()

	var (
		devAuthSuccess = newDevAuth(true, true)
		devAuthFail    = newDevAuth(true, false)
	)

	testCases := []struct {
		wantProf   *agd.Profile
		wantDev    *agd.Device
		profDBDev  *agd.Device
		srv        *agd.Server
		reqURL     *url.URL
		wantErrMsg string
		cliSrvName string
		name       string
	}{{
		wantProf:  profNormal,
		wantDev:   devAuthSuccess,
		profDBDev: devAuthSuccess,
		srv:       srvDoH,
		reqURL: &url.URL{
			Path: dnsserver.PathDoH,
			User: url.UserPassword(dnssvctest.DeviceIDStr, testPassword),
		},
		wantErrMsg: "",
		cliSrvName: dnssvctest.DomainForDevices,
		name:       "success",
	}, {
		wantProf:  nil,
		wantDev:   nil,
		profDBDev: devAuthFail,
		srv:       srvDoH,
		reqURL: &url.URL{
			Path: dnsserver.PathDoH,
			User: url.UserPassword(dnssvctest.DeviceIDStr, testPassword),
		},
		wantErrMsg: "",
		cliSrvName: dnssvctest.DomainForDevices,
		name:       "passwd_fail",
	}, {
		wantProf:   nil,
		wantDev:    nil,
		profDBDev:  devAuthSuccess,
		srv:        srvDoT,
		reqURL:     nil,
		wantErrMsg: "",
		cliSrvName: dnssvctest.DeviceIDSrvName,
		name:       "not_doh",
	}, {
		wantProf:  nil,
		wantDev:   nil,
		profDBDev: devAuthSuccess,
		srv:       srvDoH,
		reqURL: &url.URL{
			Path: dnsserver.PathDoH,
			User: nil,
		},
		wantErrMsg: "",
		cliSrvName: dnssvctest.DeviceIDSrvName,
		name:       "no_userinfo",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			profDB := &agdtest.ProfileDB{
				OnProfileByDedicatedIP: func(
					_ context.Context,
					_ netip.Addr,
				) (p *agd.Profile, d *agd.Device, err error) {
					panic("not implemented")
				},
				OnProfileByDeviceID: func(
					_ context.Context,
					devID agd.DeviceID,
				) (p *agd.Profile, d *agd.Device, err error) {
					return profNormal, tc.profDBDev, nil
				},
				OnProfileByLinkedIP: func(
					_ context.Context,
					_ netip.Addr,
				) (p *agd.Profile, d *agd.Device, err error) {
					panic("not implemented")
				},
			}

			df := devicesetter.NewDefault(&devicesetter.Config{
				ProfileDB:         profDB,
				Server:            tc.srv,
				DeviceIDWildcards: []string{dnssvctest.DeviceIDWildcard},
			})

			srvReqInfo := &dnsserver.RequestInfo{
				TLSServerName: tc.cliSrvName,
				URL:           tc.reqURL,
			}
			if tc.reqURL != nil {
				srvReqInfo.Userinfo = tc.reqURL.User
			}

			ctx := dnsserver.ContextWithRequestInfo(context.Background(), srvReqInfo)
			ri := &agd.RequestInfo{
				RemoteIP: dnssvctest.ClientAddr,
			}

			err := df.SetDevice(ctx, reqNormal, ri, dnssvctest.ServerAddrPort)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
			assert.Equal(t, tc.wantProf, ri.Profile)
			assert.Equal(t, tc.wantDev, ri.Device)
		})
	}
}

func TestDefault_SetDevice_DoH(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		wantProf   *agd.Profile
		wantDev    *agd.Device
		reqURL     *url.URL
		wantErrMsg string
		name       string
	}{{
		wantProf: profNormal,
		wantDev:  devNormal,
		reqURL: &url.URL{
			Path: path.Join(dnsserver.PathDoH, dnssvctest.DeviceIDStr),
		},
		wantErrMsg: "",
		name:       "id_path_match",
	}, {
		wantProf: nil,
		wantDev:  nil,
		reqURL: &url.URL{
			Path: path.Join(dnsserver.PathDoH, dnssvctest.DeviceIDStr, "extra"),
		},
		wantErrMsg: `http url path device id check: bad path "/dns-query/` +
			dnssvctest.DeviceIDStr + `/extra": ` + `1 extra parts`,
		name: "extra_parts",
	}, {
		wantProf: nil,
		wantDev:  nil,
		reqURL: &url.URL{
			Path: path.Join(dnsserver.PathDoH, "!!!"),
		},
		wantErrMsg: `http url path device id check: bad device id "!!!": ` +
			`bad hostname label rune '!'`,
		name: "bad_id",
	}, {
		wantProf: nil,
		wantDev:  nil,
		reqURL: &url.URL{
			Path: dnsserver.PathDoH,
		},
		wantErrMsg: "",
		name:       "no_id",
	}, {
		wantProf: nil,
		wantDev:  nil,
		reqURL: &url.URL{
			Path: "/",
		},
		wantErrMsg: `http url path device id check: bad path "/": empty elements`,
		name:       "empty_path",
	}, {
		wantProf: nil,
		wantDev:  nil,
		reqURL: &url.URL{
			Path: "/other",
		},
		wantErrMsg: `http url path device id check: bad path "/other": not a dns path`,
		name:       "not_dns_path",
	}}

	profDB := &agdtest.ProfileDB{
		OnProfileByDedicatedIP: func(
			_ context.Context,
			_ netip.Addr,
		) (p *agd.Profile, d *agd.Device, err error) {
			panic("not implemented")
		},
		OnProfileByDeviceID: newOnProfileByDeviceID(dnssvctest.DeviceID),
		OnProfileByLinkedIP: func(
			_ context.Context,
			_ netip.Addr,
		) (p *agd.Profile, d *agd.Device, err error) {
			panic("not implemented")
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			df := devicesetter.NewDefault(&devicesetter.Config{
				ProfileDB:         profDB,
				Server:            srvDoH,
				DeviceIDWildcards: []string{},
			})

			ctx := dnsserver.ContextWithRequestInfo(context.Background(), &dnsserver.RequestInfo{
				TLSServerName: dnssvctest.DomainForDevices,
				URL:           tc.reqURL,
			})
			ri := &agd.RequestInfo{
				RemoteIP: dnssvctest.ClientAddr,
			}

			err := df.SetDevice(ctx, reqNormal, ri, dnssvctest.ServerAddrPort)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
			assert.Equal(t, tc.wantProf, ri.Profile)
			assert.Equal(t, tc.wantDev, ri.Device)
		})
	}
}

func TestDefault_SetDevice_stdEncrypted(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		wantProf   *agd.Profile
		wantDev    *agd.Device
		wantErrMsg string
		cliSrvName string
		name       string
		wildcards  []string
	}{{
		wantProf:   nil,
		wantDev:    nil,
		wantErrMsg: "",
		cliSrvName: "",
		name:       "no_id",
		wildcards:  nil,
	}, {
		wantProf:   nil,
		wantDev:    nil,
		wantErrMsg: "",
		cliSrvName: dnssvctest.DeviceIDSrvName,
		name:       "no_wildcards",
		wildcards:  nil,
	}, {
		wantProf:   nil,
		wantDev:    nil,
		wantErrMsg: "",
		cliSrvName: "",
		name:       "no_cli_srvname",
		wildcards:  []string{dnssvctest.DeviceIDWildcard},
	}, {
		wantProf:   profNormal,
		wantDev:    devNormal,
		wantErrMsg: "",
		cliSrvName: dnssvctest.DeviceIDSrvName,
		name:       "id_match",
		wildcards:  []string{dnssvctest.DeviceIDWildcard},
	}, {
		wantProf: nil,
		wantDev:  nil,
		wantErrMsg: `tls server name device id check: bad device id "!!!": ` +
			`bad hostname label rune '!'`,
		cliSrvName: "!!!.d.dns.example",
		name:       "bad_id",
		wildcards:  []string{dnssvctest.DeviceIDWildcard},
	}}

	profDB := &agdtest.ProfileDB{
		OnProfileByDedicatedIP: func(
			_ context.Context,
			_ netip.Addr,
		) (p *agd.Profile, d *agd.Device, err error) {
			panic("not implemented")
		},
		OnProfileByDeviceID: newOnProfileByDeviceID(dnssvctest.DeviceID),
		OnProfileByLinkedIP: func(
			_ context.Context,
			_ netip.Addr,
		) (p *agd.Profile, d *agd.Device, err error) {
			panic("not implemented")
		},
	}

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

				df := devicesetter.NewDefault(&devicesetter.Config{
					ProfileDB:         profDB,
					Server:            sd.srv,
					DeviceIDWildcards: tc.wildcards,
				})

				ctx := dnsserver.ContextWithRequestInfo(context.Background(), &dnsserver.RequestInfo{
					TLSServerName: tc.cliSrvName,
					URL:           sd.reqURL,
				})
				ri := &agd.RequestInfo{
					RemoteIP: dnssvctest.ClientAddr,
				}

				err := df.SetDevice(ctx, reqNormal, ri, dnssvctest.ServerAddrPort)
				testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
				assert.Equal(t, tc.wantProf, ri.Profile)
				assert.Equal(t, tc.wantDev, ri.Device)
			})
		}
	}
}

package initial

import (
	"context"
	"net/url"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/dnssvctest"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeviceIDFromContext(t *testing.T) {
	testCases := []struct {
		name         string
		cliSrvName   string
		wantDeviceID agd.DeviceID
		wantErrMsg   string
		wildcards    []string
		proto        agd.Protocol
	}{{
		name:         "dns",
		cliSrvName:   "",
		wantDeviceID: "",
		wantErrMsg:   "",
		wildcards:    nil,
		proto:        agd.ProtoDNS,
	}, {
		name:         "tls_no_device_id",
		cliSrvName:   "dns.example.com",
		wantDeviceID: "",
		wantErrMsg:   "",
		wildcards:    []string{"*.dns.example.com"},
		proto:        agd.ProtoDoT,
	}, {
		name:         "tls_no_client_server_name",
		cliSrvName:   "",
		wantDeviceID: "",
		wantErrMsg:   "",
		wildcards:    []string{"*.dns.example.com"},
		proto:        agd.ProtoDoT,
	}, {
		name:         "tls_device_id",
		cliSrvName:   dnssvctest.DeviceIDStr + ".dns.example.com",
		wantDeviceID: dnssvctest.DeviceID,
		wantErrMsg:   "",
		wildcards:    []string{"*.dns.example.com"},
		proto:        agd.ProtoDoT,
	}, {
		name:         "tls_bad_device_id",
		cliSrvName:   "!!!.dns.example.com",
		wantDeviceID: "",
		wantErrMsg: `tls server name device id check: bad device id "!!!": ` +
			`bad hostname label rune '!'`,
		wildcards: []string{"*.dns.example.com"},
		proto:     agd.ProtoDoT,
	}, {
		name:         "tls_deep_subdomain",
		cliSrvName:   "abc." + dnssvctest.DeviceIDStr + ".dns.example.com",
		wantDeviceID: "",
		wantErrMsg:   "",
		wildcards:    []string{"*.dns.example.com"},
		proto:        agd.ProtoDoT,
	}, {
		name: "tls_device_id_too_long",
		cliSrvName: `abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmno` +
			`pqrstuvwxyz0123456789.dns.example.com`,
		wantDeviceID: "",
		wantErrMsg: `tls server name device id check: bad device id ` +
			`"abcdefghijklmnopqrstuvwxyz0123456789` +
			`abcdefghijklmnopqrstuvwxyz0123456789": ` +
			`too long: got 72 bytes, max 8`,
		wildcards: []string{"*.dns.example.com"},
		proto:     agd.ProtoDoT,
	}, {
		name:         "quic_device_id",
		cliSrvName:   dnssvctest.DeviceIDStr + ".dns.example.com",
		wantDeviceID: dnssvctest.DeviceID,
		wantErrMsg:   "",
		wildcards:    []string{"*.dns.example.com"},
		proto:        agd.ProtoDoQ,
	}, {
		name:         "tls_device_id_suffix",
		cliSrvName:   "dev.mydns.example.com",
		wantDeviceID: "",
		wantErrMsg:   "",
		wildcards:    []string{"*.dns.example.com"},
		proto:        agd.ProtoDoT,
	}, {
		name:         "tls_device_id_subdomain_wildcard",
		cliSrvName:   dnssvctest.DeviceIDStr + ".sub.dns.example.com",
		wantDeviceID: dnssvctest.DeviceID,
		wantErrMsg:   "",
		wildcards: []string{
			"*.dns.example.com",
			"*.sub.dns.example.com",
		},
		proto: agd.ProtoDoT,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			ctx = dnsserver.ContextWithClientInfo(ctx, dnsserver.ClientInfo{
				TLSServerName: tc.cliSrvName,
			})

			deviceID, err := deviceIDFromContext(ctx, tc.proto, tc.wildcards)
			assert.Equal(t, tc.wantDeviceID, deviceID)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}

func TestDeviceIDFromContext_https(t *testing.T) {
	testCases := []struct {
		name         string
		path         string
		wantDeviceID agd.DeviceID
		wantErrMsg   string
	}{{
		name:         "no_device_id",
		path:         "/dns-query",
		wantDeviceID: "",
		wantErrMsg:   "",
	}, {
		name:         "no_device_id_slash",
		path:         "/dns-query/",
		wantDeviceID: "",
		wantErrMsg:   "",
	}, {
		name:         "device_id",
		path:         "/dns-query/" + dnssvctest.DeviceIDStr,
		wantDeviceID: dnssvctest.DeviceID,
		wantErrMsg:   "",
	}, {
		name:         "device_id_slash",
		path:         "/dns-query/" + dnssvctest.DeviceIDStr + "/",
		wantDeviceID: dnssvctest.DeviceID,
		wantErrMsg:   "",
	}, {
		name:         "bad_url",
		path:         "/foo",
		wantDeviceID: "",
		wantErrMsg:   `http url device id check: bad path "/foo"`,
	}, {
		name:         "extra",
		path:         "/dns-query/" + dnssvctest.DeviceIDStr + "/foo",
		wantDeviceID: "",
		wantErrMsg: `http url device id check: bad path "/dns-query/` + dnssvctest.DeviceIDStr +
			`/foo": extra parts`,
	}, {
		name:         "bad_device_id",
		path:         "/dns-query/!!!",
		wantDeviceID: "",
		wantErrMsg: `http url device id check: bad device id "!!!": ` +
			`bad hostname label rune '!'`,
	}}

	const proto = agd.ProtoDoH

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			u := &url.URL{
				Scheme: "https",
				Host:   "dns.example.com",
				Path:   tc.path,
			}

			ctx := context.Background()
			ctx = dnsserver.ContextWithClientInfo(ctx, dnsserver.ClientInfo{
				URL: u,
			})

			deviceID, err := deviceIDFromContext(ctx, proto, nil)
			assert.Equal(t, tc.wantDeviceID, deviceID)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}

	t.Run("domain_name", func(t *testing.T) {
		u := &url.URL{
			Scheme: "https",
			Host:   dnssvctest.DeviceIDStr + ".dns.example.com",
			Path:   "/dns-query",
		}

		ctx := context.Background()
		ctx = dnsserver.ContextWithClientInfo(ctx, dnsserver.ClientInfo{
			URL:           u,
			TLSServerName: u.Host,
		})
		ctx = dnsserver.ContextWithServerInfo(ctx, dnsserver.ServerInfo{
			Proto: proto,
		})

		deviceID, err := deviceIDFromContext(ctx, proto, []string{"*.dns.example.com"})
		require.NoError(t, err)

		assert.Equal(t, agd.DeviceID(dnssvctest.DeviceID), deviceID)
	})
}

func TestDeviceIDFromEDNS(t *testing.T) {
	testCases := []struct {
		name         string
		opt          dns.EDNS0
		wantDeviceID agd.DeviceID
		wantErrMsg   string
	}{{
		name:         "no_device_id",
		wantDeviceID: "",
		wantErrMsg:   "",
	}, {
		name: "wrong_edns",
		opt: &dns.EDNS0_LOCAL{
			Code: dnsmasqCPEIDOption - 1,
			Data: []byte("devid"),
		},
		wantDeviceID: "",
		wantErrMsg:   "",
	}, {
		name: "no_device_id",
		opt: &dns.EDNS0_LOCAL{
			Code: dnsmasqCPEIDOption,
			Data: []byte{},
		},
		wantDeviceID: "",
		wantErrMsg: `edns option device id check: bad device id "": ` +
			`too short: got 0 bytes, min 1`,
	}, {
		name: "bad_device_id",
		opt: &dns.EDNS0_LOCAL{
			Code: dnsmasqCPEIDOption,
			Data: []byte("toolongdeviceid"),
		},
		wantDeviceID: "",
		wantErrMsg: `edns option device id check: bad device id "toolongdeviceid": ` +
			`too long: got 15 bytes, max 8`,
	}, {
		name: "device_id",
		opt: &dns.EDNS0_LOCAL{
			Code: dnsmasqCPEIDOption,
			Data: []byte("devid"),
		},
		wantDeviceID: "devid",
		wantErrMsg:   "",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			msg := dnsservertest.NewReq("example.com.", dns.TypeA, dns.ClassINET)
			if tc.opt != nil {
				msg.SetEdns0(dnsmsg.DefaultEDNSUDPSize, true)
				extra := &dns.OPT{
					Hdr:    dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT},
					Option: []dns.EDNS0{tc.opt},
				}
				msg.Extra = append(msg.Extra, extra)
			}

			deviceID, err := deviceIDFromEDNS(msg)
			assert.Equal(t, tc.wantDeviceID, deviceID)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}

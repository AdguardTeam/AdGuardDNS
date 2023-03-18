package dnssvc

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/stringutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

// testRAddr is the common remote address for tests.
var testRAddr = &net.TCPAddr{
	IP:   net.IP{1, 2, 3, 4},
	Port: 12345,
}

func TestInitMw_ServeDNS_ddr(t *testing.T) {
	const (
		resolverName = "dns.example.com"
		resolverFQDN = resolverName + "."

		deviceID     = "dev1234"
		targetWithID = deviceID + ".d." + resolverName + "."

		ddrFQDN = ddrDomain + "."

		dohPath = "/dns-query"
	)

	testDevice := &agd.Device{ID: deviceID}

	srvs := map[agd.ServerName]*agd.Server{
		"dot": {
			TLS: &tls.Config{},
			BindData: []*agd.ServerBindData{{
				AddrPort: netip.MustParseAddrPort("1.2.3.4:12345"),
			}},
			Protocol: agd.ProtoDoT,
		},
		"doh": {
			TLS: &tls.Config{},
			BindData: []*agd.ServerBindData{{
				AddrPort: netip.MustParseAddrPort("5.6.7.8:54321"),
			}},
			Protocol: agd.ProtoDoH,
		},
		"dns": {
			BindData: []*agd.ServerBindData{{
				AddrPort: netip.MustParseAddrPort("2.4.6.8:53"),
			}},
			Protocol:        agd.ProtoDNS,
			LinkedIPEnabled: true,
		},
		"dns_nolink": {
			BindData: []*agd.ServerBindData{{
				AddrPort: netip.MustParseAddrPort("2.4.6.8:53"),
			}},
			Protocol: agd.ProtoDNS,
		},
	}

	srvGrp := &agd.ServerGroup{
		TLS: &agd.TLS{
			DeviceIDWildcards: []string{"*.d." + resolverName},
		},
		DDR: &agd.DDR{
			DeviceTargets: stringutil.NewSet(),
			PublicTargets: stringutil.NewSet(),
			Enabled:       true,
		},
		Name:    agd.ServerGroupName("test_server_group"),
		Servers: maps.Values(srvs),
	}

	srvGrp.DDR.DeviceTargets.Add("d." + resolverName)
	srvGrp.DDR.PublicTargets.Add(resolverName)

	var dev *agd.Device
	mw := &initMw{
		messages: agdtest.NewConstructor(),
		fltGrp:   &agd.FilteringGroup{},
		srvGrp:   srvGrp,
		db: &agdtest.ProfileDB{
			OnProfileByDeviceID: func(
				_ context.Context,
				_ agd.DeviceID,
			) (p *agd.Profile, d *agd.Device, err error) {
				p = &agd.Profile{Devices: []*agd.Device{dev}}

				return p, dev, nil
			},
			OnProfileByIP: func(
				_ context.Context,
				_ netip.Addr,
			) (p *agd.Profile, d *agd.Device, err error) {
				p = &agd.Profile{Devices: []*agd.Device{dev}}

				return p, dev, nil
			},
		},
		geoIP: &agdtest.GeoIP{
			OnSubnetByLocation: func(
				_ agd.Country,
				_ agd.ASN,
				_ netutil.AddrFamily,
			) (_ netip.Prefix, _ error) {
				panic("not implemented")
			},
			OnData: func(_ string, _ netip.Addr) (l *agd.Location, err error) {
				return nil, nil
			},
		},
		errColl: &agdtest.ErrorCollector{
			OnCollect: func(_ context.Context, _ error) { panic("not implemented") },
		},
	}

	pubSVCBTmpls := []*dns.SVCB{
		mw.messages.NewDDRTemplate(agd.ProtoDoH, resolverName, dohPath, nil, nil, 443, 1),
		mw.messages.NewDDRTemplate(agd.ProtoDoT, resolverName, "", nil, nil, 853, 1),
		mw.messages.NewDDRTemplate(agd.ProtoDoQ, resolverName, "", nil, nil, 853, 1),
	}

	devSVCBTmpls := []*dns.SVCB{
		mw.messages.NewDDRTemplate(agd.ProtoDoH, "d."+resolverName, dohPath, nil, nil, 443, 1),
		mw.messages.NewDDRTemplate(agd.ProtoDoT, "d."+resolverName, "", nil, nil, 853, 1),
		mw.messages.NewDDRTemplate(agd.ProtoDoQ, "d."+resolverName, "", nil, nil, 853, 1),
	}

	srvGrp.DDR.PublicRecordTemplates = pubSVCBTmpls
	srvGrp.DDR.DeviceRecordTemplates = devSVCBTmpls

	var handler dnsserver.Handler = dnsserver.HandlerFunc(func(
		_ context.Context,
		_ dnsserver.ResponseWriter,
		_ *dns.Msg,
	) (_ error) {
		// Make sure we haven't reached the following middleware.
		panic("not implemented")
	})

	testCases := []struct {
		device     *agd.Device
		name       string
		srv        *agd.Server
		host       string
		wantTarget string
		wantNum    int
		qtype      uint16
	}{{
		device:     testDevice,
		name:       "id",
		srv:        srvs["dot"],
		host:       ddrFQDN,
		wantTarget: targetWithID,
		wantNum:    len(pubSVCBTmpls),
		qtype:      dns.TypeSVCB,
	}, {
		device:     testDevice,
		name:       "id_specific",
		srv:        srvs["dot"],
		host:       ddrLabel + "." + targetWithID,
		wantTarget: targetWithID,
		wantNum:    len(devSVCBTmpls),
		qtype:      dns.TypeSVCB,
	}, {
		device:     nil,
		name:       "no_id",
		srv:        srvs["dot"],
		host:       ddrFQDN,
		wantTarget: resolverFQDN,
		wantNum:    len(pubSVCBTmpls),
		qtype:      dns.TypeSVCB,
	}, {
		device:     testDevice,
		name:       "linked_ip",
		srv:        srvs["dns"],
		host:       ddrFQDN,
		wantTarget: targetWithID,
		wantNum:    len(pubSVCBTmpls),
		qtype:      dns.TypeSVCB,
	}, {
		device:     testDevice,
		name:       "no_linked_ip",
		srv:        srvs["dns_nolink"],
		host:       ddrFQDN,
		wantTarget: resolverFQDN,
		wantNum:    len(pubSVCBTmpls),
		qtype:      dns.TypeSVCB,
	}, {
		device:     testDevice,
		name:       "public_resolver_name",
		srv:        srvs["dot"],
		host:       ddrLabel + "." + resolverFQDN,
		wantTarget: targetWithID,
		wantNum:    len(pubSVCBTmpls),
		qtype:      dns.TypeSVCB,
	}, {
		device:     nil,
		name:       "arpa_not_ddr_svcb",
		srv:        srvs["dot"],
		host:       dns.Fqdn(ddrLabel + ".something.else." + resolverArpaDomain),
		wantTarget: "",
		wantNum:    0,
		qtype:      dns.TypeSVCB,
	}, {
		device:     nil,
		name:       "arpa_ddr_not_svcb",
		srv:        srvs["dot"],
		host:       ddrFQDN,
		wantTarget: "",
		wantNum:    0,
		qtype:      dns.TypeA,
	}}

	for _, tc := range testCases {
		mw.srv = tc.srv
		dev = tc.device

		var tlsServerName string
		switch mw.srv.Protocol {
		case agd.ProtoDoT, agd.ProtoDoQ:
			tlsServerName = resolverName
			if dev != nil {
				tlsServerName = string(dev.ID) + ".d." + tlsServerName
			}
		default:
			// Go on.
		}

		h := mw.Wrap(handler)

		req := &dns.Msg{
			Question: []dns.Question{{
				Name:   tc.host,
				Qtype:  tc.qtype,
				Qclass: dns.ClassINET,
			}},
		}

		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			ctx = dnsserver.ContextWithClientInfo(ctx, dnsserver.ClientInfo{
				TLSServerName: tlsServerName,
			})

			rw := dnsserver.NewNonWriterResponseWriter(nil, testRAddr)

			err := h.ServeDNS(ctx, rw, req)
			require.NoError(t, err)

			resp := rw.Msg()
			require.NotNil(t, resp)

			if tc.wantNum == 0 {
				assert.Empty(t, resp.Answer)

				return
			}

			assert.Len(t, resp.Answer, tc.wantNum)
			for _, rr := range resp.Answer {
				svcb := testutil.RequireTypeAssert[*dns.SVCB](t, rr)

				assert.Equal(t, tc.wantTarget, svcb.Target)
				assert.Equal(t, tc.host, svcb.Hdr.Name)
			}
		})
	}
}

func TestInitMw_ServeDNS_specialDomain(t *testing.T) {
	testCases := []struct {
		name          string
		host          string
		qtype         dnsmsg.RRType
		fltGrpBlocked bool
		hasProf       bool
		profBlocked   bool
		wantRCode     dnsmsg.RCode
	}{{
		name:          "private_relay_blocked_by_fltgrp",
		host:          applePrivateRelayMaskHost,
		qtype:         dns.TypeA,
		fltGrpBlocked: true,
		hasProf:       false,
		profBlocked:   false,
		wantRCode:     dns.RcodeNameError,
	}, {
		name:          "no_special_domain",
		host:          "www.example.com",
		qtype:         dns.TypeA,
		fltGrpBlocked: true,
		hasProf:       false,
		profBlocked:   false,
		wantRCode:     dns.RcodeSuccess,
	}, {
		name:          "no_private_relay_qtype",
		host:          applePrivateRelayMaskHost,
		qtype:         dns.TypeTXT,
		fltGrpBlocked: true,
		hasProf:       false,
		profBlocked:   false,
		wantRCode:     dns.RcodeSuccess,
	}, {
		name:          "private_relay_blocked_by_prof",
		host:          applePrivateRelayMaskHost,
		qtype:         dns.TypeA,
		fltGrpBlocked: false,
		hasProf:       true,
		profBlocked:   true,
		wantRCode:     dns.RcodeNameError,
	}, {
		name:          "private_relay_allowed_by_prof",
		host:          applePrivateRelayMaskHost,
		qtype:         dns.TypeA,
		fltGrpBlocked: true,
		hasProf:       true,
		profBlocked:   false,
		wantRCode:     dns.RcodeSuccess,
	}, {
		name:          "private_relay_allowed_by_both",
		host:          applePrivateRelayMaskHost,
		qtype:         dns.TypeA,
		fltGrpBlocked: false,
		hasProf:       true,
		profBlocked:   false,
		wantRCode:     dns.RcodeSuccess,
	}, {
		name:          "private_relay_blocked_by_both",
		host:          applePrivateRelayMaskHost,
		qtype:         dns.TypeA,
		fltGrpBlocked: true,
		hasProf:       true,
		profBlocked:   true,
		wantRCode:     dns.RcodeNameError,
	}, {
		name:          "firefox_canary_allowed_by_prof",
		host:          firefoxCanaryHost,
		qtype:         dns.TypeA,
		fltGrpBlocked: false,
		hasProf:       true,
		profBlocked:   false,
		wantRCode:     dns.RcodeSuccess,
	}, {
		name:          "firefox_canary_allowed_by_fltgrp",
		host:          firefoxCanaryHost,
		qtype:         dns.TypeA,
		fltGrpBlocked: false,
		hasProf:       false,
		profBlocked:   false,
		wantRCode:     dns.RcodeSuccess,
	}, {
		name:          "firefox_canary_blocked_by_prof",
		host:          firefoxCanaryHost,
		qtype:         dns.TypeA,
		fltGrpBlocked: false,
		hasProf:       true,
		profBlocked:   true,
		wantRCode:     dns.RcodeRefused,
	}, {
		name:          "firefox_canary_blocked_by_fltgrp",
		host:          firefoxCanaryHost,
		qtype:         dns.TypeA,
		fltGrpBlocked: true,
		hasProf:       false,
		profBlocked:   false,
		wantRCode:     dns.RcodeRefused,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var handler dnsserver.Handler = dnsserver.HandlerFunc(func(
				ctx context.Context,
				rw dnsserver.ResponseWriter,
				req *dns.Msg,
			) (err error) {
				if tc.wantRCode != dns.RcodeSuccess {
					return errors.Error("unexpectedly reached handler")
				}

				resp := (&dns.Msg{}).SetReply(req)

				return rw.WriteMsg(ctx, req, resp)
			})

			onProfileByIP := func(
				_ context.Context,
				_ netip.Addr,
			) (p *agd.Profile, d *agd.Device, err error) {
				if !tc.hasProf {
					return nil, nil, agd.DeviceNotFoundError{}
				}

				prof := &agd.Profile{
					BlockPrivateRelay:  tc.profBlocked,
					BlockFirefoxCanary: tc.profBlocked,
				}

				return prof, &agd.Device{}, nil
			}
			db := &agdtest.ProfileDB{
				OnProfileByDeviceID: func(
					_ context.Context,
					_ agd.DeviceID,
				) (p *agd.Profile, d *agd.Device, err error) {
					panic("not implemented")
				},
				OnProfileByIP: onProfileByIP,
			}

			geoIP := &agdtest.GeoIP{
				OnSubnetByLocation: func(
					_ agd.Country,
					_ agd.ASN,
					_ netutil.AddrFamily,
				) (n netip.Prefix, err error) {
					panic("not implemented")
				},
				OnData: func(_ string, _ netip.Addr) (l *agd.Location, err error) {
					return nil, nil
				},
			}

			errColl := &agdtest.ErrorCollector{
				OnCollect: func(_ context.Context, _ error) {
					panic("not implemented")
				},
			}

			mw := &initMw{
				messages: agdtest.NewConstructor(),
				fltGrp: &agd.FilteringGroup{
					BlockPrivateRelay:  tc.fltGrpBlocked,
					BlockFirefoxCanary: tc.fltGrpBlocked,
				},
				srvGrp: &agd.ServerGroup{},
				srv: &agd.Server{
					Protocol:        agd.ProtoDNS,
					LinkedIPEnabled: true,
				},
				db:      db,
				geoIP:   geoIP,
				errColl: errColl,
			}

			h := mw.Wrap(handler)

			ctx := context.Background()
			rw := dnsserver.NewNonWriterResponseWriter(nil, testRAddr)
			req := &dns.Msg{
				Question: []dns.Question{{
					Name:   dns.Fqdn(tc.host),
					Qtype:  tc.qtype,
					Qclass: dns.ClassINET,
				}},
			}

			err := h.ServeDNS(ctx, rw, req)
			require.NoError(t, err)

			resp := rw.Msg()
			require.NotNil(t, resp)

			assert.Equal(t, tc.wantRCode, dnsmsg.RCode(resp.Rcode))
		})
	}
}

var errSink error

func BenchmarkInitMw_Wrap(b *testing.B) {
	const devIDTarget = "dns.example.com"
	srvGrp := &agd.ServerGroup{
		TLS: &agd.TLS{
			DeviceIDWildcards: []string{"*." + devIDTarget},
		},
		DDR: &agd.DDR{
			DeviceTargets: stringutil.NewSet(),
			PublicTargets: stringutil.NewSet(),
			Enabled:       true,
		},
		Name: agd.ServerGroupName("test_server_group"),
		Servers: []*agd.Server{{
			BindData: []*agd.ServerBindData{{
				AddrPort: netip.MustParseAddrPort("1.2.3.4:12345"),
			}, {
				AddrPort: netip.MustParseAddrPort("4.3.2.1:12345"),
			}},
			Protocol: agd.ProtoDoT,
		}},
	}

	messages := agdtest.NewConstructor()

	ipv4Hints := []netip.Addr{srvGrp.Servers[0].BindData[0].AddrPort.Addr()}
	ipv6Hints := []netip.Addr{netip.MustParseAddr("2001::1234")}

	srvGrp.DDR.DeviceTargets.Add(devIDTarget)
	srvGrp.DDR.DeviceRecordTemplates = []*dns.SVCB{
		messages.NewDDRTemplate(agd.ProtoDoH, devIDTarget, "/dns", ipv4Hints, ipv6Hints, 443, 1),
		messages.NewDDRTemplate(agd.ProtoDoT, devIDTarget, "", ipv4Hints, ipv6Hints, 853, 1),
		messages.NewDDRTemplate(agd.ProtoDoQ, devIDTarget, "", ipv4Hints, ipv6Hints, 853, 1),
	}

	mw := &initMw{
		messages: messages,
		fltGrp:   &agd.FilteringGroup{},
		srvGrp:   srvGrp,
		srv:      srvGrp.Servers[0],
		geoIP: &agdtest.GeoIP{
			OnSubnetByLocation: func(
				_ agd.Country,
				_ agd.ASN,
				_ netutil.AddrFamily,
			) (n netip.Prefix, err error) {
				panic("not implemented")
			},
			OnData: func(_ string, _ netip.Addr) (l *agd.Location, err error) {
				return nil, nil
			},
		},
		errColl: &agdtest.ErrorCollector{
			OnCollect: func(_ context.Context, _ error) { panic("not implemented") },
		},
	}

	prof := &agd.Profile{}
	dev := &agd.Device{}

	ctx := context.Background()
	ctx = dnsserver.ContextWithClientInfo(ctx, dnsserver.ClientInfo{
		TLSServerName: "dev1234.dns.example.com",
	})

	req := &dns.Msg{
		Question: []dns.Question{{
			Name:   "example.net",
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}},
	}
	resp := new(dns.Msg).SetReply(req)

	var handler dnsserver.Handler = dnsserver.HandlerFunc(func(
		ctx context.Context,
		rw dnsserver.ResponseWriter,
		req *dns.Msg,
	) (err error) {
		return rw.WriteMsg(ctx, req, resp)
	})

	handler = mw.Wrap(handler)
	rw := dnsserver.NewNonWriterResponseWriter(nil, testRAddr)

	mw.db = &agdtest.ProfileDB{
		OnProfileByDeviceID: func(
			_ context.Context,
			_ agd.DeviceID,
		) (p *agd.Profile, d *agd.Device, err error) {
			return prof, dev, nil
		},
	}
	b.Run("success", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			errSink = handler.ServeDNS(ctx, rw, req)
		}

		assert.NoError(b, errSink)
	})

	mw.db = &agdtest.ProfileDB{
		OnProfileByDeviceID: func(
			_ context.Context,
			_ agd.DeviceID,
		) (p *agd.Profile, d *agd.Device, err error) {
			return nil, nil, agd.ProfileNotFoundError{}
		},
	}
	b.Run("not_found", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			errSink = handler.ServeDNS(ctx, rw, req)
		}

		assert.NoError(b, errSink)
	})

	ffReq := &dns.Msg{
		Question: []dns.Question{{
			Name:   "use-application-dns.net.",
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}},
	}
	mw.db = &agdtest.ProfileDB{
		OnProfileByDeviceID: func(
			_ context.Context,
			_ agd.DeviceID,
		) (p *agd.Profile, d *agd.Device, err error) {
			return prof, dev, nil
		},
	}
	b.Run("firefox_canary", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			errSink = handler.ServeDNS(ctx, rw, ffReq)
		}

		assert.NoError(b, errSink)
	})

	ddrReq := &dns.Msg{
		Question: []dns.Question{{
			// Check the worst case when wildcards are checked.
			Name:   "_dns.dev1234.dns.example.com.",
			Qtype:  dns.TypeSVCB,
			Qclass: dns.ClassINET,
		}},
	}
	devWithID := &agd.Device{
		ID: "dev1234",
	}
	mw.db = &agdtest.ProfileDB{
		OnProfileByDeviceID: func(
			_ context.Context,
			_ agd.DeviceID,
		) (p *agd.Profile, d *agd.Device, err error) {
			return prof, devWithID, nil
		},
	}
	b.Run("ddr", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			errSink = handler.ServeDNS(ctx, rw, ddrReq)
		}

		assert.NoError(b, errSink)
	})
}

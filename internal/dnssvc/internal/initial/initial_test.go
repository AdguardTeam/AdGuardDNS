package initial_test

import (
	"context"
	"crypto/tls"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/dnssvctest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/initial"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/stringutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

func TestMiddleware_Wrap(t *testing.T) {
	const (
		resolverName = "dns.example.com"
		resolverFQDN = resolverName + "."

		targetWithID = dnssvctest.DeviceIDStr + ".d." + resolverName + "."

		ddrFQDN = initial.DDRDomain + "."

		dohPath = "/dns-query"
	)

	testDevice := &agd.Device{ID: dnssvctest.DeviceID}

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

	geoIP := &agdtest.GeoIP{
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
	}

	messages := agdtest.NewConstructor()

	pubSVCBTmpls := []*dns.SVCB{
		messages.NewDDRTemplate(agd.ProtoDoH, resolverName, dohPath, nil, nil, 443, 1),
		messages.NewDDRTemplate(agd.ProtoDoT, resolverName, "", nil, nil, 853, 1),
		messages.NewDDRTemplate(agd.ProtoDoQ, resolverName, "", nil, nil, 853, 1),
	}

	devSVCBTmpls := []*dns.SVCB{
		messages.NewDDRTemplate(agd.ProtoDoH, "d."+resolverName, dohPath, nil, nil, 443, 1),
		messages.NewDDRTemplate(agd.ProtoDoT, "d."+resolverName, "", nil, nil, 853, 1),
		messages.NewDDRTemplate(agd.ProtoDoQ, "d."+resolverName, "", nil, nil, 853, 1),
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
		host:       initial.DDRLabel + "." + targetWithID,
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
		host:       initial.DDRLabel + "." + resolverFQDN,
		wantTarget: targetWithID,
		wantNum:    len(pubSVCBTmpls),
		qtype:      dns.TypeSVCB,
	}, {
		device: nil,
		name:   "arpa_not_ddr_svcb",
		srv:    srvs["dot"],
		host: dns.Fqdn(
			initial.DDRLabel + ".something.else." + initial.ResolverARPADomain,
		),
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
		t.Run(tc.name, func(t *testing.T) {
			db := &agdtest.ProfileDB{
				OnProfileByDeviceID: func(
					_ context.Context,
					_ agd.DeviceID,
				) (p *agd.Profile, d *agd.Device, err error) {
					return &agd.Profile{}, tc.device, nil
				},
				OnProfileByDedicatedIP: func(
					_ context.Context,
					_ netip.Addr,
				) (p *agd.Profile, d *agd.Device, err error) {
					return nil, nil, profiledb.ErrDeviceNotFound
				},
				OnProfileByLinkedIP: func(
					_ context.Context,
					_ netip.Addr,
				) (p *agd.Profile, d *agd.Device, err error) {
					return &agd.Profile{}, tc.device, nil
				},
			}

			mw := initial.New(&initial.Config{
				Messages:       agdtest.NewConstructor(),
				FilteringGroup: &agd.FilteringGroup{},
				ServerGroup:    srvGrp,
				Server:         tc.srv,
				ProfileDB:      db,
				GeoIP:          geoIP,
				ErrColl: &agdtest.ErrorCollector{
					OnCollect: func(_ context.Context, _ error) { panic("not implemented") },
				},
			})

			ctx := context.Background()
			ctx = dnsserver.ContextWithClientInfo(ctx, dnsserver.ClientInfo{
				TLSServerName: srvNameForProto(tc.device, resolverName, tc.srv.Protocol),
			})

			rw := dnsserver.NewNonWriterResponseWriter(nil, dnssvctest.RemoteAddr)
			req := &dns.Msg{
				Question: []dns.Question{{
					Name:   tc.host,
					Qtype:  tc.qtype,
					Qclass: dns.ClassINET,
				}},
			}

			h := mw.Wrap(handler)
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

// srvNameForProto returns a client's TLS server name based on the protocol and
// other data.
func srvNameForProto(dev *agd.Device, resolverName string, proto agd.Protocol) (srvName string) {
	switch proto {
	case agd.ProtoDoT, agd.ProtoDoQ:
		srvName = resolverName
		if dev != nil {
			srvName = string(dev.ID) + ".d." + srvName
		}
	default:
		// Go on.
	}

	return srvName
}

func TestMiddleware_Wrap_error(t *testing.T) {
	var handler dnsserver.Handler = dnsserver.HandlerFunc(func(
		_ context.Context,
		_ dnsserver.ResponseWriter,
		_ *dns.Msg,
	) (_ error) {
		// Make sure we haven't reached the following middleware.
		panic("not implemented")
	})

	srvGrp := &agd.ServerGroup{
		Name: agd.ServerGroupName("test_server_group"),
	}

	srv := &agd.Server{
		BindData: []*agd.ServerBindData{{
			AddrPort: netip.MustParseAddrPort("1.2.3.4:53"),
		}},
		Protocol:        agd.ProtoDNS,
		LinkedIPEnabled: true,
	}

	geoIP := &agdtest.GeoIP{
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
	}

	const testError errors.Error = errors.Error("test error")

	db := &agdtest.ProfileDB{
		OnProfileByDeviceID: func(
			_ context.Context,
			_ agd.DeviceID,
		) (p *agd.Profile, d *agd.Device, err error) {
			panic("not implemented")
		},
		OnProfileByDedicatedIP: func(
			_ context.Context,
			_ netip.Addr,
		) (p *agd.Profile, d *agd.Device, err error) {
			return nil, nil, testError
		},
		OnProfileByLinkedIP: func(
			_ context.Context,
			_ netip.Addr,
		) (p *agd.Profile, d *agd.Device, err error) {
			panic("not implemented")
		},
	}

	mw := initial.New(&initial.Config{
		Messages:       agdtest.NewConstructor(),
		FilteringGroup: &agd.FilteringGroup{},
		ServerGroup:    srvGrp,
		Server:         srv,
		ProfileDB:      db,
		GeoIP:          geoIP,
		ErrColl: &agdtest.ErrorCollector{
			OnCollect: func(_ context.Context, _ error) { panic("not implemented") },
		},
	})

	ctx := context.Background()
	rw := dnsserver.NewNonWriterResponseWriter(nil, dnssvctest.RemoteAddr)
	req := &dns.Msg{
		Question: []dns.Question{{
			Name:   "www.example.com.",
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}},
	}

	h := mw.Wrap(handler)
	err := h.ServeDNS(ctx, rw, req)
	assert.ErrorIs(t, err, testError)
}

var errSink error

func BenchmarkMiddleware_Wrap(b *testing.B) {
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

	ipv4Hints := []netip.Addr{srvGrp.Servers[0].BindData[0].AddrPort.Addr()}
	ipv6Hints := []netip.Addr{netip.MustParseAddr("2001::1234")}

	srvGrp.DDR.DeviceTargets.Add(devIDTarget)
	srvGrp.DDR.DeviceRecordTemplates = []*dns.SVCB{
		messages.NewDDRTemplate(agd.ProtoDoH, devIDTarget, "/dns", ipv4Hints, ipv6Hints, 443, 1),
		messages.NewDDRTemplate(agd.ProtoDoT, devIDTarget, "", ipv4Hints, ipv6Hints, 853, 1),
		messages.NewDDRTemplate(agd.ProtoDoQ, devIDTarget, "", ipv4Hints, ipv6Hints, 853, 1),
	}

	prof := &agd.Profile{}
	dev := &agd.Device{}

	ctx := context.Background()
	ctx = dnsserver.ContextWithClientInfo(ctx, dnsserver.ClientInfo{
		TLSServerName: dnssvctest.DeviceIDStr + ".dns.example.com",
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

	rw := dnsserver.NewNonWriterResponseWriter(nil, dnssvctest.RemoteAddr)

	b.Run("success", func(b *testing.B) {
		db := &agdtest.ProfileDB{
			OnProfileByDeviceID: func(
				_ context.Context,
				_ agd.DeviceID,
			) (p *agd.Profile, d *agd.Device, err error) {
				return prof, dev, nil
			},
			OnProfileByDedicatedIP: func(
				_ context.Context,
				_ netip.Addr,
			) (p *agd.Profile, d *agd.Device, err error) {
				panic("not implemented")
			},
			OnProfileByLinkedIP: func(
				_ context.Context,
				_ netip.Addr,
			) (p *agd.Profile, d *agd.Device, err error) {
				panic("not implemented")
			},
		}

		mw := initial.New(&initial.Config{
			Messages:       messages,
			FilteringGroup: &agd.FilteringGroup{},
			ServerGroup:    srvGrp,
			Server:         srvGrp.Servers[0],
			ProfileDB:      db,
			GeoIP:          geoIP,
			ErrColl: &agdtest.ErrorCollector{
				OnCollect: func(_ context.Context, _ error) { panic("not implemented") },
			},
		})

		h := mw.Wrap(handler)

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			errSink = h.ServeDNS(ctx, rw, req)
		}

		assert.NoError(b, errSink)
	})

	b.Run("not_found", func(b *testing.B) {
		db := &agdtest.ProfileDB{
			OnProfileByDeviceID: func(
				_ context.Context,
				_ agd.DeviceID,
			) (p *agd.Profile, d *agd.Device, err error) {
				return nil, nil, profiledb.ErrDeviceNotFound
			},
			OnProfileByDedicatedIP: func(
				_ context.Context,
				_ netip.Addr,
			) (p *agd.Profile, d *agd.Device, err error) {
				panic("not implemented")
			},
			OnProfileByLinkedIP: func(
				_ context.Context,
				_ netip.Addr,
			) (p *agd.Profile, d *agd.Device, err error) {
				panic("not implemented")
			},
		}

		mw := initial.New(&initial.Config{
			Messages:       messages,
			FilteringGroup: &agd.FilteringGroup{},
			ServerGroup:    srvGrp,
			Server:         srvGrp.Servers[0],
			ProfileDB:      db,
			GeoIP:          geoIP,
			ErrColl: &agdtest.ErrorCollector{
				OnCollect: func(_ context.Context, _ error) { panic("not implemented") },
			},
		})

		h := mw.Wrap(handler)

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			errSink = h.ServeDNS(ctx, rw, req)
		}

		assert.NoError(b, errSink)
	})

	b.Run("firefox_canary", func(b *testing.B) {
		db := &agdtest.ProfileDB{
			OnProfileByDeviceID: func(
				_ context.Context,
				_ agd.DeviceID,
			) (p *agd.Profile, d *agd.Device, err error) {
				return prof, dev, nil
			},
			OnProfileByDedicatedIP: func(
				_ context.Context,
				_ netip.Addr,
			) (p *agd.Profile, d *agd.Device, err error) {
				panic("not implemented")
			},
			OnProfileByLinkedIP: func(
				_ context.Context,
				_ netip.Addr,
			) (p *agd.Profile, d *agd.Device, err error) {
				panic("not implemented")
			},
		}

		ffReq := &dns.Msg{
			Question: []dns.Question{{
				Name:   "use-application-dns.net.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}},
		}

		mw := initial.New(&initial.Config{
			Messages:       messages,
			FilteringGroup: &agd.FilteringGroup{},
			ServerGroup:    srvGrp,
			Server:         srvGrp.Servers[0],
			ProfileDB:      db,
			GeoIP:          geoIP,
			ErrColl: &agdtest.ErrorCollector{
				OnCollect: func(_ context.Context, _ error) { panic("not implemented") },
			},
		})

		h := mw.Wrap(handler)

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			errSink = h.ServeDNS(ctx, rw, ffReq)
		}

		assert.NoError(b, errSink)
	})

	b.Run("ddr", func(b *testing.B) {
		devWithID := &agd.Device{
			ID: dnssvctest.DeviceID,
		}

		db := &agdtest.ProfileDB{
			OnProfileByDeviceID: func(
				_ context.Context,
				_ agd.DeviceID,
			) (p *agd.Profile, d *agd.Device, err error) {
				return prof, devWithID, nil
			},
			OnProfileByDedicatedIP: func(
				_ context.Context,
				_ netip.Addr,
			) (p *agd.Profile, d *agd.Device, err error) {
				panic("not implemented")
			},
			OnProfileByLinkedIP: func(
				_ context.Context,
				_ netip.Addr,
			) (p *agd.Profile, d *agd.Device, err error) {
				panic("not implemented")
			},
		}

		ddrReq := &dns.Msg{
			Question: []dns.Question{{
				// Check the worst case when wildcards are checked.
				Name:   "_dns." + dnssvctest.DeviceIDStr + ".dns.example.com.",
				Qtype:  dns.TypeSVCB,
				Qclass: dns.ClassINET,
			}},
		}

		mw := initial.New(&initial.Config{
			Messages:       messages,
			FilteringGroup: &agd.FilteringGroup{},
			ServerGroup:    srvGrp,
			Server:         srvGrp.Servers[0],
			ProfileDB:      db,
			GeoIP:          geoIP,
			ErrColl: &agdtest.ErrorCollector{
				OnCollect: func(_ context.Context, _ error) { panic("not implemented") },
			},
		})

		h := mw.Wrap(handler)

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			errSink = h.ServeDNS(ctx, rw, ddrReq)
		}

		assert.NoError(b, errSink)
	})

	// Most recent result, on a ThinkPad X13 with a Ryzen Pro 7 CPU:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/initial
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkMiddleware_Wrap/success-16         	 1970464	       735.8 ns/op	      72 B/op	       2 allocs/op
	//	BenchmarkMiddleware_Wrap/not_found-16       	 1469100	       715.9 ns/op	      48 B/op	       1 allocs/op
	//	BenchmarkMiddleware_Wrap/firefox_canary-16  	 1644410	       861.9 ns/op	      72 B/op	       2 allocs/op
	//	BenchmarkMiddleware_Wrap/ddr-16             	  252656	      4810 ns/op	    1408 B/op	      45 allocs/op
}

package initial_test

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdpasswd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/dnssvctest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/initial"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
)

func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

const (
	resolverName = "dns.example.com"
	resolverFQDN = resolverName + "."

	targetWithID = dnssvctest.DeviceIDStr + ".d." + resolverName + "."

	ddrFQDN = initial.DDRDomain + "."

	dohPath = "/dns-query"
)

func TestMiddleware_Wrap(t *testing.T) {
	testDevice := &agd.Device{
		Auth: &agd.AuthSettings{
			Enabled:      false,
			PasswordHash: agdpasswd.AllowAuthenticator{},
		},
		ID: dnssvctest.DeviceID,
	}

	geoIP := &agdtest.GeoIP{
		OnSubnetByLocation: func(
			_ *geoip.Location,
			_ netutil.AddrFamily,
		) (_ netip.Prefix, _ error) {
			panic("not implemented")
		},
		OnData: func(_ string, _ netip.Addr) (l *geoip.Location, err error) {
			return nil, nil
		},
	}

	srvs := newServers()
	// TODO(a.garipov): Use stdlib's maps in Go 1.23 or later.
	srvGrp := newServerGroup(maps.Values(srvs))

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
		wantNum:    len(srvGrp.DDR.PublicRecordTemplates),
		qtype:      dns.TypeSVCB,
	}, {
		device:     testDevice,
		name:       "id_specific",
		srv:        srvs["dot"],
		host:       initial.DDRLabel + "." + targetWithID,
		wantTarget: targetWithID,
		wantNum:    len(srvGrp.DDR.DeviceRecordTemplates),
		qtype:      dns.TypeSVCB,
	}, {
		device:     nil,
		name:       "no_id",
		srv:        srvs["dot"],
		host:       ddrFQDN,
		wantTarget: resolverFQDN,
		wantNum:    len(srvGrp.DDR.PublicRecordTemplates),
		qtype:      dns.TypeSVCB,
	}, {
		device:     testDevice,
		name:       "public_resolver_name",
		srv:        srvs["dot"],
		host:       initial.DDRLabel + "." + resolverFQDN,
		wantTarget: targetWithID,
		wantNum:    len(srvGrp.DDR.PublicRecordTemplates),
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

	prof := &agd.Profile{
		Access: access.EmptyProfile{},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ds := &dnssvctest.DeviceSetter{
				OnSetDevice: func(
					_ context.Context,
					_ *dns.Msg,
					ri *agd.RequestInfo,
					_ netip.AddrPort,
				) (err error) {
					ri.Device = tc.device
					ri.Profile = prof

					return nil
				},
			}

			mw := initial.New(&initial.Config{
				Messages:       agdtest.NewConstructor(),
				FilteringGroup: &agd.FilteringGroup{},
				ServerGroup:    srvGrp,
				Server:         tc.srv,
				DeviceSetter:   ds,
				GeoIP:          geoIP,
				ErrColl: &agdtest.ErrorCollector{
					OnCollect: func(_ context.Context, _ error) { panic("not implemented") },
				},
			})

			ctx := dnsserver.ContextWithRequestInfo(context.Background(), &dnsserver.RequestInfo{
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
			for i, rr := range resp.Answer {
				svcb := testutil.RequireTypeAssert[*dns.SVCB](t, rr)

				assert.Equalf(t, tc.wantTarget, svcb.Target, "rr at index %d", i)
				assert.Equalf(t, tc.host, svcb.Hdr.Name, "rr at index %d", i)
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

	srv := dnssvctest.NewServer("dns", agd.ProtoDNS, &agd.ServerBindData{
		AddrPort: netip.MustParseAddrPort("1.2.3.4:53"),
	})
	srv.LinkedIPEnabled = true

	geoIP := &agdtest.GeoIP{
		OnSubnetByLocation: func(
			_ *geoip.Location,
			_ netutil.AddrFamily,
		) (_ netip.Prefix, _ error) {
			panic("not implemented")
		},
		OnData: func(_ string, _ netip.Addr) (l *geoip.Location, err error) {
			return nil, nil
		},
	}

	const testError errors.Error = errors.Error("test error")

	ds := &dnssvctest.DeviceSetter{
		OnSetDevice: func(
			_ context.Context,
			_ *dns.Msg,
			ri *agd.RequestInfo,
			_ netip.AddrPort,
		) (err error) {
			return testError
		},
	}

	mw := initial.New(&initial.Config{
		Messages:       agdtest.NewConstructor(),
		FilteringGroup: &agd.FilteringGroup{},
		ServerGroup:    srvGrp,
		Server:         srv,
		DeviceSetter:   ds,
		GeoIP:          geoIP,
		ErrColl: &agdtest.ErrorCollector{
			OnCollect: func(_ context.Context, _ error) { panic("not implemented") },
		},
	})

	ctx := context.Background()
	ctx = dnsserver.ContextWithRequestInfo(ctx, &dnsserver.RequestInfo{})

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

func TestMiddleware_Wrap_access(t *testing.T) {
	const passHost = "pass.test"

	passIP := net.IP{3, 3, 3, 3}

	srvs := newServers()
	// TODO(a.garipov): Use stdlib's maps in Go 1.23 or later.
	srvGrp := newServerGroup(maps.Values(srvs))

	testDevice := &agd.Device{
		Auth: &agd.AuthSettings{
			Enabled:      false,
			PasswordHash: agdpasswd.AllowAuthenticator{},
		},
		ID: dnssvctest.DeviceID,
	}
	testProfile := &agd.Profile{
		Access: access.NewDefaultProfile(&access.ProfileConfig{
			AllowedNets: []netip.Prefix{netip.MustParsePrefix("1.1.1.1/32")},
			BlockedNets: []netip.Prefix{netip.MustParsePrefix("1.1.1.0/24")},
			AllowedASN:  []geoip.ASN{1},
			BlockedASN:  []geoip.ASN{1, 2},
			BlocklistDomainRules: []string{
				"block.test",
				"UPPERCASE.test",
				"||block_aaaa.test^$dnstype=AAAA",
				"||allowlist.test^",
				"@@||allow.allowlist.test^",
			},
		}),
	}

	ds := &dnssvctest.DeviceSetter{
		OnSetDevice: func(
			_ context.Context,
			_ *dns.Msg,
			ri *agd.RequestInfo,
			_ netip.AddrPort,
		) (err error) {
			ri.Device = testDevice
			ri.Profile = testProfile

			return nil
		},
	}

	var handler dnsserver.Handler = dnsserver.HandlerFunc(func(
		ctx context.Context,
		rw dnsserver.ResponseWriter,
		q *dns.Msg,
	) (_ error) {
		resp := dnsservertest.NewResp(
			dns.RcodeSuccess,
			q,
			dnsservertest.SectionAnswer{
				dnsservertest.NewA("test.domain", 0, netip.MustParseAddr("5.5.5.5")),
			},
		)

		err := rw.WriteMsg(ctx, q, resp)
		if err != nil {
			return err
		}

		return nil
	})

	testCases := []struct {
		loc      *geoip.Location
		wantResp assert.BoolAssertionFunc
		name     string
		host     string
		ip       net.IP
		qt       uint16
	}{{
		wantResp: assert.True,
		name:     "pass",
		host:     passHost,
		qt:       dns.TypeA,
		ip:       passIP,
		loc:      nil,
	}, {
		wantResp: assert.False,
		name:     "blocked_domain_A",
		host:     "block.test",
		qt:       dns.TypeA,
		ip:       passIP,
		loc:      nil,
	}, {
		wantResp: assert.False,
		name:     "blocked_domain_HTTPS",
		host:     "block.test",
		qt:       dns.TypeHTTPS,
		ip:       passIP,
		loc:      nil,
	}, {
		wantResp: assert.False,
		name:     "uppercase_domain",
		host:     "uppercase.test",
		qt:       dns.TypeHTTPS,
		ip:       passIP,
		loc:      nil,
	}, {
		wantResp: assert.True,
		name:     "pass_qt",
		host:     "block_aaaa.test",
		qt:       dns.TypeA,
		ip:       passIP,
		loc:      nil,
	}, {
		wantResp: assert.False,
		name:     "block_qt",
		host:     "block_aaaa.test",
		qt:       dns.TypeAAAA,
		ip:       passIP,
		loc:      nil,
	}, {
		wantResp: assert.False,
		name:     "allowlist_block",
		host:     "block.allowlist.test",
		qt:       dns.TypeA,
		ip:       passIP,
		loc:      nil,
	}, {
		wantResp: assert.True,
		name:     "allowlist_test",
		host:     "allow.allowlist.test",
		qt:       dns.TypeA,
		ip:       passIP,
		loc:      nil,
	}, {
		wantResp: assert.True,
		name:     "pass_ip",
		ip:       net.IP{1, 1, 1, 1},
		host:     passHost,
		qt:       dns.TypeA,
		loc:      nil,
	}, {
		wantResp: assert.False,
		name:     "block_subnet",
		ip:       net.IP{1, 1, 1, 2},
		host:     passHost,
		qt:       dns.TypeA,
		loc:      nil,
	}, {
		wantResp: assert.True,
		name:     "pass_subnet",
		ip:       net.IP{1, 2, 2, 2},
		host:     passHost,
		qt:       dns.TypeA,
		loc:      nil,
	}, {
		wantResp: assert.True,
		name:     "pass_asn",
		ip:       passIP,
		host:     "pass.test",
		qt:       dns.TypeA,
		loc:      &geoip.Location{ASN: 1},
	}, {
		wantResp: assert.False,
		name:     "block_host_pass_asn",
		ip:       passIP,
		host:     "block.test",
		qt:       dns.TypeA,
		loc:      &geoip.Location{ASN: 1},
	}, {
		wantResp: assert.False,
		name:     "block_asn",
		ip:       passIP,
		host:     passHost,
		qt:       dns.TypeA,
		loc:      &geoip.Location{ASN: 2},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			geoIP := &agdtest.GeoIP{
				OnSubnetByLocation: func(
					_ *geoip.Location,
					_ netutil.AddrFamily,
				) (_ netip.Prefix, _ error) {
					panic("not implemented")
				},
				OnData: func(_ string, _ netip.Addr) (l *geoip.Location, err error) {
					return tc.loc, nil
				},
			}

			mw := initial.New(&initial.Config{
				Messages:       agdtest.NewConstructor(),
				FilteringGroup: &agd.FilteringGroup{},
				ServerGroup:    srvGrp,
				Server:         srvs["dot"],
				DeviceSetter:   ds,
				GeoIP:          geoIP,
				ErrColl: &agdtest.ErrorCollector{
					OnCollect: func(_ context.Context, _ error) { panic("not implemented") },
				},
			})

			ctx := context.Background()
			ctx = dnsserver.ContextWithRequestInfo(ctx, &dnsserver.RequestInfo{
				TLSServerName: srvNameForProto(testDevice, resolverName, srvs["dot"].Protocol),
			})

			rw := dnsserver.NewNonWriterResponseWriter(nil, &net.TCPAddr{IP: tc.ip, Port: 5357})
			req := &dns.Msg{
				Question: []dns.Question{{
					Name:   tc.host,
					Qtype:  tc.qt,
					Qclass: dns.ClassINET,
				}},
			}

			h := mw.Wrap(handler)
			err := h.ServeDNS(ctx, rw, req)
			require.NoError(t, err)

			resp := rw.Msg()
			tc.wantResp(t, resp != nil)
		})
	}
}

func newServers() (srvs map[agd.ServerName]*agd.Server) {
	linkIPSrv := dnssvctest.NewServer("dns", agd.ProtoDNS, &agd.ServerBindData{
		AddrPort: netip.MustParseAddrPort("2.4.6.8:53"),
	})
	linkIPSrv.LinkedIPEnabled = true

	return map[agd.ServerName]*agd.Server{
		"dns": linkIPSrv,
		"dns_nolink": dnssvctest.NewServer("dns_nolink", agd.ProtoDNS, &agd.ServerBindData{
			AddrPort: netip.MustParseAddrPort("2.4.6.8:53"),
		}),
		"dot": dnssvctest.NewServer("dot", agd.ProtoDoT, &agd.ServerBindData{
			AddrPort: netip.MustParseAddrPort("1.2.3.4:12345"),
		}),
		"doh": dnssvctest.NewServer("doh", agd.ProtoDoH, &agd.ServerBindData{
			AddrPort: netip.MustParseAddrPort("1.2.3.4:54321"),
		}),
	}
}

func newServerGroup(srvs []*agd.Server) (srvGrp *agd.ServerGroup) {
	srvGrp = &agd.ServerGroup{
		DDR: &agd.DDR{
			DeviceTargets: container.NewMapSet[string](),
			PublicTargets: container.NewMapSet[string](),
			Enabled:       true,
		},
		TLS: &agd.TLS{
			DeviceIDWildcards: []string{"*.d." + resolverName},
		},
		Name:    "test_server_group",
		Servers: srvs,
	}

	srvGrp.DDR.DeviceTargets.Add("d." + resolverName)
	srvGrp.DDR.PublicTargets.Add(resolverName)

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

	return srvGrp
}

var errSink error

func BenchmarkMiddleware_Wrap(b *testing.B) {
	const devIDTarget = "dns.example.com"
	srvGrp := &agd.ServerGroup{
		DDR: &agd.DDR{
			DeviceTargets: container.NewMapSet[string](),
			PublicTargets: container.NewMapSet[string](),
			Enabled:       true,
		},
		TLS: &agd.TLS{
			DeviceIDWildcards: []string{"*." + devIDTarget},
		},
		Name: agd.ServerGroupName("test_server_group"),
		Servers: []*agd.Server{
			dnssvctest.NewServer("test_server_dot", agd.ProtoDoT, &agd.ServerBindData{
				AddrPort: netip.MustParseAddrPort("1.2.3.4:12345"),
			}, &agd.ServerBindData{
				AddrPort: netip.MustParseAddrPort("4.3.2.1:12345"),
			}),
		},
	}

	messages := agdtest.NewConstructor()

	geoIP := &agdtest.GeoIP{
		OnSubnetByLocation: func(
			_ *geoip.Location,
			_ netutil.AddrFamily,
		) (_ netip.Prefix, _ error) {
			panic("not implemented")
		},
		OnData: func(_ string, _ netip.Addr) (l *geoip.Location, err error) {
			return nil, nil
		},
	}

	ipv4Hints := []netip.Addr{srvGrp.Servers[0].BindData()[0].AddrPort.Addr()}
	ipv6Hints := []netip.Addr{netip.MustParseAddr("2001::1234")}

	srvGrp.DDR.DeviceTargets.Add(devIDTarget)
	srvGrp.DDR.DeviceRecordTemplates = []*dns.SVCB{
		messages.NewDDRTemplate(agd.ProtoDoH, devIDTarget, "/dns", ipv4Hints, ipv6Hints, 443, 1),
		messages.NewDDRTemplate(agd.ProtoDoT, devIDTarget, "", ipv4Hints, ipv6Hints, 853, 1),
		messages.NewDDRTemplate(agd.ProtoDoQ, devIDTarget, "", ipv4Hints, ipv6Hints, 853, 1),
	}

	prof := &agd.Profile{
		Access: access.EmptyProfile{},
	}
	dev := &agd.Device{
		Auth: &agd.AuthSettings{
			Enabled:      false,
			PasswordHash: agdpasswd.AllowAuthenticator{},
		},
	}

	ctx := context.Background()
	ctx = dnsserver.ContextWithRequestInfo(ctx, &dnsserver.RequestInfo{
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
		ds := &dnssvctest.DeviceSetter{
			OnSetDevice: func(
				_ context.Context,
				_ *dns.Msg,
				ri *agd.RequestInfo,
				_ netip.AddrPort,
			) (err error) {
				ri.Device = dev
				ri.Profile = prof

				return nil
			},
		}

		mw := initial.New(&initial.Config{
			Messages:       messages,
			FilteringGroup: &agd.FilteringGroup{},
			ServerGroup:    srvGrp,
			Server:         srvGrp.Servers[0],
			DeviceSetter:   ds,
			GeoIP:          geoIP,
			ErrColl: &agdtest.ErrorCollector{
				OnCollect: func(_ context.Context, _ error) { panic("not implemented") },
			},
		})

		h := mw.Wrap(handler)

		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			errSink = h.ServeDNS(ctx, rw, req)
		}

		assert.NoError(b, errSink)
	})

	b.Run("not_found", func(b *testing.B) {
		ds := &dnssvctest.DeviceSetter{
			OnSetDevice: func(
				_ context.Context,
				_ *dns.Msg,
				ri *agd.RequestInfo,
				_ netip.AddrPort,
			) (err error) {
				return nil
			},
		}

		mw := initial.New(&initial.Config{
			Messages:       messages,
			FilteringGroup: &agd.FilteringGroup{},
			ServerGroup:    srvGrp,
			Server:         srvGrp.Servers[0],
			DeviceSetter:   ds,
			GeoIP:          geoIP,
			ErrColl: &agdtest.ErrorCollector{
				OnCollect: func(_ context.Context, _ error) { panic("not implemented") },
			},
		})

		h := mw.Wrap(handler)

		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			errSink = h.ServeDNS(ctx, rw, req)
		}

		assert.NoError(b, errSink)
	})

	b.Run("firefox_canary", func(b *testing.B) {
		ds := &dnssvctest.DeviceSetter{
			OnSetDevice: func(
				_ context.Context,
				_ *dns.Msg,
				ri *agd.RequestInfo,
				_ netip.AddrPort,
			) (err error) {
				ri.Device = dev
				ri.Profile = prof

				return nil
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
			DeviceSetter:   ds,
			GeoIP:          geoIP,
			ErrColl: &agdtest.ErrorCollector{
				OnCollect: func(_ context.Context, _ error) { panic("not implemented") },
			},
		})

		h := mw.Wrap(handler)

		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			errSink = h.ServeDNS(ctx, rw, ffReq)
		}

		assert.NoError(b, errSink)
	})

	b.Run("ddr", func(b *testing.B) {
		devWithID := &agd.Device{
			Auth: &agd.AuthSettings{
				Enabled:      false,
				PasswordHash: agdpasswd.AllowAuthenticator{},
			},
			ID: dnssvctest.DeviceID,
		}

		ds := &dnssvctest.DeviceSetter{
			OnSetDevice: func(
				_ context.Context,
				_ *dns.Msg,
				ri *agd.RequestInfo,
				_ netip.AddrPort,
			) (err error) {
				ri.Device = devWithID
				ri.Profile = prof

				return nil
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
			DeviceSetter:   ds,
			GeoIP:          geoIP,
			ErrColl: &agdtest.ErrorCollector{
				OnCollect: func(_ context.Context, _ error) { panic("not implemented") },
			},
		})

		h := mw.Wrap(handler)

		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			errSink = h.ServeDNS(ctx, rw, ddrReq)
		}

		assert.NoError(b, errSink)
	})

	// Most recent result, on a ThinkPad X13 with a Ryzen Pro 7 CPU:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/initial
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkMiddleware_Wrap/success-16         	 2837168	       489.8 ns/op	      48 B/op	       1 allocs/op
	//	BenchmarkMiddleware_Wrap/not_found-16       	 2583918	       420.7 ns/op	      48 B/op	       1 allocs/op
	//	BenchmarkMiddleware_Wrap/firefox_canary-16  	 2658222	       505.1 ns/op	      48 B/op	       1 allocs/op
	//	BenchmarkMiddleware_Wrap/ddr-16             	  302330	      4949 ns/op	    1384 B/op	      44 allocs/op
}

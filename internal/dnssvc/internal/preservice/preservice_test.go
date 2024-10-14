package preservice_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/dnssvctest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/preservice"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/hashprefix"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

func TestPreServiceMwHandler_ServeDNS(t *testing.T) {
	const safeBrowsingHost = "scam.example.net."

	var (
		ip      = netutil.IPv4Localhost()
		name    = "example.com"
		badHash = "bad.hash"
	)

	sum := sha256.Sum256([]byte(safeBrowsingHost))
	hashStr := hex.EncodeToString(sum[:])
	host := hashStr[:hashprefix.PrefixEncLen] + filter.GeneralTXTSuffix

	// Set the context necessary for [dnsservertest.DefaultHandler].
	ctx := context.Background()
	ctx = dnsserver.ContextWithRequestInfo(ctx, &dnsserver.RequestInfo{
		StartTime: time.Now(),
	})
	ctx = dnsserver.ContextWithServerInfo(ctx, &dnsserver.ServerInfo{})

	const ttl = 60

	cloner := agdtest.NewCloner()

	testCases := []struct {
		name         string
		req          *dns.Msg
		dnscheckResp *dns.Msg
		ri           *agd.RequestInfo
		hashes       []string
		wantAns      []dns.RR
		wantRCode    dnsmsg.RCode
	}{{
		name:         "normal",
		req:          dnsservertest.CreateMessage(name, dns.TypeA),
		dnscheckResp: nil,
		ri:           &agd.RequestInfo{},
		hashes:       nil,
		wantAns: []dns.RR{
			dnsservertest.NewA(name, 100, ip),
		},
		wantRCode: dns.RcodeSuccess,
	}, {
		name: "dnscheck",
		req:  dnsservertest.CreateMessage(name, dns.TypeA),
		dnscheckResp: dnsservertest.NewResp(
			dns.RcodeSuccess,
			dnsservertest.NewReq(name, dns.TypeA, dns.ClassINET),
			dnsservertest.SectionAnswer{dnsservertest.NewA(name, ttl, ip)},
		),
		ri: &agd.RequestInfo{
			Host:   name,
			QType:  dns.TypeA,
			QClass: dns.ClassINET,
		},
		hashes: nil,
		wantAns: []dns.RR{
			dnsservertest.NewA(name, ttl, ip),
		},
		wantRCode: dns.RcodeSuccess,
	}, {
		name:         "with_hashes",
		req:          dnsservertest.CreateMessage(safeBrowsingHost, dns.TypeTXT),
		dnscheckResp: nil,
		ri:           &agd.RequestInfo{Host: host, QType: dns.TypeTXT},
		hashes:       []string{hashStr},
		wantAns: []dns.RR{&dns.TXT{
			Hdr: dns.RR_Header{
				Name:   safeBrowsingHost,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			Txt: []string{hashStr},
		}},
		wantRCode: dns.RcodeSuccess,
	}, {
		name:         "not_matched",
		req:          dnsservertest.CreateMessage(name, dns.TypeTXT),
		dnscheckResp: nil,
		ri:           &agd.RequestInfo{Host: name, QType: dns.TypeTXT},
		hashes:       nil,
		wantAns:      []dns.RR{dnsservertest.NewA(name, 100, ip)},
		wantRCode:    dns.RcodeSuccess,
	}, {
		name:         "bad_hash",
		req:          dnsservertest.CreateMessage(name, dns.TypeTXT),
		dnscheckResp: nil,
		ri:           &agd.RequestInfo{Host: badHash, QType: dns.TypeTXT},
		hashes:       nil,
		wantAns:      nil,
		wantRCode:    dns.RcodeRefused,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rw := dnsserver.NewNonWriterResponseWriter(nil, dnssvctest.ClientTCPAddr)
			tctx := agd.ContextWithRequestInfo(ctx, tc.ri)

			dnsCk := &agdtest.DNSCheck{
				OnCheck: func(
					_ context.Context,
					_ *dns.Msg,
					_ *agd.RequestInfo,
				) (resp *dns.Msg, err error) {
					return tc.dnscheckResp, nil
				},
			}

			hashMatcher := &agdtest.HashMatcher{
				OnMatchByPrefix: func(
					_ context.Context,
					host string,
				) (hashes []string, matched bool, err error) {
					if host == badHash {
						return nil, false, errors.Error("bad hash")
					}

					return tc.hashes, len(tc.hashes) > 0, nil
				},
			}
			msgs, err := dnsmsg.NewConstructor(&dnsmsg.ConstructorConfig{
				Cloner:              cloner,
				BlockingMode:        &dnsmsg.BlockingModeNullIP{},
				FilteredResponseTTL: ttl * time.Second,
			})
			require.NoError(t, err)

			mw := preservice.New(&preservice.Config{
				Messages:    msgs,
				HashMatcher: hashMatcher,
				Checker:     dnsCk,
			})
			handler := dnsservertest.DefaultHandler()
			h := mw.Wrap(handler)

			err = h.ServeDNS(tctx, rw, tc.req)
			require.NoError(t, err)

			msg := rw.Msg()
			require.NotNil(t, msg)

			assert.Equal(t, tc.wantAns, msg.Answer)
			assert.Equal(t, tc.wantRCode, dnsmsg.RCode(msg.Rcode))
		})
	}
}

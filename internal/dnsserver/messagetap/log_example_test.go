package messagetap_test

import (
	"context"
	"log/slog"
	"net/netip"
	"os"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/messagetap"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
)

func ExampleLog() {
	logger := slogutil.New(&slogutil.Config{
		Output: os.Stdout,
		Format: slogutil.FormatDefault,
		Level:  slogutil.LevelInfo,
	})

	l := messagetap.NewLog(&messagetap.LogConfig{
		Logger:   logger,
		LogLevel: slog.LevelInfo,
	})

	ctx := context.Background()
	laddr := netip.MustParseAddrPort("127.0.0.1:49152")
	raddr := netip.MustParseAddrPort("192.0.2.1:53")

	req := dnsservertest.NewReq(dnsservertest.FQDN, dns.TypeA, dns.ClassINET)
	req.Id = 0
	reqBytes, _ := req.Pack()

	resp := dnsservertest.NewResp(dns.RcodeSuccess, req)
	respBytes, _ := resp.Pack()

	l.TapRequest(ctx, testDate, laddr, raddr, reqBytes)
	l.TapResponse(ctx, testDate, laddr, raddr, respBytes)

	var badData []byte
	l.TapRequest(ctx, testDate, laddr, raddr, badData)
	l.TapResponse(ctx, testDate, laddr, raddr, badData)

	// Output:
	// INFO received dns request laddr=127.0.0.1:49152 raddr=192.0.2.1:53 request_time=2026-01-01T12:00:00.000Z
	// INFO req line_num=1 line=";; opcode: QUERY, status: NOERROR, id: 0"
	// INFO req line_num=2 line=";; flags:; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0"
	// INFO req line_num=3 line=""
	// INFO req line_num=4 line=";; QUESTION SECTION:"
	// INFO req line_num=5 line=";test.example.\tIN\t A"
	// INFO req line_num=6 line=""
	// INFO received dns response laddr=127.0.0.1:49152 raddr=192.0.2.1:53 response_time=2026-01-01T12:00:00.000Z
	// INFO resp line_num=1 line=";; opcode: QUERY, status: NOERROR, id: 0"
	// INFO resp line_num=2 line=";; flags: qr ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0"
	// INFO resp line_num=3 line=""
	// INFO resp line_num=4 line=";; QUESTION SECTION:"
	// INFO resp line_num=5 line=";test.example.\tIN\t A"
	// INFO resp line_num=6 line=""
	// INFO received dns request laddr=127.0.0.1:49152 raddr=192.0.2.1:53 request_time=2026-01-01T12:00:00.000Z
	// ERROR failed to unpack message err="bad header id: dns: overflow unpacking uint16"
	// INFO received dns response laddr=127.0.0.1:49152 raddr=192.0.2.1:53 response_time=2026-01-01T12:00:00.000Z
	// ERROR failed to unpack message err="bad header id: dns: overflow unpacking uint16"
}

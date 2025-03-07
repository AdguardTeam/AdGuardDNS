package querylog_test

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/querylog"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestLogMiddleware_Wrap(t *testing.T) {
	// A simple handler that writes a response with no RRs
	handler := dnsserver.HandlerFunc(func(
		ctx context.Context,
		rw dnsserver.ResponseWriter,
		req *dns.Msg,
	) error {
		res := new(dns.Msg)
		res.SetReply(req)

		return rw.WriteMsg(ctx, req, res)
	})

	// Create a handler with middlewares
	w := new(bytes.Buffer)
	handlerWithMiddlewares := dnsserver.WithMiddlewares(
		handler,
		querylog.NewLogMiddleware(w, slogutil.NewDiscardLogger()),
	)

	// Create a test DNS request
	req := new(dns.Msg)
	req.Id = 1
	req.RecursionDesired = true
	name := "example.org."
	req.Question = []dns.Question{
		{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}

	// Add server and request info to the context
	ctx := dnsserver.ContextWithServerInfo(
		context.Background(),
		&dnsserver.ServerInfo{
			Name:  "test",
			Addr:  "0.0.0.0:53",
			Proto: dnsserver.ProtoDNS,
		})
	ctx = dnsserver.ContextWithRequestInfo(ctx, &dnsserver.RequestInfo{
		StartTime: time.Now().Add(-time.Second),
	})

	// Init response writer with test data
	localAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 54}
	rw := dnsserver.NewNonWriterResponseWriter(localAddr, remoteAddr)

	// Finally, run the middleware handler
	err := handlerWithMiddlewares.ServeDNS(ctx, rw, req)
	require.NoError(t, err)

	// duration is different all the time so don't check it
	require.True(t,
		strings.HasPrefix(
			w.String(),
			"[test dns://0.0.0.0:53] 1 A example.org. 29 0 29",
		),
		"invalid message: %s",
		w.String(),
	)
	require.True(t, strings.HasSuffix(w.String(), "\n"))
}

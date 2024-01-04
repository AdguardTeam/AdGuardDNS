// Package querylog provides a simple middleware that prints queries to the
// specified io.Writer.
package querylog

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

// LogMiddleware is a simple middleware that prints DNS queries to the log.
// We keep it here to show an example of a middleware.
type LogMiddleware struct {
	output io.Writer
}

// NewLogMiddleware creates a new LogMiddleware with the specified output.
func NewLogMiddleware(output io.Writer) *LogMiddleware {
	return &LogMiddleware{
		output: output,
	}
}

// type check
var _ dnsserver.Middleware = (*LogMiddleware)(nil)

// Wrap implements the dnsserver.Middleware interface for *LogMiddleware.
func (l *LogMiddleware) Wrap(h dnsserver.Handler) (wrapped dnsserver.Handler) {
	f := func(ctx context.Context, rw dnsserver.ResponseWriter, req *dns.Msg) error {
		// Call the next handler and record the response that has been written
		recW := dnsserver.NewRecorderResponseWriter(rw)
		err := h.ServeDNS(ctx, recW, req)

		// Log format:
		// [{name} {proto}://{addr}] {id} {type} {name} {size} {rcode} {rsize} {duration}
		sb := strings.Builder{}

		serverInfo := dnsserver.MustServerInfoFromContext(ctx)
		requestInfo := dnsserver.MustRequestInfoFromContext(ctx)

		// [{name} {proto}://{addr}]
		sb.WriteString(
			fmt.Sprintf("[%s %s://%s] ",
				serverInfo.Name,
				serverInfo.Proto,
				serverInfo.Addr,
			),
		)

		// Request data: {id} {type} {name} {size}
		hostname := ""
		if len(req.Question) > 0 {
			hostname = req.Question[0].Name
		}
		var qType uint16
		if len(req.Question) == 1 {
			qType = req.Question[0].Qtype
		}
		qTypeStr, ok := dns.TypeToString[qType]
		if !ok {
			qTypeStr = fmt.Sprintf("TYPE%d", qType)
		}
		sb.WriteString(
			fmt.Sprintf("%d %s %s %d ",
				req.Id,
				qTypeStr,
				hostname,
				req.Len(),
			),
		)

		// Response data: {rcode} {rsize}
		rcode := 0
		rsize := 0
		if recW.Resp != nil {
			rcode = recW.Resp.Rcode
			// TODO(a.garipov): Count bytes written to the socket only once with
			// [dnsserver.ResponseWriter].
			rsize = recW.Resp.Len()
		}
		sb.WriteString(fmt.Sprintf("%d %d ", rcode, rsize))

		// Duration
		elapsed := time.Since(requestInfo.StartTime)
		sb.WriteString(fmt.Sprintf("%s\n", elapsed))

		// Suppress errors, it's not that important for a query log
		_, outErr := l.output.Write([]byte(sb.String()))
		if outErr != nil {
			log.Debug("failed to write to the query log: %v", outErr)
		}

		return err
	}

	return dnsserver.HandlerFunc(f)
}

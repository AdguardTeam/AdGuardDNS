package errcoll

import (
	"cmp"
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/forward"
	"github.com/AdguardTeam/AdGuardDNS/internal/version"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/requestid"
	"github.com/getsentry/sentry-go"
	"github.com/quic-go/quic-go"
	"golang.org/x/sys/unix"
)

// SentryErrorCollector is an [Interface] implementation that sends errors to a
// Sentry-like HTTP API.
type SentryErrorCollector struct {
	logger *slog.Logger
	sentry *sentry.Client
}

// NewSentryErrorCollector returns a new SentryErrorCollector.  All arguments
// must not be nil.
func NewSentryErrorCollector(cli *sentry.Client, l *slog.Logger) (c *SentryErrorCollector) {
	return &SentryErrorCollector{
		logger: l,
		sentry: cli,
	}
}

// type check
var _ Interface = (*SentryErrorCollector)(nil)

// Collect implements the [Interface] interface for *SentryErrorCollector.
func (c *SentryErrorCollector) Collect(ctx context.Context, err error) {
	if !isReportable(err) {
		c.logger.DebugContext(ctx, "non-reportable error", slogutil.KeyError, err)

		return
	}

	scope := sentry.NewScope()
	tags := tagsFromCtx(ctx)
	scope.SetTags(tags)

	_ = c.sentry.CaptureException(err, &sentry.EventHint{
		Context: ctx,
	}, scope)
}

// ErrorFlushCollector collects information about errors, possibly sending them
// to a remote location.  The collected errors should be flushed with the Flush.
type ErrorFlushCollector interface {
	Interface

	// Flush waits until the underlying transport sends any buffered events to
	// the sentry server, blocking for at most the predefined timeout.
	Flush()
}

// type check
var _ ErrorFlushCollector = (*SentryErrorCollector)(nil)

// flushTimeout is the timeout for flushing sentry errors.
const flushTimeout = 1 * time.Second

// Flush implements the [ErrorFlushCollector] interface for
// *SentryErrorCollector.
func (c *SentryErrorCollector) Flush() {
	_ = c.sentry.Flush(flushTimeout)
}

// SentryReportableError is the interface for errors and wrapper that can tell
// whether they should be reported or not.
type SentryReportableError interface {
	error

	IsSentryReportable() (ok bool)
}

// isReportable returns true if the error is worth reporting.
//
// TODO(a.garipov): Make sure that we use this approach everywhere.
func isReportable(err error) (ok bool) {
	var (
		sentryRepErr SentryReportableError
		fwdErr       *forward.Error
		dnsWErr      *dnsserver.WriteError
	)

	if errors.As(err, &sentryRepErr) {
		return sentryRepErr.IsSentryReportable()
	} else if errors.As(err, &fwdErr) {
		return isReportableNetwork(fwdErr.Err)
	} else if errors.As(err, &dnsWErr) {
		switch dnsWErr.Protocol {
		case "quic":
			return isReportableWriteQUIC(dnsWErr.Err)
		case "tcp":
			return isReportableWriteTCP(dnsWErr.Err)
		case "udp":
			return isReportableWriteUDP(dnsWErr.Err)
		default:
			return true
		}
	}

	return true
}

// isReportableNetwork returns true if err is a network error that should be
// reported.
func isReportableNetwork(err error) (ok bool) {
	if isConnectionBreak(err) {
		return false
	}

	var netErr net.Error

	return errors.As(err, &netErr) && !netErr.Timeout()
}

// isReportableWriteQUIC returns true if err is a QUIC error that should be
// reported.
func isReportableWriteQUIC(err error) (ok bool) {
	if isConnectionBreak(err) {
		return false
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return false
	}

	if errors.Is(err, quic.ErrServerClosed) {
		return false
	}

	var streamErr *quic.StreamError
	if errors.As(err, &streamErr) {
		// Only report local stream errors.
		return !streamErr.Remote
	}

	// Catch quic-go's IdleTimeoutError.  This error is returned from
	// [quic.Conn.AcceptStream] calls and this is an expected outcome, happens
	// all the time with different QUIC clients.
	var idleTimeoutErr *quic.IdleTimeoutError
	if errors.As(err, &idleTimeoutErr) {
		return false
	}

	// Catch quic-go's ApplicationError with error code 0.  This error is
	// returned from quic-go methods when the client closes the connection.
	// This is an expected situation, and it's not necessary to log it.
	var qAppErr *quic.ApplicationError
	if errors.As(err, &qAppErr) && qAppErr.ErrorCode == 0 {
		return false
	}

	return true
}

// isReportableWriteTCP returns true if err is a TCP or TLS error that should be
// reported.
func isReportableWriteTCP(err error) (ok bool) {
	if isConnectionBreak(err) {
		return false
	}

	// Ignore the TLS errors that are probably caused by a network error, a
	// record overflow attempt, and errors about protocol versions.
	//
	// See also AGDNS-1520.
	//
	// TODO(a.garipov): Propose exporting these from crypto/tls.
	errStr := err.Error()

	return !strings.Contains(errStr, "bad record MAC") &&
		!strings.Contains(errStr, "protocol version not supported") &&
		!strings.Contains(errStr, "local error: tls: record overflow")
}

// isReportableWriteUDP returns true if err is a UDP error that should be
// reported.
func isReportableWriteUDP(err error) (ok bool) {
	switch {
	case
		errors.Is(err, io.EOF),
		errors.Is(err, net.ErrClosed),
		errors.Is(err, os.ErrDeadlineExceeded),
		errors.Is(err, unix.ENETUNREACH):
		return false
	default:
		return true
	}
}

// isConnectionBreak returns true if err is an error about connection breaking
// or timing out.
func isConnectionBreak(err error) (ok bool) {
	switch {
	case
		errors.Is(err, io.EOF),
		errors.Is(err, net.ErrClosed),
		errors.Is(err, os.ErrDeadlineExceeded),
		errors.Is(err, unix.ECONNREFUSED),
		errors.Is(err, unix.ECONNRESET),
		errors.Is(err, unix.EHOSTUNREACH),
		errors.Is(err, unix.ENETUNREACH),
		errors.Is(err, unix.EPIPE),
		errors.Is(err, unix.ETIMEDOUT):
		return true
	default:
		return false
	}
}

// sentryTags is a convenient alias for map[string]string.
type sentryTags = map[string]string

// tagsFromCtx returns Sentry tags based on the information from ctx.
func tagsFromCtx(ctx context.Context) (tags sentryTags) {
	tags = sentryTags{
		"git_revision": version.Revision(),
	}

	// TODO(a.garipov):  Consider splitting agdctx package.
	var reqID requestid.ID
	if ri, ok := agd.RequestInfoFromContext(ctx); ok {
		tags["filtering_group_id"] = string(ri.FilteringGroup.ID)

		p, d := ri.DeviceData()
		if p != nil {
			tags["profile_id"] = string(p.ID)
			tags["device_id"] = string(d.ID)
		}
	} else if reqID, ok = requestid.IDFromContext(ctx); ok {
		// This context could be from the part of the pipeline where the request
		// ID hasn't yet been resurfaced.
		tags["request_id"] = string(reqID)
	}

	if si, ok := dnsserver.ServerInfoFromContext(ctx); ok {
		// Don't use "server_name" etc., since Sentry already uses similar tags
		// for their own stuff.
		tags["dns_server_name"] = si.Name
		tags["dns_server_addr"] = si.Addr
		tags["dns_server_proto"] = si.Proto.String()
	}

	if ri, ok := dnsserver.RequestInfoFromContext(ctx); ok {
		tlsSrvName := ""
		if ri.TLS != nil {
			tlsSrvName = ri.TLS.ServerName
		}
		tags["dns_client_tls_server_name"] = toASCII(tlsSrvName)

		if ri.URL != nil {
			// Provide only the path and the query to fit into Sentry's 200
			// characters limit.
			tags["dns_client_url_path"] = ri.URL.RequestURI()
		}
	}

	return tags
}

// toASCII escapes binary data, returning a string that only has ASCII
// characters.  ascii is never empty.
func toASCII(s string) (ascii string) {
	ascii = strconv.QuoteToASCII(s)
	ascii = ascii[1 : len(ascii)-1]

	return cmp.Or(ascii, "(empty)")
}

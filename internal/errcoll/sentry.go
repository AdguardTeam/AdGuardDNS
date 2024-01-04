package errcoll

import (
	"context"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/forward"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/getsentry/sentry-go"
	"golang.org/x/sys/unix"
)

// SentryErrorCollector is an [Interface] implementation that sends errors to a
// Sentry-like HTTP API.
type SentryErrorCollector struct {
	sentry *sentry.Client
}

// NewSentryErrorCollector returns a new SentryErrorCollector.  cli must be
// non-nil.
func NewSentryErrorCollector(cli *sentry.Client) (c *SentryErrorCollector) {
	return &SentryErrorCollector{
		sentry: cli,
	}
}

// type check
var _ Interface = (*SentryErrorCollector)(nil)

// Collect implements the [Interface] interface for *SentryErrorCollector.
func (c *SentryErrorCollector) Collect(ctx context.Context, err error) {
	if !isReportable(err) {
		log.Debug("errcoll: sentry: non-reportable error: %s", err)

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

// isReportableWriteUDP returns true if err is a UDP error that should be reported.
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
		"git_revision": agd.Revision(),
	}

	var reqID agd.RequestID
	if ri, ok := agd.RequestInfoFromContext(ctx); ok {
		tags["filtering_group_id"] = string(ri.FilteringGroup.ID)
		tags["request_id"] = ri.ID.String()

		if p := ri.Profile; p != nil {
			tags["profile_id"] = string(p.ID)

			// Assume that if we have a profile then we also have a device.
			tags["device_id"] = string(ri.Device.ID)
		}
	} else if reqID, ok = agd.RequestIDFromContext(ctx); ok {
		// This context could be from the part of the pipeline where the request
		// ID hasn't yet been resurfaced.
		tags["request_id"] = reqID.String()
	}

	if si, ok := dnsserver.ServerInfoFromContext(ctx); ok {
		// Don't use "server_name" etc., since Sentry already uses similar tags
		// for their own stuff.
		tags["dns_server_name"] = si.Name
		tags["dns_server_addr"] = si.Addr
		tags["dns_server_proto"] = si.Proto.String()
	}

	if ri, ok := dnsserver.RequestInfoFromContext(ctx); ok {
		tags["dns_client_tls_server_name"] = toASCII(ri.TLSServerName)
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

	if ascii == "" {
		ascii = "(empty)"
	}

	return ascii
}

package errcoll

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/forward"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/getsentry/raven-go"
	"golang.org/x/sys/unix"
)

// Raven API Error Collector

// RavenErrorCollector is an agd.ErrorCollector that sends errors to
// a Raven-like HTTP API.
type RavenErrorCollector struct {
	raven *raven.Client
}

// NewRavenErrorCollector returns a new RavenErrorCollector.  rc must be
// non-nil.
func NewRavenErrorCollector(rc *raven.Client) (c *RavenErrorCollector) {
	return &RavenErrorCollector{
		raven: rc,
	}
}

// type check
var _ agd.ErrorCollector = (*RavenErrorCollector)(nil)

// Collect implements the agd.ErrorCollector interface for
// *RavenErrorCollector.
func (c *RavenErrorCollector) Collect(ctx context.Context, err error) {
	if !isReportable(err) {
		log.Debug("errcoll: raven: non-reportable error: %s", err)

		return
	}

	tags := tagsFromCtx(ctx)
	tags["unwrapped_type"] = fmt.Sprintf("%T", errors.Unwrap(err))

	_ = c.raven.CaptureError(err, tags)
}

// RavenReportableError is the interface for errors and wrapper that can tell
// whether they should be reported or not.
type RavenReportableError interface {
	error

	IsRavenReportable() (ok bool)
}

// isReportable returns true if the error is worth reporting.
//
// TODO(a.garipov): Make sure that we use this approach everywhere.
func isReportable(err error) (ok bool) {
	var (
		ravErr  RavenReportableError
		fwdErr  *forward.Error
		dnsWErr *dnsserver.WriteError
	)

	if errors.As(err, &ravErr) {
		return ravErr.IsRavenReportable()
	} else if errors.As(err, &fwdErr) {
		return isReportableNetwork(fwdErr.Err)
	} else if errors.As(err, &dnsWErr) {
		switch dnsWErr.Protocol {
		case "tcp":
			return isReportableTCP(dnsWErr.Err)
		case "udp":
			return isReportableUDP(dnsWErr.Err)
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

// isReportableTCP returns true if err is a TCP or TLS error that should be
// reported.
func isReportableTCP(err error) (ok bool) {
	if isConnectionBreak(err) {
		return false
	}

	// Ignore the TLS errors that are probably caused by a network error and
	// errors about protocol versions.
	//
	// TODO(a.garipov): Propose exporting these from crypto/tls.
	errStr := err.Error()

	return !strings.Contains(errStr, "bad record MAC") &&
		!strings.Contains(errStr, "protocol version not supported")
}

// isReportableUDP returns true if err is a UDP error that should be reported.
func isReportableUDP(err error) (ok bool) {
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

// ravenTags is a convenient alias for map[string]string.
type ravenTags = map[string]string

func tagsFromCtx(ctx context.Context) (tags ravenTags) {
	tags = ravenTags{
		"git_revision": agd.Revision(),
		"position":     caller(3),
		"version":      agd.Version(),
	}

	var reqID agd.RequestID
	if ri, ok := agd.RequestInfoFromContext(ctx); ok {
		tags["filtering_group_id"] = string(ri.FilteringGroup.ID)
		tags["request_id"] = string(ri.ID)

		if p := ri.Profile; p != nil {
			tags["profile_id"] = string(p.ID)

			// Assume that if we have a profile then we also have a device.
			tags["device_id"] = string(ri.Device.ID)
		}
	} else if reqID, ok = agd.RequestIDFromContext(ctx); ok {
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

	if ci, ok := dnsserver.ClientInfoFromContext(ctx); ok {
		tags["dns_client_tls_server_name"] = toASCII(ci.TLSServerName)
		if ci.URL != nil {
			// Provide only the path and the query to fit into Sentry's 200
			// character limit.
			tags["dns_client_url_path"] = ci.URL.RequestURI()
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

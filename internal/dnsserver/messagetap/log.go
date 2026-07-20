package messagetap

import (
	"context"
	"log/slog"
	"net/netip"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
)

// LogConfig is the configuration for the Log.  See [NewLog].
type LogConfig struct {
	// Logger is used for logging the DNS requests and responses.  It must not
	// be nil.
	Logger *slog.Logger

	// LogLevel is the logging level for DNS requests and responses messages.
	LogLevel slog.Level
}

// Log is an [Interface] that records DNS requests and responses using a
// [slog.Logger].
type Log struct {
	logger *slog.Logger
	lvl    slog.Level
}

// NewLog returns a properly initialized *Log.  c must be valid.
func NewLog(c *LogConfig) (l *Log) {
	return &Log{
		logger: c.Logger,
		lvl:    c.LogLevel,
	}
}

// type check
var _ Interface = (*Log)(nil)

// TapRequest implements the [Interface] interface for *Log.
func (l *Log) TapRequest(ctx context.Context, laddr, raddr netip.AddrPort, req []byte) {
	l.logger.Log(ctx, l.lvl, "received dns request", "laddr", laddr, "raddr", raddr)

	msg := &dns.Msg{}
	err := msg.Unpack(req)
	if err != nil {
		l.logger.ErrorContext(ctx, "failed to unpack message", "err", err)

		return
	}

	slogutil.PrintLines(ctx, l.logger, l.lvl, "req", msg.String())
}

// TapResponse implements the [Interface] interface for *Log.
func (l *Log) TapResponse(ctx context.Context, laddr, raddr netip.AddrPort, resp []byte) {
	l.logger.Log(ctx, l.lvl, "received dns response", "laddr", laddr, "raddr", raddr)

	msg := &dns.Msg{}
	err := msg.Unpack(resp)
	if err != nil {
		l.logger.ErrorContext(ctx, "failed to unpack message", "err", err)

		return
	}

	slogutil.PrintLines(ctx, l.logger, l.lvl, "resp", msg.String())
}

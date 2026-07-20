package messagetap

import (
	"cmp"
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/service"
	"github.com/AdguardTeam/golibs/syncutil"
	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

// DefaultCheckConnectTimeout is the default timeout for listener check connect.
const DefaultCheckConnectTimeout = 1 * time.Second

var (
	// messageTypeRequest is the DNSTap message type for requests.
	messageTypeRequest = dnstap.Message_CLIENT_QUERY

	// messageTypeResponse is the DNSTap message type for responses.
	messageTypeResponse = dnstap.Message_CLIENT_RESPONSE
)

// DNSTapConfig is the configuration for the DNSTap.  See [NewDNSTap].
type DNSTapConfig struct {
	// Logger is used for logging the operations of DNSTap.  It must not be nil.
	Logger *slog.Logger

	// Tapper is used to send the DNSTap messages.  It must not be nil.
	Tapper Tapper

	// SocketPath is the path to the Unix domain socket to send DNSTap messages
	// to.
	SocketPath string

	// CheckInterval is the interval at which DNSTap checks whether there is a
	// listener on the socket.  It must be positive.
	CheckInterval time.Duration

	// CheckConnectTimeout is the timeout for checking the socket listener.  If
	// it's empty the [DefaultCheckConnectTimeout] is used.
	CheckConnectTimeout time.Duration
}

// The defaultBufSize is the default buffers size for marshaling messages.
const defaultBufSize = 2 * dns.MaxMsgSize

// DNSTap is an [Interface] that records DNS requests and responses using an
// underlying Tapper.  It also implements the [service.Interface] to allow for
// proper startup and shutdown of the Tapper.
type DNSTap struct {
	dialer        *net.Dialer
	logger        *slog.Logger
	tapper        Tapper
	bytesPool     *syncutil.Pool[[]byte]
	dtPool        *syncutil.Pool[dnstap.Dnstap]
	msgPool       *syncutil.Pool[dnstap.Message]
	done          chan struct{}
	socketPath    string
	checkInterval time.Duration
	hasListener   atomic.Bool
}

// NewDNSTap returns a properly initialized *DNSTap.  c must be valid.
func NewDNSTap(c *DNSTapConfig) (d *DNSTap) {
	return &DNSTap{
		dialer:    &net.Dialer{Timeout: cmp.Or(c.CheckConnectTimeout, DefaultCheckConnectTimeout)},
		logger:    c.Logger,
		tapper:    c.Tapper,
		bytesPool: syncutil.NewSlicePool[byte](defaultBufSize),
		dtPool: syncutil.NewPool(func() (v *dnstap.Dnstap) {
			return &dnstap.Dnstap{}
		}),
		msgPool: syncutil.NewPool(func() (v *dnstap.Message) {
			return &dnstap.Message{}
		}),
		done:          make(chan struct{}),
		socketPath:    c.SocketPath,
		checkInterval: c.CheckInterval,
	}
}

// type check
var _ Interface = (*DNSTap)(nil)

// TapRequest implements the [Interface] interface for *DNSTap.
func (d *DNSTap) TapRequest(ctx context.Context, laddr, raddr netip.AddrPort, req []byte) {
	if !d.hasListener.Load() {
		return
	}

	msg := d.newDNSTapMessage(laddr, raddr, &messageTypeRequest, req, nil)
	dt := d.newDNSTap(msg)
	d.send(ctx, dt)
}

// TapResponse implements the [Interface] interface for *DNSTap.
func (d *DNSTap) TapResponse(ctx context.Context, laddr, raddr netip.AddrPort, resp []byte) {
	if !d.hasListener.Load() {
		return
	}

	msg := d.newDNSTapMessage(laddr, raddr, &messageTypeResponse, nil, resp)
	dt := d.newDNSTap(msg)
	d.send(ctx, dt)
}

// send marshals dt and sends it to the output channel.  If the channel is
// full, the message is dropped.  After sending, dt and its message are reset
// and returned to the corresponding pools.
func (d *DNSTap) send(ctx context.Context, dt *dnstap.Dnstap) {
	defer func() {
		msg := dt.Message

		dt.Reset()
		d.dtPool.Put(dt)

		if msg != nil {
			msg.Reset()
			d.msgPool.Put(msg)
		}
	}()

	opts := proto.MarshalOptions{
		Deterministic: true,
	}

	var buf []byte
	bufPtr := d.bytesPool.Get()
	defer func() {
		// Retain any grown capacity.
		*bufPtr = buf
		d.bytesPool.Put(bufPtr)
	}()

	buf, err := opts.MarshalAppend((*bufPtr)[:0], dt)
	if err != nil {
		d.logger.ErrorContext(ctx, "marshaling dnstap message", slogutil.KeyError, err)

		return
	}

	d.tapper.Tap(ctx, buf)
}

// type check
var _ service.Interface = (*DNSTap)(nil)

// Start implements the [service.Interface] interface for *DNSTap.  It starts
// the DNSTap background goroutines.  It must be called before using
// [DNSTap.TapRequest] or [DNSTap.TapResponse].
func (d *DNSTap) Start(ctx context.Context) (err error) {
	go d.runListenerCheck(ctx)

	return d.tapper.Start(ctx)
}

// Shutdown implements the [service.Shutdowner] interface for *DNSTap.  It stops
// the DNSTap and waits for all pending data to be flushed.
func (d *DNSTap) Shutdown(ctx context.Context) (err error) {
	close(d.done)

	return d.tapper.Shutdown(ctx)
}

// runListenerCheck periodically checks whether there is a listener on the
// configured socket and updates [DNSTap.hasListener] accordingly.  It is
// intended to be used as a goroutine.
func (d *DNSTap) runListenerCheck(ctx context.Context) {
	defer slogutil.RecoverAndLog(ctx, d.logger)

	// Perform an initial check immediately.
	d.checkListener(ctx)

	t := time.NewTicker(d.checkInterval)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			d.checkListener(ctx)
		case <-d.done:
			return
		}
	}
}

// checkListener tries to connect to the socket and updates
// [DNSTap.hasListener].
//
// TODO(d.kolyshev):  Consider stopping the inner d.tapper if the listener is
// gone and restarting it when the listener is back.
func (d *DNSTap) checkListener(ctx context.Context) {
	conn, err := d.dialer.DialContext(ctx, "unix", d.socketPath)
	if err != nil {
		if d.hasListener.Swap(false) {
			d.logger.InfoContext(ctx, "dnstap listener is gone", slogutil.KeyError, err)
		}

		return
	}

	defer slogutil.CloseAndLog(ctx, d.logger, conn, slogutil.LevelError)

	if d.hasListener.CompareAndSwap(false, true) {
		d.logger.InfoContext(ctx, "dnstap listener found")
	}
}

package messagetap

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/service"
	"github.com/AdguardTeam/golibs/syncutil"
	dnstap "github.com/dnstap/golang-dnstap"
	framestream "github.com/farsightsec/golang-framestream"
)

// Tapper is the interface for tapping DNS messages.  It is used in testing to
// mock the DNSTap messages receiver.  It also implements the
// [service.Interface] interface to allow for proper startup and shutdown of the
// tapper.  It must be safe for concurrent use.
type Tapper interface {
	service.Interface

	// Tap handles the payload.
	Tap(ctx context.Context, payload []byte)
}

// EmptyTapper is an implementation of the [Tapper] interface that does nothing.
type EmptyTapper struct{}

// type check
var _ Tapper = EmptyTapper{}

// Start implements the [Tapper] interface for EmptyTapper.  It always returns
// nil.
func (EmptyTapper) Start(_ context.Context) (err error) {
	return nil
}

// Shutdown implements the [Tapper] interface for EmptyTapper.  It always
// returns nil.
func (EmptyTapper) Shutdown(_ context.Context) (err error) {
	return nil
}

// Tap implements the [Tapper] interface for EmptyTapper.
func (EmptyTapper) Tap(_ context.Context, _ []byte) {}

// TODO(a.garipov):  Consider making configurable.
const (
	// sockDialerTimeout sets the timeout for connection establishment.
	sockDialerTimeout = 1 * time.Second

	// sockOutputTimeout gives the time the writer will wait for reads and
	// writes to complete.
	sockOutputTimeout = 2 * time.Second

	// sockOutputRetryIvl is how long the tapper will wait between connection
	// attempts.
	sockOutputRetryIvl = 10 * time.Second

	// outputChannelSize is the number of frames that can be buffered in the
	// output channel.
	outputChannelSize = 32
)

// DefaultTapper is the default implementation of the [Tapper] interface.  It
// sends the DNSTap messages to a Unix domain socket using the [dnstap.Writer].
type DefaultTapper struct {
	addr      *net.UnixAddr
	bytesPool *syncutil.Pool[[]byte]
	dialer    *net.Dialer
	logger    *slog.Logger

	// outputChannel is the channel for frames to be written to the socket.
	outputChannel chan *[]byte

	// done is the channel used to signal the output loop to stop.
	done chan struct{}

	// stopped is used to wait for the output loop to finish on shutdown.
	stopped chan struct{}
}

// NewDefaultTapper returns a properly initialized *DefaultTapper.  l must not
// be nil.  socketPath should be a valid path to a Unix domain socket.
func NewDefaultTapper(l *slog.Logger, socketPath string) (d *DefaultTapper, err error) {
	addr, err := net.ResolveUnixAddr("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("resolving unix addr: %w", err)
	}

	return &DefaultTapper{
		addr:          addr,
		bytesPool:     syncutil.NewSlicePool[byte](defaultBufSize),
		dialer:        &net.Dialer{Timeout: sockDialerTimeout},
		logger:        l,
		outputChannel: make(chan *[]byte, outputChannelSize),
		done:          make(chan struct{}),
		stopped:       make(chan struct{}),
	}, nil
}

// type check
var _ Tapper = (*DefaultTapper)(nil)

// Tap implements the [Tapper] interface for *DefaultTapper.  It does not block.
func (t *DefaultTapper) Tap(ctx context.Context, payload []byte) {
	bufPtr := t.bytesPool.Get()

	// Copy the payload to avoid potential data races if the caller reuses the
	// payload slice after calling Tap.
	*bufPtr = append((*bufPtr)[:0], payload...)

	select {
	case <-ctx.Done():
		t.bytesPool.Put(bufPtr)
		t.logger.ErrorContext(ctx, "context done - dropping message")

		return
	default:
		// Go on.
	}

	select {
	case t.outputChannel <- bufPtr:
		// The buffer will be returned to the pool after processing.
		return
	default:
		t.bytesPool.Put(bufPtr)
		t.logger.DebugContext(ctx, "output channel full - dropping message")
	}
}

// type check
var _ service.Interface = (*DefaultTapper)(nil)

// Start implements the [service.Interface] interface for *DefaultTapper.  It
// does not block and always returns nil.
func (t *DefaultTapper) Start(ctx context.Context) (err error) {
	go t.runOutputLoop(ctx)

	return nil
}

// Shutdown implements the [service.Interface] interface for *DefaultTapper.  It
// signals the output loop to stop and waits for it to finish.
func (t *DefaultTapper) Shutdown(ctx context.Context) (err error) {
	close(t.done)

	select {
	case <-t.stopped:
		// Output loop stopped successfully.
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// runOutputLoop is the main output loop.  It dials the Unix socket, writes
// frames, and reconnects on error until the done channel is closed.  It is
// intended to run as a goroutine.
func (t *DefaultTapper) runOutputLoop(ctx context.Context) {
	defer slogutil.RecoverAndLog(ctx, t.logger)
	defer close(t.stopped)

	for {
		conn, ok := t.dial(ctx)
		if !ok {
			return
		}

		if !t.writeLoop(ctx, conn) {
			return
		}
	}
}

// dial establishes a connection to the Unix socket.  It retries with
// sockOutputRetryIvl between attempts.  It returns false if the done channel
// is closed before a connection is established.
func (t *DefaultTapper) dial(ctx context.Context) (conn net.Conn, ok bool) {
	for {
		var err error
		conn, err = t.dialer.DialContext(ctx, t.addr.Network(), t.addr.String())
		if err == nil {
			t.logger.DebugContext(ctx, "connected")

			return conn, true
		}

		t.logger.Log(ctx, slogutil.LevelTrace, "connection fail, retrying", slogutil.KeyError, err)

		select {
		case <-ctx.Done():
			return nil, false
		case <-t.done:
			return nil, false
		case <-time.After(sockOutputRetryIvl):
			// Go on.
		}
	}
}

// writeLoop writes frames from the output channel to the given conn.  It
// returns true if the caller should retry the connection, or false if the done
// channel was closed.  conn must not be nil.
func (t *DefaultTapper) writeLoop(ctx context.Context, conn net.Conn) (retry bool) {
	defer slogutil.CloseAndLog(ctx, t.logger, conn, slogutil.LevelError)

	w, err := framestream.NewWriter(conn, &framestream.WriterOptions{
		ContentTypes: [][]byte{dnstap.FSContentType},
		Timeout:      sockOutputTimeout,
		// Most dnstap receivers expect the READY/ACCEPT handshake; without it
		// they never start processing data.
		Bidirectional: true,
	})
	if err != nil {
		t.logger.ErrorContext(ctx, "creating writer", slogutil.KeyError, err)

		return true
	}

	defer slogutil.CloseAndLog(ctx, t.logger, w, slogutil.LevelError)

	for {
		select {
		case <-ctx.Done():
			// Context is done, exit the loop.
			return false
		case <-t.done:
			// Do not retry, exit the loop.
			return false
		case bufPtr := <-t.outputChannel:
			frameErr := t.processFrame(w, bufPtr)
			if frameErr != nil {
				t.logger.ErrorContext(ctx, "processing frame", slogutil.KeyError, frameErr)

				// Retry writing frames.
				return true
			}
		}
	}
}

// processFrame writes the given frame to w and flushes.  w and frame must not
// be nil.
func (t *DefaultTapper) processFrame(w *framestream.Writer, frame *[]byte) (err error) {
	defer t.bytesPool.Put(frame)

	if _, err = w.WriteFrame(*frame); err != nil {
		return fmt.Errorf("writing frame: %w", err)
	}

	if err = w.Flush(); err != nil {
		return fmt.Errorf("flushing frame: %w", err)
	}

	return nil
}

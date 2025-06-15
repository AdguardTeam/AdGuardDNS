package websvc

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil/httputil"
	"github.com/AdguardTeam/golibs/service"
)

// blockPageServer serves the blocking page contents.
type blockPageServer struct {
	// logger is used to log the refreshes.
	logger *slog.Logger

	// mu protects content and gzipContent.
	mu *sync.RWMutex

	// metrics is used for the collection of the web service requests
	// statistics.  It must not be nil.
	metrics Metrics

	// content is the content of the HTML block page.
	content []byte

	// gzipContent is the gzipped content of HTML block page.
	gzipContent []byte

	// contentFilePath is the path to HTML block page content file.
	contentFilePath string

	// group is the server group used for logging and metrics.
	group ServerGroup

	// bind are the addresses on which to serve the block page.
	bind []*BindData
}

// newBlockPageServer initializes a new instance of blockPageServer.  If conf is
// nil, srv is nil.  The server must be refreshed with [blockPageServer.Refresh]
// before use.
func newBlockPageServer(
	conf *BlockPageServerConfig,
	baseLogger *slog.Logger,
	mtrc Metrics,
	g ServerGroup,
) (srv *blockPageServer) {
	if conf == nil {
		return nil
	}

	return &blockPageServer{
		logger:          baseLogger.With(loggerKeyGroup, g),
		mu:              &sync.RWMutex{},
		metrics:         mtrc,
		contentFilePath: conf.ContentFilePath,
		group:           g,
		bind:            conf.Bind,
	}
}

// type check
var _ service.Refresher = (*blockPageServer)(nil)

// Refresh implements the [service.Refresher] interface for *blockPageServer.
// srv may be nil.
func (srv *blockPageServer) Refresh(ctx context.Context) (err error) {
	if srv == nil {
		return nil
	}

	srv.logger.InfoContext(ctx, "refresh started")
	defer srv.logger.InfoContext(ctx, "refresh finished")

	// TODO(d.kolyshev): Compare with current srv content before updating.
	content, err := os.ReadFile(srv.contentFilePath)
	if err != nil {
		return fmt.Errorf("block page server %q: reading block page file: %w", srv.group, err)
	}

	gzipContent := mustGzip(srv.group, content)

	srv.mu.Lock()
	defer srv.mu.Unlock()

	srv.content = content
	srv.gzipContent = gzipContent

	return nil
}

// newBlockPageServers is a helper function that converts a *blockPageServer
// into HTTP servers.
func newBlockPageServers(
	baseLogger *slog.Logger,
	srv *blockPageServer,
	timeout time.Duration,
) (srvs []*server) {
	if srv == nil {
		return nil
	}

	srvHdrMw := httputil.ServerHeaderMiddleware(agdhttp.UserAgent())
	handler := srv.blockPageHandler()

	for _, b := range srv.bind {
		logger := baseLogger.With(loggerKeyGroup, srv.group)
		h := httputil.Wrap(
			handler,
			srvHdrMw,
			httputil.NewLogMiddleware(logger, slog.LevelDebug),
		)

		srvs = append(srvs, newServer(&serverConfig{
			BaseLogger:     logger,
			TLSConf:        b.TLS,
			Handler:        h,
			InitialAddress: b.Address,
			Timeout:        timeout,
		}))
	}

	return srvs
}

// blockPageHandler returns an HTTP handler serving the block page content.
func (srv *blockPageServer) blockPageHandler() (h http.Handler) {
	f := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/favicon.ico":
			// Don't serve the HTML page to the favicon requests.
			http.NotFound(w, r)
		case "/robots.txt":
			// Don't serve the HTML page to the robots.txt requests.  Serve the
			// predefined response instead.
			serveRobotsDisallow(r.Context(), srv.metrics, w.Header(), w)
		default:
			srv.mu.RLock()
			defer srv.mu.RUnlock()

			srv.serve(w, r)
		}
	}

	return http.HandlerFunc(f)
}

// mustGzip uses gzip to compress b.  It panics with an informative error value
// if there are any errors.
func mustGzip(name string, b []byte) (compressed []byte) {
	buf := &bytes.Buffer{}
	zw, err := gzip.NewWriterLevel(buf, gzip.BestCompression)
	if err != nil {
		// Should never happen.
		panic(fmt.Errorf("websvc: gzipping %q: %w", name, err))
	}

	_, err = zw.Write(b)
	if err != nil {
		// Should never happen.
		panic(fmt.Errorf("websvc: writing gzipped %q: %w", name, err))
	}

	err = zw.Close()
	if err != nil {
		// Should never happen.
		panic(fmt.Errorf("websvc: flushing gzipped %q: %w", name, err))
	}

	return buf.Bytes()
}

// serve serves the block-page content taking compression headers into account.
func (srv *blockPageServer) serve(w http.ResponseWriter, r *http.Request) {
	respHdr := w.Header()
	respHdr.Set(httphdr.ContentType, agdhttp.HdrValTextHTML)

	content := srv.content

	// TODO(a.garipov): Parse the quality value.
	//
	// TODO(a.garipov): Support other compression algorithms.
	reqHdr := r.Header
	if strings.Contains(reqHdr.Get(httphdr.AcceptEncoding), agdhttp.HdrValGzip) {
		respHdr.Set(httphdr.ContentEncoding, agdhttp.HdrValGzip)
		content = srv.gzipContent
	}

	// Use HTTP 500 status code to signal that this is a block page.  See
	// AGDNS-1952.
	w.WriteHeader(http.StatusInternalServerError)

	_, err := w.Write(content)
	if err != nil {
		ctx := r.Context()
		l := slogutil.MustLoggerFromContext(ctx)
		l.Log(ctx, levelForError(err), "writing block page", slogutil.KeyError, err)
	}

	incBlockPageMetrics(r.Context(), srv.metrics, srv.group)
}

// incBlockPageMetrics increments the metrics for the block-page view counts
// depending on the server group.
func incBlockPageMetrics(ctx context.Context, mtrc Metrics, g ServerGroup) {
	switch g {
	case ServerGroupAdultBlockingPage:
		mtrc.IncrementReqCount(ctx, RequestTypeAdultBlockingPage)
	case ServerGroupGeneralBlockingPage:
		mtrc.IncrementReqCount(ctx, RequestTypeGeneralBlockingPage)
	case ServerGroupSafeBrowsingPage:
		mtrc.IncrementReqCount(ctx, RequestTypeSafeBrowsingPage)
	default:
		panic(fmt.Errorf("metrics: block-page server group: %w: %q", errors.ErrBadEnumValue, g))
	}
}

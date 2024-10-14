package websvc

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdservice"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/log"
	"github.com/prometheus/client_golang/prometheus"
)

// blockPageName is a type alias for strings that contain a block-page name for
// logging and metrics.
type blockPageName = string

// blockPageName values.
const (
	adultBlockingName   blockPageName = "adult blocking"
	generalBlockingName blockPageName = "general blocking"
	safeBrowsingName    blockPageName = "safe browsing"
)

// BlockPageServerConfig is the blocking page server configuration.
type BlockPageServerConfig struct {
	// ContentFilePath is the path to HTML block page content file.
	ContentFilePath string

	// Bind are the addresses on which to serve the block page.
	Bind []*BindData
}

// blockPageServer serves the blocking page contents.
type blockPageServer struct {
	// mu protects content and gzipContent.
	mu *sync.RWMutex

	// content is the content of the HTML block page.
	content []byte

	// gzipContent is the gzipped content of HTML block page.
	gzipContent []byte

	// contentFilePath is the path to HTML block page content file.
	contentFilePath string

	// name is the server identification used for logging and metrics.
	name blockPageName

	// bind are the addresses on which to serve the block page.
	bind []*BindData
}

// newBlockPageServer initializes a new instance of blockPageServer.  The server
// must be refreshed with [blockPageServer.Refresh] before use.
func newBlockPageServer(conf *BlockPageServerConfig, srvName blockPageName) (srv *blockPageServer) {
	if conf == nil {
		return nil
	}

	return &blockPageServer{
		mu:              &sync.RWMutex{},
		contentFilePath: conf.ContentFilePath,
		name:            srvName,
		bind:            conf.Bind,
	}
}

// type check
var _ agdservice.Refresher = (*blockPageServer)(nil)

// Refresh implements the [agdservice.Refresher] interface for *blockPageServer.
// srv may be nil.
func (srv *blockPageServer) Refresh(_ context.Context) (err error) {
	if srv == nil {
		return nil
	}

	// TODO(d.kolyshev): Compare with current srv content before updating.
	content, err := os.ReadFile(srv.contentFilePath)
	if err != nil {
		return fmt.Errorf("block page server %q: reading block page file: %w", srv.name, err)
	}

	gzipContent := mustGzip(srv.name, content)

	srv.mu.Lock()
	defer srv.mu.Unlock()

	srv.content = content
	srv.gzipContent = gzipContent

	return nil
}

// blockPageServers is a helper function that converts a *blockPageServer into
// HTTP servers.
func blockPageServers(srv *blockPageServer, timeout time.Duration) (srvs []*http.Server) {
	if srv == nil {
		return nil
	}

	h := srv.blockPageHandler()
	for _, b := range srv.bind {
		addr := b.Address.String()
		errLog := log.StdLog(fmt.Sprintf("websvc: %s: %s", srv.name, addr), log.DEBUG)
		srvs = append(srvs, &http.Server{
			Addr:              addr,
			Handler:           h,
			TLSConfig:         b.TLS,
			ErrorLog:          errLog,
			ReadTimeout:       timeout,
			WriteTimeout:      timeout,
			IdleTimeout:       timeout,
			ReadHeaderTimeout: timeout,
		})
	}

	return srvs
}

// blockPageHandler returns an HTTP handler serving the block page content.
// name is used for logging and metrics and must be one of blockPageName values.
func (srv *blockPageServer) blockPageHandler() (h http.Handler) {
	f := func(w http.ResponseWriter, r *http.Request) {
		// Set the Server header here, so that all responses carry it.
		respHdr := w.Header()
		respHdr.Set(httphdr.Server, agdhttp.UserAgent())

		switch r.URL.Path {
		case "/favicon.ico":
			// Don't serve the HTML page to the favicon requests.
			http.NotFound(w, r)
		case "/robots.txt":
			// Don't serve the HTML page to the robots.txt requests.  Serve the
			// predefined response instead.
			serveRobotsDisallow(respHdr, w, srv.name)
		default:
			srv.mu.RLock()
			defer srv.mu.RUnlock()

			serveBlockPage(w, r, srv.name, srv.content, srv.gzipContent)
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

// serveBlockPage serves the block-page content taking compression headers into
// account.
func serveBlockPage(
	w http.ResponseWriter,
	r *http.Request,
	name string,
	blockPage []byte,
	gzipped []byte,
) {
	respHdr := w.Header()
	respHdr.Set(httphdr.ContentType, agdhttp.HdrValTextHTML)

	content := blockPage

	// TODO(a.garipov): Parse the quality value.
	//
	// TODO(a.garipov): Support other compression algorithms.
	reqHdr := r.Header
	if strings.Contains(reqHdr.Get(httphdr.AcceptEncoding), agdhttp.HdrValGzip) {
		respHdr.Set(httphdr.ContentEncoding, agdhttp.HdrValGzip)
		content = gzipped
	}

	// Use HTTP 500 status code to signal that this is a block page.
	// See AGDNS-1952.
	w.WriteHeader(http.StatusInternalServerError)

	_, err := w.Write(content)
	if err != nil {
		logErrorByType(err, "websvc: %s: writing response: %s", name, err)
	}

	incBlockPageMetrics(name)
}

// incBlockPageMetrics increments the metrics for the block-page view
// counts depending on the name of the block page.
func incBlockPageMetrics(name blockPageName) {
	var totalCtr prometheus.Counter
	switch name {
	case adultBlockingName:
		totalCtr = metrics.WebSvcAdultBlockingPageRequestsTotal
	case generalBlockingName:
		totalCtr = metrics.WebSvcGeneralBlockingPageRequestsTotal
	case safeBrowsingName:
		totalCtr = metrics.WebSvcSafeBrowsingPageRequestsTotal
	default:
		panic(fmt.Errorf("metrics: bad websvc block-page metric name %q", name))
	}

	totalCtr.Inc()
}

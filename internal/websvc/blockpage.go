package websvc

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
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

// blockPageServers is a helper function that converts a *BlockPageServer into
// HTTP servers.
func blockPageServers(
	srv *BlockPageServer,
	name string,
	timeout time.Duration,
) (srvs []*http.Server) {
	if srv == nil {
		return nil
	}

	h := blockPageHandler(name, srv.Content)
	for _, b := range srv.Bind {
		addr := b.Address.String()
		errLog := log.StdLog(fmt.Sprintf("websvc: %s: %s", name, addr), log.DEBUG)
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
func blockPageHandler(name blockPageName, blockPage []byte) (h http.Handler) {
	gzipped := mustGzip(name, blockPage)

	f := func(w http.ResponseWriter, r *http.Request) {
		// Set the Server header here, so that all responses carry it.
		respHdr := w.Header()
		respHdr.Set(httphdr.Server, agdhttp.UserAgent())

		switch r.URL.Path {
		case "/favicon.ico":
			// Don't serve the HTML page to the favicon requests.
			http.NotFound(w, r)
		case "/robots.txt":
			// Don't serve the HTML page to the robots.txt requests.  Serve
			// the predefined response instead.
			serveRobotsDisallow(respHdr, w, name)
		default:
			serveBlockPage(w, r, name, blockPage, gzipped)
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

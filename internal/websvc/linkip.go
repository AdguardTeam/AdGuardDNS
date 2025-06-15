package websvc

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
)

// linkedIPHandler proxies selected requests to a remote address.
type linkedIPHandler struct {
	httpProxy     *httputil.ReverseProxy
	certValidator CertificateValidator
	errColl       errcoll.Interface
	metrics       Metrics
}

// linkedIPHandlerConfig is the configuration structure for a
// [*linkedIPHandler].
//
// TODO(a.garipov):  Consider generalizing into proxyHandler.
type linkedIPHandlerConfig struct {
	// proxyLogger logs errors from the underlying [*httputil.ReverseProxy].  It
	// must not be nil.
	proxyLogger *slog.Logger

	// targetURL is the URL to which linked IP API requests are proxied.  It
	// must not be nil.
	targetURL *url.URL

	// certValidator, if not nil, checks if an HTTP request is a TLS-certificate
	// validation request.  If it's nil, [shouldProxyRequest] is used.
	certValidator CertificateValidator

	// errColl collects errors occurring during proxying.  It must not be nil.
	errColl errcoll.Interface

	// metrics is used for the collection of the web service requests
	// statistics.  It must not be nil.
	metrics Metrics

	// timeout is the timeout for dialing and TLS handshaking.  It must be
	// positive.
	//
	// TODO(a.garipov):  Consider using it for other things as well.
	timeout time.Duration
}

// newLinkedIPHandler returns a linked IP proxy handler.  c must not be nil and
// must be valid.
func newLinkedIPHandler(c *linkedIPHandlerConfig) (h http.Handler) {
	// Use a Rewrite func to make sure we send the correct Host header and don't
	// send anything besides the path.
	rewrite := func(r *httputil.ProxyRequest) {
		r.SetURL(c.targetURL)
		r.Out.Host = c.targetURL.Host

		// Make sure that all requests are marked with our user agent.
		r.Out.Header.Set(httphdr.UserAgent, agdhttp.UserAgent())

		// Set the X-Forwarded-* headers for the backend to inspect cert
		// validation requests.
		r.SetXForwarded()
	}

	// Use largely the same transport as http.DefaultTransport, but with a
	// couple of limits and timeouts changed.
	//
	// TODO(ameshkov): Validate the configuration and consider making parts of
	// it configurable.
	//
	// TODO(e.burkov): Consider using the same transport for all the linked IP
	// handlers.
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   c.timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   c.timeout,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// Delete the Server header value from the upstream.
	modifyResponse := func(r *http.Response) (err error) {
		r.Header.Del(httphdr.Server)

		// Make sure that this URL can be used from the web page.
		r.Header.Set(httphdr.AccessControlAllowOrigin, agdhttp.HdrValWildcard)

		return nil
	}

	// Collect errors using our own error collector.
	handlerWithError := func(_ http.ResponseWriter, r *http.Request, err error) {
		ctx := r.Context()
		reqID, _ := agd.RequestIDFromContext(ctx)

		l := slogutil.MustLoggerFromContext(ctx).With("req_id", reqID)
		errcoll.Collect(ctx, c.errColl, l, "proxying", err)
	}

	return &linkedIPHandler{
		httpProxy: &httputil.ReverseProxy{
			Rewrite:        rewrite,
			Transport:      transport,
			ErrorLog:       slog.NewLogLogger(c.proxyLogger.Handler(), slog.LevelDebug),
			ModifyResponse: modifyResponse,
			ErrorHandler:   handlerWithError,
		},
		certValidator: c.certValidator,
		errColl:       c.errColl,
		metrics:       c.metrics,
	}
}

// type check
var _ http.Handler = (*linkedIPHandler)(nil)

// ServeHTTP implements the http.Handler interface for *linkedIPProxy.
func (prx *linkedIPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set the Server header here, so that all 404 and 500 responses carry it.
	respHdr := w.Header()
	respHdr.Set(httphdr.Server, agdhttp.UserAgent())

	ctx := r.Context()
	l := slogutil.MustLoggerFromContext(ctx)

	var shouldProxy bool
	if prx.certValidator != nil {
		shouldProxy = prx.certValidator.IsValidWellKnownRequest(ctx, r)
		l.DebugContext(ctx, "cert validation proxy", "should_proxy", shouldProxy)
	} else {
		shouldProxy = shouldProxyRequest(r)
		l.DebugContext(ctx, "linked ip proxy", "should_proxy", shouldProxy)
	}

	if shouldProxy {
		prx.proxyRequest(ctx, l, w, r)
	} else if r.URL.Path == "/robots.txt" {
		serveRobotsDisallow(ctx, prx.metrics, respHdr, w)
	} else {
		http.NotFound(w, r)
	}
}

// proxyRequest proxies r to the target URL.  l, w, and r must not be nil.
//
// TODO(a.garipov): Consider moving some or all this request modification to the
// Director function if there are more handlers like this in the future.
func (prx *linkedIPHandler) proxyRequest(
	ctx context.Context,
	l *slog.Logger,
	w http.ResponseWriter,
	r *http.Request,
) {
	// Remove all proxy headers before sending the request to proxy.
	hdr := r.Header
	hdr.Del(httphdr.CFConnectingIP)
	hdr.Del(httphdr.Forwarded)
	hdr.Del(httphdr.TrueClientIP)
	hdr.Del(httphdr.XRealIP)

	// Set the real IP.
	ip, err := netutil.SplitHost(r.RemoteAddr)
	if err != nil {
		err = fmt.Errorf("websvc: linked ip proxy: getting ip: %w", err)
		prx.errColl.Collect(ctx, err)

		// Send a 500 error, despite the fact that this is probably a client
		// error, because this is the code that the frontend expects.
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	hdr.Set(httphdr.XConnectingIP, ip)

	// Set the request ID.
	reqID := agd.NewRequestID()
	r = r.WithContext(agd.WithRequestID(r.Context(), reqID))
	hdr.Set(httphdr.XRequestID, reqID.String())

	l.DebugContext(ctx, "starting to proxy", "req_id", reqID)

	prx.httpProxy.ServeHTTP(w, r)

	prx.metrics.IncrementReqCount(ctx, RequestTypeLinkedIPProxy)
}

// shouldProxyRequest returns true if the request should be proxied.  Requests
// that should be proxied are the following:
//
//   - GET /linkip/{device_id}/{encrypted}
//   - GET /linkip/{device_id}/{encrypted}/status
//   - POST /ddns/{device_id}/{encrypted}/{domain}
//   - POST /linkip/{device_id}/{encrypted}
//
// TODO(a.garipov):  Use mux routes.
func shouldProxyRequest(r *http.Request) (ok bool) {
	method, urlPath := r.Method, r.URL.Path
	parts := strings.SplitN(strings.TrimPrefix(urlPath, "/"), "/", 5)
	if l := len(parts); l < 3 || l > 4 {
		return false
	}

	switch method {
	case http.MethodGet:
		return shouldProxyGet(parts)
	case http.MethodPost:
		return shouldProxyPost(parts)
	default:
		return false
	}
}

// shouldProxyGet returns true if the GET request should be proxied.  See
// shouldProxy for more info.
func shouldProxyGet(parts []string) (ok bool) {
	l := len(parts)

	return parts[0] == "linkip" &&
		(l == 3 || (l == 4 && parts[3] == "status"))
}

// shouldProxyPost returns true if the Post request should be proxied.  See
// shouldProxy for more info.
func shouldProxyPost(parts []string) (ok bool) {
	l := len(parts)
	firstPart := parts[0]

	return (firstPart == "ddns" && l == 4) ||
		(firstPart == "linkip" && l == 3)
}

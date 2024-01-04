package websvc

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/AdGuardDNS/internal/optlog"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
)

// Linked IP Proxy

// linkedIPProxy proxies selected requests to a remote address.
type linkedIPProxy struct {
	httpProxy *httputil.ReverseProxy
	errColl   errcoll.Interface
	logPrefix string
}

// linkedIPHandler returns a linked IP proxy handler.
func linkedIPHandler(
	apiURL *url.URL,
	errColl errcoll.Interface,
	name string,
	timeout time.Duration,
) (h http.Handler) {
	logPrefix := fmt.Sprintf("websvc: linked ip proxy %s", name)

	// Use a Rewrite func to make sure we send the correct Host header and don't
	// send anything besides the path.
	rewrite := func(r *httputil.ProxyRequest) {
		r.SetURL(apiURL)
		r.Out.Host = apiURL.Host

		// Make sure that all requests are marked with our user agent.
		r.Out.Header.Set(httphdr.UserAgent, agdhttp.UserAgent())
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
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   timeout,
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
	errHdlr := func(_ http.ResponseWriter, r *http.Request, err error) {
		ctx := r.Context()
		reqID, _ := agd.RequestIDFromContext(ctx)
		m, p := r.Method, r.URL.Path
		errcoll.Collectf(ctx, errColl, "%s: proxying %s %s: req %s: %w", logPrefix, m, p, reqID, err)
	}

	return &linkedIPProxy{
		httpProxy: &httputil.ReverseProxy{
			Rewrite:        rewrite,
			Transport:      transport,
			ErrorLog:       log.StdLog(logPrefix, log.DEBUG),
			ModifyResponse: modifyResponse,
			ErrorHandler:   errHdlr,
		},
		errColl:   errColl,
		logPrefix: logPrefix,
	}
}

// type check
var _ http.Handler = (*linkedIPProxy)(nil)

// ServeHTTP implements the http.Handler interface for *linkedIPProxy.
func (prx *linkedIPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set the Server header here, so that all 404 and 500 responses carry it.
	respHdr := w.Header()
	respHdr.Set(httphdr.Server, agdhttp.UserAgent())

	m, p, rAddr := r.Method, r.URL.Path, r.RemoteAddr
	optlog.Debug3("websvc: starting req %s %s from %s", m, p, rAddr)
	defer optlog.Debug3("websvc: finished req %s %s from %s", m, p, rAddr)

	if shouldProxy(m, p) {
		// TODO(a.garipov): Consider moving some or all this request
		// modification to the Director function if there are more handlers like
		// this in the future.

		// Remove all proxy headers before sending the request to proxy.
		hdr := r.Header
		hdr.Del(httphdr.Forwarded)
		hdr.Del(httphdr.TrueClientIP)
		hdr.Del(httphdr.XRealIP)

		// Set the real IP.
		ip, err := netutil.SplitHost(rAddr)
		if err != nil {
			ctx := r.Context()
			prx.errColl.Collect(ctx, fmt.Errorf("%s: getting ip: %w", prx.logPrefix, err))

			// Send a 500 error, despite the fact that this is probably a client
			// error, because this is the code that the frontend expects.
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}

		hdr.Set(httphdr.CFConnectingIP, ip)

		// Set the request ID.
		reqID := agd.NewRequestID()
		r = r.WithContext(agd.WithRequestID(r.Context(), reqID))
		hdr.Set(httphdr.XRequestID, reqID.String())

		log.Debug("%s: proxying %s %s: req %s", prx.logPrefix, m, p, reqID)

		prx.httpProxy.ServeHTTP(w, r)

		metrics.WebSvcLinkedIPProxyRequestsTotal.Inc()
	} else if r.URL.Path == "/robots.txt" {
		serveRobotsDisallow(respHdr, w, prx.logPrefix)
	} else {
		http.NotFound(w, r)
	}
}

// shouldProxy returns true if the request should be proxied.  Requests that
// should be proxied are the following:
//
//   - GET /linkip/{device_id}/{encrypted}
//   - GET /linkip/{device_id}/{encrypted}/status
//   - POST /ddns/{device_id}/{encrypted}/{domain}
//   - POST /linkip/{device_id}/{encrypted}
func shouldProxy(method, urlPath string) (ok bool) {
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

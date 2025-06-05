package websvc

import (
	"context"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"golang.org/x/sys/unix"
)

// type check
var _ http.Handler = (*Service)(nil)

// ServeHTTP implements the [http.Handler] interface for *Service.  This handler
// is used for the non-DoH queries on the DoH server as well as on the
// additional servers, which usually serve this handler over plain HTTP.
func (svc *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if svc == nil {
		http.NotFound(w, r)

		return
	}

	// TODO(a.garipov):  Refactor the 404 and 500 handling and use
	// [httputil.CodeRecorderResponseWriter] instead.
	ctx := r.Context()
	rec := httptest.NewRecorder()
	svc.serveHTTP(ctx, rec, r)

	action, body := svc.processRec(w.Header(), rec)
	w.WriteHeader(rec.Code)
	_, err := w.Write(body)
	if err != nil {
		logWriteError(ctx, action, err)
	}
}

// logWriteError logs err at the appropriate level if ctx contains a logger.
//
// TODO(a.garipov):  This is not a proper solution; remove once dnsserver starts
// adding a logger of its own.
func logWriteError(ctx context.Context, action string, err error) {
	l, ok := slogutil.LoggerFromContext(ctx)
	if ok {
		l.Log(ctx, levelForError(err), "writing response", "action", action, slogutil.KeyError, err)
	}
}

// serveHTTP processes the HTTP request.
func (svc *Service) serveHTTP(
	ctx context.Context,
	rec *httptest.ResponseRecorder,
	r *http.Request,
) {
	// TODO(a.garipov):  Use mux routes.
	switch r.URL.Path {
	case "/dnscheck/test":
		svc.dnsCheck.ServeHTTP(rec, r)

		metrics.WebSvcDNSCheckTestRequestsTotal.Inc()
	case "/robots.txt":
		serveRobotsDisallow(ctx, rec.Header(), rec)
	case "/":
		if svc.rootRedirectURL == "" {
			http.NotFound(rec, r)
		} else {
			http.Redirect(rec, r, svc.rootRedirectURL, http.StatusFound)

			metrics.WebSvcRootRedirectRequestsTotal.Inc()
		}
	default:
		svc.serveDefaultNonDoH(ctx, rec, r)
	}
}

// serveDefaultNonDoH serves either the static content, the well-known proxy
// handler's result, or a 404 page.
func (svc *Service) serveDefaultNonDoH(
	ctx context.Context,
	rec *httptest.ResponseRecorder,
	r *http.Request,
) {
	svc.staticContent.ServeHTTP(rec, r)
	if rec.Code != http.StatusNotFound {
		metrics.WebSvcStaticContentRequestsTotal.Inc()
	} else if svc.certValidator.IsValidWellKnownRequest(ctx, r) {
		// TODO(a.garipov):  Find a better way to reset the result?
		*rec = *httptest.NewRecorder()
		svc.wellKnownProxy.ServeHTTP(rec, r)
	}

	// Assume that most unknown content types are actually plain-text files.
	if h := rec.Header(); h.Get(httphdr.ContentType) == agdhttp.HdrValApplicationOctetStream {
		h.Set(httphdr.ContentType, agdhttp.HdrValTextPlain)
	}
}

// processRec processes the response code in rec and returns the appropriate
// body and a description of the action for logging.  It also sets the necessary
// headers in respHdr.
func (svc *Service) processRec(
	respHdr http.Header,
	rec *httptest.ResponseRecorder,
) (action string, body []byte) {
	switch rec.Code {
	case http.StatusNotFound:
		action = "404 page"
		if len(svc.error404) != 0 {
			body = svc.error404
			respHdr.Set(httphdr.ContentType, agdhttp.HdrValTextHTML)
		}

		metrics.WebSvcError404RequestsTotal.Inc()
	case http.StatusInternalServerError:
		action = "500 page"
		if len(svc.error500) != 0 {
			body = svc.error500
			respHdr.Set(httphdr.ContentType, agdhttp.HdrValTextHTML)
		}

		metrics.WebSvcError500RequestsTotal.Inc()
	default:
		action = "response"
		maps.Copy(respHdr, rec.Header())
	}

	if body == nil {
		body = rec.Body.Bytes()
	}

	return action, body
}

// serveRobotsDisallow writes predefined disallow-all response.
func serveRobotsDisallow(ctx context.Context, hdr http.Header, w http.ResponseWriter) {
	hdr.Set(httphdr.ContentType, agdhttp.HdrValTextPlain)

	_, err := io.WriteString(w, agdhttp.RobotsDisallowAll)
	if err != nil {
		logWriteError(ctx, "robots.txt", err)
	}

	metrics.WebSvcRobotsTxtRequestsTotal.Inc()
}

// levelForError returns a logging level depending on whether err is a network
// or a timeout error.
func levelForError(err error) (lvl slog.Level) {
	if errors.Is(err, os.ErrDeadlineExceeded) ||
		errors.Is(err, unix.EPIPE) ||
		errors.Is(err, unix.ECONNRESET) {
		return slog.LevelDebug
	}

	return slog.LevelError
}

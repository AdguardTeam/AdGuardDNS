package debugsvc

import (
	"log/slog"
	"net/http"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// middleware is the base middleware for AdGuard DNS debug API that adds a
// logger and logs the queries starting and finishing at the given level.
func (svc *Service) middleware(h http.Handler, lvl slog.Level) (wrapped http.Handler) {
	f := func(w http.ResponseWriter, r *http.Request) {
		respHdr := w.Header()
		respHdr.Add(httphdr.Server, agdhttp.UserAgent())

		l := svc.log.With(
			"raddr", r.RemoteAddr,
			"method", r.Method,
			"host", r.Host,
			"request_uri", r.RequestURI,
		)

		ctx := slogutil.ContextWithLogger(r.Context(), l)
		r = r.WithContext(ctx)

		rw := &codeRecorderResponseWriter{
			ResponseWriter: w,
		}

		l.Log(ctx, lvl, "started")
		defer func() { l.Log(ctx, lvl, "finished", "code", rw.code) }()

		h.ServeHTTP(rw, r)
	}

	return http.HandlerFunc(f)
}

// codeRecorderResponseWriter wraps an [http.ResponseWriter] allowing to save
// the response code.
//
// TODO(a.garipov): Process zero code.
//
// TODO(a.garipov): Move to golibs.
type codeRecorderResponseWriter struct {
	http.ResponseWriter

	code int
}

// type check
var _ http.ResponseWriter = (*codeRecorderResponseWriter)(nil)

// WriteHeader implements [http.ResponseWriter] for *codeRecorderResponseWriter.
func (w *codeRecorderResponseWriter) WriteHeader(code int) {
	w.code = code

	w.ResponseWriter.WriteHeader(code)
}

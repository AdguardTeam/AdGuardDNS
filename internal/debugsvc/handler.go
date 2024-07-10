package debugsvc

import (
	"io"
	"net/http"

	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// serveHealthCheck handles the GET /health-check endpoint.
//
// TODO(a.garipov):  Move to golibs.
func serveHealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(httphdr.ContentType, "text/plain")
	w.WriteHeader(http.StatusOK)

	_, err := io.WriteString(w, "OK\n")
	if err != nil {
		ctx := r.Context()
		l := slogutil.MustLoggerFromContext(ctx)
		l.DebugContext(ctx, "writing health-check response", slogutil.KeyError, err)
	}
}

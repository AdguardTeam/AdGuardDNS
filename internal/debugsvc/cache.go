package debugsvc

import (
	"encoding/json"
	"net/http"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// cacheHandler performs debug cache purges.
type cacheHandler struct {
	manager *agdcache.DefaultManager
}

// type check
var _ http.Handler = (*cacheHandler)(nil)

// cachePurgeRequest describes the request to the POST /debug/api/cache/clear
// HTTP API.
type cachePurgeRequest struct {
	// Patterns is the slice of path patterns to match the cache IDs.
	Patterns []string `json:"ids"`
}

// cachePurgeResponse describes the response to the POST /debug/api/cache/clear
// HTTP API.
type cachePurgeResponse struct {
	Results map[string]string `json:"results"`
}

// ServeHTTP implements the [http.Handler] interface for *cacheHandler.
func (h *cacheHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	l := slogutil.MustLoggerFromContext(ctx)

	req := &cachePurgeRequest{}
	err := json.NewDecoder(r.Body).Decode(req)
	if err != nil {
		l.ErrorContext(ctx, "decoding request", slogutil.KeyError, err)
		http.Error(w, err.Error(), http.StatusBadRequest)

		return
	}

	reqIDs, err := h.idsFromReq(req.Patterns)
	if err != nil {
		l.ErrorContext(ctx, "validating request", slogutil.KeyError, err)
		http.Error(w, err.Error(), http.StatusBadRequest)

		return
	}

	resp := &cachePurgeResponse{
		Results: make(map[RefresherID]string, len(reqIDs)),
	}

	for _, id := range reqIDs {
		h.manager.ClearByID(id)
		resp.Results[id] = "ok"
	}

	w.Header().Set(httphdr.ContentType, agdhttp.HdrValApplicationJSON)
	err = json.NewEncoder(w).Encode(resp)
	if err != nil {
		l.ErrorContext(ctx, "writing response", slogutil.KeyError, err)
	}
}

// idsFromReq returns the IDs of matching caches to purge.
func (h *cacheHandler) idsFromReq(patterns []string) (ids []string, err error) {
	ok, err := isWildcard(patterns)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	cacheIDs := h.manager.IDs()
	if ok {
		return cacheIDs, nil
	}

	return matchPatterns(cacheIDs, patterns), nil
}

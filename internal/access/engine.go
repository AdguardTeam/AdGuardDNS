package access

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdurlflt"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/miekg/dns"
)

// blockedHostEngine is a lazy blocklist rules engine.
//
// TODO(a.garipov):  Replace/merge with [custom.Filter].
type blockedHostEngine struct {
	initOnce   *sync.Once
	lazyEngine *urlfilter.DNSEngine
	reqPool    *syncutil.Pool[urlfilter.DNSRequest]
	resPool    *syncutil.Pool[urlfilter.DNSResult]
	metrics    ProfileMetrics
	rules      []string
}

// newBlockedHostEngine creates a new blockedHostEngine.  mtrc must not be nil.
func newBlockedHostEngine(mtrc ProfileMetrics, rules []string) (e *blockedHostEngine) {
	return &blockedHostEngine{
		initOnce: &sync.Once{},
		reqPool: syncutil.NewPool(func() (req *urlfilter.DNSRequest) {
			return &urlfilter.DNSRequest{}
		}),
		resPool: syncutil.NewPool(func() (v *urlfilter.DNSResult) {
			return &urlfilter.DNSResult{}
		}),
		metrics: mtrc,
		rules:   rules,
	}
}

// isBlocked returns true if the req is blocked by this engine.  req must have
// exactly one question.
//
// TODO(s.chzhen):  Use config.
func (e *blockedHostEngine) isBlocked(ctx context.Context, req *dns.Msg) (blocked bool) {
	e.initOnce.Do(func() {
		// TODO(s.chzhen):  Use [timeutil.Clock].
		start := time.Now()

		e.lazyEngine = e.init()

		e.metrics.ObserveProfileInit(ctx, time.Since(start))
	})

	q := req.Question[0]

	host := agdnet.NormalizeQueryDomain(q.Name)

	return matchBlocked(host, q.Qtype, e.lazyEngine, e.reqPool, e.resPool)
}

// init returns new properly initialized dns engine.
func (e *blockedHostEngine) init() (eng *urlfilter.DNSEngine) {
	lists := []filterlist.Interface{
		filterlist.NewBytes(&filterlist.BytesConfig{
			ID:             blocklistFilterID,
			RulesText:      agdurlflt.RulesToBytesLower(e.rules),
			IgnoreCosmetic: true,
		}),
	}

	rulesStrg, err := filterlist.NewRuleStorage(lists)
	if err != nil {
		// Should never happen, since the storage has only one list.
		panic(fmt.Errorf("unexpected access config error: %w", err))
	}

	return urlfilter.NewDNSEngine(rulesStrg)
}

package access

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/stringutil"
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/miekg/dns"
)

// blockedHostEngine is a lazy blocklist rules engine.
//
// TODO(a.garipov):  Replace/merge with [custom.Filter].
type blockedHostEngine struct {
	lazyEngine *urlfilter.DNSEngine
	initOnce   *sync.Once
	rules      []string
}

// newBlockedHostEngine creates a new blockedHostEngine.
func newBlockedHostEngine(rules []string) (e *blockedHostEngine) {
	return &blockedHostEngine{
		rules:    rules,
		initOnce: &sync.Once{},
	}
}

// isBlocked returns true if the req is blocked by this engine.  req must have
// exactly one question.
func (e *blockedHostEngine) isBlocked(req *dns.Msg) (blocked bool) {
	e.initOnce.Do(func() {
		start := time.Now()

		e.lazyEngine = e.init()

		metrics.AccessProfileInitDuration.Observe(time.Since(start).Seconds())
	})

	q := req.Question[0]
	res, matched := e.lazyEngine.MatchRequest(&urlfilter.DNSRequest{
		Hostname: agdnet.NormalizeQueryDomain(q.Name),
		DNSType:  q.Qtype,
	})

	if matched && res.NetworkRule != nil {
		return !res.NetworkRule.Whitelist
	}

	return matched
}

// init returns new properly initialized dns engine.
func (e *blockedHostEngine) init() (eng *urlfilter.DNSEngine) {
	b := &strings.Builder{}
	for _, h := range e.rules {
		stringutil.WriteToBuilder(b, strings.ToLower(h), "\n")
	}

	lists := []filterlist.RuleList{
		&filterlist.StringRuleList{
			ID:             blocklistFilterID,
			RulesText:      b.String(),
			IgnoreCosmetic: true,
		},
	}

	rulesStrg, err := filterlist.NewRuleStorage(lists)
	if err != nil {
		// Should never happen, since the storage has only one list.
		panic(fmt.Errorf("unexpected access config error: %w", err))
	}

	return urlfilter.NewDNSEngine(rulesStrg)
}

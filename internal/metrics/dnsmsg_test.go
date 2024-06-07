package metrics_test

import (
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
)

// type check
var _ dnsmsg.ClonerStat = metrics.ClonerStat{}

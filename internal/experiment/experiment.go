// Package experiment occasionally contains code for one-off experiments.
// Experiments can be enabled using the EXPERIMENTS environment variable, which
// is a comma-separated list of experiment IDs.
//
// Please keep every experiment in its own file.
//
// Since the code living here is short-living, the following requirements do not
// apply:
//
//   - Comments may be skipped.
//   - Some errors may be logged or ignored.
//   - Tests may be lacking.
//   - The environment may be read here as opposed to package cmd.
package experiment

import (
	"log/slog"
	"os"

	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/golibs/stringutil"
	"github.com/prometheus/client_golang/prometheus"
)

func Init(l *slog.Logger) {
	expStr := os.Getenv("EXPERIMENTS")
	if expStr == "" {
		return
	}

	expIDs := stringutil.SplitTrimmed(expStr, ",")
	for _, id := range expIDs {
		switch id {
		// NOTE: Add experiments here in the following format:
		//	case idMyExp:
		//		enableMyExp()
		default:
			l.Error("no such experiment", "id", id)
		}
	}

	enableMetrics()
}

// enableMetrics sets the labels with enabled experiments and sets the gauge
// value to 1.
func enableMetrics() {
	expGauge := metrics.ExperimentGauge(prometheus.Labels{
		// NOTE: Add experiments here in the following format:
		//	idMyExp: metrics.BoolString(expMyExpEnabled),
	})

	expGauge.Set(1)
}

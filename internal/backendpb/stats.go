package backendpb

import (
	"context"
	"log/slog"
	"time"
)

// profilesCallStats is a stateful structure that collects and reports
// statistics about a [ProfileStorage.Profiles] call.
type profilesCallStats struct {
	logger *slog.Logger

	recvStart time.Time
	decStart  time.Time

	initRecv  time.Duration
	totalRecv time.Duration
	totalDec  time.Duration

	numRecv int

	isFullSync bool
}

// startRecv starts the receive timer.
func (s *profilesCallStats) startRecv() {
	s.recvStart = time.Now()
}

// endRecv ends the receive timer and records the results.
func (s *profilesCallStats) endRecv() {
	d := time.Since(s.recvStart)
	if s.numRecv == 0 {
		// Count the initial receive separately, since it is often not
		// representative of an average receive, because this is when gRPC
		// actually performs the call.
		s.initRecv = d
	} else {
		s.totalRecv += d
	}

	s.numRecv++
}

// startDec starts the decoding timer.
func (s *profilesCallStats) startDec() {
	s.decStart = time.Now()
}

// endDec ends the decoding timer and records the results.
func (s *profilesCallStats) endDec() {
	s.totalDec += time.Since(s.decStart)
}

// report writes the statistics to the log and the metrics.
func (s *profilesCallStats) report(ctx context.Context, mtrc ProfileDBMetrics) {
	lvl := slog.LevelDebug
	if s.isFullSync {
		lvl = slog.LevelInfo
	}

	if s.numRecv == 0 {
		s.logger.Log(ctx, lvl, "no recv")

		return
	}

	n := time.Duration(s.numRecv)
	avgRecv := s.totalRecv / n
	avgDec := s.totalDec / n

	s.logger.Log(ctx, lvl, "recv stats", "total", s.totalRecv, "avg", avgRecv, "init", s.initRecv)
	s.logger.Log(ctx, lvl, "decode stats", "total", s.totalDec, "avg", avgDec)

	mtrc.UpdateStats(ctx, avgRecv, avgDec)
}

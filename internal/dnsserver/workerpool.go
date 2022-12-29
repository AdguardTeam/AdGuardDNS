package dnsserver

import (
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/panjf2000/ants/v2"
)

// antsLogger implements the [ants.Logger] interface and writes everything
// using golibs logger.
type antsLogger struct{}

// type check
var _ ants.Logger = (*antsLogger)(nil)

// Printf implements the [ants.Logger] interface for *antsLogger.
func (l *antsLogger) Printf(format string, args ...interface{}) {
	log.Info(format, args...)
}

// newPoolNonblocking creates a new instance of [*ants.Pool] configured optimally
// for using it in DNS servers.
func newPoolNonblocking() (p *ants.Pool) {
	p, err := ants.NewPool(0, ants.WithOptions(ants.Options{
		ExpiryDuration: time.Minute,
		PreAlloc:       false,
		Nonblocking:    true,
		DisablePurge:   false,
		Logger:         &antsLogger{},
	}))
	if err != nil {
		log.Fatalf("failed to init goroutines workerPool: %v", err)
	}

	return p
}

package access

import (
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/AdguardTeam/urlfilter"
)

// ProfileConstructorConfig is the configuration for the [ProfileConstructor].
type ProfileConstructorConfig struct {
	// Clock is used to get the current time.  It must not be nil.
	Clock timeutil.Clock

	// Metrics is used for the collection of the statistics of profile access
	// managers.  It must not be nil.
	Metrics ProfileMetrics

	// Standard is the standard blocker for all profiles which have enabled this
	// feature.  It must not be nil.
	Standard Blocker
}

// ProfileConstructor creates default access managers for profiles.
type ProfileConstructor struct {
	reqPool  *syncutil.Pool[urlfilter.DNSRequest]
	resPool  *syncutil.Pool[urlfilter.DNSResult]
	clock    timeutil.Clock
	metrics  ProfileMetrics
	standard Blocker
}

// NewProfileConstructor returns a properly initialized *ProfileConstructor.
// conf must not be nil.
func NewProfileConstructor(conf *ProfileConstructorConfig) (c *ProfileConstructor) {
	return &ProfileConstructor{
		reqPool: syncutil.NewPool(func() (req *urlfilter.DNSRequest) {
			return &urlfilter.DNSRequest{}
		}),
		resPool: syncutil.NewPool(func() (v *urlfilter.DNSResult) {
			return &urlfilter.DNSResult{}
		}),
		clock:    conf.Clock,
		metrics:  conf.Metrics,
		standard: conf.Standard,
	}
}

// New creates a new access manager for a profile based on the configuration.
// conf must not be nil and must be valid.
func (c *ProfileConstructor) New(conf *ProfileConfig) (p *DefaultProfile) {
	var standard Blocker = EmptyBlocker{}
	if conf.StandardEnabled {
		standard = c.standard
	}

	return newDefaultProfile(&defaultProfileConfig{
		conf:     conf,
		clock:    c.clock,
		reqPool:  c.reqPool,
		resPool:  c.resPool,
		metrics:  c.metrics,
		standard: standard,
	})
}

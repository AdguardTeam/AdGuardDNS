package dnssvc

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
)

// errCollMetricsListener extends the default prometheus.ServerMetricsListener
// and overrides OnPanic and OnError methods.  The point is to collect errors
// from inside the dnsserver.Server in addition to collecting prom metrics.
type errCollMetricsListener struct {
	errColl      errcoll.Interface
	baseListener dnsserver.MetricsListener
}

// type check
var _ dnsserver.MetricsListener = (*errCollMetricsListener)(nil)

// OnRequest implements the dnsserver.MetricsListener interface for
// *errCollMetricsListener.
func (s *errCollMetricsListener) OnRequest(
	ctx context.Context,
	info *dnsserver.QueryInfo,
	rw dnsserver.ResponseWriter,
) {
	s.baseListener.OnRequest(ctx, info, rw)
}

// OnInvalidMsg implements the dnsserver.MetricsListener interface for
// *errCollMetricsListener.
func (s *errCollMetricsListener) OnInvalidMsg(ctx context.Context) {
	s.baseListener.OnInvalidMsg(ctx)
}

// OnQUICAddressValidation implements the dnsserver.MetricsListener interface
// for *errCollMetricsListener.
func (s *errCollMetricsListener) OnQUICAddressValidation(hit bool) {
	s.baseListener.OnQUICAddressValidation(hit)
}

// OnPanic implements the dnsserver.MetricsListener interface for
// *errCollMetricsListener.
func (s *errCollMetricsListener) OnPanic(ctx context.Context, v any) {
	err, ok := v.(error)
	if !ok {
		err = fmt.Errorf("non-error panic: %v", v)
	}

	s.errColl.Collect(ctx, err)
	s.baseListener.OnPanic(ctx, v)
}

// OnError implements the dnsserver.MetricsListener interface for
// *errCollMetricsListener.
func (s *errCollMetricsListener) OnError(ctx context.Context, err error) {
	s.errColl.Collect(ctx, err)
	s.baseListener.OnError(ctx, err)
}

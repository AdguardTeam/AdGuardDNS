package composite

import (
	"context"

	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/urlfilter"
)

// RequestFilter can filter a request based on the request info.
type RequestFilter interface {
	// FilterRequest filters a DNS request based on the information provided
	// about the request.  req must be valid.
	FilterRequest(ctx context.Context, req *filter.Request) (r filter.Result, err error)
}

// RequestFilterUF can filter a request based on the request info and using
// URLFilter data to optimize allocations.
type RequestFilterUF interface {
	// FilterRequestUF filters a DNS request based on the information provided
	// about the request and using URLFilter data to optimize allocations.  req
	// must be valid.  ufReq and ufRes must not be nil and must be reset.
	FilterRequestUF(
		ctx context.Context,
		req *filter.Request,
		ufReq *urlfilter.DNSRequest,
		ufRes *urlfilter.DNSResult,
	) (r filter.Result, err error)
}

// ufRequestFilter is a wrapper around a [RequestFilterUF] that uses the
// provided URLFilter data.
type ufRequestFilter struct {
	flt RequestFilterUF
	req *urlfilter.DNSRequest
	res *urlfilter.DNSResult
}

// type check
var _ RequestFilter = (*ufRequestFilter)(nil)

// FilterRequest implements the [RequestFilter] interface for *ufRequestFilter.
func (f *ufRequestFilter) FilterRequest(
	ctx context.Context,
	req *filter.Request,
) (r filter.Result, err error) {
	f.req.Reset()
	f.res.Reset()

	return f.flt.FilterRequestUF(ctx, req, f.req, f.res)
}

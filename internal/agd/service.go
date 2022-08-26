package agd

import "context"

// Service is the interface for API servers.
type Service interface {
	// Start starts the service.  It must not block.
	Start() (err error)

	// Shutdown gracefully stops the service.  ctx is used to determine
	// a timeout before trying to stop the service less gracefully.
	Shutdown(ctx context.Context) (err error)
}

// type check
var _ Service = EmptyService{}

// EmptyService is an agd.Service that does nothing.
type EmptyService struct{}

// Start implements the Service interface for EmptyService.
func (EmptyService) Start() (err error) { return nil }

// Shutdown implements the Service interface for EmptyService.
func (EmptyService) Shutdown(_ context.Context) (err error) { return nil }

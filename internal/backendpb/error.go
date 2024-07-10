package backendpb

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/metrics"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// fixGRPCError converts a gRPC error into an application error, if necessary.
// That includes gRPC deadlines, which do not match [context.DeadlineExceeded]
// correctly.
//
// It also updates the backend gRPC metrics depending on the type, see
// [metrics.IncGRPCErrorsCounter].
func fixGRPCError(err error) (res error) {
	metricsType := metrics.GRPCErrorTypeOther
	defer func() { metrics.IncGRPCErrorsCounter(metricsType) }()

	s, ok := status.FromError(err)
	if !ok {
		// Return the error as-is.
		return err
	}

	// See https://github.com/grpc/grpc-go/issues/4822.
	//
	// TODO(d.kolyshev):  Remove after the grpc-go issue is fixed.
	if s.Code() == codes.DeadlineExceeded {
		metricsType = metrics.GRPCErrorTypeTimeout

		return fmt.Errorf("grpc: %w; original message: %s", context.DeadlineExceeded, err)
	}

	for _, d := range s.Details() {
		switch structErr := d.(type) {
		case *AuthenticationFailedError:
			metricsType = metrics.GRPCErrorTypeAuthentication

			return &profiledb.AuthenticationFailedError{
				Message: structErr.Message,
			}
		case *BadRequestError:
			metricsType = metrics.GRPCErrorTypeBadRequest

			return &profiledb.BadRequestError{
				Message: structErr.Message,
			}
		case *DeviceQuotaExceededError:
			metricsType = metrics.GRPCErrorTypeDeviceQuota

			return &profiledb.DeviceQuotaExceededError{
				Message: structErr.Message,
			}
		case *RateLimitedError:
			metricsType = metrics.GRPCErrorTypeRateLimit

			return &profiledb.RateLimitedError{
				Message:    structErr.Message,
				RetryDelay: structErr.RetryDelay.AsDuration(),
			}
		}
	}

	// Return the error as-is.
	return err
}

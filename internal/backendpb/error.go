package backendpb

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// fixGRPCError converts a gRPC error into an application error, if necessary.
// That includes gRPC deadlines, which do not match [context.DeadlineExceeded]
// correctly.
//
// It also updates the backend gRPC metrics depending on the type, see
// [GRPCMetrics.IncrementErrorCount].
func fixGRPCError(ctx context.Context, mtrc GRPCMetrics, err error) (res error) {
	metricsType := GRPCErrOther
	defer func() { mtrc.IncrementErrorCount(ctx, metricsType) }()

	s, ok := status.FromError(err)
	if !ok {
		// Return the error as-is.
		return err
	}

	// See https://github.com/grpc/grpc-go/issues/4822.
	//
	// TODO(d.kolyshev):  Remove after the grpc-go issue is fixed.
	if s.Code() == codes.DeadlineExceeded {
		metricsType = GRPCErrTimeout

		return fmt.Errorf("grpc: %w; original message: %s", context.DeadlineExceeded, err)
	}

	for _, d := range s.Details() {
		switch structErr := d.(type) {
		case *AuthenticationFailedError:
			metricsType = GRPCErrAuthentication

			return &profiledb.AuthenticationFailedError{
				Message: structErr.Message,
			}
		case *BadRequestError:
			metricsType = GRPCErrBadRequest

			return &profiledb.BadRequestError{
				Message: structErr.Message,
			}
		case *DeviceQuotaExceededError:
			metricsType = GRPCErrDeviceQuota

			return &profiledb.DeviceQuotaExceededError{
				Message: structErr.Message,
			}
		case *RateLimitedError:
			metricsType = GRPCErrRateLimit

			return &profiledb.RateLimitedError{
				Message:    structErr.Message,
				RetryDelay: structErr.RetryDelay.AsDuration(),
			}
		}
	}

	// Return the error as-is.
	return err
}

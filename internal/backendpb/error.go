package backendpb

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// GRPCError is a type alias for string that contains the gRPC error type.
//
// TODO(s.chzhen):  Rewrite as soon as the import cycle is resolved.
type GRPCError = string

// gRPC errors of [GRPCError] type.
const (
	GRPCErrAuthentication GRPCError = "auth"
	GRPCErrBadRequest     GRPCError = "bad_req"
	GRPCErrDeviceQuota    GRPCError = "dev_quota"
	GRPCErrOther          GRPCError = "other"
	GRPCErrRateLimit      GRPCError = "rate_limit"
	GRPCErrTimeout        GRPCError = "timeout"
)

// fixGRPCError converts a gRPC error into an application error, if necessary.
// That includes gRPC deadlines, which do not match [context.DeadlineExceeded]
// correctly.
//
// It also updates the backend gRPC metrics depending on the type, see
// [Metrics.IncrementGRPCErrorCount].
func fixGRPCError(ctx context.Context, mtrc Metrics, err error) (res error) {
	metricsType := GRPCErrOther
	defer func() { mtrc.IncrementGRPCErrorCount(ctx, metricsType) }()

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

package backendgrpc

import (
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/dnspb"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/internal/backendtest"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/protoadapt"
	"google.golang.org/protobuf/types/known/durationpb"
)

// Common error messages.
const (
	testErrMsgAuthFailed          = "authentication failed"
	testErrMsgBadRequest          = "bad request"
	testErrMsgDeviceQuotaExceeded = "device quota exceeded"
)

// GRPC error details.
var (
	authFailedErr = &dnspb.AuthenticationFailedError{
		Message: testErrMsgAuthFailed,
	}
	badRequestErr = &dnspb.BadRequestError{
		Message: testErrMsgBadRequest,
	}
	notFoundErr = &dnspb.NotFoundError{
		Message: "not found",
	}
	deviceQuotaExceededErr = &dnspb.DeviceQuotaExceededError{
		Message: testErrMsgDeviceQuotaExceeded,
	}
	rateLimitedErr = &dnspb.RateLimitedError{
		Message:    "rate limited",
		RetryDelay: durationpb.New(time.Second),
	}
)

func TestFixGRPCError(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		grpcErr    error
		name       string
		wantErrMsg string
	}{{
		name:       "nil_error",
		grpcErr:    nil,
		wantErrMsg: "",
	}, {
		name:       "grpc_error_ok",
		grpcErr:    status.Error(codes.OK, "OK"),
		wantErrMsg: "",
	}, {
		name:       "not_grpc_error",
		grpcErr:    errors.Error("unexpected error"),
		wantErrMsg: "unexpected error",
	}, {
		name:    "deadline_exceeded",
		grpcErr: status.Error(codes.DeadlineExceeded, "deadline exceeded"),
		wantErrMsg: "grpc: context deadline exceeded; original message: rpc error: code = " +
			"DeadlineExceeded desc = deadline exceeded",
	}, {
		name:       "unknown_error",
		grpcErr:    status.Error(codes.Unknown, "unknown"),
		wantErrMsg: "rpc error: code = Unknown desc = unknown",
	}, {
		name:       "authentication_failed_error",
		grpcErr:    newGRPCErrorWithDetails(t, codes.Unauthenticated, authFailedErr),
		wantErrMsg: testErrMsgAuthFailed,
	}, {
		name:       "bad_request_error",
		grpcErr:    newGRPCErrorWithDetails(t, codes.InvalidArgument, badRequestErr),
		wantErrMsg: testErrMsgBadRequest,
	}, {
		name:       "device_quota_exceeded_error",
		grpcErr:    newGRPCErrorWithDetails(t, codes.Internal, deviceQuotaExceededErr),
		wantErrMsg: testErrMsgDeviceQuotaExceeded,
	}, {
		name:       "not_found_error",
		grpcErr:    newGRPCErrorWithDetails(t, codes.NotFound, notFoundErr),
		wantErrMsg: "not found: certificate not found",
	}, {
		name:       "rate_limited_error",
		grpcErr:    newGRPCErrorWithDetails(t, codes.Aborted, rateLimitedErr),
		wantErrMsg: "rate limited: rate limited; retry in 1s",
	}}

	ctx := testutil.ContextWithTimeout(t, backendtest.Timeout)
	mtrc := EmptyGRPCMetrics{}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := fixGRPCError(ctx, mtrc, tc.grpcErr)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}

// newGRPCErrorWithDetails creates a new GRPC error with the given code and
// details.
func newGRPCErrorWithDetails(
	tb testing.TB,
	code codes.Code,
	details protoadapt.MessageV1,
) (err error) {
	tb.Helper()

	st := status.New(code, code.String())

	stWithDetails, err := st.WithDetails(details)
	require.NoError(tb, err)

	return stWithDetails.Err()
}

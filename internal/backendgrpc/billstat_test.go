package backendgrpc_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/dnspb"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/internal/backendtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/billstat"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestBillStat_Upload(t *testing.T) {
	t.Parallel()

	const (
		wantDeviceID    = "test"
		invalidDeviceID = "invalid"
	)

	wantRecord := &billstat.Record{
		Time:    time.Time{},
		Country: geoip.CountryCY,
		ASN:     1221,
		Queries: 1122,
		Proto:   agd.ProtoDNS,
	}

	records := billstat.Records{
		wantDeviceID:    wantRecord,
		invalidDeviceID: nil,
	}

	onSaveDevicesBillingStat := func(
		srv grpc.ClientStreamingServer[dnspb.DeviceBillingStat, emptypb.Empty],
	) (err error) {
		pt := &testutil.PanicT{}

		for {
			data, recvErr := srv.Recv()
			if recvErr != nil && errors.Is(recvErr, io.EOF) {
				return srv.SendAndClose(&emptypb.Empty{})
			}

			require.NoError(pt, recvErr)

			assert.Equal(pt, wantDeviceID, data.DeviceId)
			assert.Equal(pt, uint32(wantRecord.ASN), data.Asn)
			assert.Equal(pt, string(wantRecord.Country), data.ClientCountry)
			assert.Equal(pt, timestamppb.New(wantRecord.Time), data.LastActivityTime)
			assert.Equal(pt, uint32(wantRecord.Proto), data.Proto)
			assert.Equal(pt, uint32(wantRecord.Queries), data.Queries)
		}
	}

	srv := &testDNSServiceServer{
		OnCreateDeviceByHumanId: func(
			ctx context.Context,
			req *dnspb.CreateDeviceRequest,
		) (resp *dnspb.CreateDeviceResponse, err error) {
			panic(testutil.UnexpectedCall(ctx, req))
		},

		OnGetDNSProfiles: func(
			req *dnspb.DNSProfilesRequest,
			srv grpc.ServerStreamingServer[dnspb.DNSProfile],
		) (err error) {
			panic(testutil.UnexpectedCall(req, srv))
		},

		OnSaveDevicesBillingStat: onSaveDevicesBillingStat,
	}

	grpcSrv := grpc.NewServer(
		grpc.ConnectionTimeout(backendtest.Timeout),
		grpc.Creds(insecure.NewCredentials()),
	)
	dnspb.RegisterDNSServiceServer(grpcSrv, srv)
	endpoint := runLocalGRPCServer(t, grpcSrv)

	errColl := &agdtest.ErrorCollector{
		OnCollect: func(_ context.Context, err error) {
			testutil.AssertErrorMsg(t, `uploading records: device "invalid": null record`, err)
		},
	}

	b, err := backendgrpc.NewBillStat(&backendgrpc.BillStatConfig{
		Logger:      backendtest.Logger,
		ErrColl:     errColl,
		GRPCMetrics: backendgrpc.EmptyGRPCMetrics{},
		Endpoint:    endpoint,
	})
	require.NoError(t, err)

	ctx := context.Background()

	err = b.Upload(ctx, records)
	require.NoError(t, err)
}

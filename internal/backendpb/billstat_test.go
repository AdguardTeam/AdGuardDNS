package backendpb_test

import (
	"context"
	"io"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendpb"
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

	srv := &testDNSServiceServer{
		OnSaveDevicesBillingStat: func(
			srv backendpb.DNSService_SaveDevicesBillingStatServer,
		) (err error) {
			pt := &testutil.PanicT{}

			for {
				data, recvErr := srv.Recv()
				if recvErr != nil && errors.Is(recvErr, io.EOF) {
					return srv.SendAndClose(&emptypb.Empty{})
				}

				require.NoError(t, recvErr)

				assert.Equal(pt, wantDeviceID, data.DeviceId)
				assert.Equal(pt, uint32(wantRecord.ASN), data.Asn)
				assert.Equal(pt, string(wantRecord.Country), data.ClientCountry)
				assert.Equal(pt, timestamppb.New(wantRecord.Time), data.LastActivityTime)
				assert.Equal(pt, uint32(wantRecord.Proto), data.Proto)
				assert.Equal(pt, uint32(wantRecord.Queries), data.Queries)
			}
		},
	}

	l, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	grpcSrv := grpc.NewServer(
		grpc.ConnectionTimeout(1*time.Second),
		grpc.Creds(insecure.NewCredentials()),
	)
	backendpb.RegisterDNSServiceServer(grpcSrv, srv)

	go func() {
		pt := &testutil.PanicT{}

		srvErr := grpcSrv.Serve(l)
		require.NoError(pt, srvErr)
	}()
	t.Cleanup(grpcSrv.GracefulStop)

	errColl := &agdtest.ErrorCollector{
		OnCollect: func(_ context.Context, err error) {
			testutil.AssertErrorMsg(t, `backendpb: device "invalid": null record`, err)
		},
	}

	b, err := backendpb.NewBillStat(&backendpb.BillStatConfig{
		ErrColl: errColl,
		Endpoint: &url.URL{
			Scheme: "grpc",
			Host:   l.Addr().String(),
		},
	})
	require.NoError(t, err)

	ctx := context.Background()

	err = b.Upload(ctx, records)
	require.NoError(t, err)
}

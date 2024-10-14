package backendpb

import (
	"context"
	"fmt"
	"io"
	"net/url"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/billstat"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/errors"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// BillStatConfig is the configuration structure for the business logic backend
// billing statistics uploader.
type BillStatConfig struct {
	// ErrColl is the error collector that is used to collect critical and
	// non-critical errors.
	ErrColl errcoll.Interface

	// Metrics is used for the collection of the protobuf errors.
	Metrics Metrics

	// Endpoint is the backend API URL.  The scheme should be either "grpc" or
	// "grpcs".
	Endpoint *url.URL

	// APIKey is the API key used for authentication, if any.
	APIKey string
}

// NewBillStat creates a new billing statistics uploader.  c must not be nil.
func NewBillStat(c *BillStatConfig) (b *BillStat, err error) {
	client, err := newClient(c.Endpoint)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	return &BillStat{
		errColl: c.ErrColl,
		metrics: c.Metrics,
		client:  client,
		apiKey:  c.APIKey,
	}, nil
}

// BillStat is the implementation of the [billstat.Uploader] interface that
// uploads the billing statistics to the business logic backend.  It is safe for
// concurrent use.
//
// TODO(a.garipov): Consider uniting with [ProfileStorage] into a single
// backendpb.Client.
type BillStat struct {
	errColl errcoll.Interface
	metrics Metrics
	client  DNSServiceClient
	apiKey  string
}

// type check
var _ billstat.Uploader = (*BillStat)(nil)

// Upload implements the [billstat.Uploader] interface for *BillStat.
func (b *BillStat) Upload(ctx context.Context, records billstat.Records) (err error) {
	if len(records) == 0 {
		return nil
	}

	ctx = ctxWithAuthentication(ctx, b.apiKey)
	stream, err := b.client.SaveDevicesBillingStat(ctx)
	if err != nil {
		return fmt.Errorf("opening stream: %w", fixGRPCError(ctx, b.metrics, err))
	}

	for deviceID, record := range records {
		if record == nil {
			reportf(ctx, b.errColl, "device %q: null record", deviceID)

			continue
		}

		sendErr := stream.Send(recordToProtobuf(record, deviceID))
		if sendErr != nil {
			return fmt.Errorf(
				"uploading device %q record: %w",
				deviceID,
				fixGRPCError(ctx, b.metrics, sendErr),
			)
		}
	}

	_, err = stream.CloseAndRecv()
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("finishing stream: %w", err)
	}

	return nil
}

// recordToProtobuf converts a billstat record structure into the protobuf
// structure.
func recordToProtobuf(r *billstat.Record, devID agd.DeviceID) (s *DeviceBillingStat) {
	return &DeviceBillingStat{
		LastActivityTime: timestamppb.New(r.Time),
		DeviceId:         string(devID),
		ClientCountry:    string(r.Country),
		Proto:            uint32(r.Proto),
		Asn:              uint32(r.ASN),
		// #nosec G115 -- r.Queries must not be negative.
		Queries: uint32(r.Queries),
	}
}

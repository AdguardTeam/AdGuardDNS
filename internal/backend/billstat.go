package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdmaps"
	"github.com/AdguardTeam/AdGuardDNS/internal/billstat"
	"github.com/AdguardTeam/golibs/errors"
)

// Billing Statistics Uploader

// BillStatConfig is the configuration structure for the business logic backend
// billing statistics uploader.
type BillStatConfig struct {
	// BaseEndpoint is the base URL to which API paths are appended.
	BaseEndpoint *url.URL
}

// NewBillStat creates a new billing statistics uploader.  c must not be nil.
func NewBillStat(c *BillStatConfig) (b *BillStat) {
	return &BillStat{
		apiURL: c.BaseEndpoint.JoinPath(PathDNSAPIV1DevicesActivity),
		// Assume that the timeouts are handled by the context in Upload.
		http: agdhttp.NewClient(&agdhttp.ClientConfig{}),
	}
}

// BillStat is the implementation of the [billstat.Uploader] interface that
// uploads the billing statistics to the business logic backend.  It is safe for
// concurrent use.
//
// TODO(a.garipov): Consider uniting with [ProfileStorage] into a single
// backend.Client.
type BillStat struct {
	apiURL *url.URL
	http   *agdhttp.Client
}

// type check
var _ billstat.Uploader = (*BillStat)(nil)

// Upload implements the [billstat.Uploader] interface for *BillStat.
func (b *BillStat) Upload(ctx context.Context, records billstat.Records) (err error) {
	if len(records) == 0 {
		return nil
	}

	req := &v1DevicesActivityReq{
		Devices: billStatRecsToReq(records),
	}
	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("encoding billstat req: %w", err)
	}

	reqURL := b.apiURL.Redacted()
	resp, err := b.http.Post(ctx, b.apiURL, agdhttp.HdrValApplicationJSON, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("sending to %s: %w", reqURL, err)
	}
	defer func() { err = errors.WithDeferred(err, resp.Body.Close()) }()

	err = agdhttp.CheckStatus(resp, http.StatusOK)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	return nil
}

// v1DevicesActivityReq is a request to the devices activity HTTP API.
type v1DevicesActivityReq struct {
	Devices []*v1DevicesActivityReqDevice `json:"devices"`
}

// v1DevicesActivityReqDevice is a single device within a request to the devices
// activity HTTP API.
type v1DevicesActivityReqDevice struct {
	// ClientCountry is the detected country of the client's IP address, if any.
	ClientCountry agd.Country `json:"client_country"`

	// DeviceID is the ID of the device.
	DeviceID agd.DeviceID `json:"device_id"`

	// Time is the time of the most recent query from the device, in Unix time
	// in milliseconds.
	Time int64 `json:"time_ms"`

	// ASN is the detected ASN of the client's IP address, if any.
	ASN agd.ASN `json:"asn"`

	// Queries is the total number of Queries the device has performed since the
	// most recent sync.  This value is an int32 to be in sync with the business
	// logic backend which uses this type.  Change it if it is changed there.
	Queries int32 `json:"queries"`

	// Proto is the numeric value of the DNS protocol of the most recent query
	// from the device.  It is a uint8 and not an agd.Protocol to make sure that
	// it always remains numeric even if we implement json.Marshal on
	// agd.Protocol in the future.
	Proto uint8 `json:"proto"`
}

// billStatRecsToReq converts billing statistics records into devices for the
// devices activity HTTP API.
func billStatRecsToReq(records billstat.Records) (devices []*v1DevicesActivityReqDevice) {
	devices = make([]*v1DevicesActivityReqDevice, 0, len(records))
	agdmaps.OrderedRange(records, func(id agd.DeviceID, rec *billstat.Record) (cont bool) {
		devices = append(devices, &v1DevicesActivityReqDevice{
			ClientCountry: rec.Country,
			DeviceID:      id,
			Time:          rec.Time.UnixMilli(),
			ASN:           rec.ASN,
			Queries:       rec.Queries,
			Proto:         uint8(rec.Proto),
		})

		return true
	})

	return devices
}

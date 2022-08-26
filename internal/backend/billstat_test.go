package backend_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/backend"
	"github.com/AdguardTeam/AdGuardDNS/internal/billstat"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBillStat_Upload(t *testing.T) {
	var reqURLStr string
	var body []byte
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pt := testutil.PanicT{}

		reqURLStr = r.URL.String()

		var err error
		body, err = io.ReadAll(r.Body)
		require.NoError(pt, err)

		w.WriteHeader(http.StatusOK)
	})

	// TODO(a.garipov): Don't listen on actual sockets and use piped conns
	// instead.  Perhaps, add these to a new network test utility package in the
	// golibs module.
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)

	c := &backend.BillStatConfig{
		BaseEndpoint: u,
	}

	b := backend.NewBillStat(c)
	require.NotNil(t, b)

	reqTime := time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC)
	records := billstat.Records{
		"dev1234": &billstat.Record{
			Time:    reqTime,
			Country: agd.CountryAD,
			Queries: 123,
			ASN:     1230,
			Proto:   agd.ProtoDoH,
		},
		"dev5678": &billstat.Record{
			Time:    reqTime.Add(1 * time.Second),
			Country: agd.CountryAE,
			Queries: 42,
			ASN:     420,
			Proto:   agd.ProtoDoQ,
		},
	}

	ctx := context.Background()
	err = b.Upload(ctx, records)
	require.NoError(t, err)

	// Compare against a relative URL since the URL inside an HTTP handler
	// seems to always be relative.
	assert.Equal(t, backend.PathDNSAPIV1DevicesActivity, reqURLStr)

	type jobj = map[string]any
	type jarr = []any

	wantData := jobj{
		"devices": jarr{jobj{
			"client_country": "AD",
			"device_id":      "dev1234",
			"time_ms":        1640995200000,
			"queries":        123,
			"asn":            1230,
			"proto":          3,
		}, jobj{
			"client_country": "AE",
			"device_id":      "dev5678",
			"time_ms":        1640995201000,
			"queries":        42,
			"asn":            420,
			"proto":          4,
		}},
	}

	wantBody, err := json.Marshal(wantData)
	require.NoError(t, err)

	assert.JSONEq(t, string(wantBody), string(body))
}

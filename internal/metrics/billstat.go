package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// BillStatBufSize is a gauge with the total count of records in the local
	// billing statistics database.
	BillStatBufSize = promauto.NewGauge(prometheus.GaugeOpts{
		Name:      "buf_size",
		Namespace: namespace,
		Subsystem: subsystemBillStat,
		Help:      "Count of records in the local billstat DB.",
	})

	// BillStatUploadStatus is a gauge with the status of the last billing
	// statistics upload.
	BillStatUploadStatus = promauto.NewGauge(prometheus.GaugeOpts{
		Name:      "bill_stat_upload_status",
		Namespace: namespace,
		Subsystem: subsystemBillStat,
		Help:      "Status of the last billstat upload.",
	})

	// BillStatUploadTimestamp is a gauge with the timestamp of the last billing
	// statistics upload.
	BillStatUploadTimestamp = promauto.NewGauge(prometheus.GaugeOpts{
		Name:      "bill_stat_upload_timestamp",
		Namespace: namespace,
		Subsystem: subsystemBillStat,
		Help:      "Time when the billing statistics were uploaded last time.",
	})
)

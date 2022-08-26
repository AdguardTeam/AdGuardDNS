package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// QueryLogItemsCount is a counter with the total number of query log items
// written to the file.
var QueryLogItemsCount = promauto.NewCounter(prometheus.CounterOpts{
	Name:      "items_total",
	Subsystem: subsystemQueryLog,
	Namespace: namespace,
	Help:      "The total number of query log items written.",
})

// QueryLogItemSize is a histogram with the query log items size.
var QueryLogItemSize = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:      "items_size_bytes",
	Subsystem: subsystemQueryLog,
	Namespace: namespace,
	Help:      "A histogram with the query log items size.",
	// Query log items are measured in bytes. Most of the space might be taken
	// by domain names and filtering rules which might in theory be pretty long,
	// therefore buckets are up to 2000 bytes.
	Buckets: []float64{50, 100, 200, 300, 400, 600, 800, 1000, 2000},
})

// QueryLogWriteDuration is a histogram with the time spent writing a query log
// item to the file.
var QueryLogWriteDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:      "write_duration_seconds",
	Subsystem: subsystemQueryLog,
	Namespace: namespace,
	Help:      "A histogram with the query log items size.",
	// We chose buckets considering that writing to a file is a fast operation.
	// If for some reason it takes over 1ms, something went terribly wrong.
	Buckets: []float64{0.00001, 0.0001, 0.001, 0.01, 0.1, 1},
})

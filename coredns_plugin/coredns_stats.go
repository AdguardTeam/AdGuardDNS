package dnsfilter

import (
	"sync"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	requests             = newDNSCounter("requests_total", "Count of requests seen by dnsfilter.")
	filtered             = newDNSCounter("filtered_total", "Count of requests filtered by dnsfilter.")
	filteredLists        = newDNSCounter("filtered_lists_total", "Count of requests filtered by dnsfilter using lists.")
	filteredSafebrowsing = newDNSCounter("filtered_safebrowsing_total", "Count of requests filtered by dnsfilter using safebrowsing.")
	filteredParental     = newDNSCounter("filtered_parental_total", "Count of requests filtered by dnsfilter using parental.")
	filteredInvalid      = newDNSCounter("filtered_invalid_total", "Count of requests filtered by dnsfilter because they were invalid.")
	whitelisted          = newDNSCounter("whitelisted_total", "Count of requests not filtered by dnsfilter because they are whitelisted.")
	safesearch           = newDNSCounter("safesearch_total", "Count of requests replaced by dnsfilter safesearch.")
	errorsTotal          = newDNSCounter("errors_total", "Count of requests that dnsfilter couldn't process because of transitive errors.")
	elapsedTime          = newDNSHistogram("request_duration", "Histogram of the time (in seconds) each request took.")
)

// entries for single time period (for example all per-second entries)
type statsEntries map[string][statsHistoryElements]float64

// how far back to keep the stats
const statsHistoryElements = 60 + 1 // +1 for calculating delta

// each periodic stat is a map of arrays
type periodicStats struct {
	Entries    statsEntries
	period     time.Duration // how long one entry lasts
	LastRotate time.Time     // last time this data was rotated

	sync.RWMutex
}

type stats struct {
	PerSecond periodicStats
	PerMinute periodicStats
	PerHour   periodicStats
	PerDay    periodicStats
}

// per-second/per-minute/per-hour/per-day stats
var statistics stats

func initPeriodicStats(periodic *periodicStats, period time.Duration) {
	periodic.Entries = statsEntries{}
	periodic.LastRotate = time.Now()
	periodic.period = period
}

func init() {
	purgeStats()
}

func purgeStats() {
	initPeriodicStats(&statistics.PerSecond, time.Second)
	initPeriodicStats(&statistics.PerMinute, time.Minute)
	initPeriodicStats(&statistics.PerHour, time.Hour)
	initPeriodicStats(&statistics.PerDay, time.Hour*24)
}

func (p *periodicStats) Inc(name string, when time.Time) {
	// calculate how many periods ago this happened
	elapsed := int64(time.Since(when) / p.period)
	// trace("%s: %v as %v -> [%v]", name, time.Since(when), p.period, elapsed)
	if elapsed >= statsHistoryElements {
		return // outside of our timeframe
	}
	p.Lock()
	currentValues := p.Entries[name]
	currentValues[elapsed]++
	p.Entries[name] = currentValues
	p.Unlock()
}

func (p *periodicStats) Observe(name string, when time.Time, value float64) {
	// calculate how many periods ago this happened
	elapsed := int64(time.Since(when) / p.period)
	// trace("%s: %v as %v -> [%v]", name, time.Since(when), p.period, elapsed)
	if elapsed >= statsHistoryElements {
		return // outside of our timeframe
	}
	p.Lock()
	{
		countname := name + "_count"
		currentValues := p.Entries[countname]
		value := currentValues[elapsed]
		// trace("Will change p.Entries[%s][%d] from %v to %v", countname, elapsed, value, value+1)
		value++
		currentValues[elapsed] = value
		p.Entries[countname] = currentValues
	}
	{
		totalname := name + "_sum"
		currentValues := p.Entries[totalname]
		currentValues[elapsed] += value
		p.Entries[totalname] = currentValues
	}
	p.Unlock()
}

// counter that wraps around prometheus Counter but also adds to periodic stats
type counter struct {
	name  string // used as key in periodic stats
	value int64
	prom  prometheus.Counter
}

func newDNSCounter(name string, help string) *counter {
	// trace("called")
	c := &counter{}
	c.prom = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnsfilter",
		Name:      name,
		Help:      help,
	})
	c.name = name

	return c
}

func (c *counter) IncWithTime(when time.Time) {
	statistics.PerSecond.Inc(c.name, when)
	statistics.PerMinute.Inc(c.name, when)
	statistics.PerHour.Inc(c.name, when)
	statistics.PerDay.Inc(c.name, when)
	c.value++
	c.prom.Inc()
}

func (c *counter) Inc() {
	c.IncWithTime(time.Now())
}

func (c *counter) Describe(ch chan<- *prometheus.Desc) {
	c.prom.Describe(ch)
}

func (c *counter) Collect(ch chan<- prometheus.Metric) {
	c.prom.Collect(ch)
}

type histogram struct {
	name  string // used as key in periodic stats
	count int64
	total float64
	prom  prometheus.Histogram
}

func newDNSHistogram(name string, help string) *histogram {
	// trace("called")
	h := &histogram{}
	h.prom = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: plugin.Namespace,
		Subsystem: "dnsfilter",
		Name:      name,
		Help:      help,
	})
	h.name = name

	return h
}

func (h *histogram) ObserveWithTime(value float64, when time.Time) {
	statistics.PerSecond.Observe(h.name, when, value)
	statistics.PerMinute.Observe(h.name, when, value)
	statistics.PerHour.Observe(h.name, when, value)
	statistics.PerDay.Observe(h.name, when, value)
	h.count++
	h.total += value
	h.prom.Observe(value)
}

func (h *histogram) Observe(value float64) {
	h.ObserveWithTime(value, time.Now())
}

func (h *histogram) Describe(ch chan<- *prometheus.Desc) {
	h.prom.Describe(ch)
}

func (h *histogram) Collect(ch chan<- prometheus.Metric) {
	h.prom.Collect(ch)
}

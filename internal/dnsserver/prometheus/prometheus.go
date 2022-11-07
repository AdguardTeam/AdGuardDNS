/*
Package prometheus supplies implementation of the metrics listeners interfaces
from the dnsserver child packages. These implementations increment prometheus
metrics.

For instance, if you want to use it with dnsserver.Server, using it is as simple
as this:

	conf.Metrics = &prometheus.ServerMetricsListener{}
	srv := dnsserver.NewServerDNS(conf)

Once it's done, you can use standard methods of exposing prometheus metrics
like using "github.com/prometheus/client_golang/prometheus/promhttp" package.

dnsserver.MetricsListener metrics:

  - "dns_server_request_total" is the number of processed DNS requests.  Labels
    include the common labels: server name, address, network and protocol, and
    also include request-specific labels: "type" is a DNS query type (string);
    "family" is the Addr family. 1 for IPv4, 2 for IPv6, 0 for unknown,
    "network" is "tcp" or "udp".
  - "dns_server_request_duration_seconds" is a histogram with request durations.
  - "dns_server_request_size_bytes" is a histogram with request sizes.
  - "dns_server_response_size_bytes" is a histogram with response sizes.
  - "dns_server_response_rcode_total" is the number of received DNS responses.
    Besides basic labels, it also includes "rcode" label.  "rcode" is either a
    response code string representation or "DROPPED" if there actually was no
    response at all.
  - "dns_server_error_total" is the number of errors occurred in the DNS server.
  - "dns_server_panic_total" is the number of panics occurred in the DNS server.
  - "dns_server_invalid_msg_total" is the number of invalid messages received by
    the DNS server.  It may be just crap bytes, but it also may be incorrect DNS
    messages (i.e. no Question records, unsupported Opcode, etc).
  - "dns_server_quic_addr_validation_lookups" is the number of quic address
    validation cache lookups.  hit=1 means that a cached item was found.

forward.MetricsListener metrics:

  - "dns_forward_request_total" is the number of DNS requests sent to
    an upstream.  There's a single label: the upstream address.
  - "dns_forward_response_rcode_total" is the number of received DNS responses.
    Besides basic labels it also includes "rcode" label.
  - "dns_forward_request_duration_seconds" is a histogram with request
    durations.
  - "dns_forward_error_total" is the number of errors occurred.

cache.MetricsListener metrics:

  - "dns_cache_size" is the total number items in the cache.
  - "dns_cache_hits_total" is the total number of cache hits.
  - "dns_cache_misses_total" is the total number of cache misses.

ratelimit.MetricsListener metrics:

  - "dns_ratelimit_dropped_total" is the total number of rate-limited DNS
    queries.
*/
package prometheus

const (
	namespace          = "dns"
	subsystemServer    = "server"
	subsystemForward   = "forward"
	subsystemCache     = "cache"
	subsystemRateLimit = "ratelimit"
)

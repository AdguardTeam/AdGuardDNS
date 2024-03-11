 #  AdGuard DNS Debug HTTP API

The AdGuard DNS debug HTTP API is served on [`LISTEN_PORT`][env-listen_port] and
contains various private debugging information.

##  Contents

 *  [`GET /dnsdb/csv`](#dnsdb-csv)
 *  [`GET /health-check`](#health-check)
 *  [`GET /metrics`](#metrics)
 *  [`GET /debug/pprof`](#pprof)

[env-listen_port]: environment.md#LISTEN_PORT



##  <a href="#dnsdb-csv" id="dnsdb-csv" name="dnsdb-csv">`GET /dnsdb/csv`</a>

The CSV dump of the current DNSDB statistics.  Example of the output:

```csv
example.com,A,NOERROR,93.184.216.34,42
example.com,AAAA,NOERROR,2606:2800:220:1:248:1893:25c8:1946,123
```

The response is sent with the `Transfer-Encoding` set to `chunked` and with an
HTTP trailer named `X-Error` which describes errors that might have occurred
during the database dump.

 >  [!NOTE]
 >  For legacy software reasons, despite the endpoint being a `GET` one, it
 >  rotates the database, and so changes the internal state.



##  <a href="#health-check" id="health-check" name="health-check">`GET /health-check`</a>

A simple health check API.  Always responds with a `200 OK` status and the
plain-text body `OK`.



##  <a href="#metrics" id="metrics" name="metrics">`GET /metrics`</a>

Prometheus metrics HTTP API.  See the [metrics page][metrics] for more details.

[metrics]: metrics.md



##  <a href="#pprof" id="pprof" name="pprof">`GET /debug/pprof`</a>

The HTTP interface of Go's [PProf HTTP API][pprof api].

[pprof api]: https://pkg.go.dev/net/http/pprof

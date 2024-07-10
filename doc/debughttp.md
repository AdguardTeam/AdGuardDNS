# AdGuard DNS debug HTTP API

The AdGuard DNS debug HTTP API is served on [`LISTEN_PORT`][env-listen_port] and contains various private debugging information.

## Contents

- [`GET /health-check`](#health-check)
- [`GET /metrics`](#metrics)
- [`GET /debug/pprof`](#pprof)
- [`POST /debug/api/refresh`](#api-refresh)
- [`POST /dnsdb/csv`](#dnsdb-csv)

[env-listen_port]: environment.md#LISTEN_PORT

## <a href="#health-check" id="health-check" name="health-check">`GET /health-check`</a>

A simple health check API.  Always responds with a `200 OK` status and the plain-text body `OK`.

## <a href="#metrics" id="metrics" name="metrics">`GET /metrics`</a>

Prometheus metrics HTTP API.  See the [metrics page][metrics] for more details.

[metrics]: metrics.md

## <a href="#pprof" id="pprof" name="pprof">`GET /debug/pprof`</a>

The HTTP interface of Go's [PProf HTTP API][pprof api].

[pprof api]: https://pkg.go.dev/net/http/pprof

## <a href="#api-refresh" id="api-refresh" name="api-refresh">`POST /debug/api/refresh`</a>

Run some refresh jobs manually.  This refresh does not alter the time of the next automatic refresh.

Example request:

```sh
curl -d '{"ids":["*"]}' -v "http://${LISTEN_ADDR}:${LISTEN_PORT}/debug/api/refresh"
```

Request body example:

```json
{
  "ids": [
    "filter_storage",
    "adult_blocking"
  ]
}
```

Supported IDs:

- `adult_blocking`;
- `filter_storage`;
- `newly_registered_domains`;
- `safe_browsing`.

The special ID `*`, when used alone, causes all available refresh tasks to be performed.  Use with caution.

Response body example:

```json
{
  "results": {
    "adult_blocking": "ok",
    "filter_storage": "ok"
  }
}
```

## <a href="#dnsdb-csv" id="dnsdb-csv" name="dnsdb-csv">`POST /dnsdb/csv`</a>

The CSV dump of the current DNSDB statistics.  Example of the output:

```csv
example.com,A,NOERROR,93.184.216.34,42
example.com,AAAA,NOERROR,2606:2800:220:1:248:1893:25c8:1946,123
```

The response is sent with the `Transfer-Encoding` set to `chunked` and with an HTTP trailer named `X-Error` which describes errors that might have occurred during the database dump.

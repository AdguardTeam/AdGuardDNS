# AdGuard DNS debug HTTP API

The AdGuard DNS debug HTTP API is served on [`LISTEN_PORT`][env-listen_port] and contains various private debugging information.

## Contents

- [`GET /health-check`](#health-check)
- [`GET /metrics`](#metrics)
- [`GET /debug/pprof`](#pprof)
- [`POST /debug/api/cache/clear`](#api-cache-clear)
- [`POST /debug/api/refresh`](#api-refresh)
- [`POST /dnsdb/csv`](#dnsdb-csv)

[env-listen_port]: environment.md#LISTEN_PORT

## <a href="#health-check" id="health-check" name="health-check">`GET /health-check`</a>

A simple health check API. Always responds with a `200 OK` status and the plain-text body `OK`.

## <a href="#metrics" id="metrics" name="metrics">`GET /metrics`</a>

Prometheus metrics HTTP API. See the [metrics page][metrics] for more details.

[metrics]: metrics.md

## <a href="#pprof" id="pprof" name="pprof">`GET /debug/pprof`</a>

The HTTP interface of Go's [PProf HTTP API][pprof api].

[pprof api]: https://pkg.go.dev/net/http/pprof

## <a href="#api-cache-clear" id="api-cache-clear" name="api-cache-clear">`POST /debug/api/cache/clear`</a>

Run some cache purges manually. The `ids` is an array of path patterns to match the cache IDs.

Example request:

```sh
curl -d '{"ids":["filters/rulelist/*"]}' -v "http://${LISTEN_ADDR}:${LISTEN_PORT}/debug/api/cache/clear"
```

Request body example:

```json
{
  "ids": [
    "filters/hashprefix/adult_blocking",
    "filters/custom"
  ]
}
```

Supported IDs:

- `dns/ecscache_no_ecs`
- `dns/ecscache_with_ecs`
- `filters/blocked_service/*`
- `filters/hashprefix/adult_blocking`
- `filters/hashprefix/newly_registered_domains`
- `filters/hashprefix/safe_browsing`
- `filters/rulelist/*`
- `filters/safe_search/general_safe_search`
- `geoip/host`
- `geoip/ip`

Note that you can clear the cache of any individual blocked service, e.g. `filters/blocked_service/youtube`, and any filter rule list, e.g. `filters/rulelist/adguard_dns_filter`.

The special ID `*`, when used alone, causes all available caches to be purged. Use with caution.

Response body example:

```json
{
  "results": {
    "filters/hashprefix/adult_blocking": "ok",
    "filters/custom": "ok"
  }
}
```

## <a href="#api-refresh" id="api-refresh" name="api-refresh">`POST /debug/api/refresh`</a>

Run some refresh jobs manually. The `ids` is an array of path patterns to match the refreshers IDs. This refresh does not alter the time of the next automatic refresh.

Example request:

```sh
curl -d '{"ids":["filters/*"]}' -v "http://${LISTEN_ADDR}:${LISTEN_PORT}/debug/api/refresh"
```

Request body example:

```json
{
  "ids": [
    "filters/hashprefix/adult_blocking",
    "filters/storage"
  ]
}
```

Supported IDs:

- `allowlist`
- `billstat`
- `filters/hashprefix/adult_blocking`
- `filters/hashprefix/newly_registered_domains`
- `filters/hashprefix/safe_browsing`
- `filters/storage`
- `geoip`
- `profiledb`
- `profiledb_full`
- `rulestat`
- `ticket_rotator`
- `tlsconfig`

The special ID `*`, when used alone, causes all available refresh tasks to be performed. Note that it performs full profile DB refresh. Use with caution.

Response body example:

```json
{
  "results": {
    "filters/hashprefix/adult_blocking": "ok",
    "filters/storage": "ok"
  }
}
```

## <a href="#dnsdb-csv" id="dnsdb-csv" name="dnsdb-csv">`POST /dnsdb/csv`</a>

The CSV dump of the current DNSDB statistics. Example of the output:

```csv
example.com,A,NOERROR,93.184.216.34,42
example.com,AAAA,NOERROR,2606:2800:220:1:248:1893:25c8:1946,123
```

The response is sent with the `Transfer-Encoding` set to `chunked` and with an HTTP trailer named `X-Error` which describes errors that might have occurred during the database dump.

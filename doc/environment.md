# AdGuard DNS environment configuration

AdGuard DNS uses [environment variables][wiki-env] to store some of the more sensitive configuration. All other configuration is stored in the [configuration file][conf].

## Contents

- [`ADULT_BLOCKING_ENABLED`](#ADULT_BLOCKING_ENABLED)
- [`ADULT_BLOCKING_URL`](#ADULT_BLOCKING_URL)
- [`BACKEND_RATELIMIT_API_KEY`](#BACKEND_RATELIMIT_API_KEY)
- [`BACKEND_RATELIMIT_URL`](#BACKEND_RATELIMIT_URL)
- [`BILLSTAT_API_KEY`](#BILLSTAT_API_KEY)
- [`BILLSTAT_URL`](#BILLSTAT_URL)
- [`BLOCKED_SERVICE_ENABLED`](#BLOCKED_SERVICE_ENABLED)
- [`BLOCKED_SERVICE_INDEX_URL`](#BLOCKED_SERVICE_INDEX_URL)
- [`CONFIG_PATH`](#CONFIG_PATH)
- [`CONSUL_ALLOWLIST_URL`](#CONSUL_ALLOWLIST_URL)
- [`CONSUL_DNSCHECK_KV_URL`](#CONSUL_DNSCHECK_KV_URL)
- [`CONSUL_DNSCHECK_SESSION_URL`](#CONSUL_DNSCHECK_SESSION_URL)
- [`CRASH_OUTPUT_DIR`](#CRASH_OUTPUT_DIR)
- [`CRASH_OUTPUT_ENABLED`](#CRASH_OUTPUT_ENABLED)
- [`CRASH_OUTPUT_PREFIX`](#CRASH_OUTPUT_PREFIX)
- [`CUSTOM_DOMAINS_API_KEY`](#CUSTOM_DOMAINS_API_KEY)
- [`CUSTOM_DOMAINS_CACHE_PATH`](#CUSTOM_DOMAINS_CACHE_PATH)
- [`CUSTOM_DOMAINS_ENABLED`](#CUSTOM_DOMAINS_ENABLED)
- [`CUSTOM_DOMAINS_REFRESH_INTERVAL`](#CUSTOM_DOMAINS_REFRESH_INTERVAL)
- [`CUSTOM_DOMAINS_URL`](#CUSTOM_DOMAINS_URL)
- [`DNSCHECK_CACHE_KV_SIZE`](#DNSCHECK_CACHE_KV_SIZE)
- [`DNSCHECK_KV_TTL`](#DNSCHECK_KV_TTL)
- [`DNSCHECK_KV_TYPE`](#DNSCHECK_KV_TYPE)
- [`DNSCHECK_REMOTEKV_API_KEY`](#DNSCHECK_REMOTEKV_API_KEY)
- [`DNSCHECK_REMOTEKV_URL`](#DNSCHECK_REMOTEKV_URL)
- [`FILTER_CACHE_PATH`](#FILTER_CACHE_PATH)
- [`FILTER_INDEX_URL`](#FILTER_INDEX_URL)
- [`GENERAL_SAFE_ENABLED`](#GENERAL_SAFE_SEARCH_ENABLED)
- [`GENERAL_SAFE_SEARCH_URL`](#GENERAL_SAFE_SEARCH_URL)
- [`GEOIP_ASN_PATH` and `GEOIP_COUNTRY_PATH`](#GEOIP_ASN_PATH)
- [`LINKED_IP_TARGET_URL`](#LINKED_IP_TARGET_URL)
- [`LISTEN_ADDR`](#LISTEN_ADDR)
- [`LISTEN_PORT`](#LISTEN_PORT)
- [`LOG_FORMAT`](#LOG_FORMAT)
- [`LOG_TIMESTAMP`](#LOG_TIMESTAMP)
- [`MAX_THREADS`](#MAX_THREADS)
- [`METRICS_NAMESPACE`](#METRICS_NAMESPACE)
- [`NEW_REG_DOMAINS_ENABLED`](#NEW_REG_DOMAINS_ENABLED)
- [`NEW_REG_DOMAINS_URL`](#NEW_REG_DOMAINS_URL)
- [`NODE_NAME`](#NODE_NAME)
- [`PROFILES_API_KEY`](#PROFILES_API_KEY)
- [`PROFILES_CACHE_PATH`](#PROFILES_CACHE_PATH)
- [`PROFILES_URL`](#PROFILES_URL)
- [`REDIS_DB`](#REDIS_DB)
- [`REDIS_HOST`](#REDIS_HOST)
- [`REDIS_KEY_PREFIX`](#REDIS_KEY_PREFIX)
- [`REDIS_MAX_ACTIVE`](#REDIS_MAX_ACTIVE)
- [`REDIS_MAX_CONN_LIFETIME`](#REDIS_MAX_CONN_LIFETIME)
- [`REDIS_MAX_IDLE`](#REDIS_MAX_IDLE)
- [`REDIS_NETWORK`](#REDIS_NETWORK)
- [`REDIS_IDLE_TIMEOUT`](#REDIS_IDLE_TIMEOUT)
- [`REDIS_PORT`](#REDIS_PORT)
- [`REDIS_WAIT`](#REDIS_WAIT)
- [`QUERYLOG_PATH`](#QUERYLOG_PATH)
- [`QUERYLOG_SEMAPHORE_ENABLED`](#QUERYLOG_SEMAPHORE_ENABLED)
- [`QUERYLOG_SEMAPHORE_LIMIT`](#QUERYLOG_SEMAPHORE_LIMIT)
- [`RATELIMIT_ALLOWLIST_TYPE`](#RATELIMIT_ALLOWLIST_TYPE)
- [`RULESTAT_URL`](#RULESTAT_URL)
- [`SAFE_BROWSING_ENABLED`](#SAFE_BROWSING_ENABLED)
- [`SAFE_BROWSING_URL`](#SAFE_BROWSING_URL)
- [`SENTRY_DSN`](#SENTRY_DSN)
- [`SESSION_TICKET_API_KEY`](#SESSION_TICKET_API_KEY)
- [`SESSION_TICKET_CACHE_PATH`](#SESSION_TICKET_CACHE_PATH)
- [`SESSION_TICKET_INDEX_NAME`](#SESSION_TICKET_INDEX_NAME)
- [`SESSION_TICKET_REFRESH_INTERVAL`](#SESSION_TICKET_REFRESH_INTERVAL)
- [`SESSION_TICKET_TYPE`](#SESSION_TICKET_TYPE)
- [`SESSION_TICKET_URL`](#SESSION_TICKET_URL)
- [`STANDARD_ACCESS_API_KEY`](#STANDARD_ACCESS_API_KEY)
- [`STANDARD_ACCESS_REFRESH_INTERVAL`](#STANDARD_ACCESS_REFRESH_INTERVAL)
- [`STANDARD_ACCESS_TIMEOUT`](#STANDARD_ACCESS_TIMEOUT)
- [`STANDARD_ACCESS_TYPE`](#STANDARD_ACCESS_TYPE)
- [`STANDARD_ACCESS_URL`](#STANDARD_ACCESS_URL)
- [`SSL_KEY_LOG_FILE`](#SSL_KEY_LOG_FILE)
- [`VERBOSE`](#VERBOSE)
- [`WEB_STATIC_DIR_ENABLED`](#WEB_STATIC_DIR_ENABLED)
- [`WEB_STATIC_DIR`](#WEB_STATIC_DIR)
- [`YOUTUBE_SAFE_SEARCH_ENABLED`](#YOUTUBE_SAFE_SEARCH_ENABLED)
- [`YOUTUBE_SAFE_SEARCH_URL`](#YOUTUBE_SAFE_SEARCH_URL)

[conf]:     configuration.md
[wiki-env]: https://en.wikipedia.org/wiki/Environment_variable

## <a href="#ADULT_BLOCKING_ENABLED" id="ADULT_BLOCKING_ENABLED" name="ADULT_BLOCKING_ENABLED">`ADULT_BLOCKING_ENABLED`</a>

When set to `1`, enable the adult-blocking hash-prefix filter. When set to `0`, disable it.

**Default:** `1`.

## <a href="#ADULT_BLOCKING_URL" id="ADULT_BLOCKING_URL" name="ADULT_BLOCKING_URL">`ADULT_BLOCKING_URL`</a>

The HTTP(S) URL of source list of rules for adult blocking filter.

**Default:** No default value, the variable is required if `ADULT_BLOCKING_ENABLED` is set to `1`.

## <a href="#BACKEND_RATELIMIT_API_KEY" id="BACKEND_RATELIMIT_API_KEY" name="BACKEND_RATELIMIT_API_KEY">`BACKEND_RATELIMIT_API_KEY`</a>

The API key to use when authenticating requests to the backend rate limiter API, if any. The API key should be valid as defined by [RFC 6750].

**Default:** **Unset.**

## <a href="#BACKEND_RATELIMIT_URL" id="BACKEND_RATELIMIT_URL" name="BACKEND_RATELIMIT_URL">`BACKEND_RATELIMIT_URL`</a>

The base backend URL for backend rate limiter. Supports gRPC(S) (`grpc://` and `grpcs://`) URLs. See the [external API requirements section][ext-backend-ratelimit].

**Default:** No default value, the variable is required if the [type][conf-ratelimit-type] of rate limiter is `backend` in the configuration file.

[conf-ratelimit-type]:   configuration.md#ratelimit-type
[ext-backend-ratelimit]: externalhttp.md#backend-ratelimit

## <a href="#BILLSTAT_API_KEY" id="BILLSTAT_API_KEY" name="BILLSTAT_API_KEY">`BILLSTAT_API_KEY`</a>

The API key to use when authenticating queries to the billing statistics API, if any. The API key should be valid as defined by [RFC 6750].

**Default:** **Unset.**

[RFC 6750]: https://datatracker.ietf.org/doc/html/rfc6750#section-2.1

## <a href="#BILLSTAT_URL" id="BILLSTAT_URL" name="BILLSTAT_URL">`BILLSTAT_URL`</a>

The base backend URL for backend billing statistics uploader API. Supports gRPC(S) (`grpc://` and `grpcs://`) URLs. See the [external HTTP API requirements section][ext-billstat].

**Default:** No default value, the variable is required if there is at least one [server group][conf-sg] with profiles enabled.

[conf-sg]:      configuration.md#server_groups
[ext-billstat]: externalhttp.md#backend-billstat

## <a href="#BLOCKED_SERVICE_ENABLED" id="BLOCKED_SERVICE_ENABLED" name="BLOCKED_SERVICE_ENABLED">`BLOCKED_SERVICE_ENABLED`</a>

When set to `1`, enable the blocked service filter. When set to `0`, disable it.

**Default:** `1`.

## <a href="#BLOCKED_SERVICE_INDEX_URL" id="BLOCKED_SERVICE_INDEX_URL" name="BLOCKED_SERVICE_INDEX_URL">`BLOCKED_SERVICE_INDEX_URL`</a>

The HTTP(S) URL of the blocked service index file server. See the [external HTTP API requirements section][ext-blocked] on the expected format of the response.

**Default:** No default value, the variable is required if `BLOCKED_SERVICE_ENABLED` is set to `1`.

[ext-blocked]: externalhttp.md#filters-blocked-services

## <a href="#CONFIG_PATH" id="CONFIG_PATH" name="CONFIG_PATH">`CONFIG_PATH`</a>

The path to the configuration file.

**Default:** `./config.yaml`.

## <a href="#CONSUL_ALLOWLIST_URL" id="CONSUL_ALLOWLIST_URL" name="CONSUL_ALLOWLIST_URL">`CONSUL_ALLOWLIST_URL`</a>

The HTTP(S) URL of the Consul instance serving the dynamic part of the rate-limit allowlist. See the [external HTTP API requirements section][ext-consul] on the expected format of the response.

**Default:** No default value, the variable is required if the [type][conf-ratelimit-type] of rate limiter is `consul` in the configuration file.

[ext-consul]: externalhttp.md#consul

## <a href="#CONSUL_DNSCHECK_KV_URL" id="CONSUL_DNSCHECK_KV_URL" name="CONSUL_DNSCHECK_KV_URL">`CONSUL_DNSCHECK_KV_URL`</a>

The HTTP(S) URL of the KV API of the Consul instance used as a key-value database for the DNS server checking. It must end with `/kv/<NAMESPACE>` where `<NAMESPACE>` is any non-empty namespace. If not specified, the [`CONSUL_DNSCHECK_SESSION_URL`](#CONSUL_DNSCHECK_SESSION_URL) is also omitted.

**Default:** **Unset.**

**Example:** `http://localhost:8500/v1/kv/test`

## <a href="#CONSUL_DNSCHECK_SESSION_URL" id="CONSUL_DNSCHECK_SESSION_URL" name="CONSUL_DNSCHECK_SESSION_URL">`CONSUL_DNSCHECK_SESSION_URL`</a>

The HTTP(S) URL of the session API of the Consul instance used as a key-value database for the DNS server checking. If not specified, the [`CONSUL_DNSCHECK_KV_URL`](#CONSUL_DNSCHECK_KV_URL) is also omitted.

**Default:** **Unset.**

## <a href="#CRASH_OUTPUT_DIR" id="CRASH_OUTPUT_DIR" name="CRASH_OUTPUT_DIR">`CRASH_OUTPUT_DIR`</a>

The path to the directory used to create crash reports.  The directory must exist.

**Default:** No default value, the variable is required if `CRASH_OUTPUT_ENABLED` is set to `1`.

## <a href="#CRASH_OUTPUT_ENABLED" id="CRASH_OUTPUT_ENABLED" name="CRASH_OUTPUT_ENABLED">`CRASH_OUTPUT_ENABLED`</a>

When set to `1`, put a crash report to `CRASH_OUTPUT_DIR`.

**Default:** `0`.

## <a href="#CRASH_OUTPUT_PREFIX" id="CRASH_OUTPUT_PREFIX" name="CRASH_OUTPUT_PREFIX">`CRASH_OUTPUT_PREFIX`</a>

The prefix to use for the crash report files.  The variable is required if `CRASH_OUTPUT_ENABLED` is set to `1`.

**Default:** `agdns`.

## <a href="#CUSTOM_DOMAINS_API_KEY" id="CUSTOM_DOMAINS_API_KEY" name="CUSTOM_DOMAINS_API_KEY">`CUSTOM_DOMAINS_API_KEY`</a>

The API key to use when authenticating queries to the backend custom-domain API, if any. The API key should be valid as defined by [RFC 6750].

**Default:** No default value, the variable is required if `CUSTOM_DOMAINS_ENABLED` is set to `1`.

## <a href="#CUSTOM_DOMAINS_CACHE_PATH" id="CUSTOM_DOMAINS_CACHE_PATH" name="CUSTOM_DOMAINS_CACHE_PATH">`CUSTOM_DOMAINS_CACHE_PATH`</a>

The path to directory for storing the downloaded certificate and private-key data.

**Default:** No default value, a valid directory path is required if `CUSTOM_DOMAINS_ENABLED` is set to `1`.

## <a href="#CUSTOM_DOMAINS_ENABLED" id="CUSTOM_DOMAINS_ENABLED" name="CUSTOM_DOMAINS_ENABLED">`CUSTOM_DOMAINS_ENABLED`</a>

When set to `1`, enable the custom-domains feature. When set to `0`, disable it.

**Default:** `1`.

## <a href="#CUSTOM_DOMAINS_REFRESH_INTERVAL" id="CUSTOM_DOMAINS_REFRESH_INTERVAL" name="CUSTOM_DOMAINS_REFRESH_INTERVAL">`CUSTOM_DOMAINS_REFRESH_INTERVAL`</a>

The interval that defines how often to query the backend for the custom-domain data, as a human-readable duration.

**Default:** No default value, a positive value is required if `CUSTOM_DOMAINS_ENABLED` is set to `1`.

**Example:** `1m`

## <a href="#CUSTOM_DOMAINS_URL" id="CUSTOM_DOMAINS_URL" name="CUSTOM_DOMAINS_URL">`CUSTOM_DOMAINS_URL`</a>

The URL of the gRPC(S) API for the custom-domain data.

**Default:** No default value, the variable is required if `CUSTOM_DOMAINS_ENABLED` is set to `1`.

## <a href="#DNSCHECK_CACHE_KV_SIZE" id="DNSCHECK_CACHE_KV_SIZE" name="DNSCHECK_CACHE_KV_SIZE">`DNSCHECK_CACHE_KV_SIZE`</a>

The maximum number of the local cache key-value database entries for the DNS server checking.

**Default:** No default value, a positive value is required if `DNSCHECK_KV_TYPE` is set to `cache`.

**Example:** `1000`

## <a href="#DNSCHECK_KV_TTL" id="DNSCHECK_KV_TTL" name="DNSCHECK_KV_TTL">`DNSCHECK_KV_TTL`</a>

For how long to keep the information about a single user in remote KV, as a human-readable duration.

**Default:** **Unset.**

**Example:** `1m`

## <a href="#DNSCHECK_KV_TYPE" id="DNSCHECK_KV_TYPE" name="DNSCHECK_KV_TYPE">`DNSCHECK_KV_TYPE`</a>

Type of the remote KV storage. Allowed values are `backend`, `cache`, `consul`, and `redis`.

**Default:** **Unset.**

## <a href="#DNSCHECK_REMOTEKV_API_KEY" id="DNSCHECK_REMOTEKV_API_KEY" name="DNSCHECK_REMOTEKV_API_KEY">`DNSCHECK_REMOTEKV_API_KEY`</a>

The API key to use when authenticating queries to the backend key-value database API, if any. The API key should be valid as defined by [RFC 6750].

**Default:** **Unset.**

## <a href="#DNSCHECK_REMOTEKV_URL" id="DNSCHECK_REMOTEKV_URL" name="DNSCHECK_REMOTEKV_URL">`DNSCHECK_REMOTEKV_URL`</a>

The base backend URL used as a key-value database for the DNS server checking. Supports gRPC(S) (`grpc://` and`grpcs://`) URLs. See the [external API requirements section][ext-backend-dnscheck].

**Default:** **Unset.**

[ext-backend-dnscheck]: externalhttp.md#backend-dnscheck

## <a href="#FILTER_CACHE_PATH" id="FILTER_CACHE_PATH" name="FILTER_CACHE_PATH">`FILTER_CACHE_PATH`</a>

The path to the directory used to store the cached version of all filters and filter indexes.

**Default:** `./filters/`.

## <a href="#FILTER_INDEX_URL" id="FILTER_INDEX_URL" name="FILTER_INDEX_URL">`FILTER_INDEX_URL`</a>

The HTTP(S) URL or a hostless file URI (e.g. `file:///tmp/filters.json`) of the filtering rule index file server. See the [external HTTP API requirements section][ext-lists] on the expected format of the response.

**Default:** No default value, the variable is **required.**

[ext-lists]: externalhttp.md#filters-lists

## <a href="#GENERAL_SAFE_SEARCH_ENABLED" id="GENERAL_SAFE_SEARCH_ENABLED" name="GENERAL_SAFE_SEARCH_ENABLED">`GENERAL_SAFE_SEARCH_ENABLED`</a>

When set to `1`, enable the general safe search filter. When set to `0`, disable it.

**Default:** `1`.

## <a href="#GENERAL_SAFE_SEARCH_URL" id="GENERAL_SAFE_SEARCH_URL" name="GENERAL_SAFE_SEARCH_URL">`GENERAL_SAFE_SEARCH_URL`</a>

The HTTP(S) URL of the list of general safe search rewriting rules. See the [external HTTP API requirements section][ext-general] on the expected format of the response.

**Default:** No default value, the variable is required if `GENERAL_SAFE_SEARCH_ENABLED` is set to `1`.

[ext-general]: externalhttp.md#filters-safe-search

## <a href="#GEOIP_ASN_PATH" id="GEOIP_ASN_PATH" name="GEOIP_ASN_PATH">`GEOIP_ASN_PATH` and `GEOIP_COUNTRY_PATH`</a>

Paths to the files containing MaxMind GeoIP databases: for ASNs and for countries and continents respectively.

**Default:** `./asn.mmdb` and `./country.mmdb`.

## <a href="#LINKED_IP_TARGET_URL" id="LINKED_IP_TARGET_URL" name="LINKED_IP_TARGET_URL">`LINKED_IP_TARGET_URL`</a>

The target HTTP(S) URL to which linked IP API requests are proxied. In case [linked IP and dynamic DNS][conf-web-linked_ip] web server is configured, the variable is required. See the [external HTTP API requirements section][ext-linked_ip].

Certificate validation requests to DoH servers are also proxied to this URL when both DoH and profiles are enabled.

**Default:** **Unset.**

[conf-web-linked_ip]: configuration.md#web-linked_ip
[ext-linked_ip]: externalhttp.md#backend-linkip

## <a href="#LISTEN_ADDR" id="LISTEN_ADDR" name="LISTEN_ADDR">`LISTEN_ADDR`</a>

The IP address on which to bind the [debug HTTP API][debughttp].

**Default:** `127.0.0.1`.

[debughttp]: debughttp.md

## <a href="#LISTEN_PORT" id="LISTEN_PORT" name="LISTEN_PORT">`LISTEN_PORT`</a>

The port on which to bind the [debug HTTP API][debughttp], which includes the health check, Prometheus, `pprof`, and other endpoints.

**Default:** `8181`.

## <a href="#LOG_FORMAT" id="LOG_FORMAT" name="LOG_FORMAT">`LOG_FORMAT`</a>

The format for the server logs:

- `text`: Structured text format, it is the default value.

- `default`: Simple and human-readable plain-text format.

- `json`: JSON format.

- `jsonhybrid`: JSON with a schema consisting of `level`, `msg`, and `time` properties.

## <a href="#LOG_TIMESTAMP" id="LOG_TIMESTAMP" name="LOG_TIMESTAMP">`LOG_TIMESTAMP`</a>

If `1`, show timestamps in the plain text logs. If `0`, don't show the timestamps.

**Default:** `1`.

## <a href="#MAX_THREADS" id="MAX_THREADS" name="MAX_THREADS">`MAX_THREADS`</a>

If greater than zero, sets the maximum number of threads for the Go runtime. If zero, the number remains the default one, which is 10 000. It must not be negative.

**Default:** `0`.

## <a href="#METRICS_NAMESPACE" id="METRICS_NAMESPACE" name="METRICS_NAMESPACE">`METRICS_NAMESPACE`</a>

The namespace to be used for Prometheus metrics. It must be a valid Prometheus metric label.

**Default:** `dns`.

## <a href="#NEW_REG_DOMAINS_ENABLED" id="NEW_REG_DOMAINS_ENABLED" name="NEW_REG_DOMAINS_ENABLED">`NEW_REG_DOMAINS_ENABLED`</a>

When set to `1`, enable the newly-registered domains hash-prefix filter. When set to `0`, disable it.

**Default:** `1`.

## <a href="#NEW_REG_DOMAINS_URL" id="NEW_REG_DOMAINS_URL" name="NEW_REG_DOMAINS_URL">`NEW_REG_DOMAINS_URL`</a>

The HTTP(S) URL of source list of rules for newly registered domains safe browsing filter.

**Default:** No default value, the variable is required if `NEW_REG_DOMAINS_ENABLED` is set to `1`.

## <a href="#NODE_NAME" id="NODE_NAME" name="NODE_NAME">`NODE_NAME`</a>

The name of this server node.  Used in [debug DNS API][debug-dns-api] and [DNS checking][http-dnscheck].

[debug-dns-api]: debugdns.md#additional-node-name
[http-dnscheck]: http.md#dnscheck-test

**Default:** No default value, the variable is **required.**

## <a href="#PROFILES_API_KEY" id="PROFILES_API_KEY" name="PROFILES_API_KEY">`PROFILES_API_KEY`</a>

The API key to use when authenticating queries to the profiles API, if any. The API key should be valid as defined by [RFC 6750].

**Default:** **Unset.**

## <a href="#PROFILES_CACHE_PATH" id="PROFILES_CACHE_PATH" name="PROFILES_CACHE_PATH">`PROFILES_CACHE_PATH`</a>

The path to the profile cache file:

- `none` means that the profile caching is disabled.

- A file with the extension `.pb` means that the profiles are cached in the protobuf format.

    Use the following command to inspect the cache, assuming that the version is correct:

    ```sh
    protoc\
        --decode\
        profiledb.FileCache\
        ./internal/profiledb/internal/filecachepb/filecache.proto\
        < /path/to/profilecache.pb
    ```

The profile cache is read on start and is later updated on every [full refresh][conf-backend-full_refresh_interval].

**Default:** `./profilecache.pb`.

[conf-backend-full_refresh_interval]: configuration.md#backend-full_refresh_interval

## <a href="#PROFILES_MAX_RESP_SIZE" id="PROFILES_MAX_RESP_SIZE" name="PROFILES_MAX_RESP_SIZE">`PROFILES_MAX_RESP_SIZE`</a>

The maximum size of the response from the profiles API in a human-readable format.

**Default:** `64MB`.

## <a href="#PROFILES_URL" id="PROFILES_URL" name="PROFILES_URL">`PROFILES_URL`</a>

The base backend URL for profiles API. Supports gRPC(S) (`grpc://` and `grpcs://`) URLs. See the [external API requirements section][ext-profiles].

**Default:** No default value, the variable is required if there is at least one [server group][conf-sg] with profiles enabled.

[ext-profiles]: externalhttp.md#backend-profiles

## <a href="#REDIS_DB" id="REDIS_DB" name="REDIS_DB">`REDIS_DB`</a>

The index of Redis database to use.

**Default:** `0`.

## <a href="#REDIS_HOST" id="REDIS_HOST" name="REDIS_HOST">`REDIS_HOST`</a>

Redis server address.  Can be an IP address or a hostname.

**Default:** `localhost`, the variable is required if `DNSCHECK_KV_TYPE` is set to `redis`.

## <a href="#REDIS_KEY_PREFIX" id="REDIS_KEY_PREFIX" name="REDIS_KEY_PREFIX">`REDIS_KEY_PREFIX`</a>

The prefix for Redis keys.

**Default:** `agdns`.

## <a href="#REDIS_MAX_ACTIVE" id="REDIS_MAX_ACTIVE" name="REDIS_MAX_ACTIVE">`REDIS_MAX_ACTIVE`</a>

The maximum number of active Redis connections.

**Default:** `100`.

## <a href="#REDIS_MAX_CONN_LIFETIME" id="REDIS_MAX_CONN_LIFETIME" name="REDIS_MAX_CONN_LIFETIME">`REDIS_MAX_CONN_LIFETIME`</a>

The maximum total duration of connections in a pool.

**Default:** `0s`, which means that the lifetime is not limited.

## <a href="#REDIS_MAX_IDLE" id="REDIS_MAX_IDLE" name="REDIS_MAX_IDLE">`REDIS_MAX_IDLE`</a>

The maximum number of idle Redis connections.

**Default:** `100`.

## <a href="#REDIS_NETWORK" id="REDIS_NETWORK" name="REDIS_NETWORK">`REDIS_NETWORK`</a>

Kind of IP protocol version to use:

- `ip` means both;
- `ip4` means IPv4 only;
- `ip6` means IPv6 only.

All other values are invalid.

**Default:** `ip4`.

## <a href="#REDIS_IDLE_TIMEOUT" id="REDIS_IDLE_TIMEOUT" name="REDIS_IDLE_TIMEOUT">`REDIS_IDLE_TIMEOUT`</a>

How long until idle Redis connections are closed, as a human-readable duration.

**Default:** `5m`.

## <a href="#REDIS_PORT" id="REDIS_PORT" name="REDIS_PORT">`REDIS_PORT`</a>

Redis server port.

**Default:** `6379`.

## <a href="#REDIS_WAIT" id="REDIS_WAIT" name="REDIS_WAIT">`REDIS_WAIT`</a>

It selects if the pool must wait for a connection once the `REDIS_MAX_ACTIVE` limit is reached.

**Default:** `1`, which means to wait.

## <a href="#QUERYLOG_PATH" id="QUERYLOG_PATH" name="QUERYLOG_PATH">`QUERYLOG_PATH`</a>

The path to the file into which the query log is going to be written.

**Default:** `./querylog.jsonl`.

## <a href="#QUERYLOG_SEMAPHORE_ENABLED" id="QUERYLOG_SEMAPHORE_ENABLED" name="QUERYLOG_SEMAPHORE_ENABLED">`QUERYLOG_SEMAPHORE_ENABLED`</a>

If `1`, enabled the querylog semaphore used to limit the parallelism of writing to the querylog and thus reducing the amount of OS threads that are created.

**Default:** `0`.

## <a href="#QUERYLOG_SEMAPHORE_LIMIT" id="QUERYLOG_SEMAPHORE_LIMIT" name="QUERYLOG_SEMAPHORE_LIMIT">`QUERYLOG_SEMAPHORE_LIMIT`</a>

The amount of writes to the querylog that can run in parallel.

**Default:** No default value, the variable is required if `QUERYLOG_SEMAPHORE_ENABLED` is set to `1`.

## <a href="#RATELIMIT_ALLOWLIST_TYPE" id="RATELIMIT_ALLOWLIST_TYPE" name="RATELIMIT_ALLOWLIST_TYPE">`RATELIMIT_ALLOWLIST_TYPE`</a>

Defines where the rate limit settings are received from. Allowed values are `backend` and `consul`.

**Default:** **Unset.**

**Example:** `consul`.

## <a href="#RULESTAT_URL" id="RULESTAT_URL" name="RULESTAT_URL">`RULESTAT_URL`</a>

The HTTP(S) URL to send filtering rule list statistics to. If empty or unset, the collection of filtering rule statistics is disabled. See the [external HTTP API requirements section][ext-rulestat] on the expected format of the response.

**Default:** **Unset.**

**Example:** `https://stats.example.com/db`

[ext-rulestat]: externalhttp.md#rulestat

## <a href="#SAFE_BROWSING_ENABLED" id="SAFE_BROWSING_ENABLED" name="SAFE_BROWSING_ENABLED">`SAFE_BROWSING_ENABLED`</a>

When set to `1`, enable the safe-browsing hash-prefix filter. When set to `0`, disable it.

**Default:** `1`.

## <a href="#SAFE_BROWSING_URL" id="SAFE_BROWSING_URL" name="SAFE_BROWSING_URL">`SAFE_BROWSING_URL`</a>

The HTTP(S) URL of source list of rules for dangerous domains safe browsing filter.

**Default:** No default value, the variable is required if `SAFE_BROWSING_ENABLED` is set to `1`.

## <a href="#SENTRY_DSN" id="SENTRY_DSN" name="SENTRY_DSN">`SENTRY_DSN`</a>

Sentry error collector address. The special value `stderr` makes AdGuard DNS print these errors to standard error.

**Default:** `stderr`.

## <a href="#SESSION_TICKET_API_KEY" id="SESSION_TICKET_API_KEY" name="SESSION_TICKET_API_KEY">`SESSION_TICKET_API_KEY`</a>

The API key to use when authenticating queries to the remote TLS session ticket storage, if [`SESSION_TICKET_TYPE`](#SESSION_TICKET_TYPE) is set to `remote`. The API key should be valid as defined by [RFC 6750].

**Default:** **Unset.**

## <a href="#SESSION_TICKET_CACHE_PATH" id="SESSION_TICKET_CACHE_PATH" name="SESSION_TICKET_CACHE_PATH">`SESSION_TICKET_CACHE_PATH`</a>

The path to directory for storing downloaded TLS session tickets, when [`SESSION_TICKET_TYPE`](#SESSION_TICKET_TYPE) is set to `remote`. If directory doesn't exist, it will be created on first successful start.

**Default:** **Unset.**

## <a href="#SESSION_TICKET_INDEX_NAME" id="SESSION_TICKET_INDEX_NAME" name="SESSION_TICKET_INDEX_NAME">`SESSION_TICKET_INDEX_NAME`</a>

The base name of the file to store downloaded TLS session tickets index, when [`SESSION_TICKET_TYPE`](#SESSION_TICKET_TYPE) is set to `remote`. This name will invalidate the received tickets with the same name. If the file doesn't exist, it will be created on first successful start. The expected format of the file is as follows:

```json
{
    "tickets": {
        "ticket_1": {
            "last_update": "2006-01-02T15:04:05.999999999Z07:00"
        },
        // …
        "ticket_n": {
            "last_update": "2006-01-02T15:04:10.999999999Z07:00"
        }
    }
}
```

**Default:** **Unset.**

## <a href="#SESSION_TICKET_REFRESH_INTERVAL" id="SESSION_TICKET_REFRESH_INTERVAL" name="SESSION_TICKET_REFRESH_INTERVAL">`SESSION_TICKET_REFRESH_INTERVAL`</a>

The interval between TLS session ticket rotations, as a human-readable duration.

**Default:** **Unset.**

## <a href="#SESSION_TICKET_TYPE" id="SESSION_TICKET_TYPE" name="SESSION_TICKET_TYPE">`SESSION_TICKET_TYPE`</a>

The type of TLS session ticket storage. Its possible values are: `local` and `remote`.  When set to `remote`, the [`SESSION_TICKET_API_KEY`](#SESSION_TICKET_API_KEY), [`SESSION_TICKET_CACHE_PATH`](#SESSION_TICKET_CACHE_PATH), [`SESSION_TICKET_INDEX_NAME`](#SESSION_TICKET_INDEX_NAME), and [`SESSION_TICKET_URL`](#SESSION_TICKET_URL) variables are required.

**Default:** **Unset.**

## <a href="#SESSION_TICKET_URL" id="SESSION_TICKET_URL" name="SESSION_TICKET_URL">`SESSION_TICKET_URL`</a>

The base backend URL used as a TLS session ticket storage, when [`SESSION_TICKET_TYPE`](#SESSION_TICKET_TYPE) is set to `remote`. Supports gRPC(S) (`grpc://` and`grpcs://`) URLs. See the [external API requirements section][ext-backend-dnscheck]. **The `grpcs://` scheme is preferred because TLS session tickets are considered sensitive information.**

**Default:** **Unset.**

## <a href="#STANDARD_ACCESS_API_KEY" id="STANDARD_ACCESS_API_KEY" name="STANDARD_ACCESS_API_KEY">`STANDARD_ACCESS_API_KEY`</a>

The API key to use when authenticating requests to the standard access settings storage API, if [`STANDARD_ACCESS_TYPE`](#STANDARD_ACCESS_TYPE) is set to `backend`. The API key should be valid as defined by [RFC 6750].

**Default:** **Unset.**

## <a href="#STANDARD_ACCESS_REFRESH_INTERVAL" id="STANDARD_ACCESS_REFRESH_INTERVAL" name="STANDARD_ACCESS_REFRESH_INTERVAL">`STANDARD_ACCESS_REFRESH_INTERVAL`</a>

The interval between standard access settings updates, when [`STANDARD_ACCESS_TYPE`](#STANDARD_ACCESS_TYPE) is set to `backend`, as a human-readable duration.

**Default:** **Unset.**

## <a href="#STANDARD_ACCESS_TIMEOUT" id="STANDARD_ACCESS_TIMEOUT" name="STANDARD_ACCESS_TIMEOUT">`STANDARD_ACCESS_TIMEOUT`</a>

The timeout for standard access settings updates, when [`STANDARD_ACCESS_TYPE`](#STANDARD_ACCESS_TYPE) is set to `backend`, as a human-readable duration.

**Default:** **Unset.**

## <a href="#STANDARD_ACCESS_TYPE" id="STANDARD_ACCESS_TYPE" name="STANDARD_ACCESS_TYPE">`STANDARD_ACCESS_TYPE`</a>

The type of standard access settings storage. Its possible values are: `off` and `backend`. When set to `backend`, the [`STANDARD_ACCESS_API_KEY`](#STANDARD_ACCESS_API_KEY), [`STANDARD_ACCESS_REFRESH_INTERVAL`](#STANDARD_ACCESS_REFRESH_INTERVAL), [`STANDARD_ACCESS_TIMEOUT`](#STANDARD_ACCESS_TIMEOUT), and [`STANDARD_ACCESS_URL`](#STANDARD_ACCESS_URL) variables are required.

**Default:** **Unset.**

## <a href="#STANDARD_ACCESS_URL" id="STANDARD_ACCESS_URL" name="STANDARD_ACCESS_URL">`STANDARD_ACCESS_URL`</a>

The base backend URL used as a standard access settings storage, when [`STANDARD_ACCESS_TYPE`](#STANDARD_ACCESS_TYPE) is set to `backend`. Supports gRPC(S) (`grpc://` and`grpcs://`) URLs. See the [external API requirements section][ext-backend-dnscheck].

**Default:** **Unset.**

## <a href="#SSL_KEY_LOG_FILE" id="SSL_KEY_LOG_FILE" name="SSL_KEY_LOG_FILE">`SSL_KEY_LOG_FILE`</a>

If set, TLS key logs are written to this file to allow other programs (i.e. Wireshark) to decrypt packets. **Must only be used for debug purposes**.

**Default:** **Unset.**

## <a href="#VERBOSE" id="VERBOSE" name="VERBOSE">`VERBOSE`</a>

- `2`: Enables trace logging.

- `1`: Enables debug logging.

- `0`: The default level of verbosity: only info logs are printed.

**Default:** `0`.

## <a href="#WEB_STATIC_DIR_ENABLED" id="WEB_STATIC_DIR_ENABLED" name="WEB_STATIC_DIR_ENABLED">`WEB_STATIC_DIR_ENABLED`</a>

When set to `1`, use `WEB_STATIC_DIR` as the source of the static content.

**Default:** `0`.

## <a href="#WEB_STATIC_DIR" id="WEB_STATIC_DIR" name="WEB_STATIC_DIR">`WEB_STATIC_DIR`</a>

The absolute path to the directory used to serve static content.  The directory must exist.

The value of the `Content-Type` header is guessed from the files' contents.  Other headers cannot be modified.  If the content type of a file cannot be guessed, `text/plain` is used.

**Default:** No default value, the variable is required if `WEB_STATIC_DIR_ENABLED` is set to `1`.

## <a href="#YOUTUBE_SAFE_SEARCH_ENABLED" id="YOUTUBE_SAFE_SEARCH_ENABLED" name="YOUTUBE_SAFE_SEARCH_ENABLED">`YOUTUBE_SAFE_SEARCH_ENABLED`</a>

When set to `1`, enable the youtube safe search filter. When set to `0`, disable it.

**Default:** `1`.

## <a href="#YOUTUBE_SAFE_SEARCH_URL" id="YOUTUBE_SAFE_SEARCH_URL" name="YOUTUBE_SAFE_SEARCH_URL">`YOUTUBE_SAFE_SEARCH_URL`</a>

The HTTP(S) URL of the list of YouTube-specific safe search rewriting rules. See the [external HTTP API requirements section][ext-general] on the expected format of the response.

**Default:** No default value, the variable is required if `YOUTUBE_SAFE_SEARCH_ENABLED` is set to `1`.

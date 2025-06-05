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
- [`DNSCHECK_CACHE_KV_SIZE`](#DNSCHECK_CACHE_KV_SIZE)
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
- [`METRICS_NAMESPACE`](#METRICS_NAMESPACE)
- [`NEW_REG_DOMAINS_ENABLED`](#NEW_REG_DOMAINS_ENABLED)
- [`NEW_REG_DOMAINS_URL`](#NEW_REG_DOMAINS_URL)
- [`PROFILES_API_KEY`](#PROFILES_API_KEY)
- [`PROFILES_CACHE_PATH`](#PROFILES_CACHE_PATH)
- [`PROFILES_URL`](#PROFILES_URL)
- [`REDIS_ADDR`](#REDIS_ADDR)
- [`REDIS_KEY_PREFIX`](#REDIS_KEY_PREFIX)
- [`REDIS_MAX_ACTIVE`](#REDIS_MAX_ACTIVE)
- [`REDIS_MAX_IDLE`](#REDIS_MAX_IDLE)
- [`REDIS_IDLE_TIMEOUT`](#REDIS_IDLE_TIMEOUT)
- [`REDIS_PORT`](#REDIS_PORT)
- [`QUERYLOG_PATH`](#QUERYLOG_PATH)
- [`RULESTAT_URL`](#RULESTAT_URL)
- [`SAFE_BROWSING_ENABLED`](#SAFE_BROWSING_ENABLED)
- [`SAFE_BROWSING_URL`](#SAFE_BROWSING_URL)
- [`SENTRY_DSN`](#SENTRY_DSN)
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

**Example:** `http://localhost:8500/v1/session/create`

## <a href="#DNSCHECK_CACHE_KV_SIZE" id="DNSCHECK_CACHE_KV_SIZE" name="DNSCHECK_CACHE_KV_SIZE">`DNSCHECK_CACHE_KV_SIZE`</a>

The maximum number of the local cache key-value database entries for the DNS server checking.

**Default:** No default value, a positive value is required if the [type][conf-dnscheck-type] of the database is set to `cache`.

**Example:** `1000`

[conf-dnscheck-type]: configuration.md#check-kv-type

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

## <a href="#METRICS_NAMESPACE" id="METRICS_NAMESPACE" name="METRICS_NAMESPACE">`METRICS_NAMESPACE`</a>

The namespace to be used for Prometheus metrics. It must be a valid Prometheus metric label.

**Default:** `dns`.

## <a href="#NEW_REG_DOMAINS_ENABLED" id="NEW_REG_DOMAINS_ENABLED" name="NEW_REG_DOMAINS_ENABLED">`NEW_REG_DOMAINS_ENABLED`</a>

When set to `1`, enable the newly-registered domains hash-prefix filter. When set to `0`, disable it.

**Default:** `1`.

## <a href="#NEW_REG_DOMAINS_URL" id="NEW_REG_DOMAINS_URL" name="NEW_REG_DOMAINS_URL">`NEW_REG_DOMAINS_URL`</a>

The HTTP(S) URL of source list of rules for newly registered domains safe browsing filter.

**Default:** No default value, the variable is required if `NEW_REG_DOMAINS_ENABLED` is set to `1`.

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

## <a href="#REDIS_ADDR" id="REDIS_ADDR" name="REDIS_ADDR">`REDIS_ADDR`</a>

Redis server address.  Can be an IP address or a hostname.

**Default:** No default value, the variable is required if the [type][conf-check-kv-type] of remote KV storage for DNS server checking is `redis` in the configuration file.

[conf-check-kv-type]: configuration.md#check-kv-type

## <a href="#REDIS_KEY_PREFIX" id="REDIS_KEY_PREFIX" name="REDIS_KEY_PREFIX">`REDIS_KEY_PREFIX`</a>

The prefix for Redis keys.

**Default:** `agdns`.

## <a href="#REDIS_MAX_ACTIVE" id="REDIS_MAX_ACTIVE" name="REDIS_MAX_ACTIVE">`REDIS_MAX_ACTIVE`</a>

The maximum number of active Redis connections.

**Default:** `10`.

## <a href="#REDIS_MAX_IDLE" id="REDIS_MAX_IDLE" name="REDIS_MAX_IDLE">`REDIS_MAX_IDLE`</a>

The maximum number of idle Redis connections.

**Default:** `3`.

## <a href="#REDIS_IDLE_TIMEOUT" id="REDIS_IDLE_TIMEOUT" name="REDIS_IDLE_TIMEOUT">`REDIS_IDLE_TIMEOUT`</a>

How long until idle Redis connections are closed, as a human-readable duration.

**Default:** `30s`.

## <a href="#REDIS_PORT" id="REDIS_PORT" name="REDIS_PORT">`REDIS_PORT`</a>

Redis server port.

**Default:** `6379`.

## <a href="#QUERYLOG_PATH" id="QUERYLOG_PATH" name="QUERYLOG_PATH">`QUERYLOG_PATH`</a>

The path to the file into which the query log is going to be written.

**Default:** `./querylog.jsonl`.

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

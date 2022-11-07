 #  AdGuard DNS Environment Configuration

AdGuard DNS uses [environment variables][wiki-env] to store some of the more
sensitive configuration.  All other configuration is stored in the
[configuration file][conf].

##  Contents

 *  [`BACKEND_ENDPOINT`](#BACKEND_ENDPOINT)
 *  [`BLOCKED_SERVICE_INDEX_URL`](#BLOCKED_SERVICE_INDEX_URL)
 *  [`CONSUL_ALLOWLIST_URL`](#CONSUL_ALLOWLIST_URL)
 *  [`CONSUL_DNSCHECK_KV_URL`](#CONSUL_DNSCHECK_KV_URL)
 *  [`CONSUL_DNSCHECK_SESSION_URL`](#CONSUL_DNSCHECK_SESSION_URL)
 *  [`CONFIG_PATH`](#CONFIG_PATH)
 *  [`DNSDB_PATH`](#DNSDB_PATH)
 *  [`FILTER_INDEX_URL`](#FILTER_INDEX_URL)
 *  [`FILTER_CACHE_PATH`](#FILTER_CACHE_PATH)
 *  [`PROFILES_CACHE_PATH`](#PROFILES_CACHE_PATH)
 *  [`GENERAL_SAFE_SEARCH_URL`](#GENERAL_SAFE_SEARCH_URL)
 *  [`GEOIP_ASN_PATH` and `GEOIP_COUNTRY_PATH`](#GEOIP_ASN_PATH)
 *  [`LISTEN_ADDR`](#LISTEN_ADDR)
 *  [`LISTEN_PORT`](#LISTEN_PORT)
 *  [`LOG_TIMESTAMP`](#LOG_TIMESTAMP)
 *  [`QUERYLOG_PATH`](#QUERYLOG_PATH)
 *  [`RULESTAT_URL`](#RULESTAT_URL)
 *  [`SENTRY_DSN`](#SENTRY_DSN)
 *  [`SSL_KEY_LOG_FILE`](#SSL_KEY_LOG_FILE)
 *  [`VERBOSE`](#VERBOSE)
 *  [`YOUTUBE_SAFE_SEARCH_URL`](#YOUTUBE_SAFE_SEARCH_URL)

[conf]:     configuration.md
[wiki-env]: https://en.wikipedia.org/wiki/Environment_variable



##  <a href="#BACKEND_ENDPOINT" id="BACKEND_ENDPOINT" name="BACKEND_ENDPOINT">`BACKEND_ENDPOINT`</a>

The base backend URL to which API paths are appended.  The backend endpoints
apart from the `/ddns/`and `/linkip/` ones must reply with a 200 status code on
success.

**Default:** No default value, the variable is **required.**



##  <a href="#BLOCKED_SERVICE_INDEX_URL" id="BLOCKED_SERVICE_INDEX_URL" name="BLOCKED_SERVICE_INDEX_URL">`BLOCKED_SERVICE_INDEX_URL`</a>

The URL of the blocked service index file server.  See the [external HTTP API
requirements section][ext-blocked] on the expected format of the response.

**Default:** No default value, the variable is **required.**

[ext-blocked]: externalhttp.md#filters-blocked-services



##  <a href="#CONFIG_PATH" id="CONFIG_PATH" name="CONFIG_PATH">`CONFIG_PATH`</a>

The path to the configuration file.

**Default:** `./config.yml`.



##  <a href="#CONSUL_ALLOWLIST_URL" id="CONSUL_ALLOWLIST_URL" name="CONSUL_ALLOWLIST_URL">`CONSUL_ALLOWLIST_URL`</a>

The URL of the Consul instance serving the dynamic part of the rate-limit
allowlist.  See the [external HTTP API requirements section][ext-consul] on the
expected format of the response.

**Default:** No default value, the variable is **required.**

[ext-consul]: externalhttp.md#consul



##  <a href="#CONSUL_DNSCHECK_KV_URL" id="CONSUL_DNSCHECK_KV_URL" name="CONSUL_DNSCHECK_KV_URL">`CONSUL_DNSCHECK_KV_URL`</a>

The URL of the KV API of the Consul instance used as a key-value database for
the DNS server checking.  It must end with `/kv/<NAMESPACE>` where `<NAMESPACE>`
is any non-empty namespace.    If not specified, the
[`CONSUL_DNSCHECK_SESSION_URL`](#CONSUL_DNSCHECK_SESSION_URL) is also
omitted.

**Default:** **Unset.**

**Example:** `http://localhost:8500/v1/kv/test`



##  <a href="#CONSUL_DNSCHECK_SESSION_URL" id="CONSUL_DNSCHECK_SESSION_URL" name="CONSUL_DNSCHECK_SESSION_URL">`CONSUL_DNSCHECK_SESSION_URL`</a>

The URL of the session API of the Consul instance used as a key-value database
for the DNS server checking.  If not specified, the
[`CONSUL_DNSCHECK_KV_URL`](#CONSUL_DNSCHECK_KV_URL) is also omitted.

**Default:** **Unset.**

**Example:** `http://localhost:8500/v1/session/create`



##  <a href="#DNSDB_PATH" id="DNSDB_PATH" name="DNSDB_PATH">`DNSDB_PATH`</a>

The path to the DNSDB BoltDB database.  If empty or unset, DNSDB statistics
collection is disabled.

**Default:** **Unset.**

**Example:** `./dnsdb.bolt`.



##  <a href="#FILTER_CACHE_PATH" id="FILTER_CACHE_PATH" name="FILTER_CACHE_PATH">`FILTER_CACHE_PATH`</a>

The path to the directory with the filter lists cache.

**Default:** `./filters/`.



##  <a href="#PROFILES_CACHE_PATH" id="PROFILES_CACHE_PATH" name="PROFILES_CACHE_PATH">`PROFILES_CACHE_PATH`</a>

The path to the profile cache file.  The profile cache is read on start and is
later updated on every [full refresh][conf-backend-full_refresh_interval].

**Default:** `./profilecache.json`.

[conf-backend-full_refresh_interval]: configuration.md#backend-full_refresh_interval



##  <a href="#FILTER_INDEX_URL" id="FILTER_INDEX_URL" name="FILTER_INDEX_URL">`FILTER_INDEX_URL`</a>

The URL of the filtering rule index file server.  See the [external HTTP API
requirements section][ext-lists] on the expected format of the response.

**Default:** No default value, the variable is **required.**

[ext-lists]: externalhttp.md#filters-lists



##  <a href="#GENERAL_SAFE_SEARCH_URL" id="GENERAL_SAFE_SEARCH_URL" name="GENERAL_SAFE_SEARCH_URL">`GENERAL_SAFE_SEARCH_URL`</a>

The URL of the list of general safe search rewriting rules.  See the [external
HTTP API requirements section][ext-general] on the expected format of the
response.

**Default:** No default value, the variable is **required.**

[ext-general]: externalhttp.md#filters-safe-search



##  <a href="#GEOIP_ASN_PATH" id="GEOIP_ASN_PATH" name="GEOIP_ASN_PATH">`GEOIP_ASN_PATH` and `GEOIP_COUNTRY_PATH`</a>

Paths to the files containing MaxMind GeoIP databases: for ASNs and for
countries and continents respectively.

**Default:** `./asn.mmdb` and `./country.mmdb`.



##  <a href="#LOG_TIMESTAMP" id="LOG_TIMESTAMP" name="LOG_TIMESTAMP">`LOG_TIMESTAMP`</a>

If `1`, show timestamps in the plain text logs.  If `0`, don't show the
timestamps.

**Default:** `1`.



##  <a href="#LISTEN_ADDR" id="LISTEN_ADDR" name="LISTEN_ADDR">`LISTEN_ADDR`</a>

The IP address on which to bind the [debug HTTP API][debughttp].

**Default:** `127.0.0.1`.

[debughttp]: debughttp.md



##  <a href="#LISTEN_PORT" id="LISTEN_PORT" name="LISTEN_PORT">`LISTEN_PORT`</a>

The port on which to bind the [debug HTTP API][debughttp], which includes the
health check, Prometheus, `pprof`, and other endpoints.

**Default:** `8181`.



##  <a href="#QUERYLOG_PATH" id="QUERYLOG_PATH" name="QUERYLOG_PATH">`QUERYLOG_PATH`</a>

The path to the file into which the query log is going to be written.

**Default:** `./querylog.jsonl`.



##  <a href="#RULESTAT_URL" id="RULESTAT_URL" name="RULESTAT_URL">`RULESTAT_URL`</a>

The URL to send filtering rule list statistics to.  If empty or unset, the
collection of filtering rule statistics is disabled.  See the [external HTTP API
requirements section][ext-rulestat] on the expected format of the response.

**Default:** **Unset.**

**Example:** `https://stats.example.com/db`

[ext-rulestat]: externalhttp.md#rulestat



##  <a href="#SENTRY_DSN" id="SENTRY_DSN" name="SENTRY_DSN">`SENTRY_DSN`</a>

Sentry error collector address.  The special value `stderr` makes AdGuard DNS
print these errors to standard error.

**Default:** `stderr`.



##  <a href="#SSL_KEY_LOG_FILE" id="SSL_KEY_LOG_FILE" name="SSL_KEY_LOG_FILE">`SSL_KEY_LOG_FILE`</a>

If set, TLS key logs are written to this file to allow other programs (i.e.
Wireshark) to decrypt packets.  **Must only be used for debug purposes**.

**Default:** **Unset.**



##  <a href="#VERBOSE" id="VERBOSE" name="VERBOSE">`VERBOSE`</a>

When set to `1`, enable verbose logging.  When set to `0`, disable it.

**Default:** `0`.



##  <a href="#YOUTUBE_SAFE_SEARCH_URL" id="YOUTUBE_SAFE_SEARCH_URL" name="YOUTUBE_SAFE_SEARCH_URL">`YOUTUBE_SAFE_SEARCH_URL`</a>

The URL of the list of YouTube-specific safe search rewriting rules.  See the
[external HTTP API requirements section][ext-general] on the expected format of
the response.

**Default:** No default value, the variable is **required.**

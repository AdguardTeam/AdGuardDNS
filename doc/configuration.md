# AdGuard DNS configuration file

Besides the [environment][env], AdGuard DNS uses a [YAML][yaml] file to store configuration. See file [`config.dist.yml`][dist] for a full example of a configuration file with comments.

## Contents

- [Recommended values and notes](#recommended)
    - [Result cache sizes](#recommended-result_cache)
    - [`SO_RCVBUF` and `SO_SNDBUF` on Linux](#recommended-buffers)
    - [Connection limiter](#recommended-connection_limit)
- [Rate limiting](#ratelimit)
    - [Stream connection limit](#ratelimit-connection_limit)
- [Cache](#cache)
- [Upstream](#upstream)
    - [Healthcheck](#upstream-healthcheck)
- [Common DNS settings](#dns)
- [DNSDB](#dnsdb)
- [Backend](#backend)
- [Query log](#query_log)
- [GeoIP database](#geoip)
- [DNS-server check](#check)
- [Web API](#web)
- [Safe browsing](#safe_browsing)
- [Adult-content blocking](#adult_blocking)
- [Filters](#filters)
- [Filtering groups](#filtering_groups)
- [Network interface listeners](#interface_listeners)
- [Server groups](#server_groups)
    - [DDR](#server_groups-*-ddr)
    - [TLS](#server_groups-*-tls)
    - [Servers](#server_groups-*-servers-*)
- [Connectivity check](#connectivity-check)
- [Network settings](#network)
- [Access settings](#access)
- [Additional metrics information](#additional_metrics_info)

[dist]: ../config.dist.yml
[env]:  environment.md
[yaml]: https://yaml.org/

## <a href="#recommended" id="recommended" name="recommended">Recommended values and notes</a>

### <a href="#recommended-result_cache" id="recommended-result_cache" name="recommended-result_cache">Result cache sizes</a>

According to AdGuard DNS usage data:

- requests for the top **1000** most commonly requested domains account for approximately **85 %** of all queries;
- requests for the top **10 000** most commonly requested domains account for approximately **95 %** of all queries;
- requests for the top **50 000** most commonly requested domains account for approximately **98 %** of all queries;
- requests for the top **100 000** most commonly requested domains account for approximately **99 %** of all queries.

But these statistics are only about domain names and do not account for differences in question types (`A`, `AAAA`, `HTTPS`, etc.) or whether a cached record is a question or an answer.

So, for example, if you want to reach 95 % cache-hit rate for a cache that includes a question type in its cache key and also caches questions separately from answers, you'll need to multiply the value from the statistic by 5 or 6.

### <a href="#recommended-buffers" id="recommended-buffers" name="recommended-buffers">`SO_RCVBUF` and `SO_SNDBUF` on Linux</a>

On Linux OSs the values for these socket options coming from the configuration file (parameters [`network.so_rcvbuf`](#network-so_rcvbuf) and [`network.so_sndbuf`](#network-so_sndbuf)) is doubled, and the maximum and minimum values are controlled by the values in `/proc/`. See `man 7 socket`:

> `SO_RCVBUF`
>
> \[…\] The kernel doubles this value (to allow space for bookkeeping overhead) when it is set using setsockopt(2), and this doubled value is returned by getsockopt(2). The  default value  is set by the `/proc/sys/net/core/rmem_default` file, and the maximum allowed value is set by the `/proc/sys/net/core/rmem_max` file. The minimum (doubled) value for this option is `256`.
>
> \[…\]
>
> `SO_SNDBUF`
>
> \[…\] The  default value  is set by the `/proc/sys/net/core/wmem_default` file, and the maximum allowed value is set by the `/proc/sys/net/core/wmem_max` file. The minimum (doubled) value for this option is `2048`.

The maximum value for these parameters is the maximum value of a 32-bit signed integer (`2147483647`).

### <a href="#recommended-connection_limit" id="recommended-connection_limit" name="recommended-connection_limit">Stream connection limit</a>

Currently, there are the following recommendations for parameters [`ratelimit.connection_limit.stop`](#ratelimit-connection_limit-stop) and [`ratelimit.connection_limit.resume`](#ratelimit-connection_limit-resume):

- `stop` should be about 25 % above the current maximum daily number of used TCP sockets. That is, if the instance currently has a maximum of 100 000 TCP sockets in use every day, `stop` should be set to about `125000`.

- `resume` should be about 20 % above the current maximum daily number of used TCP sockets. That is, if the instance currently has a maximum of 100 000 TCP sockets in use every day, `resume` should be set to about `120000`.

> [!NOTE]
> The number of active stream-connections includes sockets that are in the process of accepting new connections but have not yet accepted one. That means that `resume` should be greater than the number of bound addresses.

These recommendations are to be revised based on the metrics.

## <a href="#ratelimit" id="ratelimit" name="ratelimit">Rate limiting</a>

The `ratelimit` object has the following properties:

- <a href="#ratelimit-refuseany" id="ratelimit-refuseany" name="ratelimit-refuseany">`refuseany`</a>: If true, refuse DNS queries with the `ANY` (aka `*`) type.

    **Example:** `true`.

- <a href="#ratelimit-response_size_estimate" id="ratelimit-response_size_estimate" name="ratelimit-response_size_estimate">`response_size_estimate`</a>: The size of one DNS response for the purposes of rate limiting. If a DNS response is larger than this value, it is counted as several responses.

    **Example:** `1KB`.

- <a href="#ratelimit-backoff_period" id="ratelimit-backoff_period" name="ratelimit-backoff_period">`backoff_period`</a>: The time during which to count the number of requests that a client has sent over the RPS.

    **Example:** `10m`.

- <a href="#ratelimit-backoff_duration" id="ratelimit-backoff_duration" name="ratelimit-backoff_duration">`backoff_duration`</a>: How long a client that has hit the RPS too often stays in the backoff state.

    **Example:** `30m`.

- <a href="#ratelimit-ipv4" id="ratelimit-ipv4" name="ratelimit-ipv4">`ipv4`</a>: The ipv4 configuration object. It has the following fields:

    - <a href="#ratelimit-ipv4-count" id="ratelimit-ipv4-count" name="ratelimit-ipv4-count">`count`</a>: Requests per configured interval for one subnet for IPv4 addresses. Requests above this are counted in the backoff count.

        **Example:** `300`.

    - <a href="#ratelimit-ipv4-interval" id="ratelimit-ipv4-interval" name="ratelimit-ipv4-interval">`interval`</a>: The time during which to count the number of requests.

        **Example:** `10s`.

    - <a href="#ratelimit-ipv4-subnet_key_len" id="ratelimit-ipv4-subnet_key_len" name="ratelimit-ipv4-subnet_key_len">`ipv4-subnet_key_len`</a>: The length of the subnet prefix used to calculate rate limiter bucket keys.

        **Example:** `24`.

- <a href="#ratelimit-ipv6" id="ratelimit-ipv6" name="ratelimit-ipv6">`ipv6`</a>: The `ipv6` configuration object has the same properties as the `ipv4` one above.

- <a href="#ratelimit-backoff_count" id="ratelimit-backoff_count" name="ratelimit-backoff_count">`backoff_count`</a>: Maximum number of requests a client can make above the RPS within a `backoff_period`. When a client exceeds this limit, requests aren't allowed from client's subnet until `backoff_duration` ends.

    **Example:** `1000`.

- <a href="#ratelimit-allowlist" id="ratelimit-allowlist" name="ratelimit-allowlist">`allowlist`</a>: The allowlist configuration object. It has the following fields:

    - <a href="#ratelimit-allowlist-list" id="ratelimit-allowlist-list" name="ratelimit-allowlist-list">`list`</a>: The array of the allowed IPs or CIDRs.

        **Property example:**

        ```yaml
        'list':
          - '192.168.1.4'
          - '192.175.2.1/16'
        ```

    - <a href="#ratelimit-allowlist-refresh_interval" id="ratelimit-allowlist-refresh_interval" name="ratelimit-allowlist-refresh_interval">`refresh_interval`</a>: How often AdGuard DNS refreshes the dynamic part of its allowlist from the data received from the [`CONSUL_ALLOWLIST_URL`][env-consul_allowlist_url], as a human-readable duration.

        **Example:** `30s`.

    - <a href="#ratelimit-allowlist-type" id="ratelimit-allowlist-type" name="ratelimit-allowlist-type">`type`</a>: Defines where the rate limit settings are received from. Allowed values are `backend` and `consul`.

        **Example:** `consul`.

For example, if `backoff_period` is `1m`, `backoff_count` is `10`, `ipv4-count` is `5`, and `ipv4-interval` is `1s`, a client (meaning all IP addresses within the subnet defined by `ipv4-subnet_key_len`) that made 15 requests in one second or 6 requests (one above `rps`) every second for 10 seconds within one minute, the client is blocked for `backoff_duration`.

### <a href="#ratelimit-connection_limit" id="ratelimit-connection_limit" name="ratelimit-connection_limit">Stream connection limit</a>

The `connection_limit` object has the following properties:

- <a href="#ratelimit-connection_limit-enabled" id="ratelimit-connection_limit-enabled" name="ratelimit-connection_limit-enabled">`enabled`</a>: Whether or not the stream-connection limit should be enforced.

    **Example:** `true`.

- <a href="#ratelimit-connection_limit-stop" id="ratelimit-connection_limit-stop" name="ratelimit-connection_limit-stop">`stop`</a>: The point at which the limiter stops accepting new connections. Once the number of active connections reaches this limit, new connections wait for the number to decrease to or below `resume`.

    **Example:** `1000`.

- <a href="#ratelimit-connection_limit-resume" id="ratelimit-connection_limit-resume" name="ratelimit-connection_limit-resume">`resume`</a>: The point at which the limiter starts accepting new connections again after reaching `stop`.

    **Example:** `800`.

See also [notes on these parameters](#recommended-connection_limit).

### <a href="#ratelimit-quic" id="ratelimit-quic" name="ratelimit-quic">QUIC rate limiting</a>

The `quic` object has the following properties:

- <a href="#ratelimit-quic-enabled" id="ratelimit-quic-enabled" name="ratelimit-quic-enabled">`enabled`</a>: Whether or not the QUIC connections rate limiting should be enforced.

    **Example:** `true`.

- <a href="#ratelimit-quic-max_streams_per_peer" id="ratelimit-quic-max_streams_per_peer" name="ratelimit-quic-max_streams_per_peer">`max_streams_per_peer`</a>: The maximum number of concurrent streams that a peer is allowed to open.

    **Example:** `1000`.

### <a href="#ratelimit-tcp" id="ratelimit-tcp" name="ratelimit-tcp">TCP rate limiting</a>

The `tcp` object has the following properties:

- <a href="#ratelimit-tcp-enabled" id="ratelimit-tcp-enabled" name="ratelimit-tcp-enabled">`enabled`</a>: Whether or not the TCP rate limiting should be enforced.

    **Example:** `true`.

- <a href="#ratelimit-tcp-max_pipeline_count" id="ratelimit-tcp-max_pipeline_count" name="ratelimit-tcp-max_pipeline_count">`max_pipeline_count`</a>: The maximum number of simultaneously processing TCP messages per one connection.

    **Example:** `1000`.

[env-consul_allowlist_url]: environment.md#CONSUL_ALLOWLIST_URL

## <a href="#cache" id="cache" name="cache">Cache</a>

The `cache` object has the following properties:

- <a href="#cache-type" id="cache-type" name="cache-type">`type`</a>: The type of cache to use. Can be `simple` (a simple LRU cache) or `ecs` (a ECS-aware LRU cache). If set to `ecs`, `ecs_size` must be greater than zero.

    **Example:** `simple`.

- <a href="#cache-size" id="cache-size" name="cache-size">`size`</a>: The total number of items in the cache for hostnames with no ECS support. Must be greater than or equal to zero. If zero, cache is disabled.

    **Example:** `10000`.

- <a href="#cache-ecs_size" id="cache-ecs_size" name="cache-ecs_size">`ecs_size`</a>: The total number of items in the cache for hostnames with ECS support.

    **Example:** `10000`.

- <a href="#cache-ttl_override" id="cache-ttl_override" name="cache-ttl_override">`ttl_override`</a>: The object describes cache TTL override mechanics. It has the following properties:

    - <a href="cache-ttl_override-enabled">`enabled`</a>: If true, the TTL overrides are enabled.

    - <a href="cache-ttl_override-min">`min`</a>: The minimum duration for TTL for cache items of both caches, with and without ECS support. The recommended value is `60s`.

    **Property example:**

    ```yaml
    'ttl_override':
        'enabled': true
        'min': 60s
    ```

## <a href="#upstream" id="upstream" name="upstream">Upstream</a>

The `upstream` object has the following properties:

- <a href="#upstream-servers" id="upstream-servers" name="upstream-servers">`servers`</a>: The array of the main upstream servers URLs, in the `[scheme://]ip:port` format and its timeouts for main upstream DNS requests, as a human-readable duration.

    **Property example:**

    ```yaml
    'servers':
      # Regular DNS (over UDP with TCP fallback).
      - address: '8.8.8.8:53'
        timeout: 2s
      # Regular DNS (over TCP).
      - address: 'tcp://1.1.1.1:53'
        timeout: 2s
      # Regular DNS (over UDP).
      - address: 'udp://1.1.1.1:53'
        timeout: 2s
    ```

- <a href="#upstream-fallback" id="upstream-fallback" name="upstream-fallback">`fallback`</a>: Fallback servers configuration. It has the following properties:

    - <a href="#upstream-fallback-servers" id="upstream-fallback-servers" name="upstream-fallback-servers">`servers`</a>: The array of the fallback upstream servers URLs, in the `[scheme://]ip:port` format and its timeouts for upstream DNS requests, as a human-readable duration. These are use used in case a network error occurs while requesting the main upstream server. This property has the same format as [`upstream-servers`](#upstream-servers) above.

        **Property example:**

        ```yaml
        'servers':
          - address: '1.1.1.1:53'
            timeout: 2s
          - address: '[2001:4860:4860::8888]:53'
            timeout: 2s
         ```

- `healthcheck`: Healthcheck configuration. See [below](#upstream-healthcheck).

### <a href="#upstream-healthcheck" id="upstream-healthcheck" name="upstream-healthcheck">Healthcheck</a>

If `enabled` is true, the upstream healthcheck is enabled. The healthcheck worker probes the main upstream with an `A` query for a domain created from `domain_template`. If there is an error, timeout, or a response different from a `NOERROR` one then the main upstream is considered down, and all requests are redirected to fallback upstream servers for the time set by `backoff_duration`. Afterwards, if a worker probe is successful, AdGuard DNS considers the connection to the main upstream as restored, and requests are routed back to it.

- <a href="#u-h-enabled" id="u-h-enabled" name="u-h-enabled">`enabled`</a>: If true, the upstream healthcheck is enabled.

    **Example:** `true`.

- <a href="#u-h-interval" id="u-h-interval" name="u-h-interval">`interval`</a>: How often AdGuard DNS makes upstream healthcheck requests, as a human-readable duration.

    **Example:** `2s`.

- <a href="#u-h-timeout" id="u-h-timeout" name="u-h-timeout">`timeout`</a>: Timeout for all outgoing healthcheck requests, as a human-readable duration.

    **Example:** `1s`.

- <a href="#u-h-backoff_duration" id="u-h-backoff_duration" name="u-h-backoff_duration">`backoff_duration`</a>: Backoff duration after failed healthcheck request, as a human-readable duration. If the main upstream is down, AdGuardDNS does not return back to using it until this time has passed. The healthcheck is still performed, and each failed check advances the backoff.

    **Example:** `30s`.

- <a href="#u-h-domain_template" id="u-h-domain_template" name="u-h-domain_template">`domain_template`</a>: The template for domains used to perform healthcheck queries. If the `domain_template` contains the string `${RANDOM}`, all occurrences of this string are replaced with a random string (currently, a hexadecimal form of a 64-bit integer) on every healthcheck query. Queries must return a `NOERROR` response.

    **Example:** `${RANDOM}.neverssl.com`.

## <a href="#dns" id="dns" name="dns">DNS</a>

The `dns` object has the following properties:

- <a href="#dns-read_timeout" id="dns-read_timeout" name="dns-read_timeout">`read_timeout`</a>: The timeout for any read from a UDP connection or the first read from a TCP/TLS connection, as a human-readable duration. It currently doesn't affect DNSCrypt, QUIC, or HTTPS.

    **Example:** `2s`.

- <a href="#dns-tcp_idle_timeout" id="dns-tcp_idle_timeout" name="dns-tcp_idle_timeout">`tcp_idle_timeout`</a>: The timeout for consecutive reads from a TCP/TLS connection, as a human-readable duration. It currently doesn't affect DNSCrypt, QUIC, or HTTPS.

    **Example:** `30s`.

- <a href="#dns-write_timeout" id="dns-write_timeout" name="dns-write_timeout">`write_timeout`</a>: The timeout for writing to a UDP or TCP/TLS connection, as a human-readable duration. It currently doesn't affect DNSCrypt, QUIC, or HTTPS.

    **Example:** `2s`.

- <a href="#dns-handle_timeout" id="dns-handle_timeout" name="dns-handle_timeout">`handle_timeout`</a>: The timeout for the entire handling of a single query, as a human-readable duration.

    **Example:** `1s`.

- <a href="#dns-max_udp_response_size" id="dns-max_udp_response_size" name="dns-max_udp_response_size">`max_udp_response_size`</a>: The maximum size of DNS response over UDP protocol.

    **Example:** `1024B`.

## <a href="#dnsdb" id="dnsdb" name="dnsdb">DNSDB</a>

The `dnsdb` object has the following properties:

- <a href="#dnsdb-enabled" id="dnsdb-enabled" name="dnsdb-enabled">`enabled`</a>: If true, the DNSDB memory buffer is enabled.

    **Example:** `true`.

- <a href="#dnsdb-max_size" id="dnsdb-max_size" name="dnsdb-max_size">`max_size`</a>: The maximum number of records in the in-memory buffer. The record key is a combination of the target hostname from the question and the resource-record type of the question or the answer.

    **Example:** `500000`.

## <a href="#backend" id="backend" name="backend">Backend</a>

The `backend` object has the following properties:

- <a href="#backend-timeout" id="backend-timeout" name="backend-timeout">`timeout`</a>: Timeout for all outgoing HTTP requests to the backend, as a human-readable duration. Set to `0s` to disable timeouts.

    **Example:** `10s`.

- <a href="#backend-refresh_interval" id="backend-refresh_interval" name="backend-refresh_interval">`refresh_interval`</a>: How often AdGuard DNS checks the backend for data updates, as a human-readable duration.

    **Example:** `1m`.

- <a href="#backend-full_refresh_interval" id="backend-full_refresh_interval" name="backend-full_refresh_interval">`full_refresh_interval`</a>: How often AdGuard DNS performs a full profile refresh, as a human-readable duration. If [`PROFILES_CACHE_PATH`][env-profiles_cache_path] is set, the profile cache is also saved after a full refresh.

    **Example:** `24h`.

- <a href="#backend-full_refresh_retry_interval" id="backend-full_refresh_retry_interval" name="backend-full_refresh_retry_interval">`full_refresh_retry_interval`</a>: How long to wait before attempting a new full profile synchronization after a failure, as a human-readable duration. It is recommended to keep this value greater than [`refresh_interval`](#backend-refresh_interval).

    **Example:** `1h`.

- <a href="#backend-bill_stat_interval" id="backend-bill_stat_interval" name="backend-bill_stat_interval">`bill_stat_interval`</a>: How often AdGuard DNS sends the billing statistics to the backend, as a human-readable duration.

    **Example:** `1m`.

[env-profiles_cache_path]: environment.md#PROFILES_CACHE_PATH

## <a href="#query_log" id="query_log" name="query_log">Query log</a>

The `query_log` object has the following properties:

- <a href="#query_log-file" id="query_log-file" name="query_log-file">`file`</a>: The file query log configuration object. It has the following properties:

    - <a href="#q-file-enabled" id="q-file-enabled" name="q-file-enabled">`enabled`</a>: If true, the JSONL file query logging is enabled.

        **Property example:**

        ```yaml
        'file':
            'enabled': true
        ```

## <a href="#geoip" id="geoip" name="geoip">GeoIP database</a>

The `geoip` object has the following properties:

- <a href="#geoip-host_cache_size" id="geoip-host_cache_size" name="geoip-host_cache_size">`host_cache_size`</a>: The size of the host lookup cache, in entries.

    **Example:** `100000`.

- <a href="#geoip-ip_cache_size" id="geoip-ip_cache_size" name="geoip-ip_cache_size">`ip_cache_size`</a>: The size of the IP lookup cache, in entries.

    **Example:** `100000`.

- <a href="#geoip-refresh_interval" id="geoip-refresh_interval" name="geoip-refresh_interval">`refresh_interval`</a>: Interval between the GeoIP database refreshes, as a human-readable duration.

    **Example:** `5m`.

## <a href="#check" id="check" name="check">DNS-server check</a>

The `check` object has the following properties:

- <a href="#check_kv" id="check_kv" name="check_kv">`kv`</a>: Remote key-value storage settings. It has the following properties:

    - <a href="#check-kv-type" id="check-kv-type" name="check-kv-type">`type`</a>: Type of the remote KV storage. Allowed values are `backend`, `cache`, `consul`, and `redis`.

        **Example:** `consul`.

    - <a href="#check-kv-ttl" id="check-kv-ttl" name="check-kv-ttl">`ttl`</a>: For how long to keep the information about a single user in remote KV, as a human-readable duration.

        For `backend`, the TTL must be greater than `0s`.

        For `cache`, the TTL is not used.

        For `consul`, the TTL must be between `10s` and `1d`. Note that the actual TTL can be up to twice as long.

        For `redis`, the TTL must be greater than or equal to `1ms`.

        **Example:** `30s`.

- <a href="#check-domains" id="check-domains" name="check-domains">`domains`</a>: The domain suffixes to which random IDs are prepended using a hyphen.

    **Property example:**

    ```yaml
    'domains':
      - 'dnscheck.example.com'
      - 'checkdns.example.com'
    ```

- <a href="#check-node_location" id="check-node_location" name="check-node_location">`node_location`</a>: The location code of this server node.

    **Example:** `ams`.

- <a href="#check-node_name" id="check-node_name" name="check-node_name">`node_name`</a>: The name of this server node.

    **Example:** `eu-1.dns.example.com`.

- <a href="#check-ipv4" id="check-ipv4" name="check-ipv4">`ipv4` and `ipv6`</a>: Arrays of IPv4 or IPv6 addresses with which to respond to `A` and `AAAA` queries correspondingly. Generally, those should be the IP addresses of the AdGuard DNS [main HTTP API][http-dnscheck] for the DNS server check feature to work properly. In a development setup, that means the localhost addresses.

    **Property examples:**

    ```yaml
    'ipv4':
      - '1.2.3.4'
      - '5.6.7.8'
    'ipv6':
      - '1234::cdee'
      - '1234::cdef'
    ```

[http-dnscheck]: http.md#dnscheck-test

## <a href="#web" id="web" name="web">Web API</a>

The optional `web` object has the following properties:

- <a href="#web-linked_ip" id="web-linked_ip" name="web-linked_ip">`linked_ip`</a>: The optional linked IP and dynamic DNS (DDNS, DynDNS) web server configuration. The [static content](#web-static_content) is not served on these addresses.

    See the [full description of this API][http-linked-ip-proxy] on the HTTP API page.

    Property `bind` has the same format as [`non_doh_bind`](#web-non_doh_bind) below.

    **Property example:**

    ```yaml
    'linked_ip':
        'bind':
          - 'address': '127.0.0.1:80'
          - 'address': '127.0.0.1:443'
            'certificates':
              - 'certificate': './test/cert.crt'
                'key': './test/cert.key'
    ```

- <a href="#web-safe_browsing" id="web-safe_browsing" name="web-safe_browsing">`safe_browsing`</a>: The optional safe browsing block-page web server configurations. Every request is responded with the content from the file to which the `block_page` property points.

    See the [full description of this API][http-block-pages] on the HTTP API page.

    Property `bind` has the same format as [`non_doh_bind`](#web-non_doh_bind) below. The addresses should be different from the `adult_blocking` server, and the same as the ones of the `block_host` property in the [`safe_browsing`](#safe_browsing) and [`adult_blocking`](#adult_blocking) objects correspondingly.

    While this object is optional, both `bind` and `block_page` properties within them are required.

    **Property examples:**

    ```yaml
    'safe_browsing':
      'bind':
        - 'address': '127.0.0.1:80'
        - 'address': '127.0.0.1:443'
          'certificates':
            - 'certificate': './test/cert.crt'
              'key': './test/cert.key'
      'block_page': '/var/www/block_page.html'
    ```

- <a href="#web-adult_blocking" id="web-adult_blocking" name="web-adult_blocking">`adult_blocking`</a>: The optional adult block-page web server configuration. The format of the values is the same as in the [`safe_browsing`](#web-safe_browsing) object above.

- <a href="#web-general_blocking" id="web-general_blocking" name="web-general_blocking">`general_blocking`</a>: The optional general block-page web server configuration. The format of the values is the same as in the [`safe_browsing`](#web-safe_browsing) object above.

- <a href="#web-non_doh_bind" id="web-non_doh_bind" name="web-non_doh_bind">`non_doh_bind`</a>: The optional listen addresses and optional TLS configuration for the web service in addition to the ones in the DNS-over-HTTPS handlers. The `certificates` array has the same format as the one in a server group's [TLS settings](#server_groups-*-tls). In the special case of `GET /robots.txt` requests, a special response is served; this response could be overwritten with static content.

    **Property example:**

    ```yaml
    'non_doh_bind':
      - 'address': '127.0.0.1:80'
      - 'address': '127.0.0.1:443'
        'certificates':
          - 'certificate': './test/cert.crt'
            'key': './test/cert.key'
    ```

- <a href="#web-static_content" id="web-static_content" name="web-static_content">`static_content`</a>: The optional inline static content mapping. Not served on the `linked_ip`, `safe_browsing` and `adult_blocking` servers. Paths must not duplicate the ones used by the DNS-over-HTTPS server.

    > [!NOTE]
    > This field is ignored if [`WEB_STATIC_DIR_ENABLED`][env-WEB_STATIC_DIR_ENABLED] is set to `1`.

    Inside of the `headers` map, the header `Content-Type` is required.  The paths are case-sensitive.

    **Property example:**

    ```yaml
    static_content:
        '/favicon.ico':
            content: 'base64content'
            headers:
                'Content-Type':
                  - 'image/x-icon'
    ```

- <a href="#web-root_redirect_url" id="web-root_redirect_url" name="web-root_redirect_url">`root_redirect_url`</a>: The optional URL to which non-DNS and non-Debug HTTP requests are redirected. If not set, AdGuard DNS will respond with a 404 status to all such requests.

    **Example:** `https://adguard-dns.com/`.

- <a href="#web-error_404" id="web-error_404" name="web-error_404">`error_404` and `error_500`</a>: The optional paths to the 404 page and the 500 page HTML files correspondingly. If not set, a simple plain text 404 or 500 page is served.

    **Example:** `/var/www/404.html`.

- <a href="#web-timeout" id="web-timeout" name="web-timeout">`timeout`</a>: The timeout for server operations, as a human-readable duration.

    **Example:** `30s`.

[env-WEB_STATIC_DIR_ENABLED]: environment.md#WEB_STATIC_DIR_ENABLED
[http-block-pages]:           http.md#block-pages
[http-linked-ip-proxy]:       http.md#linked-ip-proxy

## <a href="#safe_browsing" id="safe_browsing" name="safe_browsing">Safe browsing</a>

The `safe_browsing` object has the following properties:

- <a href="#safe_browsing-block_host" id="safe_browsing-block_host" name="safe_browsing-block_host">`block_host`</a>: The host with which to respond to any requests that match the filter.

    **Example:** `standard-block.dns.adguard.com`.

- <a href="#safe_browsing-cache_size" id="safe_browsing-cache_size" name="safe_browsing-cache_size">`cache_size`</a>: The size of the response cache, in entries.

    **WARNING: CURRENTLY IGNORED!**  See AGDNS-398.

    **Example:** `1024`.

- <a href="#safe_browsing-cache_ttl" id="safe_browsing-cache_ttl" name="safe_browsing-cache_ttl">`cache_ttl`</a>: The TTL of the response cache, as a human-readable duration.

    **Example:** `1h`.

- <a href="#safe_browsing-url" id="safe_browsing-url" name="safe_browsing-url">`url`</a>: The URL from which the contents can be updated. The URL must reply with a 200 status code.

    **Example:** `https://example.com/safe_browsing.txt`.

- <a href="#safe_browsing-refresh_interval" id="safe_browsing-refresh_interval" name="safe_browsing-refresh_interval">`refresh_interval`</a>: How often AdGuard DNS refreshes the filter.

    **Example:** `1m`.

- <a href="#safe_browsing-refresh_timeout" id="safe_browsing-refresh_timeout" name="safe_browsing-refresh_timeout">`refresh_timeout`</a>: The timeout for the update operation, as a human-readable duration.

    **Example:** `1m`.

## <a href="#adult_blocking" id="adult_blocking" name="adult_blocking">Adult-content blocking</a>

The `adult_blocking` object has the same properties as the [`safe_browsing`](#safe_browsing) one above.

## <a href="#filters" id="filters" name="filters">Filter Lists</a>

**TODO(a.garipov):**  Add the timeout for the blocked-service index refresh. It is currently hardcoded to 3 minutes.

The `filters` object has the following properties:

- <a href="#filters-response_ttl" id="filters-response_ttl" name="filters-response_ttl">`response_ttl`</a>: The default TTL to set for responses to queries for blocked or modified domains, as a human-readable duration. It is used for anonymous users. For users with profiles, the TTL from their profile settings are used.

    **Example:** `10s`.

- <a href="#filters-custom_filter_cache_size" id="filters-custom_filter_cache_size" name="filters-custom_filter_cache_size">`custom_filter_cache_size`</a>: The size of the LRU cache of compiled filtering rule engines for profiles with custom filtering rules, in entries. Zero means no caching, which slows
    down queries.

    **Example:** `1024`.

- <a href="#filters-safe_search_cache_size" id="filters-safe_search_cache_size" name="filters-safe_search_cache_size">`safe_search_cache_size`</a>: The size of the LRU cache of the safe-search filtering results. This value applies to both general and YouTube safe-search.

    **Example:** `1024`.

- <a href="#filters-refresh_interval" id="filters-refresh_interval" name="filters-refresh_interval">`refresh_interval`</a>: How often AdGuard DNS refreshes the rule-list filters from the filter index, as well as the blocked services list from the [blocked list index][env-blocked_services].

    **Example:** `1h`.

- <a href="#filters-refresh_timeout" id="filters-refresh_timeout" name="filters-refresh_timeout">`refresh_timeout`</a>: The timeout for the *entire* filter update operation, as a human-readable duration. Note that filter rule-list index and each filter rule-list update operations have their own timeouts, see [`index_refresh_timeout`](#filters-index_refresh_timeout) and [`rule_list_refresh_timeout`](#filters-rule_list_refresh_timeout).

    **Example:** `5m`.

- <a href="#filters-index_refresh_timeout" id="filters-index_refresh_timeout" name="filters-index_refresh_timeout">`index_refresh_timeout`</a>: The timeout for the filter rule-list index update operation, as a human-readable duration. See also [`refresh_timeout`](#filters-refresh_timeout) for the entire filter update operation.

    **Example:** `1m`.

- <a href="#filters-rule_list_refresh_timeout" id="filters-rule_list_refresh_timeout" name="filters-rule_list_refresh_timeout">`rule_list_refresh_timeout`</a>: The timeout for the filter update operation of each rule-list, including the safe-search ones, as a human-readable duration. See also [`refresh_timeout`](#filters-refresh_timeout) for the entire filter update operation.

    **Example:** `1m`.

- <a href="#filters-max_size" id="filters-max_size" name="filters-max_size">`max_size`</a>: The maximum size of the downloadable content for a rule-list in a human-readable format.

    **Example:** `256MB`.

- <a href="#filters-rule_list_cache" id="filters-rule_list_cache" name="filters-rule_list_cache">`rule_list_cache`</a>: Rule lists cache settings. It has the following properties:

    - <a href="#filters-rule_list_cache-enabled" id="filters-rule_list_cache-enabled" name="filters-rule_list_cache-enabled">`enabled`</a>: If true, use the rule-list filtering result cache. This cache is not used for users' custom rules.

        **Example:** `true`.

    - <a href="#filters-rule_list_cache-size" id="filters-rule_list_cache-size" name="filters-rule_list_cache-size">`rule_list_cache-size`</a>: The size of the LRU cache of the rule-list filtering results.

        **Example:** `10000`.

- <a href="#filters-ede_enabled" id="filters-ede_enabled" name="filters-ede_enabled">`ede_enabled`</a>: Shows if Extended DNS Error codes should be added.

    **Example:** `true`.

- <a href="#filters-sde_enabled" id="filters-sde_enabled" name="filters-sde_enabled">`sde_enabled`</a>: Shows if the experimental Structured DNS Errors feature should be enabled. `ede_enabled` must be `true` to enable SDE.

    **Example:** `true`.

[env-blocked_services]: environment.md#BLOCKED_SERVICE_INDEX_URL

## <a href="#filtering_groups" id="filtering_groups" name="filtering_groups">Filtering groups</a>

The items of the `filtering_groups` array have the following properties:

- <a href="#fg-*-id" id="fg-*-id" name="fg-*-id">`id`</a>: The unique ID of this filtering group.

    **Example:** `default`.

- <a href="#fg-*-rule_lists" id="fg-*-rule_lists" name="fg-*-rule_lists">`rule_lists`</a>: Filtering rule lists settings. This object has the following properties:

    - <a href="#fg-*-rl-enabled" id="fg-*-rl-enabled" name="fg-*-rl-enabled">`enabled`</a>: Shows if rule-list filtering should be enforced. If it is set to `false`, the rest of the settings are ignored.

        **Example:** `true`.

    - <a href="#fg-*-rl-ids" id="fg-*-rl-ids" name="fg-*-rl-ids">`ids`</a>: The array of rule-list IDs used in this filtering group.

        **Example:** `[adguard_dns_default]`.

- <a href="#fg-*-parental" id="fg-*-parental" name="fg-*-parental">`parental`</a>: Parental protection settings. This object has the following properties:

    - <a href="#fg-*-p-enabled" id="fg-*-p-enabled" name="fg-*-p-enabled">`enabled`</a>: Shows if any kind of parental protection filtering should be enforced at all. If it is set to `false`, the rest of the settings are ignored.

        **Example:** `true`.

    - <a href="#fg-*-p-block_adult" id="fg-*-p-block_adult" name="fg-*-p-block_adult">`block_adult`</a>: If true, adult content blocking is enabled for this filtering group by default. Requires `enabled` to also be true.

        **Example:** `true`.

    - <a href="#fg-*-p-general_safe_search" id="fg-*-p-general_safe_search" name="fg-*-p-general_safe_search">`general_safe_search`</a>: If true, general safe search is enabled for this filtering group by default. Requires `enabled` to also be true.

        **Example:** `true`.

    - <a href="#fg-*-p-youtube_safe_search" id="fg-*-p-youtube_safe_search" name="fg-*-p-youtube_safe_search">`youtube_safe_search`</a>: If true, YouTube safe search is enabled for this filtering group by default. Requires `enabled` to also be true.

        **Example:** `true`.

- <a href="#fg-*-safe_browsing" id="fg-*-safe_browsing" name="fg-*-safe_browsing">`safe_browsing`</a>: General safe browsing settings. This object has the following properties:

    - <a href="#fg-*-sb-enabled" id="fg-*-sb-enabled" name="fg-*-sb-enabled">`enabled`</a>: Shows if the general safe browsing filtering should be enforced. If it is set to `false`, the rest of the settings are ignored.

        **Example:** `true`.

    - <a href="#fg-*-sb-block_dangerous_domains" id="fg-*-sb-block_dangerous_domains" name="fg-*-sb-block_dangerous_domains">`block_dangerous_domains`</a>: Shows if the dangerous domains filtering should be enforced.

        **Example:** `true`.

    - <a href="#fg-*-sb-block_newly_registered_domains" id="fg-*-sb-block_newly_registered_domains" name="fg-*-sb-block_newly_registered_domains">`block_newly_registered_domains`</a>: Shows if the newly registered domains filtering should be enforced.

        **Example:** `true`.

- <a href="#fg-*-block_chrome_prefetch" id="fg-*-block_chrome_prefetch" name="fg-*-block_chrome_prefetch">`block_chrome_prefetch`</a>: If true, Chrome prefetch domain queries are blocked for requests using this filtering group, forcing the preferch proxy into preflight mode.

    **Example:** `true`.

- <a href="#fg-*-block_firefox_canary" id="fg-*-block_firefox_canary" name="fg-*-block_firefox_canary">`block_firefox_canary`</a>: If true, Firefox canary domain queries are blocked for requests using this filtering group.

    **Example:** `true`.

- <a href="#fg-*-block_private_relay" id="fg-*-block_private_relay" name="fg-*-block_private_relay">`private_relay`</a>: If true, Apple Private Relay queries are blocked for requests using this filtering group.

    **Example:** `false`.

## <a href="#interface_listeners" id="interface_listeners" name="interface_listeners">Network interface listeners</a>

> [!NOTE]
> The network interface listening works only on Linux with `SO_BINDTODEVICE` support (2.0.30 and later) and properly setup IP routes. See the [section on testing `SO_BINDTODEVICE` using Docker][dev-btd].

The `interface_listeners` object has the following properties:

- <a href="#ifl-channel_buffer_size" id="ifl-channel_buffer_size" name="ifl-channel_buffer_size">`channel_buffer_size`</a>: The size of the buffers of the channels used to dispatch TCP connections and UDP sessions.

    **Example:** `1000`.

- <a href="#ifl-list" id="ifl-list" name="ifl-list">`list`</a>: The mapping of interface-listener IDs to their configuration.

    **Property example:**

    ```yaml
    list:
        'eth0_plain_dns':
            interface: 'eth0'
            port: 53
        'eth0_plain_dns_secondary':
            interface: 'eth0'
            port: 5353
    ```

[dev-btd]: development.md#testing-bindtodevice

## <a href="#server_groups" id="server_groups" name="server_groups">Server groups</a>

The items of the `server_groups` array have the following properties:

- <a href="#sg-*-name" id="sg-*-name" name="sg-*-name">`name`</a>: The unique name of this server group.

    **Example:** `adguard_dns_default`.

- <a href="#sg-*-filtering_group" id="sg-*-filtering_group" name="sg-*-filtering_group">`filtering_group`</a>: The default filtering group for this server group. It is used for anonymous users.

    **Example:** `default`.

- `ddr`: The DDR configuration object. See [below](#server_groups-*-ddr).

- `tls`: The TLS configuration object. See [below](#server_groups-*-tls).

    > [!NOTE]
    > The `tls` object is optional unless the [`servers` array](#server_groups-*-servers-*) contains at least one item with an encrypted protocol.

- <a href="#sg-*-profiles_enabled" id="sg-*-profiles_enabled" name="sg-*-profiles_enabled">`profiles_enabled`</a>: If true, enable recognition of user devices and profiles for this server group.

    **Example:** `true`.

- `servers`: Server configuration for this filtering group. See [below](#server_groups-*-servers-*).

### <a href="#server_groups-*-ddr" id="server_groups-*-ddr" name="server_groups-*-ddr">DDR</a>

The DDR configuration object. Many of these data duplicate data from objects in the [`servers`](#server_groups-*-servers-*) array. This was done because there was an opinion that a more restrictive configuration that automatically collected the required data was not self-describing and flexible enough.

- <a href="#sg-*-ddr-enabled" id="sg-*-ddr-enabled" name="sg-*-ddr-enabled">`enabled`</a>: Shows if DDR queries are processed. If it is set to `false`, DDR domain name queries receive an `NXDOMAIN` response.

    **Example:** `true`.

- <a href="#sg-*-ddr-device_records" id="sg-*-ddr-device_records" name="sg-*-ddr-device_records">`device_records`</a>: The device ID wildcard to record template mapping. The keys should generally be kept in sync with the [`device_id_wildcards`](#sg-*-tls-device_id_wildcards) field of the `tls` object.

    The values have the following properties:

    - <a href="#sg-*-ddr-dr-*-doh_path" id="sg-*-ddr-dr-*-doh_path" name="sg-*-ddr-dr-*-doh_path">`doh_path`</a>: The path template for the DoH DDR SVCB records. It is optional, unless `https_port` below is set.

    - <a href="#sg-*-ddr-dr-*-https_port" id="sg-*-ddr-dr-*-https_port" name="sg-*-ddr-dr-*-https_port">`https_port`</a>: The optional port to use in DDR responses about the DoH resolver. If it is zero, the DoH resolver address is not included into the answer. A non-zero `https_port` should not be the same as `tls_port` below.

    - <a href="#sg-*-ddr-dr-*-quic_port" id="sg-*-ddr-dr-*-quic_port" name="sg-*-ddr-dr-*-quic_port">`quic_port`</a>: The optional port to use in DDR responses about the DoQ resolver. If it is zero, the DoQ resolver address is not included into the answer.

    - <a href="#sg-*-ddr-dr-*-tls_port" id="sg-*-ddr-dr-*-tls_port" name="sg-*-ddr-dr-*-tls_port">`tls_port`</a>: The optional port to use in DDR responses about the DoT resolver. If it is zero, the DoT resolver address is not included into the answer. A non-zero `tls_port` should not be the same as `https_port` above.

    - <a href="#sg-*-ddr-dr-*-ipv4_hints" id="sg-*-ddr-dr-*-ipv4_hints" name="sg-*-ddr-dr-*-ipv4_hints">`ipv4_hints`</a>: The optional hints about the IPv4-addresses of the server.

    - <a href="#sg-*-ddr-dr-*-ipv6_hints" id="sg-*-ddr-dr-*-ipv6_hints" name="sg-*-ddr-dr-*-ipv6_hints">`ipv6_hints`</a>: The optional hints about the IPv6-addresses of the server.

    **Property example:**

    ```yaml
    'device_records':
        '*.d.dns.example.com':
            doh_path: '/dns-query{?dns}'
            https_port: 443
            quic_port: 853
            tls_port: 853
            ipv4_hints:
              - 1.2.3.4
            ipv6_hints:
              - '2001::1234'
        '*.e.dns.example.org':
            doh_path: '/dns-query{?dns}'
            https_port: 10443
            quic_port: 10853
            tls_port: 10853
            ipv4_hints:
              - 5.6.7.8
            ipv6_hints:
              - '2001::5678'
    ```

- <a href="#sg-*-ddr-public_records" id="sg-*-ddr-public_records" name="sg-*-ddr-public_records">`public_records`</a>: The public domain name to DDR record template mapping. The format of the values is the same as in the [`device_records`](#sg-*-ddr-device_records)
    above.

### <a href="#server_groups-*-tls" id="server_groups-*-tls" name="server_groups-*-tls">TLS</a>

- <a href="#sg-*-tls-certificates" id="sg-*-tls-certificates" name="sg-*-tls-certificates">`certificates`</a>: The array of objects with paths to the certificate and the private key for this server group.

    **Property example:**

    ```yaml
    'certificates':
      - 'certificate': '/etc/dns/cert.crt'
        'key': '/etc/dns/cert.key'
    ```

- <a href="#sg-*-tls-session_keys" id="sg-*-tls-session_keys" name="sg-*-tls-session_keys">`session_keys`</a>: The array of file paths from which the each server's TLS session keys are updated. Session ticket key files must contain at least 32 bytes.

    **Property example:**

    ```yaml
    'session_keys':
      - './private/key_1'
      - './private/key_2'
    ```

- <a href="#sg-*-tls-device_id_wildcards" id="sg-*-tls-device_id_wildcards" name="sg-*-tls-device_id_wildcards">`device_id_wildcards`</a>: The array of domain name wildcards to use to detect clients' device IDs. Use this to prevent conflicts when using certificates for subdomains.

    **Property example:**

    ```yaml
    'device_id_wildcards':
      - '*.d.dns.example.com'
    ```

### <a href="#server_groups-*-servers-*" id="server_groups-*-servers-*" name="server_groups-*-servers-*">Servers</a>

The items of the `servers` array have the following properties:

- <a href="#sg-s-*-name" id="sg-s-*-name" name="sg-s-*-name">`name`</a>: The unique name of this server.

    **Example:** `default_dns`.

- <a href="#sg-s-*-protocol" id="sg-s-*-protocol" name="sg-s-*-protocol">`protocol`</a>: The protocol to use on this server. The following values are supported:

    - `dns`
    - `dnscrypt`
    - `https`
    - `quic`
    - `tls`

    **Example:** `dns`.

- <a href="#sg-s-*-linked_ip_enabled" id="sg-s-*-linked_ip_enabled" name="sg-s-*-linked_ip_enabled">`linked_ip_enabled`</a>: If true, use the profiles' linked IPs to detect.

    **Default:** `false`.

    **Example:** `true`.

- <a href="#sg-s-*-bind_addresses" id="sg-s-*-bind_addresses" name="sg-s-*-bind_addresses">`bind_addresses`</a>: The array of `ip:port` addresses to listen on. If `bind_addresses` is set, `bind_interfaces` (see below) should not be set.

    **Example:** `[127.0.0.1:53, 192.168.1.1:53]`.

- <a href="#sg-s-*-bind_interfaces" id="sg-s-*-bind_interfaces" name="sg-s-*-bind_interfaces">`bind_interfaces`</a>: The array of [interface listener](#ifl-list) data. If `bind_interfaces` is set, `bind_addresses` (see above) should not be set.

    **Property example:**

    ```yaml
    'bind_interfaces':
      - 'id': 'eth0_plain_dns'
        'subnets':
          - '172.17.0.0/16'
      - 'id': 'eth0_plain_dns_secondary'
        'subnets':
          - '172.17.0.0/16'
    ```

- <a href="#sg-s-*-dnscrypt" id="sg-s-*-dnscrypt" name="sg-s-*-dnscrypt">`dnscrypt`</a>: The optional DNSCrypt configuration object. It has the following properties:

    - <a href="#sg-s-*-dnscrypt-config_path" id="sg-s-*-dnscrypt-config_path" name="sg-s-*-dnscrypt-config_path">`config_path`</a>: The path to the DNSCrypt configuration file. See the [configuration section][dnscconf] of the DNSCrypt module.

        Must not be set if `inline` is set.

        **Example:** `/etc/dns/dnscrypt.yml`

    - <a href="#sg-s-*-dnscrypt-inline" id="sg-s-*-dnscrypt-inline" name="sg-s-*-dnscrypt-inline">`inline`</a>: The DNSCrypt configuration, inline. See the [configuration section][dnscconf] of the DNSCrypt module.

        Must not be set if `config_path` is set.

        **Property example:**

        ```yaml
        'inline':
          'provider_name': '2.dnscrypt-cert.example.org'
          'public_key': 'F11DDBCC4817E543845FDDD4CB881849B64226F3DE397625669D87B919BC4FB0'
          'private_key': '5752095FFA56D963569951AFE70FE1690F378D13D8AD6F8054DFAA100907F8B6F11DDBCC4817E543845FDDD4CB881849B64226F3DE397625669D87B919BC4FB0'
          'resolver_secret': '9E46E79FEB3AB3D45F4EB3EA957DEAF5D9639A0179F1850AFABA7E58F87C74C4'
          'resolver_public': '9327C5E64783E19C339BD6B680A56DB85521CC6E4E0CA5DF5274E2D3CE026C6B'
          'es_version': 1
          'certificate_ttl': 8760h
        ```

[dnscconf]: https://github.com/ameshkov/dnscrypt/blob/master/README.md#configure

## <a href="#connectivity-check" id="connectivity-check" name="connectivity-check">Connectivity check</a>

The `connectivity_check` object has the following properties:

- <a href="#connectivity_check-probe_ipv4" id="connectivity_check-probe_ipv4" name="connectivity_check-probe_ipv4">`probe_ipv4`</a>: The IPv4 address with port to which a connectivity check is performed.

    **Example:** `8.8.8.8:53`.

- <a href="#connectivity_check-probe_ipv6" id="connectivity_check-probe_ipv6" name="connectivity_check-probe_ipv6">`probe_ipv6`</a>: The optional IPv6 address with port to which a connectivity check is performed. This field is required in case of any IPv6 address in [`bind_addresses`](#sg-s-*-bind_addresses).

    **Example:** `[2001:4860:4860::8888]:53`.

## <a href="#network" id="network" name="network">Network settings</a>

The `network` object has the following properties:

- <a href="#network-so_rcvbuf" id="network-so_rcvbuf" name="network-so_rcvbuf">`so_rcvbuf`</a>: The size of socket receive buffer (`SO_RCVBUF`), in a human-readable format. Default is zero, which means use the default system settings.

    See also [notes on these parameters](#recommended-buffers).

    **Example:** `1MB`.

- <a href="#network-so_sndbuf" id="network-so_sndbuf" name="network-so_sndbuf">`so_sndbuf`</a>: The size of socket send buffer (`SO_SNDBUF`), in a human-readable format. Default is zero, which means use the default system settings.

    See also [notes on these parameters](#recommended-buffers).

    **Example:** `1MB`.

## <a href="#access" id="access" name="access">Access settings</a>

The `access` object has the following properties:

- <a href="#access-blocked_question_domains" id="access-blocked_question_domains" name="access-blocked_question_domains">`blocked_question_domains`</a>: The list of domains or AdBlock rules to block requests.

   **Examples:** `test.org`, `||example.org^$dnstype=AAAA`.

- <a href="#access-blocked_client_subnets" id="access-blocked_client_subnets" name="access-blocked_client_subnets">`blocked_client_subnets`</a>: The list of IP addresses or CIDR-es to block.

   **Example:** `127.0.0.1`.

## <a href="#additional_metrics_info" id="additional_metrics_info" name="additional_metrics_info">Additional metrics information</a>

The `additional_metrics_info` object is a map of strings with extra information which is exposed by `dns_app_additional_info` metric.

Map keys must match regular expression `^[a-zA-Z_][a-zA-Z0-9_]*$`. See [Prometheus documentation on valid labels][prom-label].

**Property example:**

```yaml
'additional_metrics_info':
    'info_key_1': 'info_value_1'
    'info_key_2': 'info_value_2'
```

The Prometheus metrics key is `additional_info`. For example:

```none
# HELP dns_app_additional_info A metric with a constant '1' value labeled by additional info provided in configuration
# TYPE dns_app_additional_info gauge
dns_app_additional_info{info_key_1="info_value_1",info_key_2="info_value_2"} 1
```

[prom-label]: https://pkg.go.dev/github.com/prometheus/common/model#LabelNameRE

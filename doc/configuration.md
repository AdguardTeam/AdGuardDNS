 #  AdGuard DNS Configuration File

Besides the [environment][env], AdGuard DNS uses a [YAML][yaml] file to store
configuration.  See file [`config.dist.yml`][dist] for a full example of a
configuration file with comments.

##  Contents

 *  [Rate Limiting](#ratelimit)
 *  [Cache](#cache)
 *  [Upstream](#upstream)
     *  [Healthcheck](#upstream-healthcheck)
 *  [Backend](#backend)
 *  [Query Log](#query_log)
 *  [GeoIP Database](#geoip)
 *  [DNS Server Check](#check)
 *  [Web API](#web)
 *  [Safe Browsing](#safe_browsing)
 *  [Adult Content Blocking](#adult_blocking)
 *  [Filters](#filters)
 *  [Filtering Groups](#filtering_groups)
 *  [Server Groups](#server_groups)
     *  [TLS](#server_groups-*-tls)
     *  [DDR](#server_groups-*-ddr)
     *  [Servers](#server_groups-*-servers-*)
 *  [Connectivity Check](#connectivity-check)
 *  [Additional Metrics Info](#additional_metrics_info)

[dist]: ../config.dist.yml
[env]:  environment.md
[yaml]: https://yaml.org/



##  <a href="#ratelimit" id="ratelimit" name="ratelimit">Rate Limiting</a>

The `ratelimit` object has the following properties:

 *  <a href="#ratelimit-refuseany" id="ratelimit-refuseany" name="ratelimit-refuseany">`refuseany`</a>:
    If true, refuse DNS queries with the `ANY` (aka `*`) type.

    **Example:** `true`.

 *  <a href="#ratelimit-response_size_estimate" id="ratelimit-response_size_estimate" name="ratelimit-response_size_estimate">`response_size_estimate`</a>:
    The size of one DNS response for the purposes of rate limiting.  If a DNS
    response is larger than this value, it is counted as several responses.

    **Example:** `1KB`.

 *  <a href="#ratelimit-back_off_period" id="ratelimit-back_off_period" name="ratelimit-back_off_period">`back_off_period`</a>:
    The time during which to count the number of requests that a client has sent
    over the RPS.

    **Example:** `10m`.

 *  <a href="#ratelimit-back_off_duration" id="ratelimit-back_off_duration" name="ratelimit-back_off_duration">`back_off_duration`</a>:
    How long a client that has hit the RPS too often stays in the backoff state.

    **Example:** `30m`.

 *  <a href="#ratelimit-rps" id="ratelimit-rps" name="ratelimit-rps">`rps`</a>:
    The rate of requests per second for one subnet.  Requests above this are
    counted in the backoff count.

    **Example:** `30`.

 *  <a href="#ratelimit-back_off_count" id="ratelimit-back_off_count" name="ratelimit-back_off_count">`back_off_count`</a>:
    Maximum number of requests a client can make above the RPS within
    a `back_off_period`.  When a client exceeds this limit, requests aren't
    allowed from client's subnet until `back_off_duration` ends.

    **Example:** `1000`.

 *  <a href="#ratelimit-allowlist" id="ratelimit-allowlist" name="ratelimit-allowlist">`allowlist`</a>:
    The allowlist configuration object.   It has the following fields:

     *  <a href="#ratelimit-allowlist-list" id="ratelimit-allowlist-list" name="ratelimit-allowlist-list">`list`</a>:
        The array of the allowed IPs or CIDRs.

        **Property example:**

        ```yaml
        'list':
          - '192.168.1.4'
          - '192.175.2.1/16'
        ```

     *  <a href="#ratelimit-allowlist-refresh_interval" id="ratelimit-allowlist-refresh_interval" name="ratelimit-allowlist-refresh_interval">`refresh_interval`</a>:
        How often AdGuard DNS refreshes the dynamic part of its allowlist from
        the data received from the `CONSUL_URL`, as a human-readable duration.

        **Example:** `30s`.

 *  <a href="#ratelimit-ipv4_subnet_key_len" id="ratelimit-ipv4_subnet_key_len" name="ratelimit-ipv4_subnet_key_len">`ipv4_subnet_key_len`</a>:
    The length of the subnet prefix used to calculate rate limiter bucket keys
    for IPv4 addresses.

    **Example:** `24`.

 *  <a href="#ratelimit-ipv6_subnet_key_len" id="ratelimit-ipv6_subnet_key_len" name="ratelimit-ipv6_subnet_key_len">`ipv6_subnet_key_len`</a>:
    Same as `ipv4_subnet_key_len` above but for IPv6 addresses.

    **Example:** `48`.

For example, if `back_off_period` is `1m`, `back_off_count` is `10`, and `rps`
is `5`, a client (meaning all IP addresses within the subnet defined by
`ipv4_subnet_key_len` and `ipv6_subnet_key_len`) that made 15 requests in one
second or 6 requests (one above `rps`) every second for 10 seconds within one
minute, the client is blocked for `back_off_duration`.



##  <a href="#cache" id="cache" name="cache">Cache</a>

The `cache` object has the following properties:

 *  <a href="#cache-type" id="cache-type" name="cache-type">`type`</a>:
    The type of cache to use.  Can be `simple` (a simple LRU cache) or `ecs` (a
    ECS-aware LRU cache).  If set to `ecs`, `ecs_size` must be greater than
    zero.

    **Example:** `simple`.

 *  <a href="#cache-size" id="cache-size" name="cache-size">`size`</a>:
    The total number of items in the cache for hostnames with no ECS support.
    Must be greater than or equal to zero.  If zero, cache is disabled.

    **Example:** `10000`.

 *  <a href="#cache-ecs_size" id="cache-ecs_size" name="cache-ecs_size">`ecs_size`</a>:
    The total number of items in the cache for hostnames with ECS support.

    **Example:** `10000`.



##  <a href="#upstream" id="upstream" name="upstream">Upstream</a>

The `upstream` object has the following properties:

 *  <a href="#upstream-server" id="upstream-server" name="upstream-server">`server`</a>:
    The address of the main upstream server, in the `ip:port` format.

    **Example:** `8.8.8.8:53` or `[2001:4860:4860::8844]:53`.

 *  <a href="#upstream-timeout" id="upstream-timeout" name="upstream-timeout">`timeout`</a>:
    Timeout for all outgoing DNS requests, as a human-readable duration.

    **Example:** `2s`.

 *  <a href="#upstream-fallback" id="upstream-fallback" name="upstream-fallback">`fallback`</a>:
    The array of addresses of the fallback upstream servers, in the `ip:port`
    format.  These are use used in case a network error occurs while requesting
    the main upstream server.

    **Example:** `['1.1.1.1:53', '[2001:4860:4860::8888]:53']`.

 *  `healthcheck`: Healthcheck configuration.  See
    [below](#upstream-healthcheck).



   ###  <a href="#upstream-healthcheck" id="upstream-healthcheck" name="upstream-healthcheck">Healthcheck</a>

If `enabled` is true, the upstream healthcheck is enabled.  The healthcheck
worker probes the main upstream with an `A` query for a domain created from
`domain_template`.  If there is an error, timeout, or a response different from
a `NOERROR` one then the main upstream is considered down, and all requests are
redirected to fallback upstream servers for the time set by `backoff_duration`.
Afterwards, if a worker probe is successful, AdGuard DNS considers the
connection to the main upstream as restored, and requests are routed back to it.

 *  <a href="#u-h-enabled" id="u-h-enabled" name="u-h-enabled">`enabled`</a>:

    If true, the upstream healthcheck is enabled.

    **Example:** `true`.

 *  <a href="#u-h-interval" id="u-h-interval" name="u-h-interval">`interval`</a>:
    How often AdGuard DNS makes upstream healthcheck requests, as a
    human-readable duration.

    **Example:** `2s`.

 *  <a href="#u-h-timeout" id="u-h-timeout" name="u-h-timeout">`timeout`</a>:
    Timeout for all outgoing healthcheck requests, as a human-readable duration.

    **Example:** `1s`.

 *  <a href="#u-h-backoff_duration" id="u-h-backoff_duration" name="u-h-backoff_duration">`backoff_duration`</a>:
    Backoff duration after failed healthcheck request, as a human-readable
    duration.  If the main upstream is down, AdGuardDNS does not return back to
    using it until this time has passed.  The healthcheck is still performed,
    and each failed check advances the backoff.

    **Example:** `30s`.

 *  <a href="#u-h-domain_template" id="u-h-domain_template" name="u-h-domain_template">`domain_template`</a>:
    The template for domains used to perform healthcheck queries.  If the
    `domain_template` contains the string `${RANDOM}`, all occurrences of this
    string are replaced with a random string (currently, a hexadecimal form of a
    64-bit integer) on every healthcheck query.  Queries must return a `NOERROR`
    response.

    **Example:** `${RANDOM}.neverssl.com`.



##  <a href="#backend" id="backend" name="backend">Backend</a>

The `backend` object has the following properties:

 *  <a href="#backend-timeout" id="backend-timeout" name="backend-timeout">`timeout`</a>:
    Timeout for all outgoing HTTP requests to the backend, as a human-readable
    duration.  Set to `0s` to disable timeouts.

    **Example:** `10s`.

 *  <a href="#backend-refresh_interval" id="backend-refresh_interval" name="backend-refresh_interval">`refresh_interval`</a>:
    How often AdGuard DNS checks the backend for data updates, as a
    human-readable duration.

    **Example:** `1m`.

 *  <a href="#backend-full_refresh_interval" id="backend-full_refresh_interval" name="backend-full_refresh_interval">`full_refresh_interval`</a>:
    How often AdGuard DNS performs full synchronization, as a human-readable
    duration.

    **Example:** `24h`.

 *  <a href="#backend-bill_stat_interval" id="backend-bill_stat_interval" name="backend-bill_stat_interval">`bill_stat_interval`</a>:
    How often AdGuard DNS sends the billing statistics to the backend, as
    a human-readable duration.

    **Example:** `1m`.



##  <a href="#query_log" id="query_log" name="query_log">Query Log</a>

The `query_log` object has the following properties:

 *  <a href="#query_log-file" id="query_log-file" name="query_log-file">`file`</a>:
    The file query log configuration object.  It has the following properties:

     *  <a href="#q-file-enabled" id="q-file-enabled" name="q-file-enabled">`enabled`</a>:
        If true, the JSONL file query logging is enabled.

        **Property example:**

        ```yaml
        'file':
            'enabled': true
        ```



##  <a href="#geoip" id="geoip" name="geoip">GeoIP Database</a>

The `geoip` object has the following properties:

 *  <a href="#geoip-host_cache_size" id="geoip-host_cache_size" name="geoip-host_cache_size">`host_cache_size`</a>:
    The size of the host lookup cache, in entries.

    **Example:** `100000`.

 *  <a href="#geoip-ip_cache_size" id="geoip-ip_cache_size" name="geoip-ip_cache_size">`ip_cache_size`</a>:
    The size of the IP lookup cache, in entries.

    **Example:** `100000`.

 *  <a href="#geoip-refresh_interval" id="geoip-refresh_interval" name="geoip-refresh_interval">`refresh_interval`</a>:
    Interval between the GeoIP database refreshes, as a human-readable duration.

    **Example:** `5m`.



##  <a href="#check" id="check" name="check">DNS Server Check</a>

The `check` object has the following properties:

 *  <a href="#check-domains" id="check-domains" name="check-domains">`domains`</a>:
    The domain suffixes to which random IDs are prepended using a hyphen.

    **Property example:**

    ```yaml
    'domains':
      - 'dnscheck.example.com'
      - 'checkdns.example.com'
    ```

 *  <a href="#check-node_location" id="check-node_location" name="check-node_location">`node_location`</a>:
    The location code of this server node.

    **Example:** `ams`.

 *  <a href="#check-node_name" id="check-node_name" name="check-node_name">`node_name`</a>:
    The name of this server node.

    **Example:** `eu-1.dns.example.com`.

 *  <a href="#check-ttl" id="check-ttl" name="check-ttl">`ttl`</a>:
    For how long to keep the information about a single user in Consul KV, as
    a human-readable duration.  Note the actual TTL may be up to twice as long
    due to Consul's peculiarities.

    **Example:** `30s`.

 *  <a href="#check-ipv4" id="check-ipv4" name="check-ipv4">`ipv4` and `ipv6`</a>:
    Arrays of IPv4 or IPv6 addresses with which to respond to `A` and `AAAA`
    queries correspondingly.  Generally, those should be the IP addresses of the
    AdGuard DNS [main HTTP API][http-dnscheck] for the DNS server check feature
    to work properly.  In a development setup, that means the localhost
    addresses.

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



##  <a href="#web" id="web" name="web">Web API</a>

The optional `web` object has the following properties:

 *  <a href="#web-linked_ip" id="web-linked_ip" name="web-linked_ip">`linked_ip`</a>:
    The optional linked IP and dynamic DNS (DDNS, DynDNS) web server
    configuration.  The [static content](#web-static_content) is not served on
    these addresses.

    See the [full description of this API][http-linked-ip-proxy] on the HTTP API
    page.

    Property `bind` has the same format as [`non_doh_bind`](#web-non_doh_bind)
    below.

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

 *  <a href="#web-safe_browsing" id="web-safe_browsing" name="web-safe_browsing">`safe_browsing`</a>:
    The optional safe browsing web server configurations.  Every request is
    responded with the content from the file to which the `block_page` property
    points.

    See the [full description of this API][http-block-pages] on the HTTP API
    page.

    Property `bind` has the same format as [`non_doh_bind`](#web-non_doh_bind)
    below.  The addresses should be different from the `adult_blocking` server,
    and the same as the ones of the `block_host` property in the
    [`safe_browsing`](#safe_browsing) and [`adult_blocking`](#adult_blocking)
    objects correspondingly.

    While this object is optional, both `bind` and `block_page` properties
    within them are required.

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

 *  <a href="#web-adult_blocking" id="web-adult_blocking" name="web-adult_blocking">`adult_blocking`</a>:
    The optional adult blocking web server configurations.  The format of the
    values is the same as in the [`safe_browsing`](#web-safe_browsing) object
    above.

 *  <a href="#web-non_doh_bind" id="web-non_doh_bind" name="web-non_doh_bind">`non_doh_bind`</a>:
    The optional listen addresses and optional TLS configuration for the web
    service in addition to the ones in the DNS-over-HTTPS handlers.  The
    `certificates` array has the same format as the one in a server group's [TLS
    settings](#sg-*-tls).  In the special case of `GET /robots.txt` requests, a
    special response is served; this response could be overwritten with static
    content.

    **Property example:**

    ```yaml
    'non_doh_bind':
      - 'address': '127.0.0.1:80'
      - 'address': '127.0.0.1:443'
        'certificates':
          - 'certificate': './test/cert.crt'
            'key': './test/cert.key'
    ```

 *  <a href="#web-static_content" id="web-static_content" name="web-static_content">`static_content`</a>:
    The optional inline static content mapping.  Not served on the `linked_ip`,
    `safe_browsing` and `adult_blocking` servers.  Paths must not duplicate the
    ones used by the DNS-over-HTTPS server.

    **Property example:**

    ```yaml
    'static_content':
        '/favicon.ico':
            'content_type': 'image/x-icon'
            'content': 'base64content'
    ```

 *  <a href="#web-root_redirect_url" id="web-root_redirect_url" name="web-root_redirect_url">`root_redirect_url`</a>:
    The optional URL to which non-DNS and non-Debug HTTP requests are
    redirected.  If not set, AdGuard DNS will respond with a 404 status to all
    such requests.

    **Example:** `https://adguard-dns.com/`.

 *  <a href="#web-error_404" id="web-error_404" name="web-error_404">`error_404` and `error_500`</a>:
    The optional paths to the 404 page and the 500 page HTML files
    correspondingly.  If not set, a simple plain text 404 or 500 page is served.

    **Example:** `/var/www/404.html`.

 *  <a href="#web-timeout" id="web-timeout" name="web-timeout">`timeout`</a>:
    The timeout for server operations, as a human-readable duration.

    **Example:** `30s`.

[http-block-pages]:     http.md#block-pages
[http-dnscheck-test]:   http.md#dhscheck-test
[http-linked-ip-proxy]: http.md#linked-ip-proxy



##  <a href="#safe_browsing" id="safe_browsing" name="safe_browsing">Safe Browsing</a>

The `safe_browsing` object has the following properties:

 *  <a href="#safe_browsing-block_host" id="safe_browsing-block_host" name="safe_browsing-block_host">`block_host`</a>:
    The host with which to respond to any requests that match the filter.

    **Example:** `standard-block.dns.adguard.com`.

 *  <a href="#safe_browsing-cache_size" id="safe_browsing-cache_size" name="safe_browsing-cache_size">`cache_size`</a>:
    The size of the response cache, in entries.

    **WARNING: CURRENTLY IGNORED!**  See AGDNS-398.

    **Example:** `1024`.

 *  <a href="#safe_browsing-cache_ttl" id="safe_browsing-cache_ttl" name="safe_browsing-cache_ttl">`cache_ttl`</a>:
    The TTL of the response cache, as a human-readable duration.

    **Example:** `1h`.

 *  <a href="#safe_browsing-url" id="safe_browsing-url" name="safe_browsing-url">`url`</a>:
    The URL from which the contents can be updated.  The URL must reply with
    a 200 status code.

    **Example:** `https://example.com/safe_browsing.txt`.

 *  <a href="#safe_browsing-refresh_interval" id="safe_browsing-refresh_interval" name="safe_browsing-refresh_interval">`refresh_interval`</a>:
    How often AdGuard DNS refreshes the filter.

    **Example:** `1m`.



##  <a href="#adult_blocking" id="adult_blocking" name="adult_blocking">Adult Content Blocking</a>

The `adult_blocking` object has the same properties as the
[`safe_browsing`](#safe_browsing) one above.



##  <a href="#filters" id="filters" name="filters">Filter Lists</a>

The `filters` object has the following properties:

 *  <a href="#filters-response_ttl" id="filters-response_ttl" name="filters-response_ttl">`response_ttl`</a>:
    The default TTL to set for responses to queries for blocked or modified
    domains, as a human-readable duration.  It is used for anonymous users.  For
    users with profiles, the TTL from their profile settings are used.

    **Example:** `10s`.

 *  <a href="#filters-custom_filter_cache_size" id="filters-custom_filter_cache_size" name="filters-custom_filter_cache_size">`custom_filter_cache_size`</a>:
    The size of the LRU cache of compiled filtering rule engines for profiles
    with custom filtering rules, in entries.  Zero means no caching, which slows
    down queries.

    **Example:** `1024`.

 *  <a href="#filters-refresh_interval" id="filters-refresh_interval" name="filters-refresh_interval">`refresh_interval`</a>:
    How often AdGuard DNS refreshes the rule-list filters from the filter index,
    as well as the blocked services list from the [blocked list
    index][env-blocked_services)].

    **Example:** `1h`.

 *  <a href="#filters-refresh_timeout" id="filters-refresh_timeout" name="filters-refresh_timeout">`refresh_timeout`</a>:
    The timeout for the *entire* filter update operation, as a human-readable
    duration.  Be aware that each individual refresh operation also has its own
    hardcoded 30s timeout.

    **Example:** `5m`.

[env-blocked_services]: environment.md#BLOCKED_SERVICE_INDEX_URL



##  <a href="#filtering_groups" id="filtering_groups" name="filtering_groups">Filtering Groups</a>

The items of the `filtering_groups` array have the following properties:

 *  <a href="#fg-*-id" id="fg-*-id" name="fg-*-id">`id`</a>:
    The unique ID of this filtering group.


    **Example:** `default`.

 *  <a href="#fg-*-rule_lists" id="fg-*-rule_lists" name="fg-*-rule_lists">`rule_lists`</a>:
    Filtering rule lists settings.  This object has the following properties:

     *  <a href="#fg-*-rl-enabled" id="fg-*-rl-enabled" name="fg-*-rl-enabled">`enabled`</a>:
        Shows if rule-list filtering should be enforced.  If it is set to
        `false`, the rest of the settings are ignored.

        **Example:** `true`.

     *  <a href="#fg-*-rl-ids" id="fg-*-rl-ids" name="fg-*-rl-ids">`ids`</a>:
        The array of rule-list IDs used in this filtering group.

        **Example:** `[adguard_dns_default]`.

 *  <a href="#fg-*-parental" id="fg-*-parental" name="fg-*-parental">`parental`</a>:
    Parental protection settings.  This object has the following properties:

     *  <a href="#fg-*-p-enabled" id="fg-*-p-enabled" name="fg-*-p-enabled">`enabled`</a>:
        Shows if any kind of parental protection filtering should be enforced at
        all.  If it is set to `false`, the rest of the settings are ignored.

        **Example:** `true`.

     *  <a href="#fg-*-p-block_adult" id="fg-*-p-block_adult" name="fg-*-p-block_adult">`block_adult`</a>:
        If true, adult content blocking is enabled for this filtering group by
        default.  Requires `enabled` to also be true.

        **Example:** `true`.

     *  <a href="#fg-*-p-general_safe_search" id="fg-*-p-general_safe_search" name="fg-*-p-general_safe_search">`general_safe_search`</a>:
        If true, general safe search is enabled for this filtering group by
        default.  Requires `enabled` to also be true.

        **Example:** `true`.

     *  <a href="#fg-*-p-youtube_safe_search" id="fg-*-p-youtube_safe_search" name="fg-*-p-youtube_safe_search">`youtube_safe_search`</a>:
        If true, YouTube safe search is enabled for this filtering group by
        default.  Requires `enabled` to also be true.

        **Example:** `true`.

 *  <a href="#fg-*-safe_browsing" id="fg-*-safe_browsing" name="fg-*-safe_browsing">`safe_browsing`</a>:
    General safe browsing settings.  This object has the following properties:

     *  <a href="#fg-*-sb-enabled" id="fg-*-sb-enabled" name="fg-*-sb-enabled">`enabled`</a>:
        Shows if the general safe browsing filtering should be enforced.  If it
        is set to `false`, the rest of the settings are ignored.

        **Example:** `true`.

 *  <a href="#fg-*-block_private_relay" id="fg-*-block_private_relay" name="fg-*-block_private_relay">`private_relay`</a>:
    If true, Apple Private Relay queries are blocked for requests using this
    filtering group.

    **Example:** `false`.



##  <a href="#server_groups" id="server_groups" name="server_groups">Server Groups</a>

The items of the `server_groups` array have the following properties:

 *  <a href="#sg-*-name" id="sg-*-name" name="sg-*-name">`name`</a>:
    The unique name of this server group.

    **Example:** `adguard_dns_default`.

 *  <a href="#sg-*-filtering_group" id="sg-*-filtering_group" name="sg-*-filtering_group">`filtering_group`</a>:
    The default filtering group for this server group.  It is used for anonymous
    users.

    **Example:** `default`.

 *  `tls`: The optional TLS configuration object.  See
    [below](#server_groups-*-tls).

 *  `ddr`: The DDR configuration object.  See [below](#server_groups-*-ddr).

 *  `servers`: Server configuration for this filtering group.  See
    [below](#server_groups-*-servers-*).



   ###  <a href="#server_groups-*-tls" id="server_groups-*-tls" name="server_groups-*-tls">TLS</a>

 *  <a href="#sg-*-tls-certificates" id="sg-*-tls-certificates" name="sg-*-tls-certificates">`certificates`</a>:
    The array of objects with paths to the certificate and the private key for
    this server group.

    **Property example:**

    ```yaml
    'certificates':
      - 'certificate': '/etc/dns/cert.crt'
        'key': '/etc/dns/cert.key'
    ```

 *  <a href="#sg-*-tls-session_keys" id="sg-*-tls-session_keys" name="sg-*-tls-session_keys">`session_keys`</a>:
    The array of file paths from which the each server's TLS session keys are
    updated.  Session ticket key files must contain at least 32 bytes.

    **Property example:**

    ```yaml
    'session_keys':
      - './private/key_1'
      - './private/key_2'
    ```

 *  <a href="#sg-*-tls-device_id_wildcards" id="sg-*-tls-device_id_wildcards" name="sg-*-tls-device_id_wildcards">`device_id_wildcards`</a>:
    The array of domain name wildcards to use to detect clients' device IDs.
    Use this to prevent conflicts when using certificates for subdomains.

    **Property example:**

    ```yaml
    'device_id_wildcards':
      - '*.d.dns.example.com'
    ```



   ###  <a href="#server_groups-*-ddr" id="server_groups-*-ddr" name="server_groups-*-ddr">DDR</a>

The DDR configuration object.  Many of these data duplicate data from objects in
the [`servers`](#server_groups-*-servers-*) array.  This was done because there
was an opinion that a more restrictive configuration that automatically
collected the required data was not self-describing and flexible enough.

 *  <a href="#sg-*-ddr-enabled" id="sg-*-ddr-enabled" name="sg-*-ddr-enabled">`enabled`</a>:
    Shows if DDR queries are processed.  If it is set to `false`, DDR domain
    name queries receive an `NXDOMAIN` response.

    **Example:** `true`.

 *  <a href="#sg-*-ddr-device_records" id="sg-*-ddr-device_records" name="sg-*-ddr-device_records">`device_records`</a>:
    The device ID wildcard to record template mapping.  The keys should
    generally be kept in sync with the
    [`device_id_wildcards`](#sg-*-tls-device_id_wildcards) field of the `tls`
    object.

    The values have the following properties:

     *  <a href="#sg-*-ddr-dr-*-doh_path" id="sg-*-ddr-dr-*-doh_path" name="sg-*-ddr-dr-*-doh_path">`doh_path`</a>:
        The path template for the DoH DDR SVCB records.  It is optional, unless
        `https_port` below is set.

     *  <a href="#sg-*-ddr-dr-*-https_port" id="sg-*-ddr-dr-*-https_port" name="sg-*-ddr-dr-*-https_port">`https_port`</a>:
        The optional port to use in DDR responses about the DoH resolver.  If it
        is zero, the DoH resolver address is not included into the answer.  A
        non-zero `https_port` should not be the same as `tls_port` below.

     *  <a href="#sg-*-ddr-dr-*-quic_port" id="sg-*-ddr-dr-*-quic_port" name="sg-*-ddr-dr-*-quic_port">`quic_port`</a>:
        The optional port to use in DDR responses about the DoQ resolver.  If it
        is zero, the DoQ resolver address is not included into the answer.

     *  <a href="#sg-*-ddr-dr-*-tls_port" id="sg-*-ddr-dr-*-tls_port" name="sg-*-ddr-dr-*-tls_port">`tls_port`</a>:
        The optional port to use in DDR responses about the DoT resolver.  If it
        is zero, the DoT resolver address is not included into the answer.  A
        non-zero `tls_port` should not be the same as `https_port` above.

     *  <a href="#sg-*-ddr-dr-*-ipv4_hints" id="sg-*-ddr-dr-*-ipv4_hints" name="sg-*-ddr-dr-*-ipv4_hints">`ipv4_hints`</a>:
        The optional hints about the IPv4-addresses of the server.

     *  <a href="#sg-*-ddr-dr-*-ipv6_hints" id="sg-*-ddr-dr-*-ipv6_hints" name="sg-*-ddr-dr-*-ipv6_hints">`ipv6_hints`</a>:
        The optional hints about the IPv6-addresses of the server.

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


 *  <a href="#sg-*-ddr-public_records" id="sg-*-ddr-public_records" name="sg-*-ddr-public_records">`public_records`</a>:
    The public domain name to DDR record template mapping.  The format of the
    values is the same as in the [`device_records`](#sg-*-ddr-device_records)
    above.



   ###  <a href="#server_groups-*-servers-*" id="server_groups-*-servers-*" name="server_groups-*-servers-*">Servers</a>

The items of the `servers` array have the following properties:

 *  <a href="#sg-s-*-name" id="sg-s-*-name" name="sg-s-*-name">`name`</a>:
    The unique name of this server.

    **Example:** `default_dns`.

 *  <a href="#sg-s-*-protocol" id="sg-s-*-protocol" name="sg-s-*-protocol">`protocol`</a>:
    The protocol to use on this server.  The following values are supported:

     *  `dns`
     *  `dnscrypt`
     *  `https`
     *  `quic`
     *  `tls`

    **Example:** `dns`.

 *  <a href="#sg-s-*-linked_ip_enabled" id="sg-s-*-linked_ip_enabled" name="sg-s-*-linked_ip_enabled">`linked_ip_enabled`</a>:
    If true, use the profiles' linked IPs to detect.

    **Default:** `false`.

    **Example:** `true`.

 *  <a href="#sg-s-*-bind_addresses" id="sg-s-*-bind_addresses" name="sg-s-*-bind_addresses">`bind_addresses`</a>:
    The array of `ip:port` addresses to listen on.

    **Example:** `[127.0.0.1:53, 192.168.1.1:53]`.

 *  <a href="#sg-s-*-dnscrypt" id="sg-s-*-dnscrypt" name="sg-s-*-dnscrypt">`dnscrypt`</a>:
    The optional DNSCrypt configuration object.  It has the following
    properties:

     *  <a href="#sg-s-*-dnscrypt-config_path" id="sg-s-*-dnscrypt-config_path" name="sg-s-*-dnscrypt-config_path">`config_path`</a>:
        The path to the DNSCrypt configuration file.  See the [configuration
        section][dnscconf] of the DNSCrypt module.

        Must not be set if `inline` is set.

        **Example:** `/etc/dns/dnscrypt.yml`

     *  <a href="#sg-s-*-dnscrypt-inline" id="sg-s-*-dnscrypt-inline" name="sg-s-*-dnscrypt-inline">`inline`</a>:
        The DNSCrypt configuration, inline.  See the [configuration
        section][dnscconf] of the DNSCrypt module.

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



##  <a href="#connectivity-check" id="connectivity-check" name="connectivity-check">Connectivity Check</a>

The `connectivity_check` object has the following properties:

 *  <a href="#connectivity_check-probe_ipv4" id="connectivity_check-probe_ipv4" name="connectivity_check-probe_ipv4">`probe_ipv4`</a>:
    The IPv4 address with port to which a connectivity check is performed.

    **Example:** `8.8.8.8:53`.

 *  <a href="#connectivity_check-probe_ipv6" id="connectivity_check-probe_ipv6" name="connectivity_check-probe_ipv6">`probe_ipv6`</a>:
    The optional IPv6 address with port to which a connectivity check is
    performed.  This field is required in case of any IPv6 address in
    [`bind_addresses`](#sg-s-*-bind_addresses).

    **Example:** `[2001:4860:4860::8888]:53`.



##  <a href="#additional_metrics_info" id="additional_metrics_info" name="additional_metrics_info">Additional Metrics Info</a>

The `additional_metrics_info` object is a map of strings with extra information
which is exposed by `dns_app_additional_info` metric.

Map keys must match reqular expression `^[a-zA-Z_][a-zA-Z0-9_]*$`.  See
[Prometheus documentation on valid labels][prom-label].

**Property example:**

```yaml
'additional_metrics_info':
    'info_key_1': 'info_value_1'
    'info_key_2': 'info_value_2'
```

The Prometheus metrics key is `additional_info`.  For example:

```none
# HELP dns_app_additional_info A metric with a constant '1' value labeled by additional info provided in configuration
# TYPE dns_app_additional_info gauge
dns_app_additional_info{info_key_1="info_value_1",info_key_2="info_value_2"} 1
```

[prom-label]: https://pkg.go.dev/github.com/prometheus/common/model#LabelNameRE

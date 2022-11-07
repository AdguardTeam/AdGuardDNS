 #  AdGuard DNS Development Setup

Development is supported on Linux and macOS (aka Darwin) systems.

1.  Install Go 1.18 or later.

1.  Call `make init` to set up the Git pre-commit hook.

1.  Call `make go-tools` to install analyzers and other tools into the `bin`
    directory.



##  <a href="#makefile" id="makefile" name="makefile">Common Makefile Macros And Targets</a>

Most development tasks are done through the use of our Makefile.  Please keep
the Makefile POSIX-compliant and portable.



   ###  <a href="#makefile-macros" id="makefile-macros" name="makefile-macros">Macros</a>

This is not an extensive list.  See `../Makefile` and the scripts in the
`../scripts/make/` directory.

<dl>
    <dt><code>OUT</code></dt>
    <dd>
        The name of the binary to build.  Default: <code>./AdGuardDNS</code>.
    </dd>
    <dt><code>RACE</code></dt>
    <dd>
        Set to <code>1</code> to enable the race detector.  The race detector is
        always enabled for <code>make go-test</code>.
    </dd>
    <dt><code>VERBOSE</code></dt>
    <dd>
        Set to <code>1</code> to enable verbose mode.  Default: <code>0</code>.
    </dd>
</dl>



   ###  <a href="#makefile-targets" id="makefile-targets" name="makefile-targets">Targets</a>

This is not an extensive list.  See `../Makefile`.

<dl>
    <dt><code>make init</code></dt>
    <dd>
        Set up the pre-commit hook that runs checks, linters, and tests.
    </dd>
    <dt><code>make go-build</code></dt>
    <dd>
        Build the binary.  See also the <code>OUT</code> and <code>RACE</code>
        macros.
    </dd>
    <dt><code>make go-gen</code></dt>
    <dd>
        Regenerate the automatically generated Go files.  Those generated files
        are <code>../internal/agd/country_generate.go</code> and
        <code>../internal/geoip/asntops_generate.go</code>.  They need to be
        periodically updated.
    </dd>
    <dt><code>make go-lint</code></dt>
    <dd>
        Run Go checkers and static analysis.
    </dd>
    <dt><code>make go-test</code></dt>
    <dd>
        Run Go tests.
    </dd>
    <dt><code>make go-bench</code></dt>
    <dd>
        Run Go benchmarks.
    </dd>
    <dt><code>make go-tools</code></dt>
    <dd>
        Install the Go static analysis tools locally.
    </dd>
    <dt><code>make test</code></dt>
    <dd>
        Currently does the same thing as <code>make go-test</code> but is
        defined both because it's a common target and also in case code in
        another language appears in the future.
    </dd>
    <dt><code>make txt-lint</code></dt>
    <dd>
        Run plain text checkers.
    </dd>
</dl>



##  <a href="#run" id="run" name="run">How To Run AdGuard DNS</a>

This is an example on how to run AdGuard DNS locally.



   ###  <a href="#run-1" id="run-1" name="run-1">Step 1: Prepare The TLS Certificate And The Key</a>

Keeping the test files in the `test` directory since it's added to `.gitignore`:

```sh
mkdir test
cd test
```

Generate the TLS certificate and the key:

```sh
openssl req -nodes -new -x509 -keyout cert.key -out cert.crt
```

Also, generate TLS session tickets:

```sh
openssl rand 32 > ./tls_key_1
openssl rand 32 > ./tls_key_2
```



   ###  <a href="#run-2" id="run-2" name="run-2">Step 2: Prepare The DNSCrypt Configuration</a>

Install the [`dnscrypt`][dnsc] tool:

 *  On macOS, install from Brew:

    ```sh
    brew install ameshkov/tap/dnscrypt
    ```

 *  On other unixes, such as Linux, [download][dnscdl] and install the latest
    release manually.

Then, generate the configuration:

```sh
dnscrypt generate -p testdns -o ./dnscrypt.yml
```



   ###  <a href="#run-3" id="run-3" name="run-3">Step 3: Prepare The Configuration File</a>

```sh
cd ../
cp -f config.dist.yml config.yml
```



   ###  <a href="#run-4" id="run-4" name="run-4">Step 4: Prepare The Test Data</a>

```sh
echo '<html><body>Dangerous content ahead</body></html>' > ./test/block_page_sb.html
echo '<html><body>Adult content ahead</body></html>' > ./test/block_page_adult.html
echo '<html><body>Error 404</body></html>' > ./test/error_404.html
echo '<html><body>Error 500</body></html>' > ./test/error_500.html
```



   ###  <a href="#run-5" id="run-5" name="run-5">Step 5: Compile AdGuard DNS</a>

```sh
make build
```



   ###  <a href="#run-6" id="run-6" name="run-6">Step 6: Prepare Cache Data And GeoIP</a>

We'll use the test versions of the GeoIP databases here.

```sh
rm -f -r ./test/cache/
mkdir ./test/cache
curl 'https://raw.githubusercontent.com/maxmind/MaxMind-DB/main/test-data/GeoIP2-Country-Test.mmdb' -o ./test/GeoIP2-Country-Test.mmdb
curl 'https://raw.githubusercontent.com/maxmind/MaxMind-DB/main/test-data/GeoLite2-ASN-Test.mmdb' -o ./test/GeoLite2-ASN-Test.mmdb
```



   ###  <a href="#run-7" id="run-7" name="run-7">Step 7: Run AdGuard DNS</a>

You'll need to supply the following:

 *  [`BACKEND_ENDPOINT`](#env-BACKEND_ENDPOINT)
 *  [`CONSUL_ALLOWLIST_URL`](#env-CONSUL_ALLOWLIST_URL)
 *  [`GENERAL_SAFE_SEARCH_URL`](#env-GENERAL_SAFE_SEARCH_URL)
 *  [`YOUTUBE_SAFE_SEARCH_URL`](#env-YOUTUBE_SAFE_SEARCH_URL)

See the [external HTTP API documentation][externalhttp].

You may need to change the listen ports in `config.yml` which are less than 1024
to some other ports.  Otherwise, `sudo` or `doas` is required to run
`AdGuardDNS`.

Examples below are for the configuration with the following changes:

 *  Plain DNS: `53` → `5354`
 *  DoT: `853` → `8853`
 *  DoH: `443` → `8443`
 *  DoQ: `853` → `8853`

You may also need to remove `probe_ipv6` if your network does not support IPv6.

```sh
env \
    BACKEND_ENDPOINT='PUT BACKEND URL HERE' \
    BLOCKED_SERVICE_INDEX_URL='https://atropnikov.github.io/HostlistsRegistry/assets/services.json'\
    CONSUL_ALLOWLIST_URL='PUT CONSUL ALLOWLIST URL HERE' \
    CONFIG_PATH='./config.yml' \
    DNSDB_PATH='./test/cache/dnsdb.bolt' \
    FILTER_INDEX_URL='https://atropnikov.github.io/HostlistsRegistry/assets/filters.json' \
    FILTER_CACHE_PATH='./test/cache' \
    PROFILES_CACHE_PATH='./test/profilecache.json' \
    GENERAL_SAFE_SEARCH_URL='https://adguardteam.github.io/HostlistsRegistry/assets/engines_safe_search.txt' \
    GEOIP_ASN_PATH='./test/GeoLite2-ASN-Test.mmdb' \
    GEOIP_COUNTRY_PATH='./test/GeoIP2-Country-Test.mmdb' \
    QUERYLOG_PATH='./test/cache/querylog.jsonl' \
    LISTEN_ADDR='127.0.0.1' \
    LISTEN_PORT='8081' \
    RULESTAT_URL='https://testchrome.adtidy.org/api/1.0/rulestats.html' \
    SENTRY_DSN='https://1:1@localhost/1' \
    VERBOSE='1' \
    YOUTUBE_SAFE_SEARCH_URL='https://adguardteam.github.io/HostlistsRegistry/assets/youtube_safe_search.txt' \
    ./AdGuardDNS
```

[externalhttp]: externalhttp.md



   ###  <a href="#run-8" id="run-8" name="run-8">Step 8: Test Your Instance</a>

Plain DNS:

```sh
dnslookup example.org 127.0.0.1:5354
```

DoT:

```sh
VERIFY=0 dnslookup example.org tls://127.0.0.1:8853
```

DoH:

```sh
VERIFY=0 dnslookup example.org https://127.0.0.1:8443/dns-query
```

DoQ:

```sh
VERIFY=0 dnslookup example.org quic://127.0.0.1:8853
```

Open `http://127.0.0.1:8081/metrics` to see the server's metrics.

DNSCrypt is a bit trickier.  You need to open `dnscrypt.yml` and use values from
there to generate an SDNS stamp on <https://dnscrypt.info/stamps>.

**NOTE:**  The example below is for a test configuration that won't work for
you.

```sh
dnslookup example.org sdns://AQcAAAAAAAAADjEyNy4wLjAuMTo1NDQzIAbKgP3dmXybr1DaKIFgKjsc8zSFX4rgT_hFgymSq6w1FzIuZG5zY3J5cHQtY2VydC50ZXN0ZG5z
```

[dnsc]: https://github.com/ameshkov/dnscrypt
[dnscdl]: https://github.com/ameshkov/dnscrypt/releases

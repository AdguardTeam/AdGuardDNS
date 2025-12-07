# AdGuard DNS Development Setup

## Contents

- [Initial setup](#init)
- [Common Makefile macros and targets](#makefile)
- [How to run AdGuard DNS](#run)
- [Testing](#testing)

## <a href="#init" id="init" name="init">Initial setup</a>

Development is supported on Linux and macOS (aka Darwin) systems.

1. Install Go 1.25 or later.

2. Call `make init` to set up the Git pre-commit hook.

3. Call `make go-tools` to install analyzers and other tools into the `bin` directory.

## <a href="#makefile" id="makefile" name="makefile">Common Makefile macros and targets</a>

Most development tasks are done through the use of our Makefile. Please keep the Makefile POSIX-compliant and portable.

### <a href="#makefile-macros" id="makefile-macros" name="makefile-macros">Macros</a>

This is not an extensive list. See `../Makefile` and the scripts in the `../scripts/make/` directory.

- `OUT`: The name of the binary to build. Default: `./AdGuardDNS`.

- `RACE`: Set to `1` to enable the race detector. The race detector is always enabled for `make go-test`.

- `VERBOSE`: Set to `1` to enable verbose mode. Default: `0`.

### <a href="#makefile-targets" id="makefile-targets" name="makefile-targets">Targets</a>

This is not an extensive list. See `../Makefile`.

- `make init`: Set up the pre-commit hook that runs checks, linters, and tests.

- `make go-build`: Build the binary. See also the `OUT` and `RACE` macros.

- `make go-gen`: Regenerate the automatically generated Go files that need to be periodically updated. Those generated files are:

    - `../internal/backendpb/dns.pb.go`
    - `../internal/backendpb/dns_grpc.pb.go`
    - `../internal/ecscache/ecsblocklist_generate.go`
    - `../internal/geoip/asntops_generate.go`
    - `../internal/geoip/country_generate.go`
    - `../internal/profiledb/internal/filecachepb/filecache.pb.go`

    You'll need to [install `protoc`][protoc] for the last one.

    Use the `ONLY` environment variable to generate selected parts. This generates only the backend and file-cache protobuf files:

    ```sh
    make ONLY='backendpb filecachepb' go-gen
    ```

    Available values:

    - `backendpb`
    - `ecscache`
    - `filecachepb`
    - `geoip_asntops`
    - `geoip_country`

- `make go-lint`: Run Go checkers and static analysis.

- `make go-test`: Run Go tests.

- `make go-bench`: Run Go benchmarks.

- `make go-tools`: Install the Go static analysis tools locally.

- `make test`: Currently does the same thing as `make go-test` but is defined both because it's a common target and also in case code in another language appears in the future.

- `make txt-lint`: Run plain text checkers.

[protoc]: https://protobuf.dev/getting-started/gotutorial/#compiling-protocol-buffers

## <a href="#run" id="run" name="run">How to run AdGuard DNS</a>

This is an example on how to run AdGuard DNS locally.

### <a href="#run-1" id="run-1" name="run-1">Step 1: prepare the TLS certificate and the key</a>

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

### <a href="#run-2" id="run-2" name="run-2">Step 2: prepare the DNSCrypt configuration</a>

Install the [`dnscrypt`][dnsc] tool:

- On macOS, install from Brew:

    ```sh
    brew install ameshkov/tap/dnscrypt
    ```

- On other unixes, such as Linux, [download][dnscdl] and install the latest release manually.

Then, generate the configuration:

```sh
dnscrypt generate -p testdns -o ./dnscrypt.yml
```

### <a href="#run-3" id="run-3" name="run-3">Step 3: prepare the configuration file</a>

```sh
cd ../
cp -f config.dist.yaml config.yaml
```

### <a href="#run-4" id="run-4" name="run-4">Step 4: prepare the test data</a>

```sh
echo '<html><body>General content ahead</body></html>' > ./test/block_page_general.html
echo '<html><body>Dangerous content ahead</body></html>' > ./test/block_page_sb.html
echo '<html><body>Adult content ahead</body></html>' > ./test/block_page_adult.html
echo '<html><body>Error 404</body></html>' > ./test/error_404.html
echo '<html><body>Error 500</body></html>' > ./test/error_500.html
```

### <a href="#run-5" id="run-5" name="run-5">Step 5: compile AdGuard DNS</a>

```sh
make build
```

### <a href="#run-6" id="run-6" name="run-6">Step 6: prepare cache data and GeoIP</a>

We'll use the test versions of the GeoIP databases here.

```sh
rm -f -r ./test/cache/
mkdir ./test/cache
curl 'https://raw.githubusercontent.com/maxmind/MaxMind-DB/main/test-data/GeoIP2-Country-Test.mmdb' -o ./test/GeoIP2-Country-Test.mmdb
curl 'https://raw.githubusercontent.com/maxmind/MaxMind-DB/main/test-data/GeoIP2-City-Test.mmdb' -o ./test/GeoIP2-City-Test.mmdb
curl 'https://raw.githubusercontent.com/maxmind/MaxMind-DB/main/test-data/GeoIP2-ISP-Test.mmdb' -o ./test/GeoIP2-ISP-Test.mmdb
```

### <a href="#run-7" id="run-7" name="run-7">Step 7: run AdGuard DNS</a>

You'll need to supply the following:

- [`ADULT_BLOCKING_URL`][env-ADULT_BLOCKING_URL]
- [`BILLSTAT_URL`][env-BILLSTAT_URL]
- [`CONSUL_ALLOWLIST_URL`][env-CONSUL_ALLOWLIST_URL]
- [`GENERAL_SAFE_SEARCH_URL`][env-GENERAL_SAFE_SEARCH_URL]
- [`LINKED_IP_TARGET_URL`][env-LINKED_IP_TARGET_URL]
- [`NEW_REG_DOMAINS_URL`][env-NEW_REG_DOMAINS_URL]
- [`PROFILES_URL`][env-PROFILES_URL]
- [`SAFE_BROWSING_URL`][env-SAFE_BROWSING_URL]
- [`YOUTUBE_SAFE_SEARCH_URL`][env-YOUTUBE_SAFE_SEARCH_URL]

See the [external HTTP API documentation][externalhttp].

You may use `go run ./scripts/backend` to start mock GRPC server for `BACKEND_PROFILES_URL`, `BILLSTAT_URL`, `DNSCHECK_REMOTEKV_URL`, and `PROFILES_URL` endpoints.

You may need to change the listen ports in `config.yaml` which are less than 1024 to some other ports. Otherwise, `sudo` or `doas` is required to run `AdGuardDNS`.

Examples below are for the configuration with the following changes:

- Plain DNS: `53` → `5354`
- DoT: `853` → `8853`
- DoH: `443` → `8443`
- DoQ: `853` → `8853`

You may also need to remove `probe_ipv6` if your network does not support IPv6.

If you're using an OS different from Linux, you also need to make these changes:

- Remove the `interface_listeners` section.
- Remove `bind_interfaces` from the `default_dns` server configuration and replace it with `bind_addresses`.

<!--
    TODO(a.garipov,e.burkov): Update the script below.
-->

```sh
env \
    ADULT_BLOCKING_URL='https://raw.githubusercontent.com/ameshkov/stuff/master/DNS/adult_blocking.txt' \
    BILLSTAT_URL='grpc://localhost:6062' \
    BLOCKED_SERVICE_INDEX_URL='https://adguardteam.github.io/HostlistsRegistry/assets/services.json' \
    CATEGORY_FILTER_INDEX_URL='https://filters.adtidy.org/dns/category/filters.json' \
    CONSUL_ALLOWLIST_URL='https://raw.githubusercontent.com/ameshkov/stuff/master/DNS/consul_allowlist.json' \
    CONFIG_PATH='./config.yaml' \
    FILTER_INDEX_URL='https://adguardteam.github.io/HostlistsRegistry/assets/filters.json' \
    FILTER_CACHE_PATH='./test/cache' \
    NEW_REG_DOMAINS_URL='https://raw.githubusercontent.com/ameshkov/stuff/master/DNS/nrd.txt' \
    PROFILES_CACHE_PATH='./test/profilecache.pb' \
    PROFILES_URL='grpc://localhost:6062' \
    SAFE_BROWSING_URL='https://raw.githubusercontent.com/ameshkov/stuff/master/DNS/safe_browsing.txt' \
    GENERAL_SAFE_SEARCH_URL='https://adguardteam.github.io/HostlistsRegistry/assets/engines_safe_search.txt' \
    GEOIP_ASN_PATH='./test/GeoIP2-ISP-Test.mmdb' \
    GEOIP_COUNTRY_PATH='./test/GeoIP2-City-Test.mmdb' \
    QUERYLOG_PATH='./test/cache/querylog.jsonl' \
    LINKED_IP_TARGET_URL='https://httpbin.agrd.workers.dev/anything' \
    LISTEN_ADDR='127.0.0.1' \
    LISTEN_PORT='8081' \
    RULESTAT_URL='https://httpbin.agrd.workers.dev/post' \
    SENTRY_DSN='https://1:1@localhost/1' \
    VERBOSE='1' \
    YOUTUBE_SAFE_SEARCH_URL='https://adguardteam.github.io/HostlistsRegistry/assets/youtube_safe_search.txt' \
    ./AdGuardDNS
```

[env-ADULT_BLOCKING_URL]:      environment.md#ADULT_BLOCKING_URL
[env-BILLSTAT_URL]:            environment.md#BILLSTAT_URL
[env-CONSUL_ALLOWLIST_URL]:    environment.md#CONSUL_ALLOWLIST_URL
[env-GENERAL_SAFE_SEARCH_URL]: environment.md#GENERAL_SAFE_SEARCH_URL
[env-LINKED_IP_TARGET_URL]:    environment.md#LINKED_IP_TARGET_URL
[env-NEW_REG_DOMAINS_URL]:     environment.md#NEW_REG_DOMAINS_URL
[env-PROFILES_URL]:            environment.md#PROFILES_URL
[env-SAFE_BROWSING_URL]:       environment.md#SAFE_BROWSING_URL
[env-YOUTUBE_SAFE_SEARCH_URL]: environment.md#YOUTUBE_SAFE_SEARCH_URL

[externalhttp]: externalhttp.md

### <a href="#run-8" id="run-8" name="run-8">Step 8: test your instance</a>

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

DNSCrypt is a bit trickier. You need to open `dnscrypt.yml` and use values from there to generate an SDNS stamp on <https://dnscrypt.info/stamps>.

> [!NOTE]
> The example below is for a test configuration that won't work for you.

```sh
dnslookup example.org sdns://AQcAAAAAAAAADjEyNy4wLjAuMTo1NDQzIAbKgP3dmXybr1DaKIFgKjsc8zSFX4rgT_hFgymSq6w1FzIuZG5zY3J5cHQtY2VydC50ZXN0ZG5z
```

[dnsc]: https://github.com/ameshkov/dnscrypt
[dnscdl]: https://github.com/ameshkov/dnscrypt/releases

## <a href="#testing" id="testing" name="testing">Testing</a>

The `go-bench` and `go-test` targets [described earlier](#makefile-targets) should generally be enough, but there are cases where additional testing setup is required. One such case is package `bindtodevice`.

### <a href="#testing-bindtodevice" id="testing-bindtodevice" name="testing-bindtodevice">Testing `SO_BINDTODEVICE` features</a>

The `SO_BINDTODEVICE` features require a Linux machine with a particular IP routing set up. In order to test these features on architectures other than Linux, this repository has a Dockerfile and a convenient script to use it, see `scripts/test/bindtodevice.sh`.

A simple example:

- If your Docker is installed in a way that doesn't require `sudo` to use it:

    ```sh
    sh ./scripts/test/bindtodevice.sh
    ```

- Otherwise:

    ```sh
    env USE_SUDO=1 sh ./scripts/test/bindtodevice.sh
    ```

This will build the image and open a shell within the container. The container environment is defined by `scripts/test/bindtodevice.docker`, and has all utilities required to build the `AdGuardDNS` binary and test it. The working directory is also shared with the container through the `/test` directory inside it. The container also routes all IP connections to any address in the `172.17.0.0/16` subnet to the `eth0` network interface. So, calling `make go-test` or a similar command from within the container will actually test the `SO_BINDTODEVICE` features:

```sh
go test --cover -v ./internal/bindtodevice/
```

If you want to open an additional terminal (for example to launch `AdGuardDNS` in one and `dig` it in the other), use `docker exec` like this (you may need `sudo` for that):

```sh
docker exec -i -t agdns_bindtodevice_test /bin/sh
```

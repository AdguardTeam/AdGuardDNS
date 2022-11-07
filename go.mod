module github.com/AdguardTeam/AdGuardDNS

go 1.19

require (
	github.com/AdguardTeam/AdGuardDNS/internal/dnsserver v0.100.0
	github.com/AdguardTeam/golibs v0.11.3
	github.com/AdguardTeam/urlfilter v0.16.0
	github.com/ameshkov/dnscrypt/v2 v2.2.5
	github.com/bluele/gcache v0.0.2
	github.com/c2h5oh/datasize v0.0.0-20220606134207-859f65c6625b
	github.com/caarlos0/env/v6 v6.10.1
	github.com/getsentry/sentry-go v0.14.0
	github.com/google/renameio v1.0.1
	github.com/miekg/dns v1.1.50
	github.com/oschwald/maxminddb-golang v1.10.0
	github.com/patrickmn/go-cache v2.1.1-0.20191004192108-46f407853014+incompatible
	github.com/prometheus/client_golang v1.13.1
	github.com/prometheus/client_model v0.3.0
	github.com/prometheus/common v0.37.0
	github.com/stretchr/testify v1.8.0
	go.etcd.io/bbolt v1.3.6
	golang.org/x/exp v0.0.0-20221031165847-c99f073a8326
	golang.org/x/net v0.1.0
	golang.org/x/sys v0.1.0
	golang.org/x/time v0.1.0
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/aead/chacha20 v0.0.0-20180709150244-8b13a72661da // indirect
	github.com/aead/poly1305 v0.0.0-20180717145839-3fee0db0b635 // indirect
	github.com/ameshkov/dnsstamps v1.0.3 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fsnotify/fsnotify v1.5.4 // indirect
	github.com/go-logr/logr v1.2.3 // indirect
	github.com/go-task/slim-sprig v0.0.0-20210107165309-348f09dbbbc0 // indirect
	github.com/golang/mock v1.6.0 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/lucas-clemente/quic-go v0.29.2 // indirect
	github.com/marten-seemann/qpack v0.3.0 // indirect
	github.com/marten-seemann/qtls-go1-18 v0.1.3 // indirect
	github.com/marten-seemann/qtls-go1-19 v0.1.1 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/nxadm/tail v1.4.8 // indirect
	github.com/onsi/ginkgo v1.16.5 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/procfs v0.8.0 // indirect
	golang.org/x/crypto v0.1.0 // indirect
	golang.org/x/mod v0.6.0 // indirect
	golang.org/x/text v0.4.0 // indirect
	golang.org/x/tools v0.2.0 // indirect
	google.golang.org/protobuf v1.28.1 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/AdguardTeam/AdGuardDNS/internal/dnsserver => ./internal/dnsserver

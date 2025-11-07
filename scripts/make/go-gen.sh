#!/bin/sh

verbose="${VERBOSE:-0}"
readonly verbose

if [ "$verbose" -gt '1' ]; then
	env
	set -x
elif [ "$verbose" -gt '0' ]; then
	set -x
else
	set +x
fi

# Exit the script if a pipeline fails (-e), prevent accidental filename
# expansion (-f), and consider undefined variables as errors (-u).
set -e -f -u

# Allow users to override the go command from environment.  For example, to
# build two releases with two different Go versions and test the difference.
go="${GO:-go}"
readonly go

backendpb() (
	cd ./internal/backendpb/
	protoc \
		--go-grpc_opt=Mdns.proto=./backendpb \
		--go-grpc_opt=paths=source_relative \
		--go-grpc_out=. \
		--go_opt=Mdns.proto=./backendpb \
		--go_opt=paths=source_relative \
		--go_out=. \
		./dns.proto
)

ecscache() (
	cd ./internal/ecscache/
	"$go" run ./ecsblocklist_generate.go
	# Force format code, because it's not possible to make an accurate
	# template for a long list of strings with different lengths.
	gofumpt -l -w ./ecsblocklist.go
)

fcpb() (
	# TODO(f.setrakov): Change directory to ./internal/profiledb/internal/, so
	# we don't need to go up later.
	cd ./internal/profiledb/internal/filecachepb/
	protoc \
		--go_opt=paths=source_relative \
		--go_out=../fcpb/ \
		--go_opt=default_api_level=API_OPAQUE \
		--go_opt=Mfilecache.proto=github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal/fcpb \
		./filecache.proto
)

filecachepb() (
	cd ./internal/profiledb/internal/filecachepb/
	protoc \
		--go_opt=paths=source_relative \
		--go_out=. \
		--go_opt=Mfilecache.proto=github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal/filecachepb \
		./filecache.proto
)

geoip_asntops() (
	cd ./internal/geoip/
	"$go" run ./asntops_generate.go
)

geoip_country() (
	cd ./internal/geoip/
	"$go" run ./country_generate.go
)

if [ -z "${ONLY:-}" ]; then
	backendpb
	ecscache
	fcpb
	filecachepb
	geoip_asntops
	geoip_country
else
	padded=" ${ONLY} "

	if [ "${padded##* backendpb *}" = '' ]; then
		backendpb
	fi

	if [ "${padded##* ecscache *}" = '' ]; then
		ecscache
	fi

	if [ "${padded##* fcpb *}" = '' ]; then
		fcpb
	fi

	if [ "${padded##* filecachepb *}" = '' ]; then
		filecachepb
	fi

	if [ "${padded##* geoip_asntops *}" = '' ]; then
		geoip_asntops
	fi

	if [ "${padded##* geoip_country *}" = '' ]; then
		geoip_country
	fi
fi

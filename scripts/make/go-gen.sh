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

(
	cd ./internal/geoip/
	"$go" run ./country_generate.go
)

(
	cd ./internal/geoip/
	"$go" run ./asntops_generate.go
)

(
	cd ./internal/ecscache/
	"$go" run ./ecsblocklist_generate.go
	# Force format code, because it's not possible to make an accurate
	# template for a long list of strings with different lengths.
	gofumpt -l -w ./ecsblocklist.go
)

(
	cd ./internal/profiledb/internal/filecachepb/
	protoc --go_opt=paths=source_relative --go_out=. ./filecache.proto
)

(
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

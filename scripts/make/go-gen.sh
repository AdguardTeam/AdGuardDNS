#!/bin/sh

verbose="${VERBOSE:-0}"
readonly verbose

if [ "$verbose" -gt '1' ]
then
	env
	set -x
elif [ "$verbose" -gt '0' ]
then
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
    cd ./internal/agd/
    "$go" run ./country_generate.go
)

(
    cd ./internal/geoip/
    "$go" run ./asntops_generate.go
)

(
    cd ./internal/profiledb/internal/filecachepb/
	protoc --go_opt=paths=source_relative --go_out=. ./filecache.proto
)

(
    cd ./internal/backendpb/
	protoc --go_opt=paths=source_relative --go_out=.\
	--go-grpc_opt=paths=source_relative --go-grpc_out=. ./backend.proto
)

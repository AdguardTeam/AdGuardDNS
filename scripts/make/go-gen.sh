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

protoc_gen_go_grpc_path="$("$go" tool -n protoc-gen-go-grpc)"
protoc_gen_go_path="$("$go" tool -n protoc-gen-go)"
readonly protoc_gen_go_grpc_path protoc_gen_go_path

dnspb() (
	cd ./internal/backendgrpc/dnspb/
	protoc \
		--go-grpc_opt='Mdns.proto=./dnspb' \
		--go-grpc_opt='paths=source_relative' \
		--go-grpc_out='.' \
		--go_opt=Mdns.proto=./dnspb \
		--go_opt=paths='source_relative' \
		--go_out='.' \
		--plugin="protoc-gen-go-grpc=${protoc_gen_go_grpc_path}" \
		--plugin="protoc-gen-go=${protoc_gen_go_path}" \
		./dns.proto \
		;
)

ecscache() (
	cd ./internal/ecscache/
	"$go" run ./ecsblocklist_generate.go
	# Force format code, because it's not possible to make an accurate template
	# for a long list of strings with different lengths.
	"$go" tool gofumpt -l -w ./ecsblocklist.go
)

fcpb() (
	cd ./internal/profiledb/internal/fcpb/
	protoc \
		--go_opt='Mfc.proto=github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal/fcpb' \
		--go_opt='default_api_level=API_OPAQUE' \
		--go_opt='paths=source_relative' \
		--go_out='.' \
		--plugin="protoc-gen-go=${protoc_gen_go_path}" \
		./fc.proto \
		;
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
	dnspb
	ecscache
	fcpb
	geoip_asntops
	geoip_country
else
	padded=" ${ONLY} "

	if [ "${padded##* dnspb *}" = '' ]; then
		dnspb
	fi

	if [ "${padded##* ecscache *}" = '' ]; then
		ecscache
	fi

	if [ "${padded##* fcpb *}" = '' ]; then
		fcpb
	fi

	if [ "${padded##* geoip_asntops *}" = '' ]; then
		geoip_asntops
	fi

	if [ "${padded##* geoip_country *}" = '' ]; then
		geoip_country
	fi
fi

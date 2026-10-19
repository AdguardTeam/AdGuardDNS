# syntax=docker/dockerfile:1

# Use the golang:alpine as the base image as it already has most of the
# necessary ip(8) tooling installed.
FROM golang:alpine
RUN <<-'EOF'
set -e -f -o 'pipefail' -u -x

apk add bind-tools bmake gcc git libc-dev
ln /usr/bin/bmake /usr/bin/make
mkdir /test
git config --global --add safe.directory /test
EOF

WORKDIR /test/

ENV ADGUARD_DNS_TEST_NET_INTERFACE='eth0'

COPY --chmod=0755 bindtodevice-entrypoint.sh /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/bindtodevice-entrypoint.sh"]

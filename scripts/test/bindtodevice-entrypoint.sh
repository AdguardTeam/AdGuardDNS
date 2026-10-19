#!/bin/sh

net_interface="${ADGUARD_DNS_TEST_NET_INTERFACE:-eth0}"
readonly net_interface

set -e -f -o 'pipefail' -u -x

ip route del '172.17.0.0/16' dev "$net_interface"
ip route add local '172.17.0.0/16' dev "$net_interface"
ip route add '172.17.0.1' dev "$net_interface"

# TODO(m.kazantsev):  Consider adding more arguments.
exec sh

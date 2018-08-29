#!/bin/bash
set -e -x -o pipefail
echo "executing $0"

# Unlink logs dir
rm -rf /opt/<%= project %>/logs

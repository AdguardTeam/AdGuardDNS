#!/bin/bash
set -e -x -o pipefail
echo "executing $0"

case "$1" in
    configure)
        if ! getent passwd "<%= user %>" > /dev/null ; then
                echo "Adding user for <%= project %>" >&2

                adduser --system -ingroup nogroup --quiet \
                    --no-create-home \
                    --disabled-login \
                    --gecos "<%= project %> user" \
                    --shell /bin/bash "<%= user %>"
        fi
        URL="https://filters.adtidy.org/android/filters/15.txt"
        OUTFILE="/var/lib/dnsfilter/dns.txt"

        mkdir -p /var/lib/dnsfilter
        wget -q --timeout=90 "$URL" -O "$OUTFILE"
        if [ $? -ne 0 ]
            then
            echo "Filter rules could not be downloaded."
        fi

        # Link logs dir (Required for request logs)
        ln -s /var/log/<%= project %> /opt/<%= project %>/logs

        chown -R <%= user %>: /opt/<%= project %>
    ;;
    *)
        echo "postinst called with unknown argument \`$1'" >&2
        exit 1
    ;;
esac

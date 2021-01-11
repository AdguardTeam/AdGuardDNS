## Patches

Changes that we applied to the dependencies.

1. Patched version of CoreDNS:
    * QUIC support: https://github.com/ameshkov/coredns/commit/f68e85dc5881503c2a0acd5b79ab45a393f3c51c
    * Always compress DNS responses: https://github.com/ameshkov/coredns/commit/0c4bc69162ac07aaf85504ca65d14c9ee7a6be74

2. "health" plugin fork

    Use "/health-check" instead of "/health"
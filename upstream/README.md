# forward

A simple replacement for the CoreDNS forward plugin.

Here's what issues it solves:

1. Less memory allocations (currently, `forward` is the main reason for extra allocations).
2. Supports fallback upstreams.

Simplifications:

1. One upstream only (we don't need other upstreams)
2. Supports only plain DNS upstreams
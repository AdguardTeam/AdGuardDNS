package ratelimit

import (
	"context"
	"net/netip"
	"sync"
)

// IP Address And Network Allowlist

// Allowlist decides whether ip should be excluded from rate limiting.  All
// methods bust be safe for concurrent use.
type Allowlist interface {
	IsAllowed(ctx context.Context, ip netip.Addr) (ok bool, err error)
}

// DynamicAllowlist is an allowlist that has a dynamic and a persistent list of
// IP networks to allow.
type DynamicAllowlist struct {
	// mu protects dynamic.
	mu      *sync.RWMutex
	dynamic []netip.Prefix

	persistent []netip.Prefix
}

// NewDynamicAllowlist returns a new dynamic allow list.
func NewDynamicAllowlist(persistent, dynamic []netip.Prefix) (l *DynamicAllowlist) {
	l = &DynamicAllowlist{
		mu:         &sync.RWMutex{},
		dynamic:    dynamic,
		persistent: persistent,
	}

	return l
}

// IsAllowed implements the Allowlist interface for *DynamicAllowlist.
func (l *DynamicAllowlist) IsAllowed(_ context.Context, ip netip.Addr) (ok bool, err error) {
	for _, n := range l.persistent {
		if n.Contains(ip) {
			return true, nil
		}
	}

	l.mu.RLock()
	defer l.mu.RUnlock()

	for _, n := range l.dynamic {
		if n.Contains(ip) {
			return true, nil
		}
	}

	return false, nil
}

// Update replaces the previous list of dynamic subnets with nets.
func (l *DynamicAllowlist) Update(subnets []netip.Prefix) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.dynamic = subnets
}

// Package rulestat contains the filtering rule statistics collector and API.
package rulestat

import (
	"context"

	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
)

// Interface is an ephemeral storage of the filtering rule list statistics
// interface.
//
// All methods must be safe for concurrent use.
type Interface interface {
	Collect(ctx context.Context, id filter.ID, r filter.RuleText)
}

// type check
var _ Interface = Empty{}

// Empty is an Interface implementation that does nothing.
type Empty struct{}

// Collect implements the Interface interface for Empty.
func (Empty) Collect(_ context.Context, _ filter.ID, _ filter.RuleText) {}

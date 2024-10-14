package agdcache

import (
	"maps"
	"slices"
	"sync"
)

// Manager is the cache manager interface.  All methods must be safe for
// concurrent use.
type Manager interface {
	// Add adds cache by id.  cache must not be nil.
	//
	// TODO(s.chzhen):  Add Set method that rewrites the cache associated with
	// id (current Add implementation).
	//
	// TODO(s.chzhen):  Add panic on adding cache with duplicate id.
	Add(id string, cache Clearer)

	// ClearByID clears cache by id.
	ClearByID(id string)
}

// DefaultManager implements the [Manager] interface that stores caches and can
// clear them by id
type DefaultManager struct {
	mu     *sync.Mutex
	caches map[string]Clearer
}

// NewDefaultManager returns a new initialized *DefaultManager.
func NewDefaultManager() (m *DefaultManager) {
	return &DefaultManager{
		mu:     &sync.Mutex{},
		caches: map[string]Clearer{},
	}
}

// type check
var _ Manager = (*DefaultManager)(nil)

// Add implements the [Manager] interface for *DefaultManager.  Note that it
// replaces the saved cache with the same id if there is one.
func (m *DefaultManager) Add(id string, cache Clearer) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.caches[id] = cache
}

// ClearByID implements the [Manager] interface for *DefaultManager.
func (m *DefaultManager) ClearByID(id string) {
	cache := m.findByID(id)
	if cache != nil {
		cache.Clear()
	}
}

// findByID returns the stored cache by id or nil.
func (m *DefaultManager) findByID(id string) (cache Clearer) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.caches[id]
}

// IDs returns a sorted list of stored cache identifiers.
func (m *DefaultManager) IDs() (ids []string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return slices.Sorted(maps.Keys(m.caches))
}

// EmptyManager implements the [Manager] interface that does nothing.
type EmptyManager struct{}

// type check
var _ Manager = EmptyManager{}

// Add implements the [Manager] interface for *EmptyManager.
func (EmptyManager) Add(_ string, _ Clearer) {}

// ClearByID implements the [Manager] interface for *EmptyManager.
func (EmptyManager) ClearByID(_ string) {}

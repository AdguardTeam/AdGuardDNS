package remotekv

import "context"

// KeyNamespaceConfig is the configuration structure for [KeyNamespace].
type KeyNamespaceConfig struct {
	// KV is the key-value storage to be wrapped.  It must not be nil.
	KV Interface

	// Prefix is the custom prefix to be added to the keys.  Prefix should be in
	// accordance with the wrapped KV storage keys.
	Prefix string
}

// KeyNamespace is wrapper around [Interface] that adds a custom prefix to the
// keys.
type KeyNamespace struct {
	// kv is the key-value storage to be wrapped.
	kv Interface

	// prefix is the custom prefix to be added to the keys.  prefix should be in
	// accordance with the wrapped KV storage keys.
	prefix string
}

// NewKeyNamespace returns a properly initialized *KeyNamespace. conf must not
// be nil.
func NewKeyNamespace(conf *KeyNamespaceConfig) (n *KeyNamespace) {
	return &KeyNamespace{
		kv:     conf.KV,
		prefix: conf.Prefix,
	}
}

// type check
var _ Interface = (*KeyNamespace)(nil)

// Get implements the [Interface] interface for *KeyNamespace.
func (n *KeyNamespace) Get(ctx context.Context, key string) (val []byte, ok bool, err error) {
	// TODO(s.chzhen):  Improve memory allocation.
	prefixed := n.prefix + key

	return n.kv.Get(ctx, prefixed)
}

// Set implements the [Interface] interface for *KeyNamespace.
func (n *KeyNamespace) Set(ctx context.Context, key string, val []byte) (err error) {
	// TODO(s.chzhen):  Improve memory allocation.
	prefixed := n.prefix + key

	return n.kv.Set(ctx, prefixed, val)
}

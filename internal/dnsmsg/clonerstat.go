package dnsmsg

// ClonerStat is an interface for entities that collect statistics about a
// [Cloner].
//
// All methods must be safe for concurrent use.
type ClonerStat interface {
	// OnClone is called on [Cloner.Clone] calls.  isFull is true if the clone
	// was full.
	OnClone(isFull bool)
}

// EmptyClonerStat is a [ClonerStat] implementation that does nothing.
type EmptyClonerStat struct{}

// type check
var _ ClonerStat = EmptyClonerStat{}

// OnClone implements the [ClonerStat] interface for EmptyClonerStat.
func (EmptyClonerStat) OnClone(_ bool) {}

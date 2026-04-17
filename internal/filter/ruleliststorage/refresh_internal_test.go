package ruleliststorage

import (
	"testing"

	"github.com/AdguardTeam/golibs/container"
	"github.com/stretchr/testify/assert"
)

func TestDifference(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		inA   *container.SortedSliceSet[int]
		inB   *container.SortedSliceSet[int]
		wantA *container.SortedSliceSet[int]
		name  string
	}{{
		inA:   nil,
		inB:   nil,
		wantA: nil,
		name:  "both_nil",
	}, {
		inA:   nil,
		inB:   container.NewSortedSliceSet(1, 2, 3),
		wantA: nil,
		name:  "nil_a",
	}, {
		inA:   container.NewSortedSliceSet(1, 2, 3),
		inB:   nil,
		wantA: container.NewSortedSliceSet(1, 2, 3),
		name:  "nil_b",
	}, {
		inA:   container.NewSortedSliceSet(1, 2, 3),
		inB:   container.NewSortedSliceSet(1, 2, 3),
		wantA: container.NewSortedSliceSet([]int{}...),
		name:  "same",
	}, {
		inA:   container.NewSortedSliceSet(1, 2, 3),
		inB:   container.NewSortedSliceSet(2, 3, 4),
		wantA: container.NewSortedSliceSet(1),
		name:  "intersect",
	}, {
		inA:   container.NewSortedSliceSet(1, 2, 3),
		inB:   container.NewSortedSliceSet(4, 5, 6),
		wantA: container.NewSortedSliceSet(1, 2, 3),
		name:  "no_intersect",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			prevB := tc.inB.Clone()
			tc.inA = difference(tc.inA, tc.inB)
			assert.Equal(t, tc.wantA, tc.inA)
			assert.Equal(t, prevB, tc.inB)
		})
	}
}

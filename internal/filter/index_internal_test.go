package filter

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIndexRespFilter_compare(t *testing.T) {
	var (
		fltA = &indexRespFilter{
			Key: "a",
		}
		fltB = &indexRespFilter{
			Key: "b",
		}
	)

	want := []*indexRespFilter{
		fltA,
		fltB,
		nil,
		nil,
	}

	got := []*indexRespFilter{
		fltB,
		nil,
		fltA,
		nil,
	}

	slices.SortStableFunc(got, (*indexRespFilter).compare)

	assert.Equal(t, want, got)
}

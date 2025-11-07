package tlsconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSortedMap(t *testing.T) {
	var m *sortedMap[string, int]

	letters := []string{}
	for i := range 10 {
		r := string('a' + rune(i))
		letters = append(letters, r)
	}

	t.Run("create_and_fill", func(t *testing.T) {
		m = newSortedMap[string, int]()

		nums := []int{}
		for i, r := range letters {
			m.set(r, i)
			nums = append(nums, i)
		}

		gotLetters := []string{}
		gotNums := []int{}
		m.rangeFn(func(k string, v int) bool {
			gotLetters = append(gotLetters, k)
			gotNums = append(gotNums, v)

			return true
		})

		assert.Equal(t, letters, gotLetters)
		assert.Equal(t, nums, gotNums)

		n, ok := m.get(letters[0])
		assert.True(t, ok)
		assert.Equal(t, nums[0], n)
	})

	t.Run("clear", func(t *testing.T) {
		lastLetter := letters[len(letters)-1]
		m.del(lastLetter)

		_, ok := m.get(lastLetter)
		assert.False(t, ok)

		m.clear()

		gotLetters := []string{}
		m.rangeFn(func(k string, _ int) bool {
			gotLetters = append(gotLetters, k)

			return true
		})

		assert.Len(t, gotLetters, 0)
	})
}

func TestNewSortedMap_nil(t *testing.T) {
	const (
		key = "key"
		val = "val"
	)

	var m sortedMap[string, string]

	assert.Panics(t, func() {
		m.set(key, val)
	})

	assert.NotPanics(t, func() {
		_, ok := m.get(key)
		assert.False(t, ok)
	})

	assert.NotPanics(t, func() {
		m.rangeFn(func(_, _ string) (cont bool) {
			return true
		})
	})

	assert.NotPanics(t, func() {
		m.del(key)
	})

	assert.NotPanics(t, func() {
		m.clear()
	})
}

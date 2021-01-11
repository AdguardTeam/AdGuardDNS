package upstream

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConnPool(t *testing.T) {
	pool := &connsPool{}

	// empty pool
	c := pool.Get()
	assert.Nil(t, c)
	c = &Conn{}
	pool.Put(c)

	// not empty
	c2 := pool.Get()
	assert.True(t, c == c2)

	// closed
	pool.Close()
	pool.Put(c)
	assert.Nil(t, pool.Get())
}

package bitmap

import "testing"

func TestBitMap(t *testing.T) {
	m := NewBitMap(100)
	m.Set(10)
	m.Set(20)
	m.Set(30)

	t.Log(m.IsExists(10))
}

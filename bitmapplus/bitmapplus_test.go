package bitmapplus

import "testing"

func TestBitMapPlus(t *testing.T) {
	m := NewBitMapPlus(100)
	m.Set(10)
	m.Set(10)
	m.Set(20)
	m.Set(20)
	m.Set(20)
	t.Log(m.IsExist(10))
	t.Log(m.IsExist(20))
	t.Log(m.IsExist(30))
}

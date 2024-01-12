package bitmapplus

type BitMapPlus struct {
	MaxValue  uint32
	ByteSlice []byte
}

func NewBitMapPlus(maxValue uint32) *BitMapPlus {
	return &BitMapPlus{
		MaxValue:  maxValue,
		ByteSlice: make([]byte, ((maxValue+1)*2+8)/8),
	}
}

func (m *BitMapPlus) Set(num uint32) {
	if num > m.MaxValue {
		return
	}
	byteIndex := num / 4
	b := m.ByteSlice[byteIndex]
	bitIndex2 := (num % 4) * 2
	bitIndex1 := bitIndex2 + 1

	//没有出现过，00
	if (b&(1<<bitIndex1)) == 0 && (b&(1<<bitIndex2)) == 0 {
		m.ByteSlice[byteIndex] = b | (1 << bitIndex2)
		return
	}
	//出现过一次，01
	if (b&(1<<bitIndex1)) == 0 && (b&(1<<bitIndex2)) != 0 {
		m.ByteSlice[byteIndex] = b | (1 << bitIndex1)
		return
	}
}

func (m *BitMapPlus) IsExist(num uint32) int {
	if num > m.MaxValue {
		return 0
	}
	byteIndex := num / 4
	b := m.ByteSlice[byteIndex]
	bitIndex2 := (num % 4) * 2
	bitIndex1 := bitIndex2 + 1
	if (b&(1<<bitIndex1)) == 0 && (b&(1<<bitIndex2)) == 0 {
		return 0
	}
	if (b&(1<<bitIndex1)) == 0 && (b&(1<<bitIndex2)) != 0 {
		return 1
	}
	if (b & (1 << bitIndex1)) == 1 {
		return 2
	}
	return 0
}

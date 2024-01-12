package bitmap

type BitMap struct {
	MaxValue  uint32
	ByteSlice []byte
}

func NewBitMap(maxValue uint32) *BitMap {
	return &BitMap{
		MaxValue:  maxValue,
		ByteSlice: make([]byte, (maxValue+8)/8),
	}
}

// Set 可以在*BitMap类型的实例上调用，修改其状态。m *BitMap的作用相当于this.Set
func (m *BitMap) Set(num uint32) {
	if num > m.MaxValue {
		return
	}
	byteIndex := num / 8
	b := m.ByteSlice[byteIndex]
	bitIndex := num % 8
	m.ByteSlice[byteIndex] = b | 1<<bitIndex //把 num 对应的 bit 位设置为 1
}

func (m *BitMap) IsExists(num uint32) bool {
	if num > m.MaxValue {
		return false
	}
	byteIndex := num / 8
	b := m.ByteSlice[byteIndex]
	bitIndex := num % 8
	return b&1<<bitIndex != 0
}

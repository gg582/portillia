package policy

import "sync/atomic"

// LoadManager tracks coarse connection counters for relay diagnostics.
type LoadManager struct {
	active   int64
	bytesIn  int64
	bytesOut int64
}

func NewLoadManager() *LoadManager {
	return &LoadManager{}
}

func (m *LoadManager) ActiveConns() int64 {
	if m == nil {
		return 0
	}
	return atomic.LoadInt64(&m.active)
}

func (m *LoadManager) RecordConnStart() {
	if m == nil {
		return
	}
	atomic.AddInt64(&m.active, 1)
}

func (m *LoadManager) RecordConnEnd() {
	if m == nil {
		return
	}
	atomic.AddInt64(&m.active, -1)
}

func (m *LoadManager) RecordBytesIn(n int64) {
	if m == nil || n <= 0 {
		return
	}
	atomic.AddInt64(&m.bytesIn, n)
}

func (m *LoadManager) RecordBytesOut(n int64) {
	if m == nil || n <= 0 {
		return
	}
	atomic.AddInt64(&m.bytesOut, n)
}

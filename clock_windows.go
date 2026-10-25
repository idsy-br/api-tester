package main

import (
	"syscall"
	"time"
	"unsafe"
)

// No Windows o relógio monotônico do Go anda em passos de ~0,5 ms, o que zera as
// latências de API local. O QueryPerformanceCounter tem resolução de 100 ns.
var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	qpc      = kernel32.NewProc("QueryPerformanceCounter")
	qpf      = kernel32.NewProc("QueryPerformanceFrequency")
	qpcFreq  = func() int64 {
		var f int64
		qpf.Call(uintptr(unsafe.Pointer(&f)))
		return f
	}()
)

type instant int64

func now() instant {
	var c int64
	qpc.Call(uintptr(unsafe.Pointer(&c)))
	return instant(c)
}

func since(start instant) time.Duration { return between(start, now()) }

func between(start, end instant) time.Duration {
	if start == 0 || end == 0 {
		return 0
	}
	ticks := int64(end - start)
	return time.Duration(ticks/qpcFreq*int64(time.Second) + ticks%qpcFreq*int64(time.Second)/qpcFreq)
}

//go:build !windows

package main

import "time"

// Fora do Windows o relógio monotônico do Go já tem resolução de nanossegundos.
var epoch = time.Now()

type instant int64

func now() instant { return instant(time.Since(epoch)) }

func since(start instant) time.Duration { return time.Duration(now() - start) }

func between(start, end instant) time.Duration {
	if start == 0 || end == 0 {
		return 0
	}
	return time.Duration(end - start)
}

package main

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// recorder junta os resultados de várias goroutines.
type recorder struct {
	mu      sync.Mutex
	durs    []time.Duration
	status  map[int]int
	errs    map[string]int
	bytes   int64
	blocked bool // a API respondeu 429: IP bloqueado
}

func newRecorder() *recorder {
	return &recorder{status: map[int]int{}, errs: map[string]int{}}
}

func (r *recorder) add(res result) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.durs = append(r.durs, res.dur)
	r.bytes += res.bytes
	if res.err != nil {
		r.errs[errorKind(res.err)]++
		return
	}
	r.status[res.status]++
	if res.status == 429 {
		r.blocked = true
	}
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.durs)
}

func (r *recorder) isBlocked() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.blocked
}

// summary é o resumo de uma rodada. Tempos em milissegundos.
type summary struct {
	Requests  int            `json:"requisicoes"`
	OK        int            `json:"ok"`
	Failed    int            `json:"falhas"`
	ErrorRate float64        `json:"taxa_de_erro"`
	Seconds   float64        `json:"segundos"`
	RPS       float64        `json:"rps"`
	MBps      float64        `json:"mb_por_segundo"`
	Latency   latencyMS      `json:"latencia_ms"`
	Status    map[string]int `json:"status"`
	Errors    map[string]int `json:"erros,omitempty"`
}

type latencyMS struct {
	Min  float64 `json:"min"`
	Mean float64 `json:"media"`
	P50  float64 `json:"p50"`
	P90  float64 `json:"p90"`
	P95  float64 `json:"p95"`
	P99  float64 `json:"p99"`
	Max  float64 `json:"max"`
}

func (r *recorder) summary(elapsed time.Duration) summary {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := summary{Requests: len(r.durs), Seconds: elapsed.Seconds(), Status: map[string]int{}, Errors: map[string]int{}}
	for code, n := range r.status {
		s.Status[strconv.Itoa(code)] = n
		if code < 400 {
			s.OK += n
		}
	}
	for kind, n := range r.errs {
		s.Errors[kind] = n
	}
	s.Failed = s.Requests - s.OK
	if s.Requests > 0 {
		s.ErrorRate = float64(s.Failed) / float64(s.Requests)
	}
	if elapsed > 0 {
		s.RPS = float64(s.Requests) / elapsed.Seconds()
		s.MBps = float64(r.bytes) / 1e6 / elapsed.Seconds()
	}
	s.Latency = latencies(r.durs)
	return s
}

func latencies(durs []time.Duration) latencyMS {
	if len(durs) == 0 {
		return latencyMS{}
	}
	sorted := append([]time.Duration(nil), durs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	var total time.Duration
	for _, d := range sorted {
		total += d
	}
	return latencyMS{
		Min:  ms(sorted[0]),
		Mean: ms(total / time.Duration(len(sorted))),
		P50:  ms(percentile(sorted, 50)),
		P90:  ms(percentile(sorted, 90)),
		P95:  ms(percentile(sorted, 95)),
		P99:  ms(percentile(sorted, 99)),
		Max:  ms(sorted[len(sorted)-1]),
	}
}

// percentile pelo método do posto mais próximo; sorted já em ordem.
func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	rank := int(math.Ceil(p / 100 * float64(len(sorted))))
	rank = max(1, min(rank, len(sorted)))
	return sorted[rank-1]
}

func ms(d time.Duration) float64 {
	return math.Round(float64(d)/float64(time.Microsecond)) / 1000
}

func (s summary) print(title string) {
	fmt.Printf("\n%s\n%s\n", title, strings.Repeat("─", len([]rune(title))))
	fmt.Printf("  requisições  %d em %.1fs  (%.1f/s, %.2f MB/s)\n", s.Requests, s.Seconds, s.RPS, s.MBps)
	fmt.Printf("  sucesso      %d  (erro: %.2f%%)\n", s.OK, s.ErrorRate*100)
	l := s.Latency
	fmt.Printf("  latência ms  min %.1f · média %.1f · p50 %.1f · p90 %.1f · p95 %.1f · p99 %.1f · máx %.1f\n",
		l.Min, l.Mean, l.P50, l.P90, l.P95, l.P99, l.Max)
	fmt.Printf("  status       %s\n", formatCounts(s.Status))
	if len(s.Errors) > 0 {
		fmt.Printf("  erros        %s\n", formatCounts(s.Errors))
	}
}

func formatCounts(m map[string]int) string {
	if len(m) == 0 {
		return "-"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s: %d", k, m[k])
	}
	return strings.Join(parts, " · ")
}

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"time"
)

// phases são os tempos de uma requisição, separados por fase.
type phases struct {
	dns, connect, tls, server, total time.Duration
	reused                           bool
}

type latencyRoute struct {
	Route     string         `json:"rota"`
	Requests  int            `json:"requisicoes"`
	Errors    int            `json:"erros"`
	Status    map[string]int `json:"status"`
	Total     latencyMS      `json:"total_ms"`
	Server    latencyMS      `json:"servidor_ms"`
	DNSMean   float64        `json:"dns_media_ms"`
	Connect   float64        `json:"conexao_media_ms"`
	TLSMean   float64        `json:"tls_media_ms"`
	NewConns  int            `json:"conexoes_novas"`
	Reused    int            `json:"conexoes_reaproveitadas"`
	Threshold float64        `json:"limite_p95_ms,omitempty"`
	OverLimit bool           `json:"acima_do_limite,omitempty"`
}

type latencyResult struct {
	Location string         `json:"url"`
	Routes   []latencyRoute `json:"rotas"`
}

func cmdLatency(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("latencia", flag.ContinueOnError)
	var o options
	o.register(fs)
	var routes routeList
	fs.Var(&routes, "rota", "rota a medir, pode repetir (padrão /healthz e /readyz, mais GET /v1/me com sessão)")
	n := fs.Int("n", 200, "requisições por rota")
	warmup := fs.Int("aquecer", 5, "requisições descartadas antes de medir")
	gap := fs.Duration("intervalo", 0, "pausa entre uma requisição e outra")
	fresh := fs.Bool("nova-conexao", false, "abre conexão nova a cada requisição (mede conexão e TLS sempre)")
	limit := fs.Float64("limite-p95", 0, "marca a rota quando o p95 passa disso em ms (0 = não confere)")
	body := fs.String("corpo", "", "corpo JSON para as rotas (POST/PUT/PATCH)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := o.validate(); err != nil {
		return err
	}
	client := newClient(&o, 1, !*fresh)
	if err := o.ping(ctx, client); err != nil {
		return err
	}
	token, err := o.session(ctx, client)
	if err != nil {
		return err
	}
	rq := &requester{client: client, base: o.baseURL, token: token, device: o.device}
	if err := o.checkToken(ctx, rq); err != nil {
		return err
	}
	if len(routes) == 0 {
		routes = latencyDefaults(token)
	}
	for i := range routes {
		if *body != "" {
			routes[i].Body = []byte(*body)
		}
	}
	res, over := runLatency(ctx, rq, routes, *n, *warmup, *gap, *limit)
	res.Location = o.baseURL
	if err := writeJSON(o.jsonOut, res); err != nil {
		return err
	}
	if over {
		return errFindings
	}
	return nil
}

func latencyDefaults(token string) []target {
	routes := []target{{Method: http.MethodGet, Path: "/healthz"}, {Method: http.MethodGet, Path: "/readyz"}}
	if token != "" {
		routes = append(routes, target{Method: http.MethodGet, Path: "/v1/me"})
	}
	return routes
}

func runLatency(ctx context.Context, rq *requester, routes []target, n, warmup int, gap time.Duration, limit float64) (latencyResult, bool) {
	fmt.Printf("Tempo de resposta em %s · %d requisições por rota, uma de cada vez\n", rq.base, n)
	var res latencyResult
	anyOver := false
	for _, t := range routes {
		if ctx.Err() != nil {
			break
		}
		for range warmup {
			rq.do(ctx, t)
		}
		lr := latencyRoute{Route: t.String(), Status: map[string]int{}, Threshold: limit}
		var totals, servers []time.Duration
		var dns, conn, tlsT time.Duration
		for i := range n {
			if ctx.Err() != nil {
				break
			}
			p, status, err := traced(ctx, rq, t)
			lr.Requests++
			if err != nil {
				lr.Errors++
				lr.Status[errorKind(err)]++
				continue
			}
			lr.Status[fmt.Sprint(status)]++
			totals = append(totals, p.total)
			servers = append(servers, p.server)
			dns += p.dns
			conn += p.connect
			tlsT += p.tls
			if p.reused {
				lr.Reused++
			} else {
				lr.NewConns++
			}
			if gap > 0 && i < n-1 {
				time.Sleep(gap)
			}
		}
		lr.Total, lr.Server = latencies(totals), latencies(servers)
		if lr.NewConns > 0 {
			lr.DNSMean = ms(dns / time.Duration(lr.NewConns))
			lr.Connect = ms(conn / time.Duration(lr.NewConns))
			lr.TLSMean = ms(tlsT / time.Duration(lr.NewConns))
		}
		lr.OverLimit = limit > 0 && lr.Total.P95 > limit
		anyOver = anyOver || lr.OverLimit
		res.Routes = append(res.Routes, lr)
		printLatency(lr)
	}
	return res, anyOver
}

func printLatency(lr latencyRoute) {
	title := lr.Route
	if lr.OverLimit {
		title += fmt.Sprintf("  ⚠ p95 acima de %.0f ms", lr.Threshold)
	}
	fmt.Printf("\n%s\n", title)
	t, s := lr.Total, lr.Server
	fmt.Printf("  total ms     p50 %.1f · p95 %.1f · p99 %.1f · min %.1f · média %.1f · máx %.1f\n", t.P50, t.P95, t.P99, t.Min, t.Mean, t.Max)
	fmt.Printf("  servidor ms  p50 %.1f · p95 %.1f · p99 %.1f  (do envio ao primeiro byte)\n", s.P50, s.P95, s.P99)
	if lr.NewConns > 0 {
		fmt.Printf("  conexão nova %d× · DNS %.1f ms · TCP %.1f ms · TLS %.1f ms (médias)\n", lr.NewConns, lr.DNSMean, lr.Connect, lr.TLSMean)
	}
	fmt.Printf("  status       %s\n", formatCounts(lr.Status))
}

// traced faz a requisição medindo cada fase com httptrace.
func traced(ctx context.Context, rq *requester, t target) (phases, int, error) {
	var p phases
	var dnsStart, connStart, tlsStart, wrote, firstByte instant
	trace := &httptrace.ClientTrace{
		DNSStart:             func(httptrace.DNSStartInfo) { dnsStart = now() },
		DNSDone:              func(httptrace.DNSDoneInfo) { p.dns = since(dnsStart) },
		ConnectStart:         func(string, string) { connStart = now() },
		ConnectDone:          func(string, string, error) { p.connect = since(connStart) },
		TLSHandshakeStart:    func() { tlsStart = now() },
		TLSHandshakeDone:     func(tls.ConnectionState, error) { p.tls = since(tlsStart) },
		GotConn:              func(info httptrace.GotConnInfo) { p.reused = info.Reused },
		WroteRequest:         func(httptrace.WroteRequestInfo) { wrote = now() },
		GotFirstResponseByte: func() { firstByte = now() },
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), t.Method, rq.base+t.Path, bodyOf(t))
	if err != nil {
		return p, 0, err
	}
	if t.Body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if rq.token != "" {
		req.Header.Set("Authorization", "Bearer "+rq.token)
	}
	if rq.device != "" {
		req.Header.Set("X-Device", rq.device)
	}
	start := now()
	resp, err := rq.client.Do(req)
	if err != nil {
		return p, 0, err
	}
	_, err = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	p.total = since(start)
	p.server = between(wrote, firstByte)
	return p, resp.StatusCode, err
}

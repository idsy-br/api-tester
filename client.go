package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// target é uma rota a chamar: "GET /v1/me", ou só "/healthz" (GET).
type target struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Body   []byte `json:"-"`
}

func (t target) String() string { return t.Method + " " + t.Path }

func parseTarget(s string) (target, error) {
	s = strings.TrimSpace(s)
	method, path, ok := strings.Cut(s, " ")
	if !ok {
		method, path = http.MethodGet, s
	}
	path = strings.TrimSpace(path)
	if strings.Contains(path, ":/") && strings.Contains(path, "/Git/") {
		return target{}, fmt.Errorf("rota %q: o Git Bash trocou a rota por uma pasta; rode com MSYS_NO_PATHCONV=1 ou no PowerShell", s)
	}
	if !strings.HasPrefix(path, "/") {
		return target{}, fmt.Errorf("rota inválida %q: use \"GET /v1/me\" ou \"/healthz\"", s)
	}
	return target{Method: strings.ToUpper(method), Path: path}, nil
}

// newClient cria o cliente HTTP. conns é quantas conexões manter abertas com a
// API: sem isso o Go abre e fecha conexão a cada requisição e, no Windows, as
// portas locais acabam antes da API.
func newClient(o *options, conns int, keepAlive bool) *http.Client {
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second,
		MaxIdleConns:        conns,
		MaxIdleConnsPerHost: conns,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   !keepAlive,
		ForceAttemptHTTP2:   true,
	}
	if o.insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // pedido com -inseguro
	}
	return &http.Client{
		Transport: transport,
		Timeout:   o.timeout,
		// redirecionamento é resultado de teste, não para seguir
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// requester faz as chamadas de carga com a sessão e o dispositivo.
type requester struct {
	client *http.Client
	base   string
	token  string
	device string
}

type result struct {
	status int
	dur    time.Duration
	bytes  int64
	err    error
}

func (r *requester) do(ctx context.Context, t target) result {
	req, err := http.NewRequestWithContext(ctx, t.Method, r.base+t.Path, bodyOf(t))
	if err != nil {
		return result{err: err}
	}
	if t.Body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if r.token != "" {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}
	if r.device != "" {
		req.Header.Set("X-Device", r.device)
	}
	req.Header.Set("User-Agent", "idsy-apitester/1")
	start := now()
	resp, err := r.client.Do(req)
	if err != nil {
		return result{dur: since(start), err: err}
	}
	n, err := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return result{status: resp.StatusCode, dur: since(start), bytes: n, err: err}
}

// bodyOf devolve nil sem corpo: um io.Reader nil dentro da interface faria o Go
// mandar Transfer-Encoding chunked.
func bodyOf(t target) io.Reader {
	if t.Body == nil {
		return nil
	}
	return bytes.NewReader(t.Body)
}

// errorKind resume o erro de rede para agrupar no relatório.
func errorKind(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "Client.Timeout") || strings.Contains(msg, "deadline exceeded"):
		return "tempo esgotado"
	case strings.Contains(msg, "connection refused") || strings.Contains(msg, "actively refused"):
		return "conexão recusada"
	case strings.Contains(msg, "connection reset") || strings.Contains(msg, "forcibly closed"):
		return "conexão derrubada"
	case strings.Contains(msg, "EOF"):
		return "conexão fechada pela API"
	case strings.Contains(msg, "only one usage of each socket address") || strings.Contains(msg, "cannot assign requested address"):
		return "portas locais esgotadas"
	case strings.Contains(msg, "no such host"):
		return "host não encontrado"
	case strings.Contains(msg, "certificate"):
		return "certificado TLS"
	}
	if len(msg) > 80 {
		msg = msg[:80]
	}
	return msg
}

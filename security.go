package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type verdict string

const (
	pass verdict = "OK"
	fail verdict = "FALHA"
	warn verdict = "AVISO"
	skip verdict = "PULADO"
)

type finding struct {
	Group  string  `json:"grupo"`
	Name   string  `json:"teste"`
	Result verdict `json:"resultado"`
	Detail string  `json:"detalhe,omitempty"`
}

type securityResult struct {
	Location string         `json:"url"`
	Refusals int            `json:"recusas_gastas"`
	Totals   map[string]int `json:"totais"`
	Findings []finding      `json:"testes"`
}

// securityRun guarda o estado dos testes. A API conta como recusa cada senha,
// código ou token errado, e 20 recusas do mesmo IP em 24 horas bloqueiam o IP para
// tudo. Os testes que gastam recusa ficam limitados por budget; os outros foram
// montados para não gastar nenhuma (formato de token inválido, corpo inválido).
type securityRun struct {
	o         *options
	client    *http.Client
	token     string
	budget    int
	spent     int
	blockedIP bool
	group     string
	findings  []finding
}

type response struct {
	status int
	header http.Header
	body   []byte
	err    error
}

func (r response) code() string {
	var p problem
	_ = json.Unmarshal(r.body, &p)
	return p.Code
}

func (r response) String() string {
	if r.err != nil {
		return errorKind(r.err)
	}
	if c := r.code(); c != "" {
		return fmt.Sprintf("%d %s", r.status, c)
	}
	return fmt.Sprint(r.status)
}

func cmdSecurity(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("seguranca", flag.ContinueOnError)
	var o options
	o.register(fs)
	budget := fs.Int("max-recusas", 5, "máximo de recusas (token/senha errados) que os testes podem gastar; 20 em 24h bloqueiam o IP")
	origin := fs.String("origem", "", "origem liberada no CORS, para conferir que ela é aceita (ex.: https://app.idsy.com.br)")
	logout := fs.Bool("testar-logout", false, "entra de novo com -team/-login, sai e confere que o token morreu (gasta 1 recusa)")
	brute := fs.Bool("forca-bruta", false, "manda senhas erradas até o IP ser bloqueado (BLOQUEIA ESTE IP POR 24h; precisa de -team e -login)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := o.validate(); err != nil {
		return err
	}
	res, err := runSecurity(ctx, &o, *budget, *origin, *logout, *brute)
	if err != nil {
		return err
	}
	if err := writeJSON(o.jsonOut, res); err != nil {
		return err
	}
	if res.Totals[string(fail)] > 0 {
		return errFindings
	}
	return nil
}

func runSecurity(ctx context.Context, o *options, budget int, origin string, logout, brute bool) (securityResult, error) {
	s := &securityRun{o: o, client: newClient(o, 4, true), budget: budget}
	if err := o.ping(ctx, s.client); err != nil {
		return securityResult{}, err
	}
	token, err := o.session(ctx, s.client)
	if err != nil {
		return securityResult{}, err
	}
	s.token = token
	fmt.Printf("Testes de segurança em %s", o.baseURL)
	if token == "" {
		fmt.Print(" · sem sessão (use -token ou -team/-login para testar também as rotas com login)")
	}
	fmt.Println()

	if r := s.send(ctx, http.MethodGet, "/healthz", nil, nil); r.err != nil {
		return securityResult{}, fmt.Errorf("a API não respondeu em %s: %w", o.baseURL, r.err)
	}

	// primeiro tudo que não gasta recusa
	s.checkTransport(ctx)
	s.checkHeaders(ctx)
	s.checkRouting(ctx)
	s.checkUnauthenticated(ctx)
	s.checkCORS(ctx, origin)
	s.checkBodies(ctx)
	s.checkLimits(ctx)
	if token != "" {
		s.checkSession(ctx)
	}
	// depois o que gasta, dentro do orçamento
	s.checkInvalidToken(ctx)
	s.checkInjection(ctx)
	if logout {
		s.checkLogout(ctx)
	}
	if brute {
		s.checkBruteForce(ctx)
	}

	res := securityResult{Location: o.baseURL, Refusals: s.spent, Totals: map[string]int{}, Findings: s.findings}
	for _, f := range s.findings {
		res.Totals[string(f.Result)]++
	}
	s.print(res)
	return res, nil
}

func (s *securityRun) section(name string) { s.group = name }

func (s *securityRun) add(name string, v verdict, detail string, args ...any) {
	if len(args) > 0 {
		detail = fmt.Sprintf(detail, args...)
	}
	s.findings = append(s.findings, finding{Group: s.group, Name: name, Result: v, Detail: detail})
}

// spend reserva uma recusa; false quando o orçamento acabou ou o IP já está bloqueado.
func (s *securityRun) spend(name string) bool {
	if s.blockedIP {
		s.add(name, skip, "o IP já está bloqueado pela API")
		return false
	}
	if s.spent >= s.budget {
		s.add(name, skip, "sem recusas no orçamento (-max-recusas %d)", s.budget)
		return false
	}
	s.spent++
	return true
}

func (s *securityRun) send(ctx context.Context, method, path string, headers map[string]string, body []byte) response {
	return s.sendURL(ctx, method, s.o.baseURL+path, headers, body)
}

func (s *securityRun) sendURL(ctx context.Context, method, rawURL string, headers map[string]string, body []byte) response {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, reader)
	if err != nil {
		return response{err: err}
	}
	req.Header.Set("User-Agent", "idsy-apitester/1")
	if s.o.device != "" {
		req.Header.Set("X-Device", s.o.device)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return response{err: err}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return response{status: resp.StatusCode, header: resp.Header, body: raw, err: err}
}

func (s *securityRun) authed() map[string]string {
	return map[string]string{"Authorization": "Bearer " + s.token}
}

// leak procura no corpo sinais de detalhe interno que não deveria sair.
func leak(body []byte) string {
	text := strings.ToLower(string(body))
	for _, sign := range []string{"goroutine ", "panic:", "runtime error", "sql:", "error 1064", "sql syntax", "mysql", "mariadb",
		".go:", "idsy.com.br/api/", "idsy_secret", "idsy_database", "root:x:0", "stack trace", "argon2", "$2y$"} {
		if strings.Contains(text, sign) {
			return sign
		}
	}
	return ""
}

// ---- transporte: HTTPS, versão do TLS, redirecionamento ----

func (s *securityRun) checkTransport(ctx context.Context) {
	s.section("Transporte")
	u, _ := url.Parse(s.o.baseURL)
	if u.Scheme == "http" {
		if s.o.isLocal() {
			s.add("HTTPS", skip, "API local em HTTP; em produção ela serve HTTPS com IDSY_TLS_DOMAINS")
		} else {
			s.add("HTTPS", fail, "API fora do computador local respondendo em HTTP: senha e token passam abertos")
		}
		return
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", host, &tls.Config{ServerName: u.Hostname(), InsecureSkipVerify: s.o.insecure}) //nolint:gosec // -inseguro
	if err != nil {
		s.add("Certificado TLS", fail, "%v", err)
	} else {
		state := conn.ConnectionState()
		conn.Close()
		if state.Version >= tls.VersionTLS12 {
			s.add("Versão do TLS", pass, "%s", tls.VersionName(state.Version))
		} else {
			s.add("Versão do TLS", fail, "negociou %s", tls.VersionName(state.Version))
		}
		if len(state.PeerCertificates) > 0 {
			left := time.Until(state.PeerCertificates[0].NotAfter)
			switch {
			case left < 0:
				s.add("Validade do certificado", fail, "vencido")
			case left < 14*24*time.Hour:
				s.add("Validade do certificado", warn, "vence em %.0f dias", left.Hours()/24)
			default:
				s.add("Validade do certificado", pass, "vence em %.0f dias", left.Hours()/24)
			}
		}
	}
	old, err := tls.DialWithDialer(dialer, "tcp", host, &tls.Config{ServerName: u.Hostname(), InsecureSkipVerify: true, MaxVersion: tls.VersionTLS11}) //nolint:gosec // teste de versão antiga
	if err == nil {
		old.Close()
		s.add("TLS 1.0/1.1 recusado", fail, "a API aceitou TLS antigo")
	} else {
		s.add("TLS 1.0/1.1 recusado", pass, "")
	}
	r := s.send(ctx, http.MethodGet, "/healthz", nil, nil)
	if hsts := r.header.Get("Strict-Transport-Security"); hsts != "" {
		s.add("HSTS", pass, "%s", hsts)
	} else {
		s.add("HSTS", fail, "sem Strict-Transport-Security em HTTPS")
	}
	plain := "http://" + u.Hostname() + "/healthz"
	r = s.sendURL(ctx, http.MethodGet, plain, nil, nil)
	switch {
	case r.err != nil:
		s.add("HTTP redireciona para HTTPS", skip, "porta 80 não respondeu (%s)", r)
	case (r.status == 301 || r.status == 302 || r.status == 307 || r.status == 308) && strings.HasPrefix(r.header.Get("Location"), "https://"):
		s.add("HTTP redireciona para HTTPS", pass, "%d → %s", r.status, r.header.Get("Location"))
	default:
		s.add("HTTP redireciona para HTTPS", fail, "%s em http:// sem ir para https://", r)
	}
}

// ---- cabeçalhos de segurança ----

func (s *securityRun) checkHeaders(ctx context.Context) {
	s.section("Cabeçalhos")
	r := s.send(ctx, http.MethodGet, "/healthz", nil, nil)
	h := r.header
	want := func(name, header, contains string) {
		value := h.Get(header)
		if value != "" && strings.Contains(strings.ToLower(value), contains) {
			s.add(name, pass, "%s: %s", header, value)
		} else {
			s.add(name, fail, "%s esperado com %q, veio %q", header, contains, value)
		}
	}
	want("Sem farejar tipo", "X-Content-Type-Options", "nosniff")
	want("CSP bloqueando tudo", "Content-Security-Policy", "default-src 'none'")
	want("Sem moldura (clickjacking)", "Content-Security-Policy", "frame-ancestors 'none'")
	want("Sem referrer", "Referrer-Policy", "no-referrer")
	want("Sem cache", "Cache-Control", "no-store")
	if h.Get("X-Request-Id") != "" {
		s.add("X-Request-Id", pass, "")
	} else {
		s.add("X-Request-Id", warn, "sem id da requisição para rastrear no log")
	}
	var revealed []string
	for _, name := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"} {
		if v := h.Get(name); v != "" {
			revealed = append(revealed, name+": "+v)
		}
	}
	if len(revealed) == 0 {
		s.add("Não revela o servidor", pass, "")
	} else {
		s.add("Não revela o servidor", warn, "%s", strings.Join(revealed, "; "))
	}
	if ct := h.Get("Content-Type"); strings.HasPrefix(ct, "application/json") {
		s.add("Content-Type do JSON", pass, "%s", ct)
	} else {
		s.add("Content-Type do JSON", warn, "veio %q", ct)
	}
}

// ---- rotas: 404, métodos, travessia de pasta ----

func (s *securityRun) checkRouting(ctx context.Context) {
	s.section("Rotas")
	r := s.send(ctx, http.MethodGet, "/nao-existe-"+randomHex(4), nil, nil)
	if r.status == 404 && strings.Contains(r.header.Get("Content-Type"), "json") {
		s.add("Rota desconhecida", pass, "%s", r)
	} else {
		s.add("Rota desconhecida", warn, "esperado 404 em JSON, veio %s (%s)", r, r.header.Get("Content-Type"))
	}
	if l := leak(r.body); l != "" {
		s.add("Erro sem detalhe interno", fail, "o 404 contém %q", l)
	}

	r = s.send(ctx, "TRACE", "/healthz", map[string]string{"X-Eco": "teste"}, nil)
	if r.status == 405 || r.status == 404 || r.status == 400 || r.status == 501 || r.err != nil {
		s.add("TRACE desligado", pass, "%s", r)
	} else {
		s.add("TRACE desligado", fail, "TRACE respondeu %s", r)
	}

	var bad []string
	for _, path := range []string{"/../../etc/passwd", "/%2e%2e/%2e%2e/etc/passwd", "/v1/build/arquivos/..%2f..%2f.env", "/.env", "/.git/config", "/storage/", "/certs/"} {
		r := s.send(ctx, http.MethodGet, path, nil, nil)
		text := string(r.body)
		if r.status == 200 || strings.Contains(text, "root:") || strings.Contains(text, "IDSY_") || strings.Contains(text, "[core]") {
			bad = append(bad, fmt.Sprintf("%s → %s", path, r))
		}
	}
	if len(bad) == 0 {
		s.add("Travessia de pasta e arquivos internos", pass, "7 caminhos recusados")
	} else {
		s.add("Travessia de pasta e arquivos internos", fail, "%s", strings.Join(bad, "; "))
	}
}

// ---- rotas com login chamadas sem login ----

var protectedRoutes = []string{
	"GET /v1/me", "GET /v1/me/two-factor", "GET /v1/teams", "GET /v1/teams/1", "GET /v1/teams/1/members",
	"GET /v1/teams/1/firewall", "GET /v1/teams/1/databases", "GET /v1/teams/1/integrations", "GET /v1/users",
	"GET /v1/users/1", "GET /v1/permissions", "GET /v1/structures", "GET /v1/integrations", "GET /v1/audit",
	"GET /v1/timeline", "GET /v1/ip-blocks", "GET /v1/cors-origins",
	"GET /v1/build/agencias", "GET /v1/build/bancos", "GET /v1/build/caixa", "GET /v1/build/contas", "GET /v1/build/empreendimentos",
	"POST /v1/users", "POST /v1/teams", "PATCH /v1/users/1", "DELETE /v1/users/1", "PUT /v1/me/password",
	"DELETE /v1/sessions/current", "PUT /v1/ip-blocks/203.0.113.9", "POST /v1/cors-origins", "PUT /v1/teams/1/permissions",
	"POST /v1/build/agencias", "DELETE /v1/build/agencias/1",
}

func (s *securityRun) checkUnauthenticated(ctx context.Context) {
	s.section("Sem login")
	var bad []string
	wwwAuth := true
	for _, spec := range protectedRoutes {
		t, _ := parseTarget(spec)
		var body []byte
		headers := map[string]string{}
		if t.Method != http.MethodGet && t.Method != http.MethodDelete {
			body, headers["Content-Type"] = []byte("{}"), "application/json"
		}
		r := s.send(ctx, t.Method, t.Path, headers, body)
		if r.status != 401 {
			bad = append(bad, fmt.Sprintf("%s → %s", spec, r))
			continue
		}
		if !strings.HasPrefix(r.header.Get("WWW-Authenticate"), "Bearer") {
			wwwAuth = false
		}
	}
	if len(bad) == 0 {
		s.add("Rotas protegidas sem token", pass, "%d rotas responderam 401", len(protectedRoutes))
	} else {
		s.add("Rotas protegidas sem token", fail, "%s", strings.Join(bad, "; "))
	}
	if wwwAuth {
		s.add("WWW-Authenticate no 401", pass, "")
	} else {
		s.add("WWW-Authenticate no 401", warn, "algum 401 sem WWW-Authenticate: Bearer")
	}

	// Formatos que nem chegam a ser token: a API recusa antes de procurar a sessão,
	// sem contar recusa no firewall.
	cases := map[string]string{
		"Basic":                "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:admin")),
		"Bearer vazio":         "Bearer ",
		"token curto":          "Bearer idsy_abc",
		"sem prefixo idsy_":    "Bearer " + strings.Repeat("A", 48),
		"SQL no token":         "Bearer idsy_' OR '1'='1' -- ",
		"JWT alg none":         "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIiwiYWRtaW4iOnRydWV9.",
		"token prefixo errado": "Bearer idsyl_" + base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	}
	bad = bad[:0]
	for name, header := range cases {
		r := s.send(ctx, http.MethodGet, "/v1/me", map[string]string{"Authorization": header}, nil)
		if r.status != 401 {
			bad = append(bad, fmt.Sprintf("%s → %s", name, r))
		}
	}
	if len(bad) == 0 {
		s.add("Authorization mal formado", pass, "%d formatos recusados com 401", len(cases))
	} else {
		s.add("Authorization mal formado", fail, "%s", strings.Join(bad, "; "))
	}
}

// ---- CORS ----

func (s *securityRun) checkCORS(ctx context.Context, allowed string) {
	s.section("CORS")
	for _, evil := range []string{"https://site-malicioso.example", "null"} {
		r := s.send(ctx, http.MethodGet, "/healthz", map[string]string{"Origin": evil}, nil)
		acao := r.header.Get("Access-Control-Allow-Origin")
		switch {
		case acao == "*":
			s.add("Origem "+evil, fail, "Access-Control-Allow-Origin: *")
		case acao != "":
			s.add("Origem "+evil, fail, "liberada: Access-Control-Allow-Origin: %s", acao)
		default:
			s.add("Origem "+evil, pass, "não liberada")
		}
	}
	r := s.send(ctx, http.MethodOptions, "/v1/me", map[string]string{
		"Origin": "https://site-malicioso.example", "Access-Control-Request-Method": "DELETE", "Access-Control-Request-Headers": "authorization",
	}, nil)
	if r.header.Get("Access-Control-Allow-Methods") == "" && r.header.Get("Access-Control-Allow-Origin") == "" {
		s.add("Preflight de origem estranha", pass, "%s sem liberar métodos", r)
	} else {
		s.add("Preflight de origem estranha", fail, "liberou %q", r.header.Get("Access-Control-Allow-Methods"))
	}
	if r.header.Get("Access-Control-Allow-Credentials") == "true" {
		s.add("Sem credenciais de navegador", fail, "Access-Control-Allow-Credentials: true")
	}
	if allowed == "" {
		s.add("Origem do app aceita", skip, "informe -origem https://app... para conferir")
		return
	}
	r = s.send(ctx, http.MethodOptions, "/v1/me", map[string]string{"Origin": allowed, "Access-Control-Request-Method": "GET"}, nil)
	if r.header.Get("Access-Control-Allow-Origin") == allowed {
		s.add("Origem do app aceita", pass, "%s", allowed)
	} else {
		s.add("Origem do app aceita", warn, "%s não foi liberada (cadastre em /v1/cors-origins)", allowed)
	}
}

// ---- corpo: a API confere o JSON antes de olhar a senha, então nada disso gasta recusa ----

func (s *securityRun) checkBodies(ctx context.Context) {
	s.section("Entrada inválida (POST /v1/sessions)")
	big := append([]byte(`{"team":"`), bytes.Repeat([]byte("a"), (1<<20)+512)...)
	big = append(big, []byte(`"}`)...)
	cases := []struct {
		name, contentType string
		body              []byte
	}{
		{"Content-Type errado", "text/plain", []byte(`{"team":"a","login":"b","password":"c"}`)},
		{"JSON mal formado", "application/json", []byte(`{"team":`)},
		{"Corpo vazio", "application/json", []byte(``)},
		{"Campo a mais (admin=true)", "application/json", []byte(`{"team":"a","login":"b","password":"c","admin":true}`)},
		{"Tipo errado", "application/json", []byte(`{"team":123,"login":["b"],"password":{}}`)},
		{"Dois objetos", "application/json", []byte(`{"team":"a"}{"team":"b"}`)},
		{"Corpo acima de 1 MB", "application/json", big},
		{"JSON muito aninhado", "application/json", []byte(`{"team":` + strings.Repeat("[", 10000) + strings.Repeat("]", 10000) + `}`)},
	}
	for _, c := range cases {
		r := s.send(ctx, http.MethodPost, "/v1/sessions", map[string]string{"Content-Type": c.contentType}, c.body)
		switch {
		case r.err != nil && c.name == "Corpo acima de 1 MB":
			s.add(c.name, pass, "a API cortou a conexão (%s)", r)
		case r.err != nil:
			s.add(c.name, warn, "%s", r)
		case r.status == 401 || r.status == 429:
			s.add(c.name, warn, "%s: a entrada chegou na conferência da senha", r)
		case r.status >= 400 && r.status < 500:
			s.add(c.name, pass, "%s", r)
		default:
			s.add(c.name, fail, "%s", r)
		}
		if l := leak(r.body); l != "" {
			s.add(c.name+": sem detalhe interno", fail, "a resposta contém %q", l)
		}
	}
}

// ---- limites do servidor: cabeçalho gigante e conexão lenta ----

func (s *securityRun) checkLimits(ctx context.Context) {
	s.section("Limites do servidor")
	// em HTTP/1.1: no HTTP/2 o próprio cliente Go recusa o cabeçalho antes de mandar
	h2 := s.client
	s.client = newClient(s.o, 1, false)
	if tr, ok := s.client.Transport.(*http.Transport); ok {
		tr.ForceAttemptHTTP2 = false
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	r := s.send(ctx, http.MethodGet, "/healthz", map[string]string{"X-Grande": strings.Repeat("a", 2<<20)}, nil)
	s.client = h2
	switch {
	case r.err != nil:
		s.add("Cabeçalho de 2 MB", pass, "conexão recusada (%s)", r)
	case r.status == 431 || r.status == 400:
		s.add("Cabeçalho de 2 MB", pass, "%s", r)
	default:
		s.add("Cabeçalho de 2 MB", fail, "aceitou: %s", r)
	}

	closed, err := slowHeaders(ctx, s.o, 20*time.Second)
	switch {
	case err != nil:
		s.add("Conexão lenta (slowloris)", skip, "%v", err)
	case closed == 0:
		s.add("Conexão lenta (slowloris)", fail, "conexão com cabeçalho pela metade continuou aberta por 20s")
	case closed <= 15*time.Second:
		s.add("Conexão lenta (slowloris)", pass, "a API fechou em %.1fs", closed.Seconds())
	default:
		s.add("Conexão lenta (slowloris)", warn, "a API demorou %.1fs para fechar", closed.Seconds())
	}
}

// slowHeaders abre uma conexão, manda metade dos cabeçalhos e espera a API fechar.
// Devolve 0 se ela não fechou dentro de wait.
func slowHeaders(ctx context.Context, o *options, wait time.Duration) (time.Duration, error) {
	u, _ := url.Parse(o.baseURL)
	host := u.Host
	if u.Port() == "" {
		port := "80"
		if u.Scheme == "https" {
			port = "443"
		}
		host = net.JoinHostPort(u.Hostname(), port)
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	var conn net.Conn
	var err error
	if u.Scheme == "https" {
		conn, err = tls.DialWithDialer(dialer, "tcp", host, &tls.Config{ServerName: u.Hostname(), InsecureSkipVerify: o.insecure, NextProtos: []string{"http/1.1"}}) //nolint:gosec // -inseguro
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", host)
	}
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	start := time.Now()
	if _, err := fmt.Fprintf(conn, "GET /healthz HTTP/1.1\r\nHost: %s\r\nX-Lento: 1\r\n", u.Host); err != nil {
		return 0, err
	}
	_ = conn.SetReadDeadline(start.Add(wait))
	_, err = io.Copy(io.Discard, bufio.NewReader(conn))
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return 0, nil
	}
	return time.Since(start), nil
}

// ---- com sessão ----

func (s *securityRun) checkSession(ctx context.Context) {
	s.section("Com sessão")
	r := s.send(ctx, http.MethodGet, "/v1/me", s.authed(), nil)
	if r.status != 200 {
		s.add("Sessão válida", fail, "GET /v1/me respondeu %s", r)
		return
	}
	s.add("Sessão válida", pass, "")
	lower := strings.ToLower(string(r.body))
	var exposed []string
	for _, field := range []string{`"password`, `"senha`, `"hash`, `"secret`, `"totp`, `"token`, "$argon2", "$2y$"} {
		if strings.Contains(lower, field) {
			exposed = append(exposed, field)
		}
	}
	if len(exposed) == 0 {
		s.add("/v1/me sem dado sensível", pass, "")
	} else {
		s.add("/v1/me sem dado sensível", fail, "contém %s", strings.Join(exposed, ", "))
	}

	// token na URL não pode valer: fica em log de proxy e no histórico do navegador
	var accepted []string
	for _, param := range []string{"access_token", "token", "auth"} {
		r := s.send(ctx, http.MethodGet, "/v1/me?"+param+"="+url.QueryEscape(s.token), nil, nil)
		if r.status == 200 {
			accepted = append(accepted, param)
		}
	}
	if len(accepted) == 0 {
		s.add("Token na URL recusado", pass, "")
	} else {
		s.add("Token na URL recusado", fail, "aceitou ?%s=", strings.Join(accepted, ", ?"))
	}

	// percorre as rotas de leitura: com sessão, 200/403/404 são esperados, 500 não
	counts := map[string]int{}
	var broken []string
	for _, spec := range protectedRoutes {
		t, _ := parseTarget(spec)
		if t.Method != http.MethodGet {
			continue
		}
		r := s.send(ctx, t.Method, t.Path, s.authed(), nil)
		counts[fmt.Sprint(r.status)]++
		// sem procurar vazamento no corpo: com sessão, DSN e nomes de banco são dado legítimo
		if r.status >= 500 || r.err != nil {
			broken = append(broken, fmt.Sprintf("%s → %s", spec, r))
		}
	}
	if len(broken) == 0 {
		s.add("Leitura com sessão sem erro interno", pass, "%s", formatCounts(counts))
	} else {
		s.add("Leitura com sessão sem erro interno", fail, "%s", strings.Join(broken, "; "))
	}
}

// ---- os que gastam recusa ----

func (s *securityRun) checkInvalidToken(ctx context.Context) {
	s.section("Token e senha errados (gastam recusa)")
	name := "Token bem formado mas inexistente"
	if !s.spend(name) {
		return
	}
	fake := "idsy_" + base64.RawURLEncoding.EncodeToString(randomBytes(32))
	r := s.send(ctx, http.MethodGet, "/v1/me", map[string]string{"Authorization": "Bearer " + fake}, nil)
	switch {
	case r.status == 401:
		s.add(name, pass, "%s", r)
	case r.status == 429:
		s.blockedIP = true
		s.add(name, warn, "este IP já está bloqueado (%s); libere com idsyctl ip unblock -ip SEU_IP", r)
	default:
		s.add(name, fail, "%s", r)
	}
}

func (s *securityRun) checkInjection(ctx context.Context) {
	payloads := []struct{ name, team, login, password string }{
		{"SQL injection no login", "control", "admin' OR '1'='1' -- ", "x' OR '1'='1"},
		{"SQL injection no team", "x' UNION SELECT 1,2,3 -- ", "admin", "x"},
		{"Injeção com aspas e comentário", `control"; DROP TABLE users; #`, `{"$ne":null}`, `\'; SELECT SLEEP(5); --`},
	}
	for _, p := range payloads {
		if !s.spend(p.name) {
			continue
		}
		body, _ := json.Marshal(map[string]string{"team": p.team, "login": p.login, "password": p.password})
		start := time.Now()
		r := s.send(ctx, http.MethodPost, "/v1/sessions", map[string]string{"Content-Type": "application/json"}, body)
		took := time.Since(start)
		switch {
		case r.status == 429:
			s.blockedIP = true
			s.add(p.name, warn, "IP bloqueado (%s)", r)
		case r.err != nil:
			s.add(p.name, warn, "%s", r)
		case r.status >= 500:
			s.add(p.name, fail, "erro interno: %s", r)
		case r.status < 300:
			s.add(p.name, fail, "entrou! %s", r)
		case took > 4*time.Second:
			s.add(p.name, fail, "demorou %.1fs (SLEEP executado?)", took.Seconds())
		default:
			s.add(p.name, pass, "%s em %.0f ms", r, float64(took.Milliseconds()))
		}
		if l := leak(r.body); l != "" {
			s.add(p.name+": sem detalhe interno", fail, "a resposta contém %q", l)
		}
	}
}

func (s *securityRun) checkLogout(ctx context.Context) {
	name := "Token morre depois de sair"
	if s.o.login == "" || s.o.team == "" {
		s.add(name, skip, "precisa de -team e -login")
		return
	}
	if !s.spend(name) {
		return
	}
	fmt.Println("\nEntrando de novo para o teste de saída...")
	// sem o -token, o session entra de verdade em vez de devolver a sessão em uso
	o := *s.o
	o.token = ""
	tok, err := o.session(ctx, s.client)
	if err != nil {
		s.spent--
		s.add(name, skip, "não entrou: %v", err)
		return
	}
	h := map[string]string{"Authorization": "Bearer " + tok}
	if r := s.send(ctx, http.MethodDelete, "/v1/sessions/current", h, nil); r.status != 204 {
		s.add(name, fail, "DELETE /v1/sessions/current respondeu %s", r)
		return
	}
	r := s.send(ctx, http.MethodGet, "/v1/me", h, nil)
	if r.status == 401 {
		s.add(name, pass, "token recusado depois da saída")
	} else {
		s.add(name, fail, "token ainda vale: %s", r)
	}
}

func (s *securityRun) checkBruteForce(ctx context.Context) {
	name := "Força bruta bloqueia o IP"
	if s.o.login == "" || s.o.team == "" {
		s.add(name, skip, "precisa de -team e -login (pode ser um login que não existe)")
		return
	}
	fmt.Println("\n⚠ Força bruta: mandando senhas erradas até a API bloquear este IP (24h).")
	for attempt := 1; attempt <= 30; attempt++ {
		body, _ := json.Marshal(map[string]string{"team": s.o.team, "login": s.o.login, "password": "errada-" + randomHex(6)})
		r := s.send(ctx, http.MethodPost, "/v1/sessions", map[string]string{"Content-Type": "application/json"}, body)
		s.spent++
		if r.status == 429 {
			s.blockedIP = true
			if attempt <= 21 {
				s.add(name, pass, "bloqueado na tentativa %d (%s). Libere com: idsyctl ip unblock -ip SEU_IP", attempt, r.code())
			} else {
				s.add(name, warn, "só bloqueou na tentativa %d", attempt)
			}
			return
		}
		if r.status < 300 {
			s.add(name, fail, "a senha %q entrou?! %s", "errada-...", r)
			return
		}
	}
	s.add(name, fail, "30 senhas erradas e o IP não foi bloqueado")
}

// ---- relatório ----

func (s *securityRun) print(res securityResult) {
	icon := map[verdict]string{pass: "✓", fail: "✗", warn: "!", skip: "-"}
	group := ""
	for _, f := range res.Findings {
		if f.Group != group {
			group = f.Group
			fmt.Printf("\n%s\n", group)
		}
		line := fmt.Sprintf("  %s %-6s %s", icon[f.Result], f.Result, f.Name)
		if f.Detail != "" {
			line += ": " + f.Detail
		}
		fmt.Println(line)
	}
	fmt.Printf("\nTotal: %d OK · %d falhas · %d avisos · %d pulados · %d recusas gastas no firewall\n",
		res.Totals[string(pass)], res.Totals[string(fail)], res.Totals[string(warn)], res.Totals[string(skip)], res.Refusals)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func randomHex(n int) string { return fmt.Sprintf("%x", randomBytes(n)) }

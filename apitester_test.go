package main

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPercentile(t *testing.T) {
	var durs []time.Duration
	for i := 1; i <= 100; i++ {
		durs = append(durs, time.Duration(i)*time.Millisecond)
	}
	for p, want := range map[float64]time.Duration{50: 50 * time.Millisecond, 95: 95 * time.Millisecond, 99: 99 * time.Millisecond, 100: 100 * time.Millisecond} {
		if got := percentile(durs, p); got != want {
			t.Errorf("p%.0f = %s, esperado %s", p, got, want)
		}
	}
	if got := percentile(nil, 50); got != 0 {
		t.Errorf("vazio = %s", got)
	}
}

func TestParseTarget(t *testing.T) {
	cases := map[string]string{"/healthz": "GET /healthz", "post /v1/sessions": "POST /v1/sessions", " DELETE  /v1/users/1 ": "DELETE /v1/users/1"}
	for in, want := range cases {
		got, err := parseTarget(in)
		if err != nil || got.String() != want {
			t.Errorf("parseTarget(%q) = %q, %v; esperado %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"healthz", "GET v1", "C:/Program Files/Git/healthz"} {
		if _, err := parseTarget(bad); err == nil {
			t.Errorf("parseTarget(%q) devia falhar", bad)
		}
	}
}

func TestParseRates(t *testing.T) {
	got, err := parseRates("50, 100,200")
	if err != nil || len(got) != 3 || got[2] != 200 {
		t.Fatalf("parseRates = %v, %v", got, err)
	}
	if _, err := parseRates("10,x"); err == nil {
		t.Error("devia recusar x")
	}
}

func TestGuardLoad(t *testing.T) {
	for _, u := range []string{"http://localhost:8090", "http://127.0.0.1:8090", "http://[::1]:8090", "http://api.localhost"} {
		o := options{baseURL: u}
		if err := o.guardLoad(); err != nil {
			t.Errorf("%s é local: %v", u, err)
		}
	}
	o := options{baseURL: "https://api.idsy.com.br"}
	if err := o.guardLoad(); err == nil {
		t.Error("servidor de fora sem -sim devia ser recusado")
	}
	o.yes = true
	if err := o.guardLoad(); err != nil {
		t.Errorf("com -sim: %v", err)
	}
}

// fakeAPI imita o comportamento da API que os testes conferem.
func fakeAPI() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		if strings.HasPrefix(r.URL.Path, "/v1/") {
			w.Header().Set("WWW-Authenticate", `Bearer realm="idsy"`)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"status":401,"code":"nao_autenticado"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"status":404,"code":"rota_nao_encontrada"}`))
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("X-Request-Id", "abc")
		mux.ServeHTTP(w, r)
	})
}

func TestClientsAndRPS(t *testing.T) {
	srv := httptest.NewServer(fakeAPI())
	defer srv.Close()
	o := options{baseURL: srv.URL, timeout: 2 * time.Second}
	routes := []target{{Method: http.MethodGet, Path: "/healthz"}}

	rq := &requester{client: newClient(&o, 10, true), base: srv.URL}
	cl, err := runClients(context.Background(), rq, routes, 10, 5*time.Second, 300, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if cl.Summary.Requests != 300 || cl.Summary.OK != 300 {
		t.Errorf("clientes: %d requisições, %d ok; esperado 300", cl.Summary.Requests, cl.Summary.OK)
	}

	res := runRPS(context.Background(), rq, routes, []int{100}, time.Second, 50, 0.1)
	got := res.Steps[0].Summary.Requests
	if got < 90 || got > 110 {
		t.Errorf("rps: %d requisições em 1s a 100/s", got)
	}
}

func TestSecurityAgainstFake(t *testing.T) {
	srv := httptest.NewUnstartedServer(fakeAPI())
	srv.Config.ReadHeaderTimeout = time.Second // o teste de conexão lenta espera a API fechar
	srv.Start()
	defer srv.Close()
	o := options{baseURL: srv.URL, timeout: 2 * time.Second}
	res, err := runSecurity(context.Background(), &o, 0, "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range res.Findings {
		if f.Group == "Cabeçalhos" && f.Result != pass {
			t.Errorf("%s: %s %s", f.Name, f.Result, f.Detail)
		}
		if f.Name == "Rotas protegidas sem token" && f.Result != pass {
			t.Errorf("%s: %s", f.Name, f.Detail)
		}
	}
	if res.Refusals != 0 {
		t.Errorf("com -max-recusas 0 gastou %d recusas", res.Refusals)
	}
}

func TestReportHeader(t *testing.T) {
	var b strings.Builder
	r := &report{Company: "Toth Tec", Tester: "Eric", URL: "http://x", Security: []*securityResult{{Totals: map[string]int{}}}}
	if err := reportTemplate.Execute(&b, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "<b>Empresa:</b> Toth Tec · <b>Responsável pelo teste:</b> Eric") {
		t.Error("cabeçalho sem empresa e responsável")
	}
}

// TestLoginTwoFactor segue o contrato da API: 202 com o pedido do código e
// depois /v1/sessions/confirm com pending_token e code.
func TestLoginTwoFactor(t *testing.T) {
	const pending = "idsyl_pendente"
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in["team"] != "control" || in["login"] != "eric" || in["password"] != "Sênha certa " {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"status":401,"code":"credenciais_invalidas"}`))
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"challenge":{"pending_token":"` + pending + `","email":"e***@x.com","methods":["email"],"email_sent":true}}`))
	})
	mux.HandleFunc("POST /v1/sessions/confirm", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		if in["pending_token"] != pending || in["code"] != "12345678" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"status":401,"code":"codigo_invalido"}`))
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"session":{"token":"idsy_ok","expires_at":"2030-01-01T00:00:00Z"}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	old := stdin
	defer func() { stdin = old }()
	stdin = bufio.NewReader(strings.NewReader("Sênha certa \n 12345678 \n"))

	o := options{baseURL: srv.URL, team: "control", login: "eric", timeout: 2 * time.Second}
	token, err := o.session(context.Background(), newClient(&o, 1, true))
	if err != nil || token != "idsy_ok" {
		t.Fatalf("session = %q, %v", token, err)
	}
	if o.twoFactor != "email" {
		t.Errorf("twoFactor = %q", o.twoFactor)
	}
}

func TestStressSkipsBrokenRoutes(t *testing.T) {
	srv := httptest.NewServer(fakeAPI())
	defer srv.Close()
	o := options{baseURL: srv.URL, timeout: 2 * time.Second}
	rq := &requester{client: newClient(&o, 50, true), base: srv.URL}
	routes := []target{{Method: http.MethodGet, Path: "/healthz"}, {Method: http.MethodGet, Path: "/nao-existe"}}
	cfg := stressConfig{Start: 50, Factor: 2, Step: 500 * time.Millisecond, MaxRPS: 100, MaxOpen: 50, ErrLimit: 0.05, P95Limit: 1000}
	res := runStress(context.Background(), rq, routes, cfg)
	if len(res.Removed) != 1 || len(res.Routes) != 1 {
		t.Fatalf("rotas = %v, fora = %v", res.Routes, res.Removed)
	}
	if res.BreakRPS != 0 || res.MaxHealthyRPS == 0 {
		t.Errorf("limite = %d, máximo = %.0f, motivo = %s", res.BreakRPS, res.MaxHealthyRPS, res.Reason)
	}
	if got := overloadRate(summary{Requests: 10, Status: map[string]int{"404": 5, "503": 1}, Errors: map[string]int{"tempo esgotado": 1}}); got != 0.2 {
		t.Errorf("overloadRate = %v, esperado 0.2", got)
	}
}

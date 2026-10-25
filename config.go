package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// options são as opções comuns a todos os comandos.
type options struct {
	baseURL  string
	token    string
	team     string
	login    string
	code     string
	device   string
	timeout  time.Duration
	insecure bool
	jsonOut  string
	yes      bool

	password  string // só em memória: vem de IDSY_PASSWORD ou do terminal
	twoFactor string // como foi o último login: "", "app" ou "email"
}

func (o *options) register(fs *flag.FlagSet) {
	fs.StringVar(&o.baseURL, "url", envOr("IDSY_URL", "http://localhost:8090"), "endereço da API")
	fs.StringVar(&o.token, "token", os.Getenv("IDSY_TOKEN"), "sessão pronta (idsy_...); sem ela, entra com -team/-login")
	fs.StringVar(&o.team, "team", os.Getenv("IDSY_TEAM"), "slug do team para entrar")
	fs.StringVar(&o.login, "login", os.Getenv("IDSY_LOGIN"), "login para entrar (a senha vem de IDSY_PASSWORD ou é perguntada)")
	fs.StringVar(&o.code, "codigo", "", "código de dois fatores (sem ele, é perguntado no terminal)")
	fs.StringVar(&o.device, "device", os.Getenv("IDSY_DEVICE"), "valor do header X-Device (firewall por dispositivo)")
	fs.DurationVar(&o.timeout, "timeout", 10*time.Second, "tempo máximo de cada requisição")
	fs.BoolVar(&o.insecure, "inseguro", false, "aceita certificado TLS inválido")
	fs.StringVar(&o.jsonOut, "json", "", "grava o resultado em JSON neste arquivo")
	fs.BoolVar(&o.yes, "sim", false, "confirma carga em servidor que não é local")
}

func (o *options) validate() error {
	u, err := url.Parse(o.baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("-url inválida: %q (use http://host:porta ou https://host)", o.baseURL)
	}
	o.baseURL = strings.TrimRight(o.baseURL, "/")
	return nil
}

// isLocal diz se a API está no próprio computador.
func (o *options) isLocal() bool {
	u, err := url.Parse(o.baseURL)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// guardLoad recusa carga em servidor de fora sem -sim: carga em produção derruba
// quem está usando.
func (o *options) guardLoad() error {
	if o.isLocal() || o.yes {
		return nil
	}
	return fmt.Errorf("%s não é local; carga pode derrubar quem está usando. Rode de novo com -sim para confirmar", o.baseURL)
}

// session devolve o token: o -token, ou entra com -team/-login. Sem nenhum dos
// dois, devolve vazio e os testes rodam só nas rotas públicas.
func (o *options) session(ctx context.Context, client *http.Client) (string, error) {
	if o.token != "" {
		return o.token, nil
	}
	if o.login == "" {
		return "", nil
	}
	if o.team == "" {
		return "", errors.New("-login precisa do -team")
	}
	if o.password == "" {
		o.password = os.Getenv("IDSY_PASSWORD")
	}
	if o.password == "" {
		var err error
		if o.password, err = promptSecret("Senha de " + o.login + ": "); err != nil {
			return "", err
		}
	}
	return o.loginFlow(ctx, client)
}

// loginFlow entra com team, login e senha. Com dois fatores pergunta o código e
// anota em o.twoFactor como foi ("app" ou "email"), o que decide a carga de logins.
func (o *options) loginFlow(ctx context.Context, client *http.Client) (string, error) {
	var res struct {
		Session *struct {
			Token string `json:"token"`
		} `json:"session"`
		Challenge *struct {
			PendingToken string   `json:"pending_token"`
			Email        string   `json:"email"`
			Methods      []string `json:"methods"`
		} `json:"challenge"`
	}
	status, err := o.postJSON(ctx, client, "/v1/sessions", map[string]string{"team": o.team, "login": o.login, "password": o.password}, &res)
	if err != nil {
		return "", fmt.Errorf("entrar: %w", err)
	}
	if status == http.StatusCreated && res.Session != nil {
		o.twoFactor = ""
		return res.Session.Token, nil
	}
	if status != http.StatusAccepted || res.Challenge == nil {
		return "", fmt.Errorf("entrar: a API respondeu %d", status)
	}
	o.twoFactor = "email"
	where := "do e-mail enviado para " + res.Challenge.Email
	if len(res.Challenge.Methods) > 0 && res.Challenge.Methods[0] == "app" {
		o.twoFactor = "app"
		where = "do aplicativo autenticador"
	}
	code := o.code
	if code == "" {
		if code, err = prompt("Código " + where + ": "); err != nil {
			return "", err
		}
	}
	status, err = o.postJSON(ctx, client, "/v1/sessions/confirm", map[string]string{"pending_token": res.Challenge.PendingToken, "code": code}, &res)
	if err != nil {
		return "", fmt.Errorf("confirmar código: %w", err)
	}
	if status != http.StatusCreated || res.Session == nil {
		return "", fmt.Errorf("confirmar código: a API respondeu %d", status)
	}
	return res.Session.Token, nil
}

// postJSON manda body e lê a resposta em out. Erro de API vem como erro com o code.
func (o *options) postJSON(ctx context.Context, client *http.Client, path string, body, out any) (int, error) {
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.baseURL+path, bytes.NewReader(raw))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if o.device != "" {
		req.Header.Set("X-Device", o.device)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		var p problem
		_ = json.NewDecoder(resp.Body).Decode(&p)
		return resp.StatusCode, fmt.Errorf("%d %s: %s", resp.StatusCode, p.Code, p.Detail)
	}
	return resp.StatusCode, json.NewDecoder(resp.Body).Decode(out)
}

// ping confere que a API está no ar antes de medir: sem isso, cada requisição
// vira "conexão recusada" e o relatório sai cheio de zeros.
func (o *options) ping(ctx context.Context, client *http.Client) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.baseURL+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		hint := ""
		if o.isLocal() {
			hint = " Ela está rodando? Suba com: go run ./cmd/api (na pasta idsy\\api)"
		}
		return fmt.Errorf("a API não respondeu em %s (%s).%s", o.baseURL, errorKind(err), hint)
	}
	resp.Body.Close()
	return nil
}

// checkToken confere a sessão antes da carga: com token errado, cada requisição
// seria uma recusa e 20 bloqueiam o IP por 24 horas.
func (o *options) checkToken(ctx context.Context, rq *requester) error {
	if rq.token == "" {
		return nil
	}
	res := rq.do(ctx, target{Method: http.MethodGet, Path: "/v1/me"})
	switch {
	case res.err != nil:
		return fmt.Errorf("conferir a sessão: %w", res.err)
	case res.status == http.StatusOK:
		return nil
	case res.status == http.StatusTooManyRequests:
		return errors.New("este IP está bloqueado pela API (muitas recusas); libere com: idsyctl ip unblock -ip SEU_IP")
	default:
		return fmt.Errorf("a sessão não vale (GET /v1/me respondeu %d); a carga pararia com o IP bloqueado", res.status)
	}
}

type problem struct {
	Status int               `json:"status"`
	Code   string            `json:"code"`
	Detail string            `json:"detail"`
	Fields map[string]string `json:"fields"`
}

// stdin é um leitor só para o programa todo: um bufio novo a cada pergunta
// engoliria o que já estava no buffer.
var stdin = bufio.NewReader(os.Stdin)

func prompt(label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	line, err := stdin.ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("ler do terminal: %w", err)
	}
	return strings.TrimSpace(line), nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// routeList é uma flag que pode se repetir: -rota "GET /v1/me" -rota /healthz.
type routeList []target

func (r *routeList) String() string {
	parts := make([]string, len(*r))
	for i, t := range *r {
		parts[i] = t.String()
	}
	return strings.Join(parts, ", ")
}

func (r *routeList) Set(value string) error {
	t, err := parseTarget(value)
	if err != nil {
		return err
	}
	*r = append(*r, t)
	return nil
}

// defaultRoutes: sem sessão só dá para medir as rotas públicas.
func defaultRoutes(token string) []target {
	if token == "" {
		return []target{{Method: http.MethodGet, Path: "/healthz"}}
	}
	return []target{{Method: http.MethodGet, Path: "/v1/me"}}
}

func writeJSON(path string, v any) error {
	if path == "" {
		return nil
	}
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return err
	}
	fmt.Printf("\nResultado gravado em %s\n", path)
	return nil
}

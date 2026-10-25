package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// interactive é o modo de duplo clique: pergunta a API e o login, conecta e
// mostra o menu. Cada teste roda com Ctrl+C para interromper e volta ao menu.
type interactive struct {
	o      *options
	rep    *report
	token  string
	warned bool // já confirmou a carga em servidor que não é local
}

func runInteractive() {
	fmt.Println("════════════════════════════════════════")
	fmt.Println("  apitester · testes da API da Idsy")
	fmt.Println("════════════════════════════════════════")
	fmt.Println("(no terminal também dá para rodar direto: apitester.exe -h)")

	app := &interactive{o: &options{timeout: 10 * time.Second}}
	fmt.Println("\nQuem está fazendo o teste (sai no relatório).")
	company := ask("Empresa", os.Getenv("IDSY_EMPRESA"))
	tester := ask("Responsável pelo teste", os.Getenv("IDSY_RESPONSAVEL"))
	if !app.connect() {
		pause()
		return
	}
	app.rep.Company, app.rep.Tester = company, tester
	app.menu()
}

func (app *interactive) connect() bool {
	ctx := context.Background()
	o := app.o
	client := newClient(o, 4, true)
	for {
		o.baseURL = ask("\nEndereço da API", envOr("IDSY_URL", "http://localhost:8090"))
		if !strings.Contains(o.baseURL, "://") {
			o.baseURL = "https://" + o.baseURL
		}
		if err := o.validate(); err != nil {
			fmt.Println("  ", err)
			continue
		}
		fmt.Print("  conectando... ")
		if err := o.ping(ctx, client); err != nil {
			fmt.Println("\n  ✗", err)
			if !yes("  Tentar outro endereço?", true) {
				return false
			}
			continue
		}
		fmt.Println("a API respondeu.")
		break
	}

	// como o painel, manda sempre o mesmo X-Device, para o firewall do team poder liberar este computador
	if o.device == "" {
		o.device = deviceID()
	}
	fmt.Println("\nLogin (cada senha errada conta para o bloqueio do IP: 20 em 24 horas).")
	showPassword := false
	for attempt := 1; ; attempt++ {
		o.team = ask("Team", envOr("IDSY_TEAM", "control"))
		o.login = ask("Login (Enter para testar só as rotas públicas)", os.Getenv("IDSY_LOGIN"))
		if o.login == "" {
			fmt.Println("  Sem login: a carga usa /healthz e a segurança fica nas rotas públicas.")
			break
		}
		o.password = ""
		if showPassword {
			o.password, _ = promptRaw("Senha de " + o.login + " (visível): ")
		}
		token, err := o.session(ctx, client)
		if err == nil {
			app.token = token
			break
		}
		fmt.Println("  ✗", err)
		switch msg := err.Error(); {
		case strings.Contains(msg, "dispositivo_nao_autorizado"):
			fmt.Printf("  O firewall do team só aceita dispositivos cadastrados. Cadastre este no painel\n  (Firewall do team → dispositivo): %s\n", o.device)
		case strings.Contains(msg, "ip_bloqueado"):
			fmt.Println("  Este IP foi bloqueado por excesso de tentativas. Na VPS: idsyctl ip unblock -ip SEU_IP")
		case strings.Contains(msg, "confirmar código"):
			fmt.Println("  A senha estava certa; o código não. Use o código mais recente (vale uma vez e vence em poucos minutos).")
		}
		if strings.Contains(err.Error(), "credenciais_invalidas") {
			// a API responde igual para team, login ou senha errados, para não revelar qual
			fmt.Printf("  A API não diz qual dos três está errado. Confira:\n")
			fmt.Printf("   · o team \"%s\" é o slug do team em que o usuário está (não o nome)\n", o.team)
			fmt.Println("   · o login é o nome de usuário, não o e-mail")
			fmt.Println("   · a senha diferencia maiúsculas e minúsculas")
		}
		if attempt >= 3 || !yes("  Tentar de novo?", true) {
			return false
		}
		showPassword = yes("  Mostrar a senha enquanto digita, para conferir?", false)
	}

	app.rep = &report{URL: o.baseURL, Started: time.Now()}
	if app.token != "" {
		o.token = app.token
		if me, err := fetchMe(ctx, client, o); err == nil {
			app.rep.User = fmt.Sprintf("%s (%s)", me.User.Name, me.User.Login)
			app.rep.Team = me.Team.Slug
			fmt.Printf("\n✓ Conectado como %s no team %s · %d permissões\n", app.rep.User, me.Team.Name, len(me.Permissions))
		} else {
			fmt.Println("\n✓ Conectado")
		}
	}
	return true
}

// deviceID é o identificador deste computador, guardado na pasta de configuração
// do usuário (no Windows, %AppData%\idsy-apitester\device).
func deviceID() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	path := filepath.Join(dir, "idsy-apitester", "device")
	if raw, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(raw))) > 0 {
		return strings.TrimSpace(string(raw))
	}
	b := randomBytes(16)
	id := fmt.Sprintf("apitester-%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
	if os.MkdirAll(filepath.Dir(path), 0o755) == nil {
		_ = os.WriteFile(path, []byte(id), 0o600)
	}
	return id
}

type meInfo struct {
	User struct {
		Name  string `json:"name"`
		Login string `json:"login"`
	} `json:"user"`
	Team struct {
		Slug string `json:"slug"`
		Name string `json:"name"`
	} `json:"team"`
	Permissions []string `json:"permissions"`
}

func fetchMe(ctx context.Context, client *http.Client, o *options) (meInfo, error) {
	var me meInfo
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.baseURL+"/v1/me", nil)
	if err != nil {
		return me, err
	}
	req.Header.Set("Authorization", "Bearer "+o.token)
	resp, err := client.Do(req)
	if err != nil {
		return me, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return me, fmt.Errorf("GET /v1/me respondeu %d", resp.StatusCode)
	}
	return me, json.NewDecoder(resp.Body).Decode(&me)
}

func (app *interactive) menu() {
	for {
		fmt.Print(`
Menu
  1  Carga de requisições até o limite (sobe até a API parar de responder)
  2  Verificação de segurança
  3  Tempo de resposta (média, p50, p95, p99)
  4  Testar tudo: segurança, carga até o limite e tempo de resposta depois da carga
  5  Gerar relatório HTML do que já rodou
  6  Limpar os resultados (começar um relatório novo)
  0  Sair
`)
		choice := ask("Escolha", "")
		var err error
		switch choice {
		case "1":
			err = app.stress()
		case "2":
			err = app.security()
		case "3":
			err = app.latency("avulso")
		case "4":
			err = app.all()
		case "5":
			app.writeReport()
			continue
		case "6":
			app.clear()
			continue
		case "0", "sair":
			if !app.rep.empty() && yes("Gerar o relatório antes de sair?", true) {
				app.writeReport()
			}
			return
		default:
			fmt.Println("Opção inválida.")
			continue
		}
		if err != nil {
			fmt.Println("\n✗", err)
		}
		ask("\nEnter para voltar ao menu", "")
	}
}

// withCtx roda fn com Ctrl+C interrompendo só o teste, não o programa.
func withCtx(fn func(ctx context.Context) error) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return fn(ctx)
}

func (app *interactive) confirmLoad() bool {
	if app.o.isLocal() || app.warned {
		return true
	}
	fmt.Printf("\n⚠ %s não é local. A carga vai até a API parar de responder:\n", app.o.baseURL)
	fmt.Println("  quem estiver usando essa API fica sem ela durante o teste.")
	if !yes("  Confirma que ela ainda não está em produção?", false) {
		return false
	}
	app.warned, app.o.yes = true, true
	return true
}

func (app *interactive) routes() []target {
	def := defaultRoutes(app.token)[0].String()
	text := ask("Rotas (separe com vírgula)", def)
	var routes []target
	for _, part := range strings.Split(text, ",") {
		t, err := parseTarget(part)
		if err != nil {
			fmt.Println("  ignorada:", err)
			continue
		}
		routes = append(routes, t)
	}
	if len(routes) == 0 {
		return defaultRoutes(app.token)
	}
	return routes
}

func (app *interactive) stressConfig() stressConfig {
	cfg := defaultStressConfig()
	cfg.Start = askInt("Começar com quantas requisições por segundo", cfg.Start)
	cfg.Step = askDuration("Duração de cada etapa", cfg.Step)
	cfg.P95Limit = float64(askInt("p95 (ms) que conta como lento demais", int(cfg.P95Limit)))
	return cfg
}

func (app *interactive) requester(conns int) *requester {
	return &requester{client: newClient(app.o, conns, true), base: app.o.baseURL, token: app.token, device: app.o.device}
}

func (app *interactive) stress() error {
	if !app.confirmLoad() {
		return nil
	}
	if len(app.rep.Stress) > 0 {
		app.askClear()
	}
	routes := app.routes()
	cfg := app.stressConfig()
	return withCtx(func(ctx context.Context) error {
		rq := app.requester(cfg.MaxOpen)
		if err := app.o.checkToken(ctx, rq); err != nil {
			return err
		}
		res := runStress(ctx, rq, routes, cfg)
		res.Location = app.o.baseURL
		app.rep.Stress = append(app.rep.Stress, &res)
		return nil
	})
}

func (app *interactive) security() error {
	if len(app.rep.Security) > 0 {
		app.askClear()
	}
	return withCtx(func(ctx context.Context) error {
		res, err := runSecurity(ctx, app.o, 5, "", false, false)
		if err != nil {
			return err
		}
		app.rep.Security = append(app.rep.Security, &res)
		return nil
	})
}

func (app *interactive) latency(label string) error {
	if len(app.rep.Latency) > 0 {
		app.askClear()
	}
	n := askInt("Requisições por rota", 200)
	return withCtx(func(ctx context.Context) error {
		return app.runLatency(ctx, label, n)
	})
}

func (app *interactive) runLatency(ctx context.Context, label string, n int) error {
	rq := app.requester(1)
	if err := app.o.checkToken(ctx, rq); err != nil {
		return err
	}
	res, _ := runLatency(ctx, rq, latencyDefaults(app.token), n, 5, 0, 0)
	res.Location = app.o.baseURL
	app.rep.Latency = append(app.rep.Latency, namedLatency{Label: label, Result: &res})
	return nil
}

// clear apaga os resultados guardados; empresa, responsável e conexão continuam.
func (app *interactive) clear() {
	app.rep.Security, app.rep.Stress, app.rep.Latency = nil, nil, nil
	app.rep.Started = time.Now()
	fmt.Println("✓ Resultados limpos: o próximo relatório só terá os testes daqui em diante.")
}

// askClear pergunta antes de um teste se os resultados anteriores ficam no relatório.
func (app *interactive) askClear() {
	if app.rep.empty() {
		return
	}
	if yes("Já há resultados de testes anteriores. Limpar para o relatório ter só este teste?", true) {
		app.clear()
	}
}

func (app *interactive) all() error {
	if !app.confirmLoad() {
		return nil
	}
	app.askClear()
	routes := app.routes()
	cfg := app.stressConfig()
	return withCtx(func(ctx context.Context) error {
		banner("1/4 Segurança")
		sec, err := runSecurity(ctx, app.o, 5, "", false, false)
		if err != nil {
			return err
		}
		app.rep.Security = append(app.rep.Security, &sec)

		banner("2/4 Tempo de resposta antes da carga")
		if err := app.runLatency(ctx, "antes da carga", 100); err != nil {
			return err
		}

		banner("3/4 Carga de requisições até o limite")
		rq := app.requester(cfg.MaxOpen)
		res := runStress(ctx, rq, routes, cfg)
		res.Location = app.o.baseURL
		app.rep.Stress = append(app.rep.Stress, &res)
		if ctx.Err() != nil {
			return errors.New("interrompido")
		}

		banner("4/4 Tempo de resposta depois da carga")
		if res.BreakRPS > 0 && !res.Recovered {
			fmt.Println("A API ainda não voltou; medindo assim mesmo.")
		}
		if err := app.runLatency(ctx, "depois da carga", 100); err != nil {
			return err
		}
		if yes("\nGerar o relatório agora?", true) {
			app.writeReport()
		}
		return nil
	})
}

func (app *interactive) writeReport() {
	if app.rep.empty() {
		fmt.Println("Nada rodou ainda: escolha um teste primeiro.")
		return
	}
	path, err := app.rep.write()
	if err != nil {
		fmt.Println("✗ gravar relatório:", err)
		return
	}
	fmt.Println("✓ Relatório gravado em", path)
	fmt.Println("  Abrindo no navegador. Para PDF: botão \"Imprimir / salvar PDF\" e \"Salvar como PDF\".")
	openFile(path)
}

// ---- perguntas ----

func ask(label, def string) string {
	text := label + ": "
	if def != "" {
		text = fmt.Sprintf("%s [%s]: ", label, def)
	}
	answer, err := prompt(text)
	if err != nil {
		// sem terminal (entrada fechada) não há como seguir no menu
		fmt.Fprintln(os.Stderr)
		os.Exit(0)
	}
	if answer == "" {
		return def
	}
	return answer
}

func askInt(label string, def int) int {
	for {
		n, err := strconv.Atoi(ask(label, strconv.Itoa(def)))
		if err == nil && n > 0 {
			return n
		}
		fmt.Println("  digite um número maior que zero")
	}
}

func askDuration(label string, def time.Duration) time.Duration {
	for {
		text := ask(label+" (ex.: 15s, 1m)", def.String())
		if d, err := time.ParseDuration(text); err == nil && d >= time.Second {
			return d
		}
		if n, err := strconv.Atoi(text); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
		fmt.Println("  use 15s, 30s, 1m...")
	}
}

func yes(label string, def bool) bool {
	hint := "s/N"
	if def {
		hint = "S/n"
	}
	answer := strings.ToLower(ask(label+" ("+hint+")", ""))
	if answer == "" {
		return def
	}
	return strings.HasPrefix(answer, "s") || strings.HasPrefix(answer, "y")
}

func pause() { ask("\nEnter para sair", "") }

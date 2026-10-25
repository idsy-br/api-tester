package main

import (
	"context"
	"flag"
	"fmt"
	"math"
	"net/http"
	"time"
)

// Carga até o limite: sobe a taxa de requisições por etapas até a API deixar de
// dar conta (erro, lentidão ou requisições se acumulando). A última etapa saudável
// é o máximo que ela aguenta. Depois confere quanto tempo ela leva para voltar.

type stressConfig struct {
	Start    int           `json:"rps_inicial"`
	Factor   float64       `json:"multiplicador"`
	Step     time.Duration `json:"-"`
	StepText string        `json:"duracao_etapa"`
	MaxRPS   int           `json:"rps_teto"`
	MaxOpen  int           `json:"max_abertas"`
	ErrLimit float64       `json:"limite_erro"`
	P95Limit float64       `json:"limite_p95_ms"`
}

type stressResult struct {
	Location        string       `json:"url"`
	Routes          []target     `json:"rotas"`
	Removed         []string     `json:"rotas_fora,omitempty"`
	Config          stressConfig `json:"config"`
	Steps           []rpsStep    `json:"etapas"`
	MaxHealthyRPS   float64      `json:"max_rps_saudavel"`
	BreakRPS        int          `json:"rps_no_limite,omitempty"`
	Reason          string       `json:"motivo"`
	Recovered       bool         `json:"recuperou"`
	RecoverySeconds float64      `json:"segundos_para_recuperar"`
}

func defaultStressConfig() stressConfig {
	return stressConfig{Start: 50, Factor: 1.5, Step: 15 * time.Second, MaxRPS: 20000, MaxOpen: 5000, ErrLimit: 0.05, P95Limit: 1000}
}

func cmdStress(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("limite", flag.ContinueOnError)
	var o options
	o.register(fs)
	var routes routeList
	fs.Var(&routes, "rota", "rota a chamar, pode repetir (padrão /healthz, ou GET /v1/me com sessão)")
	cfg := defaultStressConfig()
	fs.IntVar(&cfg.Start, "inicio", cfg.Start, "requisições por segundo da primeira etapa")
	fs.Float64Var(&cfg.Factor, "fator", cfg.Factor, "quanto multiplica a taxa a cada etapa")
	fs.DurationVar(&cfg.Step, "duracao", cfg.Step, "duração de cada etapa")
	fs.IntVar(&cfg.MaxRPS, "teto", cfg.MaxRPS, "para de subir nessa taxa mesmo sem a API cair")
	fs.IntVar(&cfg.MaxOpen, "max-abertas", cfg.MaxOpen, "máximo de requisições em andamento")
	fs.Float64Var(&cfg.ErrLimit, "limite-erro", cfg.ErrLimit, "taxa de erro que marca o limite (0 a 1)")
	fs.Float64Var(&cfg.P95Limit, "limite-p95", cfg.P95Limit, "p95 em ms que marca o limite")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if cfg.Start < 1 || cfg.Factor <= 1 {
		return fmt.Errorf("-inicio precisa ser 1 ou mais e -fator maior que 1")
	}
	rq, err := setupLoad(ctx, &o, &routes, "", cfg.MaxOpen)
	if err != nil {
		return err
	}
	res := runStress(ctx, rq, routes, cfg)
	res.Location = o.baseURL
	return writeJSON(o.jsonOut, res)
}

func runStress(ctx context.Context, rq *requester, routes []target, cfg stressConfig) stressResult {
	cfg.StepText = cfg.Step.String()
	res := stressResult{Config: cfg}
	routes, res.Removed = preflight(ctx, rq, routes)
	res.Routes = routes
	for _, note := range res.Removed {
		fmt.Println("  ⚠ fora da carga:", note)
	}
	if len(routes) == 0 {
		res.Reason = "nenhuma rota respondeu com sucesso antes da carga; confira as rotas"
		printStressConclusion(res)
		return res
	}
	fmt.Printf("Carga até o limite em %s · começa em %d req/s, ×%.1f a cada %s · rotas: %s\n",
		rq.base, cfg.Start, cfg.Factor, cfg.Step, (*routeList)(&routes).String())
	fmt.Printf("Limite = erro acima de %.0f%%, p95 acima de %.0f ms ou menos de 90%% da taxa pedida. Ctrl+C interrompe.\n",
		cfg.ErrLimit*100, cfg.P95Limit)

	rate := cfg.Start
	for {
		if ctx.Err() != nil {
			res.Reason = "interrompido"
			break
		}
		step, blocked := rpsStepRun(ctx, rq, routes, rate, cfg.Step, cfg.MaxOpen)
		res.Steps = append(res.Steps, step)
		if blocked {
			res.Reason = "a API bloqueou este IP (429); libere com idsyctl ip unblock -ip SEU_IP"
			res.BreakRPS = rate
			break
		}
		if reason := unhealthy(step, rate, cfg); reason != "" {
			res.Reason = reason
			res.BreakRPS = rate
			break
		}
		res.MaxHealthyRPS = step.Achieved
		if rate >= cfg.MaxRPS {
			res.Reason = fmt.Sprintf("chegou ao teto de %d req/s sem a API cair", cfg.MaxRPS)
			break
		}
		rate = min(int(math.Ceil(float64(rate)*cfg.Factor)), cfg.MaxRPS)
	}
	printRPSTable(res.Steps)

	if res.BreakRPS > 0 && ctx.Err() == nil {
		fmt.Print("\nConferindo se a API volta a responder...")
		res.Recovered, res.RecoverySeconds = waitRecovery(ctx, rq, 60*time.Second)
		fmt.Print("\r\033[K")
	}
	printStressConclusion(res)
	return res
}

// unhealthy diz por que a etapa passou do limite, ou vazio se ela foi bem.
func unhealthy(step rpsStep, rate int, cfg stressConfig) string {
	s := step.Summary
	switch {
	case s.Requests == 0:
		return "a API não respondeu nenhuma requisição"
	case overloadRate(s) > cfg.ErrLimit:
		return fmt.Sprintf("%.1f%% de erro em %d req/s (%s)", overloadRate(s)*100, rate, mainErrors(s))
	case s.Latency.P95 > cfg.P95Limit:
		return fmt.Sprintf("p95 de %.0f ms em %d req/s", s.Latency.P95, rate)
	case step.Achieved < 0.9*float64(rate):
		return fmt.Sprintf("só respondeu %.0f de %d req/s (requisições acumulando)", step.Achieved, rate)
	}
	return ""
}

// overloadRate conta só o que é sinal de API sem fôlego: erro de rede (tempo
// esgotado, conexão recusada) e 5xx. Um 404 ou 403 é a API respondendo certo a uma
// rota errada, e não pode passar por limite de carga.
func overloadRate(s summary) float64 {
	if s.Requests == 0 {
		return 0
	}
	bad := 0
	for _, n := range s.Errors {
		bad += n
	}
	for code, n := range s.Status {
		if code >= "500" {
			bad += n
		}
	}
	return float64(bad) / float64(s.Requests)
}

// preflight chama cada rota uma vez antes da carga e tira as que não respondem com
// sucesso (rota que não existe, id que não existe, sem permissão).
func preflight(ctx context.Context, rq *requester, routes []target) ([]target, []string) {
	var ok []target
	var removed []string
	for _, t := range routes {
		res := rq.do(ctx, t)
		switch {
		case res.err != nil:
			removed = append(removed, fmt.Sprintf("%s (%s)", t, errorKind(res.err)))
		case res.status >= 400:
			why := map[int]string{401: "sem login", 403: "sem permissão", 404: "não existe", 405: "método errado", 422: "precisa de corpo"}[res.status]
			removed = append(removed, fmt.Sprintf("%s respondeu %d %s", t, res.status, why))
		default:
			ok = append(ok, t)
		}
	}
	return ok, removed
}

func mainErrors(s summary) string {
	counts := map[string]int{}
	for k, v := range s.Errors {
		counts[k] = v
	}
	for k, v := range s.Status {
		if k >= "400" {
			counts["status "+k] = v
		}
	}
	return formatCounts(counts)
}

// waitRecovery chama /healthz a cada segundo até três respostas boas seguidas.
func waitRecovery(ctx context.Context, rq *requester, limit time.Duration) (bool, float64) {
	start := time.Now()
	ok := 0
	for time.Since(start) < limit && ctx.Err() == nil {
		res := rq.do(ctx, target{Method: http.MethodGet, Path: "/healthz"})
		if res.err == nil && res.status == http.StatusOK {
			ok++
			if ok == 3 {
				return true, time.Since(start).Seconds()
			}
		} else {
			ok = 0
		}
		time.Sleep(time.Second)
	}
	return false, time.Since(start).Seconds()
}

func printStressConclusion(res stressResult) {
	fmt.Printf("\nConclusão\n─────────\n")
	if res.MaxHealthyRPS > 0 {
		fmt.Printf("  Máximo que a API aguentou: %.0f req/s\n", res.MaxHealthyRPS)
	} else {
		fmt.Println("  A API não aguentou nem a primeira etapa: comece com -inicio menor")
	}
	fmt.Printf("  Parou porque: %s\n", res.Reason)
	switch {
	case res.BreakRPS == 0:
	case res.Recovered:
		fmt.Printf("  Voltou a responder em %.0f s\n", res.RecoverySeconds)
	default:
		fmt.Printf("  ⚠ Não voltou a responder em %.0f s: confira o serviço na VPS\n", res.RecoverySeconds)
	}
	fmt.Println("  (o limite pode ser do seu computador ou da sua internet, não da API: rode de uma máquina perto da VPS para confirmar)")
}

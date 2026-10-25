package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// setupLoad lê as opções comuns, confere a URL e a sessão e monta o requester.
func setupLoad(ctx context.Context, o *options, routes *routeList, body string, conns int) (*requester, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}
	if err := o.guardLoad(); err != nil {
		return nil, err
	}
	client := newClient(o, conns, true)
	if err := o.ping(ctx, client); err != nil {
		return nil, err
	}
	token, err := o.session(ctx, client)
	if err != nil {
		return nil, err
	}
	rq := &requester{client: client, base: o.baseURL, token: token, device: o.device}
	if err := o.checkToken(ctx, rq); err != nil {
		return nil, err
	}
	if len(*routes) == 0 {
		*routes = defaultRoutes(token)
	}
	if body != "" {
		for i := range *routes {
			(*routes)[i].Body = []byte(body)
		}
	}
	return rq, nil
}

// progress mostra a contagem a cada segundo até ctx acabar.
func progress(ctx context.Context, rec *recorder, label func() string) func() {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		last, start := 0, time.Now()
		for {
			select {
			case <-done:
				fmt.Fprint(os.Stderr, "\r\033[K")
				return
			case <-ticker.C:
				n := rec.count()
				fmt.Fprintf(os.Stderr, "\r\033[K  %s %5.0fs  %d requisições  %d/s", label(), time.Since(start).Seconds(), n, n-last)
				last = n
			}
		}
	}()
	return func() { close(done) }
}

// ---- clientes: N clientes fazendo requisições em sequência, sem parar ----

type clientsResult struct {
	Routes   []target `json:"rotas"`
	Clients  int      `json:"clientes"`
	Ramp     string   `json:"rampa"`
	Think    string   `json:"pausa"`
	Summary  summary  `json:"resumo"`
	Blocked  bool     `json:"ip_bloqueado,omitempty"`
	Location string   `json:"url"`
}

func cmdClients(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("clientes", flag.ContinueOnError)
	var o options
	o.register(fs)
	var routes routeList
	fs.Var(&routes, "rota", "rota a chamar, pode repetir: \"GET /v1/me\" (padrão /healthz, ou GET /v1/me com sessão)")
	clients := fs.Int("clientes", 50, "clientes simultâneos")
	duration := fs.Duration("duracao", 30*time.Second, "quanto tempo dura")
	total := fs.Int("n", 0, "para depois de N requisições (0 = só pelo tempo)")
	ramp := fs.Duration("rampa", 0, "tempo para todos os clientes entrarem (0 = todos de uma vez)")
	think := fs.Duration("pausa", 0, "pausa de cada cliente entre uma requisição e outra")
	body := fs.String("corpo", "", "corpo JSON para as rotas (POST/PUT/PATCH)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *clients < 1 {
		return errors.New("-clientes precisa ser 1 ou mais")
	}
	rq, err := setupLoad(ctx, &o, &routes, *body, *clients)
	if err != nil {
		return err
	}
	res, err := runClients(ctx, rq, routes, *clients, *duration, *total, *ramp, *think)
	if err != nil {
		return err
	}
	res.Location = o.baseURL
	return writeJSON(o.jsonOut, res)
}

func runClients(ctx context.Context, rq *requester, routes []target, clients int, duration time.Duration, total int, ramp, think time.Duration) (clientsResult, error) {
	fmt.Printf("Clientes simultâneos: %d em %s · %s · rotas: %s\n", clients, rq.base, duration, (*routeList)(&routes).String())
	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()

	rec := newRecorder()
	var active atomic.Int64
	var sent atomic.Int64
	stop := progress(ctx, rec, func() string { return fmt.Sprintf("[%d clientes]", active.Load()) })

	start := time.Now()
	var wg sync.WaitGroup
	for i := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ramp > 0 {
				select {
				case <-time.After(ramp * time.Duration(i) / time.Duration(clients)):
				case <-ctx.Done():
					return
				}
			}
			active.Add(1)
			defer active.Add(-1)
			for n := i; ctx.Err() == nil; n++ {
				// sem cancelar o ctx: as que estão em andamento ainda contam
				if total > 0 && sent.Add(1) > int64(total) {
					return
				}
				res := rq.do(ctx, routes[n%len(routes)])
				if res.err != nil && ctx.Err() != nil {
					return // cortada pelo fim do teste, não conta
				}
				rec.add(res)
				if res.status == 429 {
					cancel()
					return
				}
				if think > 0 {
					select {
					case <-time.After(think):
					case <-ctx.Done():
					}
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	stop()

	s := rec.summary(elapsed)
	s.print(fmt.Sprintf("Resultado: %d clientes simultâneos", clients))
	res := clientsResult{Routes: routes, Clients: clients, Ramp: ramp.String(), Think: think.String(), Summary: s, Blocked: rec.isBlocked()}
	if res.Blocked {
		fmt.Println("\n  ⚠ A API respondeu 429: o IP foi bloqueado e o teste parou. Libere com: idsyctl ip unblock -ip SEU_IP")
	}
	return res, nil
}

// ---- rps: taxa fixa de chegada, independente de quanto a API demora ----

type rpsStep struct {
	Target   int     `json:"rps_alvo"`
	Achieved float64 `json:"rps_atingido"`
	Dropped  int64   `json:"descartadas"`
	Summary  summary `json:"resumo"`
	Saturado bool    `json:"saturado"`
}

type rpsResult struct {
	Routes   []target  `json:"rotas"`
	Steps    []rpsStep `json:"etapas"`
	Location string    `json:"url"`
}

func cmdRPS(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("rps", flag.ContinueOnError)
	var o options
	o.register(fs)
	var routes routeList
	fs.Var(&routes, "rota", "rota a chamar, pode repetir: \"GET /v1/me\" (padrão /healthz, ou GET /v1/me com sessão)")
	rates := fs.String("rps", "50,100,200,400", "requisições por segundo; com vírgulas, uma etapa para cada")
	duration := fs.Duration("duracao", 20*time.Second, "duração de cada etapa")
	maxOpen := fs.Int("max-abertas", 1000, "máximo de requisições em andamento; acima disso descarta")
	stopAt := fs.Float64("parar", 0.10, "para as etapas seguintes quando a taxa de erro passa disso (0 a 1)")
	body := fs.String("corpo", "", "corpo JSON para as rotas (POST/PUT/PATCH)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	steps, err := parseRates(*rates)
	if err != nil {
		return err
	}
	rq, err := setupLoad(ctx, &o, &routes, *body, *maxOpen)
	if err != nil {
		return err
	}
	res := runRPS(ctx, rq, routes, steps, *duration, *maxOpen, *stopAt)
	res.Location = o.baseURL
	return writeJSON(o.jsonOut, res)
}

func parseRates(s string) ([]int, error) {
	var rates []int
	for _, part := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || n < 1 {
			return nil, fmt.Errorf("-rps inválido: %q (use 100 ou 50,100,200)", s)
		}
		rates = append(rates, n)
	}
	return rates, nil
}

func runRPS(ctx context.Context, rq *requester, routes []target, rates []int, duration time.Duration, maxOpen int, stopAt float64) rpsResult {
	fmt.Printf("Requisições por segundo em %s · etapas de %s: %v · rotas: %s\n", rq.base, duration, rates, (*routeList)(&routes).String())
	res := rpsResult{Routes: routes}
	for _, rate := range rates {
		if ctx.Err() != nil {
			break
		}
		step, blocked := rpsStepRun(ctx, rq, routes, rate, duration, maxOpen)
		res.Steps = append(res.Steps, step)
		if blocked {
			fmt.Println("\n  ⚠ A API respondeu 429: o IP foi bloqueado e o teste parou. Libere com: idsyctl ip unblock -ip SEU_IP")
			break
		}
		if step.Summary.ErrorRate > stopAt {
			fmt.Printf("\n  Taxa de erro %.1f%% passou de %.1f%%: as etapas seguintes não rodam.\n", step.Summary.ErrorRate*100, stopAt*100)
			break
		}
	}
	printRPSTable(res.Steps)
	return res
}

func rpsStepRun(parent context.Context, rq *requester, routes []target, rate int, duration time.Duration, maxOpen int) (rpsStep, bool) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	rec := newRecorder()
	var dropped atomic.Int64
	sem := make(chan struct{}, maxOpen)
	stop := progress(ctx, rec, func() string { return fmt.Sprintf("[%d/s alvo, %d abertas]", rate, len(sem)) })

	// Agenda por relógio: a cada volta dispara todas as que já venceram. Assim a
	// taxa não depende da precisão do sleep (que no Windows chega a 1 ms ou mais).
	interval := time.Second / time.Duration(rate)
	var wg sync.WaitGroup
	start := time.Now()
	fired := 0
loop:
	for {
		elapsed := time.Since(start)
		if elapsed >= duration || ctx.Err() != nil || rec.isBlocked() {
			break
		}
		due := int(elapsed/interval) + 1
		for ; fired < due; fired++ {
			select {
			case sem <- struct{}{}:
			default:
				dropped.Add(1)
				continue
			}
			wg.Add(1)
			go func(t target) {
				defer wg.Done()
				defer func() { <-sem }()
				res := rq.do(ctx, t)
				if res.err != nil && ctx.Err() != nil {
					return
				}
				rec.add(res)
			}(routes[fired%len(routes)])
		}
		wait := time.Until(start.Add(time.Duration(fired) * interval))
		select {
		case <-time.After(max(wait, 200*time.Microsecond)):
		case <-ctx.Done():
			break loop
		}
	}
	// espera as que ainda estão em andamento (cada uma tem o -timeout)
	wg.Wait()
	elapsed := time.Since(start)
	stop()

	s := rec.summary(elapsed)
	step := rpsStep{Target: rate, Achieved: s.RPS, Dropped: dropped.Load(), Summary: s}
	step.Saturado = s.RPS < 0.95*float64(rate) || step.Dropped > 0 || s.ErrorRate > 0.01
	s.print(fmt.Sprintf("Etapa: %d req/s", rate))
	if step.Dropped > 0 {
		fmt.Printf("  descartadas %d (já havia %d em andamento)\n", step.Dropped, maxOpen)
	}
	return step, rec.isBlocked()
}

func printRPSTable(steps []rpsStep) {
	if len(steps) == 0 {
		return
	}
	fmt.Printf("\nResumo por etapa\n────────────────\n")
	fmt.Printf("  %8s %10s %8s %9s %9s %9s %11s\n", "alvo/s", "atingido/s", "erro %", "p50 ms", "p95 ms", "p99 ms", "")
	for _, st := range steps {
		flagText := "ok"
		if st.Saturado {
			flagText = "⚠ saturou"
		}
		l := st.Summary.Latency
		fmt.Printf("  %8d %10.1f %8.2f %9.1f %9.1f %9.1f %11s\n", st.Target, st.Achieved, st.Summary.ErrorRate*100, l.P50, l.P95, l.P99, flagText)
	}
	fmt.Println("  (saturou = não atingiu 95% do alvo, descartou requisições ou passou de 1% de erro)")
}

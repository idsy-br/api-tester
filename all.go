package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"
)

type allResult struct {
	Security *securityResult `json:"seguranca,omitempty"`
	Latency  *latencyResult  `json:"latencia,omitempty"`
	Clients  *clientsResult  `json:"clientes,omitempty"`
	RPS      *rpsResult      `json:"rps,omitempty"`
}

// cmdAll roda os quatro testes em sequência, com valores moderados.
func cmdAll(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("tudo", flag.ContinueOnError)
	var o options
	o.register(fs)
	var routes routeList
	fs.Var(&routes, "rota", "rota para latência e carga, pode repetir (padrão /healthz, ou GET /v1/me com sessão)")
	clients := fs.Int("clientes", 25, "clientes simultâneos")
	rates := fs.String("rps", "50,100,200", "etapas de requisições por segundo")
	duration := fs.Duration("duracao", 15*time.Second, "duração da carga de clientes e de cada etapa de rps")
	n := fs.Int("n", 100, "requisições por rota na latência")
	budget := fs.Int("max-recusas", 5, "máximo de recusas que os testes de segurança podem gastar")
	if err := fs.Parse(args); err != nil {
		return err
	}
	steps, err := parseRates(*rates)
	if err != nil {
		return err
	}
	if err := o.validate(); err != nil {
		return err
	}
	if err := o.guardLoad(); err != nil {
		return err
	}
	// entra uma vez só e usa a mesma sessão em tudo
	pc := newClient(&o, 1, true)
	if err := o.ping(ctx, pc); err != nil {
		return err
	}
	token, err := o.session(ctx, pc)
	if err != nil {
		return err
	}
	o.token = token

	var res allResult
	banner("1/4 Segurança")
	sec, err := runSecurity(ctx, &o, *budget, "", false, false)
	if err != nil {
		return err
	}
	res.Security = &sec

	banner("2/4 Tempo de resposta")
	lclient := newClient(&o, 1, true)
	lrq := &requester{client: lclient, base: o.baseURL, token: token, device: o.device}
	if err := o.checkToken(ctx, lrq); err != nil {
		return err
	}
	lroutes := []target(routes)
	if len(lroutes) == 0 {
		lroutes = latencyDefaults(token)
	}
	lat, _ := runLatency(ctx, lrq, lroutes, *n, 5, 0, 0)
	res.Latency = &lat

	if len(routes) == 0 {
		routes = defaultRoutes(token)
	}
	banner("3/4 Clientes simultâneos")
	crq := &requester{client: newClient(&o, *clients, true), base: o.baseURL, token: token, device: o.device}
	cl, err := runClients(ctx, crq, routes, *clients, *duration, 0, 0, 0)
	if err != nil {
		return err
	}
	res.Clients = &cl

	if !cl.Blocked && ctx.Err() == nil {
		banner("4/4 Requisições por segundo")
		rrq := &requester{client: newClient(&o, 1000, true), base: o.baseURL, token: token, device: o.device}
		r := runRPS(ctx, rrq, routes, steps, *duration, 1000, 0.10)
		res.RPS = &r
	}

	if err := writeJSON(o.jsonOut, res); err != nil {
		return err
	}
	if sec.Totals[string(fail)] > 0 {
		return errFindings
	}
	return nil
}

func banner(title string) {
	fmt.Printf("\n\n%s\n%s\n", strings.ToUpper(title), strings.Repeat("═", len([]rune(title))))
}

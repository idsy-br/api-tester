package main

import (
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// report junta o que rodou na sessão para gerar o relatório HTML. O HTML tem um
// botão de imprimir: "Salvar como PDF" do navegador vira o PDF.
type report struct {
	Company  string // empresa que faz o teste
	Tester   string // quem está fazendo o teste
	URL      string
	User     string
	Team     string
	Started  time.Time
	Security []*securityResult
	Stress   []*stressResult
	Latency  []namedLatency
}

type namedLatency struct {
	Label  string
	Result *latencyResult
}

func (r *report) empty() bool {
	return len(r.Security) == 0 && len(r.Stress) == 0 && len(r.Latency) == 0
}

// write grava o relatório na pasta atual e devolve o caminho completo.
func (r *report) write() (string, error) {
	name := "relatorio-" + time.Now().Format("2006-01-02-150405") + ".html"
	path, err := filepath.Abs(name)
	if err != nil {
		return "", err
	}
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if err := reportTemplate.Execute(f, r); err != nil {
		return "", err
	}
	return path, nil
}

// openFile abre o relatório no navegador padrão.
func openFile(path string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", path)
	case "darwin":
		cmd = exec.Command("open", path)
	default:
		cmd = exec.Command("xdg-open", path)
	}
	_ = cmd.Start()
}

// stressChart desenha as etapas: barra com o atingido (vermelha quando passou do
// limite) e o p95 escrito em cima.
func stressChart(res *stressResult) template.HTML {
	if len(res.Steps) == 0 {
		return ""
	}
	const width, height, pad = 720, 260, 36
	maxRPS := 1.0
	for _, s := range res.Steps {
		maxRPS = max(maxRPS, float64(s.Target), s.Achieved)
	}
	slot := float64(width-2*pad) / float64(len(res.Steps))
	bar := slot * 0.6
	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %d %d" class="chart" role="img" aria-label="Requisições por segundo por etapa">`, width, height)
	base := float64(height - pad)
	fmt.Fprintf(&b, `<line x1="%d" y1="%.0f" x2="%d" y2="%.0f" class="axis"/>`, pad, base, width-pad, base)
	for i, s := range res.Steps {
		x := float64(pad) + slot*float64(i) + (slot-bar)/2
		hTarget := (float64(s.Target) / maxRPS) * (base - 30)
		hGot := (s.Achieved / maxRPS) * (base - 30)
		class := "ok"
		if res.BreakRPS == s.Target && i == len(res.Steps)-1 {
			class = "bad"
		}
		fmt.Fprintf(&b, `<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" class="target"/>`, x, base-hTarget, bar, hTarget)
		fmt.Fprintf(&b, `<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" class="%s"><title>%d alvo · %.0f atingido · p95 %.0f ms</title></rect>`,
			x, base-hGot, bar, hGot, class, s.Target, s.Achieved, s.Summary.Latency.P95)
		fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" class="lbl">%.0f ms</text>`, x+bar/2, base-hTarget-6, s.Summary.Latency.P95)
		fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" class="lbl">%d/s</text>`, x+bar/2, base+16, s.Target)
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String()) //nolint:gosec // números gerados aqui
}

var reportTemplate = template.Must(template.New("r").Funcs(template.FuncMap{
	"pct":   func(f float64) string { return fmt.Sprintf("%.2f%%", f*100) },
	"num":   func(f float64) string { return fmt.Sprintf("%.1f", f) },
	"int":   func(f float64) string { return fmt.Sprintf("%.0f", f) },
	"chart": stressChart,
	"date":  func(t time.Time) string { return t.Format("02/01/2006 15:04") },
	"now":   func() string { return time.Now().Format("02/01/2006 15:04") },
	"cls": func(v verdict) string {
		return map[verdict]string{pass: "ok", fail: "bad", warn: "warn", skip: "skip"}[v]
	},
	"counts": formatCounts,
}).Parse(`<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Relatório da API</title>
<style>
:root{--bg:#fff;--fg:#1d1d1f;--mut:#6b6b70;--line:#e3e3e6;--ok:#1a7f4b;--bad:#c62828;--warn:#b26a00;--bar:#3b6fd8;--target:#dfe6f6}
@media (prefers-color-scheme:dark){:root{--bg:#141416;--fg:#ececf0;--mut:#9a9aa2;--line:#2c2c31;--ok:#4cc38a;--bad:#ff6b6b;--warn:#ffb347;--bar:#6d97ff;--target:#26304a}}
body{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,Segoe UI,sans-serif;margin:0;padding:24px 16px}
main{max-width:960px;margin:auto}h1{margin:0 0 4px}h2{margin-top:36px;border-bottom:1px solid var(--line);padding-bottom:6px}
.meta{color:var(--mut)}.by{margin:4px 0}table{border-collapse:collapse;width:100%;margin:8px 0;font-variant-numeric:tabular-nums}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--mut);font-weight:600}
.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}.skip{color:var(--mut)}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin:12px 0}.card{border:1px solid var(--line);border-radius:10px;padding:10px 14px;min-width:150px}
.card b{display:block;font-size:22px}.wrap{overflow-x:auto}
.chart{width:100%;height:auto}.chart .axis{stroke:var(--line)}.chart .target{fill:var(--target)}.chart rect.ok{fill:var(--bar)}.chart rect.bad{fill:var(--bad)}
.chart .lbl{fill:var(--mut);font-size:11px;text-anchor:middle}
button{font:inherit;padding:6px 14px;border-radius:8px;border:1px solid var(--line);background:transparent;color:var(--fg);cursor:pointer}
@media print{button{display:none}body{padding:0}}
</style></head><body><main>
<h1>Relatório da API</h1>
{{if or .Company .Tester}}<p class="by">{{if .Company}}<b>Empresa:</b> {{.Company}}{{end}}{{if and .Company .Tester}} · {{end}}{{if .Tester}}<b>Responsável pelo teste:</b> {{.Tester}}{{end}}</p>{{end}}
<p class="meta">{{.URL}}{{if .User}} · {{.User}}{{end}}{{if .Team}} · team {{.Team}}{{end}} · gerado em {{now}}</p>
<button onclick="window.print()">Imprimir / salvar PDF</button>

{{range .Stress}}
<h2>Carga de requisições até o limite</h2>
<div class="cards">
<div class="card">Máximo aguentado<b>{{if .MaxHealthyRPS}}{{int .MaxHealthyRPS}} req/s{{else}}nenhuma etapa{{end}}</b></div>
{{if .BreakRPS}}<div class="card">Limite em<b class="bad">{{.BreakRPS}} req/s</b></div>
<div class="card">Recuperação<b class="{{if .Recovered}}ok{{else}}bad{{end}}">{{if .Recovered}}{{int .RecoverySeconds}} s{{else}}não voltou{{end}}</b></div>{{end}}
</div>
<p><b>Parou porque:</b> {{.Reason}}.</p>
{{if .Removed}}<p class="warn">Rotas tiradas da carga porque não responderam com sucesso antes de começar: {{range $i, $r := .Removed}}{{if $i}}; {{end}}{{$r}}{{end}}.</p>{{end}}
<div class="wrap">{{chart .}}</div>
<div class="wrap"><table><tr><th>alvo/s</th><th>atingido/s</th><th>erro</th><th>p50 ms</th><th>p95 ms</th><th>p99 ms</th><th>descartadas</th><th>status e erros</th></tr>
{{range .Steps}}<tr><td>{{.Target}}</td><td>{{num .Achieved}}</td><td>{{pct .Summary.ErrorRate}}</td><td>{{num .Summary.Latency.P50}}</td><td>{{num .Summary.Latency.P95}}</td><td>{{num .Summary.Latency.P99}}</td><td>{{.Dropped}}</td><td>{{counts .Summary.Status}}{{if .Summary.Errors}} · {{counts .Summary.Errors}}{{end}}</td></tr>
{{end}}</table></div>
<p class="meta">Etapas de {{.Config.StepText}}, começando em {{.Config.Start}} req/s e multiplicando por {{.Config.Factor}}. Rotas: {{range $i, $r := .Routes}}{{if $i}}, {{end}}{{$r.Method}} {{$r.Path}}{{end}}. O limite pode ser do computador ou da internet de onde o teste rodou.</p>
{{end}}

{{range .Latency}}
<h2>Tempo de resposta · {{.Label}}</h2>
<div class="wrap"><table><tr><th>rota</th><th>média ms</th><th>p50</th><th>p95</th><th>p99</th><th>máx</th><th>servidor p50</th><th>status</th></tr>
{{range .Result.Routes}}<tr><td>{{.Route}}</td><td>{{num .Total.Mean}}</td><td>{{num .Total.P50}}</td><td>{{num .Total.P95}}</td><td>{{num .Total.P99}}</td><td>{{num .Total.Max}}</td><td>{{num .Server.P50}}</td><td>{{counts .Status}}</td></tr>
{{end}}</table></div>
{{end}}

{{range .Security}}
<h2>Segurança</h2>
<div class="cards">
<div class="card">OK<b class="ok">{{index .Totals "OK"}}</b></div>
<div class="card">Falhas<b class="bad">{{index .Totals "FALHA"}}</b></div>
<div class="card">Avisos<b class="warn">{{index .Totals "AVISO"}}</b></div>
<div class="card">Pulados<b class="skip">{{index .Totals "PULADO"}}</b></div>
</div>
<div class="wrap"><table><tr><th>grupo</th><th>teste</th><th>resultado</th><th>detalhe</th></tr>
{{range .Findings}}<tr><td>{{.Group}}</td><td>{{.Name}}</td><td class="{{cls .Result}}">{{.Result}}</td><td>{{.Detail}}</td></tr>
{{end}}</table></div>
<p class="meta">{{.Refusals}} recusa(s) gasta(s) no firewall da API (20 em 24 horas bloqueiam o IP).</p>
{{end}}
</main></body></html>
`))

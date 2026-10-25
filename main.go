// Command apitester testa a API da Idsy: segurança, carga de requisições até o
// limite, carga de clientes simultâneos e tempo de resposta.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
)

const uso = `apitester: testes da API da Idsy

Sem comando (duplo clique), abre o menu: pergunta a API e o login e mostra os testes.

Uso:
  apitester <comando> [opções]

Comandos:
  limite      sobe as requisições por segundo até a API parar de responder
  seguranca   cabeçalhos, autenticação, CORS, entrada inválida, TLS, timeouts
  latencia    tempo de resposta em série: média, p50/p95/p99 e fases (DNS, conexão, TLS, servidor)
  clientes    N clientes simultâneos fazendo requisições sem parar
  rps         taxa fixa de requisições por segundo (uma ou várias etapas)
  tudo        segurança, latência, clientes e rps com valores moderados

Cada comando aceita -h para ver as opções. As principais valem para todos:
  -url      endereço da API (IDSY_URL, padrão http://localhost:8090)
  -token    sessão pronta, idsy_... (IDSY_TOKEN)
  -team, -login  para o programa entrar sozinho (IDSY_TEAM, IDSY_LOGIN; senha em IDSY_PASSWORD)
  -json     grava o resultado em um arquivo JSON
`

func main() {
	// sem comando é quase sempre duplo clique: abre o menu e segura a janela aberta
	if len(os.Args) < 2 {
		runInteractive()
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	name := os.Args[1]
	run, ok := commands[name]
	if !ok {
		if name != "-h" && name != "--help" && name != "help" {
			fmt.Fprintf(os.Stderr, "comando desconhecido: %s\n\n", name)
		}
		fmt.Fprint(os.Stderr, uso)
		os.Exit(2)
	}
	err := run(ctx, os.Args[2:])
	switch {
	case err == nil:
	case errors.Is(err, flag.ErrHelp):
		os.Exit(2)
	case errors.Is(err, errFindings):
		os.Exit(1)
	default:
		fmt.Fprintln(os.Stderr, "erro:", err)
		os.Exit(1)
	}
}

var commands = map[string]func(context.Context, []string) error{
	"limite":    cmdStress,
	"seguranca": cmdSecurity,
	"clientes":  cmdClients,
	"rps":       cmdRPS,
	"latencia":  cmdLatency,
	"tudo":      cmdAll,
}

// errFindings sai com código 1 sem repetir a mensagem: o relatório já mostrou o que falhou.
var errFindings = errors.New("há testes com falha")

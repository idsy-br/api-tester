# Idsy API Tester

Programa em Go para testar a API da Idsy antes de ir para produção: carga de
requisições até a API parar de responder, verificação de segurança e tempo de
resposta (média, p50, p95, p99). No fim, gera um relatório HTML que vira PDF pelo
navegador.

> **Teste só a API da Idsy, e só antes de ela entrar em produção.** A carga vai até
> a API parar de responder: quem estiver usando fica sem ela durante o teste.

## Instalar

Precisa do Go 1.24 ou mais novo.

```powershell
git clone https://github.com/idsy-br/api-tester.git
cd api-tester
go build -o apitester.exe .
```

## Usar (menu)

Abra o `apitester.exe` com duplo clique, ou rode `.\apitester.exe` no terminal sem
nenhum comando. O programa pergunta, nesta ordem:

1. **Empresa** e **Responsável pelo teste**: saem no topo do relatório.
2. **Endereço da API**, por exemplo `https://api-v3.idsy.com.br`. Se a API não
   responder, ele avisa na hora.
3. **Team**, **Login** e **Senha** (a senha não aparece na tela). O team é o slug
   (`control`, não "Control"); o login é o nome de usuário, não o e-mail. Com dois
   fatores, ele pede o código do e-mail ou do aplicativo. Deixando o login em branco,
   os testes ficam só nas rotas públicas.

Conectado, aparece o menu:

| Opção | O que faz |
|---|---|
| 1 Carga até o limite | Começa numa taxa (padrão 50 req/s) e multiplica por 1,5 a cada etapa (padrão 15 s) até a API não dar conta. Mostra o máximo que ela aguentou, onde parou e quanto tempo levou para voltar. |
| 2 Segurança | HTTPS e TLS, cabeçalhos, rotas protegidas sem login, token mal formado, CORS, JSON inválido, cabeçalho gigante, conexão lenta (slowloris), injeção de SQL no login. |
| 3 Tempo de resposta | Requisições uma de cada vez em `/healthz`, `/readyz` e `/v1/me`: média, p50, p95, p99 e o tempo só do servidor. |
| 4 Testar tudo | Segurança, tempo de resposta antes, carga até o limite e tempo de resposta depois da carga. |
| 5 Gerar relatório | Grava `relatorio-AAAA-MM-DD-HHMMSS.html` na pasta de onde o programa rodou e abre no navegador. O botão "Imprimir / salvar PDF" gera o PDF. |
| 6 Limpar os resultados | Começa um relatório novo. Ao repetir um teste, o programa também pergunta se quer limpar os anteriores. |
| 0 Sair | Oferece gerar o relatório antes de sair. |

Ctrl+C interrompe o teste em andamento e volta ao menu.

### Carga até o limite

- **Rotas**: o padrão é `GET /v1/me` com login (passa pela sessão e pelo banco) ou
  `GET /healthz` sem login. Dá para informar outras, separadas por vírgula:
  `GET /v1/teams, GET /v1/timeline`.
- Antes de começar, cada rota é chamada uma vez. As que respondem erro (404 de id que
  não existe, 403 sem permissão) ficam fora da carga, com aviso no relatório.
- Uma etapa passa do limite quando há mais de 5% de erro de sobrecarga (tempo
  esgotado, conexão recusada, 5xx), quando o p95 passa do limite pedido (padrão
  1000 ms) ou quando a API não responde 90% da taxa pedida.
- O limite pode ser do computador ou da internet de quem roda o teste, e não da API.
  Para confirmar, rode o testador de uma máquina perto da VPS.

## Cuidado com o firewall da API

A API conta como **recusa** cada senha, código ou token errado, e **20 recusas do
mesmo IP em 24 horas bloqueiam o IP para tudo**.

- Senha errada no início do programa também conta.
- A verificação de segurança gasta no máximo 5 recusas (token inexistente e
  injeção de SQL no login). O resto foi montado para não gastar nenhuma.
- A carga confere a sessão antes de começar e para no primeiro 429 (IP bloqueado).

Para liberar um IP, no servidor da API: `idsyctl ip unblock -ip IP`.

O testador manda sempre o mesmo `X-Device` (guardado em
`%AppData%\idsy-apitester\device`). Se o team tiver firewall por dispositivo e o
login for recusado por isso, o programa mostra o identificador para cadastrar no
painel.

## Linha de comando

Para scripts e CI, cada teste também roda direto. `apitester <comando> -h` mostra
as opções.

| Comando | O que faz |
|---|---|
| `limite` | carga até o limite (`-inicio`, `-fator`, `-duracao`, `-limite-erro`, `-limite-p95`, `-teto`) |
| `seguranca` | verificação de segurança (`-max-recusas`, `-origem`, `-testar-logout`, `-forca-bruta`) |
| `latencia` | tempo de resposta (`-n`, `-nova-conexao`, `-limite-p95`) |
| `clientes` | N clientes simultâneos fazendo requisições sem parar |
| `rps` | taxa fixa de requisições por segundo, em uma ou várias etapas |
| `tudo` | segurança, latência, clientes e rps com valores moderados |

Opções comuns: `-url` (ou `IDSY_URL`), `-token` (ou `IDSY_TOKEN`), `-team` e
`-login` (ou `IDSY_TEAM`, `IDSY_LOGIN`; a senha vem de `IDSY_PASSWORD` ou é
perguntada), `-json arquivo.json` para gravar o resultado. Carga contra um endereço
que não é local exige `-sim`. O código de saída é 1 quando há falha de segurança.

```powershell
.\apitester.exe seguranca -url https://api-v3.idsy.com.br -origem https://app.idsy.com.br
.\apitester.exe latencia -url https://api-v3.idsy.com.br -nova-conexao -limite-p95 300
.\apitester.exe limite -url https://api-v3.idsy.com.br -team control -login seu.login -sim
```

`-forca-bruta` confere que o bloqueio funciona e, de propósito, **bloqueia o seu IP
por 24 horas**.

## Variáveis de ambiente

Todas são opcionais e só preenchem as perguntas do menu.

| Variável | Para quê |
|---|---|
| `IDSY_EMPRESA`, `IDSY_RESPONSAVEL` | empresa e responsável do relatório |
| `IDSY_URL`, `IDSY_TEAM`, `IDSY_LOGIN` | endereço, team e login |
| `IDSY_PASSWORD` | senha (prefira digitar: a variável fica no ambiente) |
| `IDSY_TOKEN` | sessão pronta, `idsy_...` |

## Observações

- Os relatórios gerados têm o endereço da API, o usuário e os resultados, e ficam
  fora do git (`.gitignore`).
- No Git Bash, rotas como `-rota /healthz` viram caminho do Windows; rode no
  PowerShell ou com `MSYS_NO_PATHCONV=1`.
- No Windows os tempos usam o `QueryPerformanceCounter`: o relógio do Go anda em
  passos de ~0,5 ms e zeraria a latência de uma API local.

## Desenvolvimento

```sh
go test ./...
```

Os testes sobem uma API falsa em memória; não precisam da API de verdade.

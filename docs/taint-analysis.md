# Taint Analysis

O motor de PII diz **o que** é sensível. O Taint Analysis acompanha **por onde** esse dado passa e decide se ele pode chegar a cada destino. A decisão não depende de procurar palavras no destino: o dado carrega desde a origem a informação de que é sensível.

## Como o dado fica contaminado

- **Campo rotulado.** Propriedades de DTO marcadas com `[Sensitive(DataCategory.X)]` (CPF, e-mail, endereço, origem, destino e coordenadas do trajeto) viram `Tainted<string>` assim que o serviço chama `TaintAnnotatedFields`.
- **Detecção no conteúdo.** Texto livre (local e descrição de ocorrência, argumentos de log, prompt da IA) passa por `TaintByContent`, que usa o motor de PII. O valor recebe a categoria da detecção mais grave e guarda todas as categorias encontradas. Candidatos inválidos, como um CPF com dígitos errados, não contaminam.

## `Tainted<T>`

- O valor bruto é `internal`. O código da aplicação só recebe o dado de volta por `SinkResult.ReleasedValue`, depois da decisão da política, ou por `RevealAsync`, que exige ator autorizado, finalidade igual à do contexto e grava auditoria.
- `ToString()` devolve `[TAINTED:Categoria]`, para que uma interpolação acidental não vaze o valor.
- `Propagate` mantém a contaminação numa transformação e registra o passo no histórico.
- `Combine` (e o atalho `Concat`) junta valores: o resultado herda a maior sensibilidade e reúne categorias e históricos. "Texto público + CPF" continua sendo tratado como CPF.
- `Sanitize` marca o valor como sanitizado. Mesmo assim, antes de liberar, o rastreador varre o texto de novo e só libera direto se nada for encontrado.

## Destinos (sinks)

`Log`, `PublicHttpResponse`, `InternalHttpResponse`, `ExternalAiService`, `Report`, `Export` e `Database`.

## Política

| Categoria | Log | Resposta pública | Resposta interna | IA externa | Relatório / Export | Banco |
|---|---|---|---|---|---|---|
| Credencial | Bloqueia | Bloqueia | Bloqueia | Bloqueia | Bloqueia | Bloqueia |
| Dado pessoal | Mascara | Mascara | Libera com autorização e finalidade; senão bloqueia | Mascara | Mascara | Libera (gravado cifrado) |
| Localização | Mascara | Mascara | Libera com autorização e finalidade; senão bloqueia | Mascara | Mascara | Libera (gravado cifrado) |
| Saúde | Bloqueia | Bloqueia | Libera só com autorização e finalidade de saúde | Bloqueia | Bloqueia | Bloqueia |
| Nenhuma | Libera | Libera | Libera | Libera | Libera | Libera |

Autorização sem finalidade declarada não libera dado pessoal nem localização.

## Auditoria e incidentes

- Cada entrega de dado sensível gera um `AuditEvent` com fluxo, origem, destino, categoria, decisão e regra. O resumo cita apenas nomes de categoria e destino, nunca o valor.
- Entregas em lote viram um único evento por grupo de decisões iguais, com "Quantidade: N" no resumo.
- Bloqueios e mascaramentos geram também um `SecurityIncident`, que alimenta o Risco Cidadão. A exceção são saídas de rotina (`IsRoutineOutput`), como a resposta pública com CPF mascarado: elas são auditadas, mas não inflam o indicador, porque nada vazou.

## Onde o rastreador é usado

| Fluxo | O que acontece |
|---|---|
| Cadastro e consulta de cidadão ([CitizenService](../src/AlertaSP.Application/Services/CitizenService.cs)) | Campos rotulados → `Database` (liberado e cifrado) → `Log` (CPF mascarado) → `PublicHttpResponse` (mascarado). Entrada, gravação, log e resposta compartilham o mesmo FlowId. |
| Trajetos ([RouteService](../src/AlertaSP.Application/Services/RouteService.cs)) | Endereços e coordenadas rotulados como localização. Depois de liberados para o destino `Database`, são cifrados antes de gravar. A resposta pública omite o endereço e arredonda as coordenadas. |
| Consulta de risco do trajeto | As coordenadas exatas são lidas como uso interno autorizado (finalidade `RouteRiskAnalysis`), com decisão auditada. |
| Geração de alertas ([AlertService](../src/AlertaSP.Application/Services/AlertService.cs)) | Mesmo princípio, finalidade `RouteAlertGeneration`: é o cenário 4 do enunciado acontecendo no fluxo real. |
| Ocorrências ([FloodOccurrenceService](../src/AlertaSP.Application/Services/FloodOccurrenceService.cs)) | Local e descrição são públicos e vão ao destino `PublicHttpResponse` antes de gravar: credencial ou saúde fazem o cadastro ser recusado com 400 e geram incidente; CPF, e-mail e endereço são gravados mascarados. |
| Logs ([SecureLogger](../src/AlertaSP.Security/Logging/SecureLogger.cs)) | Cada argumento passa pelo destino `Log`; um valor bloqueado vira `[BLOQUEADO:Categoria]`. |
| Tradução por IA ([LlmRemediationService](../src/AlertaSP.Security/Remediation/LlmRemediationService.cs)) | O prompt passa pelo destino `ExternalAiService` antes de sair. |

## Cenários do enunciado

`POST /api/security/demo/scenarios` (só em `Development`, ou pelo botão do painel) executa os quatro cenários com o mesmo `TaintTracker` usado pela aplicação, com dados fictícios:

| Cenário | Origem → destino | Decisão |
|---|---|---|
| CPF enviado para o log | `/api/citizens` → `Log` | Mascara (`***.***.***-88`) e registra incidente |
| Endereço em resposta pública | `/api/routes` → `PublicHttpResponse` | Mascara (`[ENDEREÇO PROTEGIDO]`) e registra incidente |
| Credencial a caminho da IA externa | `/api/security/remediation` → `ExternalAiService` | Bloqueia e registra incidente crítico |
| Uso interno autorizado para gerar alerta | `/api/alerts/generate` → `InternalHttpResponse` | Libera e registra só auditoria |

A resposta mostra, para cada cenário, destino, categoria, decisão e o valor que seria liberado (nulo quando bloqueado).

## Limitações

- A herança por concatenação depende de o código usar `Combine`/`Concat`. Concatenar o valor bruto por fora do rastreador quebra o rastro.
- `IsRoutineOutput` é definido pelo serviço que chama o rastreador. Ele muda só a criação de incidente, nunca a decisão da política.
- `POST /api/security/analyze` é uma ferramenta de inspeção: mostra detecções e o texto mascarado, mas não move o dado para nenhum destino e por isso não gera auditoria.

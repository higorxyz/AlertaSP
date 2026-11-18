# Segurança do AlertaSP

O AlertaSP guarda CPF, e-mail, endereço e os trajetos diários de cada pessoa. Este documento descreve como esses dados são identificados, protegidos e auditados. O fluxo de contaminação (Taint Analysis) está em [taint-analysis.md](taint-analysis.md) e as ameaças consideradas em [threat-model.md](threat-model.md).

## Motor de detecção de PII

`PiiDetectionService` aplica todas as regras registradas como `IPiiRule` e devolve as detecções ordenadas pela posição no texto. Cada detecção traz categoria, regra, início, tamanho, sensibilidade, confiança e ação recomendada (`Mask`, `Redact` ou `Block`). Uma regra nova entra no motor só com o registro no contêiner de DI, sem mudar o serviço.

| Regra | Categoria | Como detecta |
|---|---|---|
| `CpfPiiRule` | Dado pessoal | `000.000.000-00` ou 11 dígitos seguidos, sem fazer parte de um número maior. Valida os dígitos verificadores e recusa sequências repetidas (`111.111.111-11`). Um número com formato de CPF mas dígitos errados volta como candidato com `IsValid = false` e confiança 0,35: não é tratado como CPF, não é mascarado e não gera bloqueio. |
| `EmailPiiRule` | Dado pessoal | Endereços de e-mail. |
| `CredentialsPiiRule` | Credencial | Pela estrutura, não pela palavra: pares chave/valor e JSON (`password`, `senha`, `access_token`, `api_key`, `client_secret` e outros), `Authorization: Bearer` e `Basic`, prefixos de token conhecidos (`sk-`, `ghp_`, `github_pat_`, `AKIA`, `xox`, `AIza`) e valores de alta entropia (Shannon ≥ 3,5 bits por caractere) atribuídos a chaves com nome de segredo. A palavra "senha" sozinha não é detecção. |
| `HealthDataPiiRule` | Saúde | Catálogo em [health-rules.json](../src/AlertaSP.Security/Pii/Rules/health-rules.json), trocável por `Pii:HealthRulesPath`. Cada frase recebe a soma dos pesos dos termos encontrados e só vira detecção ao chegar no limiar (4). Assim, "hospital" ou "diabetes" sozinhos não disparam, mas "paciente diagnosticado com diabetes" dispara. Termos marcados como críticos (HIV, câncer, laudo médico) elevam a sensibilidade. |
| `LocationPiiRule` | Localização | CEP (`00000-000`) e logradouro com número (`Rua Augusta, 1500`). |
| `CoordinatesPiiRule` | Localização | Pares latitude/longitude com 4 ou mais casas decimais (precisão de uns 11 m) dentro da faixa válida. |

Todas as expressões regulares têm tempo limite de 250 ms. Se uma regra estoura o tempo, o texto é tratado como sensível em vez de passar sem análise.

### Mascaramento

| Dado | Resultado |
|---|---|
| CPF | `***.***.***-25` (só os 2 últimos dígitos) |
| E-mail | `ma***@exemplo.com` |
| Endereço com bairro (`... - Bairro, Cidade - UF`) | `*** - Bairro, Cidade - UF` |
| Endereço sem essa estrutura, ou dentro de texto livre | `[ENDEREÇO PROTEGIDO]` |
| Coordenada em campo próprio | arredondada para 2 casas (cerca de 1 km) |
| Coordenada dentro de texto livre | `[COORDENADA PROTEGIDA]` |
| Senha ou token | `[REDACTED]` |
| Dado de saúde | `[DADO DE SAÚDE SUPRIMIDO]` |

Quando duas regras casam trechos que se sobrepõem (`api_key=sk-...`), os trechos são unidos e substituídos uma vez só, com a categoria mais sensível.

## Proteção em repouso

- CPF, e-mail e endereço do cidadão são gravados cifrados com a API de Data Protection do ASP.NET Core (`DataProtectionCryptoService`). Não há criptografia própria.
- Origem, destino e coordenadas dos trajetos também são gravados cifrados (`RouteLocationProtector`). Liberar o dado para o destino `Database` não basta: o serviço cifra antes de gravar. A localização só é decifrada em memória, para a resposta pública generalizada e para os usos internos autorizados (risco do trajeto e geração de alertas). Um teste de integração lê os bytes do arquivo SQLite e confirma que nenhum CPF, e-mail, endereço ou coordenada aparece em claro.
- A duplicidade de CPF é verificada por um HMAC-SHA256 do CPF normalizado, guardado numa coluna com índice único. Não é preciso decifrar os cadastros para comparar, e uma corrida entre dois cadastros iguais termina em 409, não em erro 500.
- A chave do HMAC (`Security:HmacSecret`) vem de configuração. As chaves do Data Protection ficam no perfil do usuário do Windows, cifradas com DPAPI, fora do banco: copiar o arquivo SQLite não basta para ler os dados. Elas persistem entre reinícios, e um teste de integração reinicia a API sobre o mesmo banco e confirma que cadastros e trajetos continuam legíveis. Em produção, com vários servidores, deveriam ficar num cofre de chaves compartilhado.

## Tradução de incidentes por IA

A IA só escreve a explicação para o cidadão. Bloquear ou mascarar é decidido antes, pela política, de forma determinística.

1. O prompt é montado só com descritores do incidente: categoria, destino, decisão e regra. O resumo interno e qualquer conteúdo original ficam de fora.
2. O prompt passa pelo `TaintTracker` com destino `ExternalAiService`, como qualquer dado que sai do sistema. Se o detector achar qualquer PII nele, o envio é cancelado.
3. O envio usa `IHttpClientFactory`, com timeout, cancelamento e novas tentativas apenas para falhas transitórias (408, 429 e 5xx).
4. A resposta é tratada como não confiável: até 1.000 caracteres, sem PII, sem links, sem blocos de código e sem pedidos para executar comandos. Marcação de markdown é removida.
5. Em qualquer falha (sem chave, sem rede, timeout, resposta recusada), entra o `DeterministicRemediationService`. O resultado sai sempre com `Origin = Fallback`, e o painel mostra "Texto de reserva", para não ser confundido com IA.

Os testes inspecionam o corpo HTTP que seria enviado ao modelo e verificam que nele não há CPF, senha nem o resumo interno.

## Indicador Risco Cidadão

Calculado sobre os incidentes da janela de análise (padrão de 7 dias):

```text
peso_i      = severidade_i × categoria_i × resultado_i
exposição   = Σ peso_i
Risco       = round(100 × (1 − e^(−exposição / K))),   K = 30
```

| Severidade | Peso | Categoria | Peso | Resultado | Peso |
|---|---:|---|---:|---|---:|
| Baixa | 1 | Dado pessoal | 1,2 | Bloqueado | 0,3 |
| Média | 2 | Localização | 1,0 | Mascarado | 0,5 |
| Alta | 4 | Saúde | 1,3 | Liberado com violação | 1,0 |
| Crítica | 8 | Credencial | 1,5 | | |

Sem incidentes, o risco é 0. Um incidente novo nunca reduz o valor dentro da janela, e o índice se aproxima de 100 sem passar. Faixas: 0 a 20 muito baixo, 21 a 40 baixo, 41 a 60 moderado, 61 a 80 alto, 81 a 100 crítico.

Como o sistema sempre bloqueia ou mascara, o resultado "liberado com violação" não ocorre hoje. O peso existe para que uma exposição real, se um dia for registrada, pese mais que uma tentativa barrada.

O indicador representa risco de exposição no ambiente monitorado, não uma previsão de que determinado cidadão sofrerá um incidente. O painel mostra esse aviso.

As contagens do painel saem de consultas agrupadas no banco (por categoria, sensibilidade, resultado, decisão e dia). Os dias do histórico seguem o horário de Brasília.

## Outros controles

- **Chave de API** nos endpoints `/api/security/*` (cabeçalho `X-Api-Key`), comparada em tempo constante.
- **Falha cedo:** a API não inicia sem `Security:ApiKey` e `Security:HmacSecret`, e valida as demais configurações na inicialização.
- **Erros** sempre em `application/problem+json`, sem stack trace; o `traceId` é o mesmo do cabeçalho `X-Correlation-ID`.
- **Cabeçalhos** `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` e `Referrer-Policy: no-referrer` em todas as respostas.
- **Correlação:** um `X-Correlation-ID` recebido só é aceito com até 64 caracteres seguros; caso contrário, outro é gerado.
- **Logs:** o código de negócio escreve pelo `ISecureLogger`, que passa cada valor pelo rastreador. Como segunda barreira, todo evento do Serilog passa pelo motor de PII antes de chegar ao console, inclusive a mensagem e o stack trace de exceções anexadas.
- **Painel:** todo texto vindo da API, inclusive a resposta da IA, é escapado antes de entrar no HTML.
- **SQL:** só consultas LINQ parametrizadas pelo EF Core.
- **Validação de entrada** por atributos nos DTOs e nos parâmetros (raio de 1 a 10.000 m, paginação de 1 a 100, severidade e status só com valores conhecidos).

## Configuração

| Chave | Obrigatória | Para quê |
|---|---|---|
| `Security:ApiKey` | Sim | Chave dos endpoints `/api/security/*`. |
| `Security:HmacSecret` | Sim | Chave do HMAC do CPF. |
| `Risk:NearbyRadiusMeters` | Não | Raio padrão de proximidade (500). |
| `Risk:CitizenRiskK`, `Risk:AnalysisWindowDays` | Não | K da fórmula (30) e janela em dias (7). |
| `Pii:HealthRulesPath` | Não | Catálogo de saúde alternativo. Um catálogo inválido impede a inicialização. |
| `AiRemediation:*` | Não | `Endpoint`, `ApiKey`, `Model`, `TimeoutSeconds`, `MaxAttempts`, `RetryDelayMs`, `MaxTokens`, `ReasoningEffort`. Sem `ApiKey`, usa o texto de reserva. |

Use variáveis de ambiente (`Security__ApiKey`) ou User Secrets. Nenhuma chave real fica no repositório.

# Modelo de ameaças

Ameaças organizadas pelas categorias STRIDE, com o controle que existe no código e o que fica de risco residual.

## Ativos

- **Dados pessoais:** CPF, e-mail e nome.
- **Localização:** endereço residencial e coordenadas de origem e destino dos trajetos, que revelam onde a pessoa mora e trabalha.
- **Segredos:** `Security:ApiKey`, `Security:HmacSecret`, chave do provedor de IA e chaves do Data Protection.
- **Trilha de auditoria e incidentes:** registro do que aconteceu com cada dado.

## Entradas e destinos

- **Entradas:** endpoints de cidadãos, trajetos, ocorrências e `/api/security/analyze`; resposta do provedor de IA.
- **Destinos sensíveis:** logs, respostas públicas da API, provedor de IA externo, banco de dados.

## Ameaças e controles

| STRIDE | Ameaça | Controle | Risco residual |
|---|---|---|---|
| Divulgação | CPF ou endereço em resposta da API | Taint Analysis com destino `PublicHttpResponse`: CPF e e-mail mascarados, endereço omitido, coordenadas arredondadas. | Nenhum conhecido. |
| Divulgação | CPF, senha ou dado de saúde em log | `ISecureLogger` passa cada valor pelo rastreador; o Serilog filtra todo evento pelo motor de PII, inclusive mensagens e stack traces de exceção. | Nenhum conhecido. |
| Divulgação | Dado pessoal no prompt enviado ao LLM | Prompt só com descritores; passa pelo rastreador com destino `ExternalAiService`; qualquer detecção cancela o envio. | Nenhum conhecido. |
| Divulgação | Banco copiado ou exposto | CPF, e-mail e endereço do cidadão, e origem, destino e coordenadas dos trajetos, cifrados com Data Protection; CPF comparado por HMAC; teste que lê o arquivo SQLite confirma que nada disso aparece em claro. | Chaves do Data Protection no perfil do usuário da máquina. |
| Divulgação | Segredos no código ou no painel | Nenhuma chave versionada; a API não sobe sem `ApiKey` e `HmacSecret`; o painel pede a chave a cada uso e não a guarda. | Depende do cuidado de quem configura a máquina. |
| Divulgação | Enumeração de cidadãos e trajetos | As listagens só devolvem dados mascarados e generalizados. | Sem autenticação de usuários, qualquer pessoa vê nomes e trajetos generalizados. |
| Adulteração | Injeção de SQL | Somente LINQ parametrizado pelo EF Core; nenhuma concatenação de SQL. | Nenhum conhecido. |
| Adulteração | Injeção de instruções pela resposta da IA ou XSS no painel | Resposta limitada a 1.000 caracteres e recusada se tiver PII, link, código ou comando; o painel escapa todo texto antes de exibir. | Um texto enganoso, mas inofensivo, ainda pode passar. |
| Adulteração | Dois cadastros simultâneos com o mesmo CPF | Índice único no hash do CPF; a violação vira 409. | Nenhum conhecido. |
| Falsificação | Ocorrências falsas para gerar alertas indevidos | Validação de entrada e marcação `IsDemo`. | Sem autenticação, qualquer pessoa pode registrar ocorrências. Em produção, só fontes confiáveis deveriam fazer isso. |
| Elevação de privilégio | Acesso ao painel e aos incidentes | Chave de API nos endpoints `/api/security/*`, comparada em tempo constante. | Chave única compartilhada, sem perfis de acesso. |
| Elevação de privilégio | Dado pessoal liberado em fluxo "interno" sem justificativa | A política exige ator autorizado e finalidade declarada para liberar em claro. | A finalidade é declarada pelo próprio código que chama o rastreador. |
| Elevação de privilégio | Endpoint de demonstração em produção | `POST /api/security/demo/scenarios` responde 404 fora de `Development`. | Nenhum conhecido. |
| Negação de serviço | ReDoS nas regras de PII | Tempo limite de 250 ms em todas as expressões; estouro é tratado como dado sensível. | Nenhum conhecido. |
| Negação de serviço | Requisições pesadas | Texto de até 20.000 caracteres em `/analyze`; raio de 1 a 10.000 m; páginas de até 100 itens; caixa delimitadora no banco antes do cálculo exato. | Não há limite de taxa por cliente. |
| Repúdio | Não saber o que aconteceu com um dado | Auditoria de cada decisão (origem, destino, categoria, decisão, regra), sem o valor; `X-Correlation-ID` em toda resposta e no `traceId` dos erros. | A trilha fica no mesmo banco da aplicação. |

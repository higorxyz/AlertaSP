# Endpoints

A documentação interativa fica em `http://localhost:5193/swagger`. Respostas em JSON; erros em `application/problem+json` (RFC 9457) com `traceId` igual ao cabeçalho `X-Correlation-ID`. Enums aparecem como texto (`"Alto"`, `"Resolvida"`) e também são aceitos assim na entrada.

Listagens aceitam `page` (a partir de 1) e `pageSize` (1 a 100) e devolvem `items`, `page`, `pageSize`, `totalCount`, `totalPages`, `hasNextPage` e `hasPreviousPage`. Parâmetros fora da faixa retornam 400.

Onde há `radiusMeters`, o valor vai de 1 a 10.000 m; sem ele, vale o padrão de 500 m (`Risk:NearbyRadiusMeters`).

## Cidadãos

| Método | Rota | Descrição | Respostas |
|---|---|---|---|
| POST | `/api/citizens` | Cadastra. Valida CPF pelos dígitos verificadores; grava CPF, e-mail e endereço cifrados. | 201, 400, 409 (CPF já cadastrado) |
| GET | `/api/citizens` | Lista com dados mascarados. | 200, 400 |
| GET | `/api/citizens/{id}` | Consulta com dados mascarados. | 200, 404 |
| PUT | `/api/citizens/{id}` | Atualiza nome, e-mail e endereço (o CPF não muda). | 200, 400, 404 |
| DELETE | `/api/citizens/{id}` | Remove o cidadão com seus trajetos e alertas. | 204, 404 |

## Trajetos

| Método | Rota | Descrição | Respostas |
|---|---|---|---|
| POST | `/api/routes` | Cadastra um trajeto já monitorado. A resposta omite o endereço e arredonda as coordenadas para 2 casas. | 201, 400, 404 (cidadão inexistente) |
| GET | `/api/routes` | Lista. | 200, 400 |
| GET | `/api/routes/{id}` | Consulta. | 200, 404 |
| GET | `/api/routes/citizen/{citizenId}` | Trajetos de um cidadão. | 200 |
| PUT | `/api/routes/{id}` | Atualiza nome, origem, destino e coordenadas. | 200, 400, 404 |
| PATCH | `/api/routes/{id}/monitoring` | Liga ou desliga o monitoramento: `{ "isActive": false }`. | 200, 404 |
| GET | `/api/routes/{id}/risk?radiusMeters=` | Ocorrências ativas perto do trajeto, da mais próxima para a mais distante, com recomendação por severidade. Sem ocorrências, a mensagem diz que não há registro, sem afirmar que o caminho é seguro. | 200, 400, 404 |
| DELETE | `/api/routes/{id}` | Remove o trajeto e seus alertas. | 204, 404 |

## Ocorrências de alagamento

| Método | Rota | Descrição | Respostas |
|---|---|---|---|
| POST | `/api/flood-occurrences` | Registra. Severidade: `Baixo`, `Moderado`, `Alto` ou `Critico`. Local e descrição passam pelo Taint Analysis: credencial ou dado de saúde recusam o cadastro; CPF, e-mail e endereço são gravados mascarados. | 201, 400 |
| GET | `/api/flood-occurrences?severity=&status=` | Lista com filtros opcionais; o total respeita os filtros. | 200, 400 |
| GET | `/api/flood-occurrences/{id}` | Consulta. | 200, 404 |
| PATCH | `/api/flood-occurrences/{id}/status` | `{ "status": "Resolvida" }` ou `"Ativa"`. Resolvidas não geram alertas. | 200, 400, 404 |
| GET | `/api/flood-occurrences/nearby?lat=&lon=&radiusMeters=` | Ocorrências ativas em volta de um ponto. `lat` e `lon` são obrigatórios. | 200, 400 |

## Alertas

| Método | Rota | Descrição | Respostas |
|---|---|---|---|
| POST | `/api/alerts/generate?radiusMeters=` | Gera alertas para os trajetos monitorados com ocorrência ativa no raio. Cada par trajeto/ocorrência gera no máximo um alerta. | 200, 400 |
| GET | `/api/alerts` | Lista. | 200, 400 |
| GET | `/api/alerts/{id}` | Consulta. | 200, 404 |
| GET | `/api/alerts/citizen/{citizenId}` | Alertas de um cidadão. | 200, 400 |
| PATCH | `/api/alerts/{id}/read` | Marca como lido. | 204, 404 |

## Segurança (cabeçalho `X-Api-Key` obrigatório)

Sem a chave, ou com a chave errada, todos respondem 401.

| Método | Rota | Descrição | Respostas |
|---|---|---|---|
| POST | `/api/security/analyze` | Mostra as detecções de PII de um texto (até 20.000 caracteres) e o texto mascarado. Não grava nada. | 200, 400 |
| GET | `/api/security/incidents` | Incidentes, do mais recente para o mais antigo. | 200, 400 |
| GET | `/api/security/incidents/{id}` | Um incidente. | 200, 404 |
| POST | `/api/security/incidents/{id}/remediation` | Traduz o incidente para o cidadão. `origin` diz se veio da IA (`Llm`) ou do texto de reserva (`Fallback`). | 200, 404 |
| GET | `/api/security/dashboard` | Indicadores do painel, Risco Cidadão, histórico de 14 dias e itens recentes. | 200 |
| GET | `/api/security/dashboard/history?days=` | Incidentes por dia (1 a 365 dias, horário de Brasília). | 200, 400 |
| GET | `/api/security/audit` | Trilha de auditoria. | 200, 400 |
| POST | `/api/security/demo/scenarios` | Executa os quatro cenários de Taint Analysis. Só em `Development`. | 200, 404 |

## Saúde

| Método | Rota | Descrição | Respostas |
|---|---|---|---|
| GET | `/health` | Estado da API e da conexão com o banco. | 200, 503 |

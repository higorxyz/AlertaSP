# Arquitetura

## Projetos e dependências

```text
AlertaSP.Api ──────────┬──> AlertaSP.Application ──> AlertaSP.Core
                       ├──> AlertaSP.Infrastructure ─┬─> AlertaSP.Core
                       │                             └─> AlertaSP.Application
                       └──> AlertaSP.Security ──────> AlertaSP.Core
```

| Projeto | Responsabilidade |
|---|---|
| **Core** | Entidades, enums, exceções de domínio e todos os contratos: repositórios, `ICryptoService` e os de segurança (`IPiiDetector`, `ITaintTracker`, `ISecurityPolicy`, `IAuditSink`...). Não depende de nenhum outro projeto. |
| **Application** | Casos de uso (cidadãos, trajetos, ocorrências, alertas), DTOs com validação e a busca de ocorrências próximas. Usa o rastreador pelos contratos do Core, sem conhecer o projeto Security. |
| **Infrastructure** | `ApplicationDbContext`, configurações do EF Core, migrações, repositórios e cifragem com Data Protection. |
| **Security** | Motor de PII, rastreador e política, auditoria, tradução por IA, Risco Cidadão e serviços do painel. Depende só do Core, por isso Core + Security + SecurityTests compilam e rodam sozinhos. |
| **Api** | Controllers, tratamento de erros, filtro de chave de API, cabeçalhos de segurança, Swagger e o painel estático (`wwwroot`). |

Cada camada registra suas dependências numa extensão (`AddApplication`, `AddInfrastructure`, `AddSecurity`). Parâmetros configuráveis usam `IOptions<T>` validado na inicialização.

## Domínio

- `Citizen` recebe CPF, e-mail e endereço já cifrados e o hash do CPF; o nome é obrigatório.
- `Route` exige nome, origem, destino e coordenadas válidas tanto na criação quanto na atualização, e começa monitorado.
- `FloodOccurrence` nasce ativa; `Resolve()` e `Reactivate()` mudam o status.
- `Alert.For(route, occurrence, distância)` só cria alerta para trajeto monitorado e ocorrência ativa, e monta a mensagem sem dados pessoais.

Violações dessas regras lançam `DomainException`, que a API devolve como 400.

## Proximidade

Cada trajeto é aproximado por um segmento reto entre origem A e destino B. As coordenadas são projetadas num plano local (projeção equiretangular, latitude média φm, R = 6.371 km):

```text
x = λ · R · cos(φm)        y = φ · R
t = clamp((AP · AB) / |AB|², 0, 1)
distância = |AP − t · AB|
```

A busca (`NearbyOccurrenceFinder`) tem duas etapas:

1. Uma caixa delimitadora em volta do segmento, com a margem do raio, filtra as ocorrências ativas no banco:

   ```csharp
   _context.FloodOccurrences.Where(f => f.Latitude >= minLat && f.Latitude <= maxLat
                                     && f.Longitude >= minLon && f.Longitude <= maxLon)
   ```

2. A distância ponto–segmento é calculada só para essas candidatas; as que passam do raio são descartadas.

O mesmo componente atende a consulta de risco do trajeto, a geração de alertas e a busca em volta de um ponto (segmento com início e fim iguais). O raio padrão é 500 m (`Risk:NearbyRadiusMeters`).

## Persistência

- SQLite com EF Core 9; migração em `Infrastructure/Migrations`, aplicada na inicialização em `Development`.
- Enums gravados como texto; coordenadas como `double`; datas em UTC. O SQLite não guarda fuso, então um conversor marca toda data lida do banco como UTC, e a API devolve as datas com `Z`.
- Índices únicos: `CpfHash` e o par (`RouteId`, `OccurrenceId`) dos alertas.
- Remover um cidadão remove em cascata seus trajetos e alertas.

## Fluxo de um cadastro de cidadão

```text
POST /api/citizens
  → validação do DTO (atributos) e do CPF (dígitos verificadores)
  → TaintAnnotatedFields: CPF, e-mail e endereço viram Tainted<string>
  → HMAC do CPF → checagem de duplicidade (409)
  → destino Database: liberado → cifrado com Data Protection → gravado
  → destino Log: CPF escrito mascarado
  → destino PublicHttpResponse: resposta com CPF, e-mail e endereço mascarados
  (cada decisão vira um AuditEvent; todas com o mesmo FlowId)
```

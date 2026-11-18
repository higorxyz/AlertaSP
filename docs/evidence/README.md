# Evidências

Registros reais de execução, anexados antes da entrega.

| Pasta | Conteúdo |
|---|---|
| `tests/` | Saída de `dotnet build` e `dotnet test` com a contagem de testes aprovados. |
| `csharp/` | Swagger com todos os endpoints (cadeado só nos de segurança), health check, cadastro de cidadão com CPF mascarado (201), CPF duplicado (409) e inválido (400) em ProblemDetails, trajeto com coordenadas generalizadas, ocorrência, consulta de risco do trajeto, alerta gerado, segunda geração sem duplicar e alertas do cidadão paginados. |
| `pii-detection/` | `POST /api/security/analyze` com CPF, credencial, saúde e endereço no mesmo texto; e um texto com CPF de dígitos errados e a palavra "senha" solta, sem detecção indevida. |
| `taint-analysis/` | Resposta de `POST /api/security/demo/scenarios`, a trilha de auditoria, os incidentes e um cadastro de cidadão com o CPF mascarado na resposta. |
| `ai-remediation/` | Uma tradução com origem `Llm` e outra com origem `Fallback`. |
| `dashboard/` | Painel com Risco Cidadão 0 e depois dos cenários de demonstração. Vídeo: https://youtu.be/afiyWpdN1nY |

Nenhum print mostra chaves reais.

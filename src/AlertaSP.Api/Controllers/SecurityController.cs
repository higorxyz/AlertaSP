using System.ComponentModel.DataAnnotations;
using AlertaSP.Api.Filters;
using AlertaSP.Application.DTOs.Common;
using AlertaSP.Core.Interfaces.Security;
using AlertaSP.Security.Contracts;
using AlertaSP.Security.Dashboard;
using AlertaSP.Security.Incidents;
using AlertaSP.Security.Pii;
using Microsoft.AspNetCore.Mvc;

namespace AlertaSP.Api.Controllers;

/// <summary>Módulo de segurança: análise de PII, incidentes, auditoria e painel. Exige o cabeçalho X-Api-Key.</summary>
[ApiController]
[Route("api/[controller]")]
[ApiKeyAuth]
public class SecurityController : ControllerBase
{
    private readonly IWebHostEnvironment _environment;
    private readonly IPiiAnalysisService _piiAnalysis;
    private readonly ISecurityIncidentService _incidents;
    private readonly ISecurityDashboardService _dashboard;

    public SecurityController(
        IWebHostEnvironment environment,
        IPiiAnalysisService piiAnalysis,
        ISecurityIncidentService incidents,
        ISecurityDashboardService dashboard)
    {
        _environment = environment;
        _piiAnalysis = piiAnalysis;
        _incidents = incidents;
        _dashboard = dashboard;
    }

    /// <summary>Mostra o que o motor de PII encontra no texto e como ele ficaria mascarado.</summary>
    /// <remarks>Detecta CPF, e-mail, credenciais, dados de saúde, endereço, CEP e coordenadas. Não grava nada.</remarks>
    [HttpPost("analyze")]
    [ProducesResponseType(typeof(PiiAnalysisResult), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    public ActionResult<PiiAnalysisResult> Analyze([FromBody] AnalyzeContentRequest request)
        => _piiAnalysis.Analyze(request.Content);

    /// <summary>Incidentes registrados pelo Taint Analysis, do mais recente para o mais antigo.</summary>
    [HttpGet("incidents")]
    [ProducesResponseType(typeof(PagedResult<SecurityIncidentDto>), StatusCodes.Status200OK)]
    public async Task<PagedResult<SecurityIncidentDto>> GetIncidents(
        [FromQuery, Range(1, int.MaxValue)] int page = 1,
        [FromQuery, Range(1, Paging.MaxPageSize)] int pageSize = 10,
        CancellationToken ct = default)
    {
        var result = await _incidents.GetIncidentsAsync(page, pageSize, ct);
        return new PagedResult<SecurityIncidentDto>(result.Items, result.TotalCount, page, pageSize);
    }

    /// <summary>Consulta um incidente de segurança.</summary>
    [HttpGet("incidents/{id:int}")]
    [ProducesResponseType(typeof(SecurityIncidentDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
    public async Task<ActionResult<SecurityIncidentDto>> GetIncident(int id, CancellationToken ct)
        => await _incidents.GetIncidentAsync(id, ct) is { } incident ? incident : NotFound();

    /// <summary>Traduz o incidente para o cidadão com IA. Sem IA disponível, usa o texto de reserva, com origem "Fallback".</summary>
    [HttpPost("incidents/{id:int}/remediation")]
    [ProducesResponseType(typeof(RemediationResult), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
    public async Task<ActionResult<RemediationResult>> Translate(int id, CancellationToken ct)
        => await _incidents.TranslateAsync(id, ct) is { } result ? result : NotFound();

    /// <summary>Indicadores do painel e Risco Cidadão, calculados a partir dos incidentes e da auditoria gravados.</summary>
    [HttpGet("dashboard")]
    [ProducesResponseType(typeof(SecurityDashboardMetrics), StatusCodes.Status200OK)]
    public Task<SecurityDashboardMetrics> GetDashboard(CancellationToken ct)
        => _dashboard.GetDashboardMetricsAsync(ct);

    /// <summary>Incidentes por dia (horário de Brasília), incluindo os dias sem incidente.</summary>
    [HttpGet("dashboard/history")]
    [ProducesResponseType(typeof(IReadOnlyList<DailyIncidentCount>), StatusCodes.Status200OK)]
    public Task<IReadOnlyList<DailyIncidentCount>> GetHistory(
        [FromQuery, Range(1, 365)] int days = 30, CancellationToken ct = default)
        => _dashboard.GetHistoryAsync(days, ct);

    /// <summary>Trilha de auditoria: cada decisão da política, sem o valor sensível.</summary>
    [HttpGet("audit")]
    [ProducesResponseType(typeof(PagedResult<AuditEventDto>), StatusCodes.Status200OK)]
    public async Task<PagedResult<AuditEventDto>> GetAudit(
        [FromQuery, Range(1, int.MaxValue)] int page = 1,
        [FromQuery, Range(1, Paging.MaxPageSize)] int pageSize = 20,
        CancellationToken ct = default)
    {
        var result = await _incidents.GetAuditTrailAsync(page, pageSize, ct);
        return new PagedResult<AuditEventDto>(result.Items, result.TotalCount, page, pageSize);
    }

    /// <summary>Executa os quatro cenários de vazamento do enunciado. Disponível só em Development.</summary>
    [HttpPost("demo/scenarios")]
    [ProducesResponseType(typeof(DemoScenariosResult), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
    public async Task<ActionResult<DemoScenariosResult>> RunDemoScenarios(CancellationToken ct)
    {
        // Os cenários gravam incidentes fictícios; fora de Development o endpoint não existe.
        if (!_environment.IsDevelopment())
            return NotFound();

        return await _dashboard.ExecuteDemoScenariosAsync(ct);
    }
}

public class AnalyzeContentRequest
{
    [Required(ErrorMessage = "O conteúdo é obrigatório.")]
    [StringLength(20000, ErrorMessage = "O conteúdo deve ter no máximo 20000 caracteres.")]
    public string Content { get; set; } = string.Empty;
}

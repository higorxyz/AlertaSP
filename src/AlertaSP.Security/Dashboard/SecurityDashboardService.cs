using AlertaSP.Core.Enums;
using AlertaSP.Core.Interfaces.Security;
using AlertaSP.Security.Contracts;
using AlertaSP.Security.Risk;
using Microsoft.Extensions.Options;

namespace AlertaSP.Security.Dashboard;

public class SecurityDashboardMetrics
{
    public int WindowDays { get; init; }
    public int TotalIncidents { get; init; }
    public int BlockedAttempts { get; init; }
    public int SanitizedAttempts { get; init; }

    /// <summary>
    /// Decisões da trilha de auditoria na janela: liberadas, mascaradas e bloqueadas. Ao contrário dos
    /// incidentes, inclui as operações liberadas.
    /// </summary>
    public int AllowedOperations { get; init; }
    public int SanitizedOperations { get; init; }
    public int BlockedOperations { get; init; }

    public int PersonalDataDetectedCount { get; init; }
    public int CredentialsDetectedCount { get; init; }
    public int LocationDetectedCount { get; init; }
    public int HealthDataDetectedCount { get; init; }
    public CitizenRiskScore CitizenRisk { get; init; } = null!;
    public IReadOnlyDictionary<string, int> IncidentsByCategory { get; init; } = new Dictionary<string, int>();
    public IReadOnlyDictionary<string, int> IncidentsBySeverity { get; init; } = new Dictionary<string, int>();
    public IReadOnlyList<DailyIncidentCount> DailyIncidents { get; init; } = Array.Empty<DailyIncidentCount>();
    public IReadOnlyList<SecurityIncidentDto> RecentIncidents { get; init; } = Array.Empty<SecurityIncidentDto>();
    public IReadOnlyList<AuditEventDto> RecentAuditEvents { get; init; } = Array.Empty<AuditEventDto>();

    public string Disclaimer { get; } =
        "O indicador representa risco de exposição no ambiente monitorado, não uma previsão de que determinado cidadão sofrerá um incidente.";
}

public sealed record DemoScenarioOutcome(
    string Scenario, string Source, string Sink, string Category, string Decision, string? ReleasedValue);

public sealed class DemoScenariosResult
{
    public string Summary { get; init; } = string.Empty;
    public IReadOnlyList<DemoScenarioOutcome> Scenarios { get; init; } = Array.Empty<DemoScenarioOutcome>();
}

public interface ISecurityDashboardService
{
    Task<SecurityDashboardMetrics> GetDashboardMetricsAsync(CancellationToken ct = default);
    Task<IReadOnlyList<DailyIncidentCount>> GetHistoryAsync(int days, CancellationToken ct = default);
    Task<DemoScenariosResult> ExecuteDemoScenariosAsync(CancellationToken ct = default);
}

public class SecurityDashboardService : ISecurityDashboardService
{
    private const int RecentItems = 20;
    private const int ChartDays = 14;

    private readonly ISecurityIncidentRepository _incidentRepository;
    private readonly IAuditSink _auditSink;
    private readonly ICitizenRiskCalculator _riskCalculator;
    private readonly ITaintTracker _taintTracker;
    private readonly int _windowDays;
    private readonly int _utcOffsetHours;

    public SecurityDashboardService(
        ISecurityIncidentRepository incidentRepository,
        IAuditSink auditSink,
        ICitizenRiskCalculator riskCalculator,
        ITaintTracker taintTracker,
        IOptions<CitizenRiskOptions> options)
    {
        _incidentRepository = incidentRepository;
        _auditSink = auditSink;
        _riskCalculator = riskCalculator;
        _taintTracker = taintTracker;
        _windowDays = options.Value.AnalysisWindowDays;
        _utcOffsetHours = options.Value.ReportingUtcOffsetHours;
    }

    public async Task<SecurityDashboardMetrics> GetDashboardMetricsAsync(CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        var from = now.AddDays(-_windowDays);

        var groups = await _incidentRepository.CountByGroupAsync(from, now, ct);
        var decisions = await _auditSink.CountByDecisionAsync(from, now, ct);
        var daily = await GetHistoryAsync(ChartDays, ct);
        var recentIncidents = await _incidentRepository.GetAllAsync(1, RecentItems, ct);
        var recentAudit = await _auditSink.GetEventsAsync(1, RecentItems, ct);

        int Sum(Func<IncidentCount, bool> filter) => groups.Where(filter).Sum(g => g.Count);

        return new SecurityDashboardMetrics
        {
            WindowDays = _windowDays,
            TotalIncidents = Sum(_ => true),
            BlockedAttempts = Sum(g => g.Result == IncidentResult.Blocked),
            SanitizedAttempts = Sum(g => g.Result == IncidentResult.Sanitized),
            AllowedOperations = decisions.GetValueOrDefault(PolicyDecision.Allow),
            SanitizedOperations = decisions.GetValueOrDefault(PolicyDecision.AllowSanitized),
            BlockedOperations = decisions.GetValueOrDefault(PolicyDecision.Block),
            PersonalDataDetectedCount = Sum(g => g.Category == DataCategory.PersonalData),
            CredentialsDetectedCount = Sum(g => g.Category == DataCategory.Credentials),
            LocationDetectedCount = Sum(g => g.Category == DataCategory.Location),
            HealthDataDetectedCount = Sum(g => g.Category == DataCategory.HealthData),
            CitizenRisk = _riskCalculator.Calculate(groups),
            IncidentsByCategory = CountBy(groups, g => g.Category.ToString()),
            IncidentsBySeverity = CountBy(groups, g => g.Sensitivity.ToString()),
            DailyIncidents = daily,
            RecentIncidents = recentIncidents.Select(SecurityIncidentDto.From).ToList(),
            RecentAuditEvents = recentAudit.Select(AuditEventDto.From).ToList()
        };
    }

    /// <summary>
    /// Incidentes por dia (no fuso de relatório) nos últimos <paramref name="days"/> dias, incluindo os
    /// dias sem incidente, para o gráfico não pular datas.
    /// </summary>
    public async Task<IReadOnlyList<DailyIncidentCount>> GetHistoryAsync(int days, CancellationToken ct = default)
    {
        var now = DateTime.UtcNow;
        var firstLocalDay = DateOnly.FromDateTime(now.AddHours(_utcOffsetHours)).AddDays(-(days - 1));
        var fromUtc = DateTime.SpecifyKind(firstLocalDay.ToDateTime(TimeOnly.MinValue).AddHours(-_utcOffsetHours), DateTimeKind.Utc);

        var counts = await _incidentRepository.CountByDayAsync(fromUtc, now, _utcOffsetHours, ct);
        var byDay = counts.ToDictionary(c => c.Day);

        return Enumerable.Range(0, days)
            .Select(offset => firstLocalDay.AddDays(offset))
            .Select(day => byDay.TryGetValue(day, out var c) ? c : new DailyIncidentCount(day, 0, 0, 0))
            .ToList();
    }

    /// <summary>
    /// Os quatro cenários do enunciado, executados pelo mesmo rastreador que os serviços usam
    /// (origem → destino → política → auditoria/incidente). Os dados são fictícios.
    /// </summary>
    public async Task<DemoScenariosResult> ExecuteDemoScenariosAsync(CancellationToken ct = default)
    {
        var outcomes = new List<DemoScenarioOutcome>
        {
            await RunAsync("CPF enviado para o log",
                new DataFlowContext { Source = "/api/citizens", Purpose = "CitizenRegistrationLog", Actor = "PublicApi" },
                "Cadastro concluído para o CPF 384.920.184-88 (dado fictício).", SinkType.Log, ct),

            await RunAsync("Endereço em resposta pública",
                new DataFlowContext { Source = "/api/routes", Purpose = "PublicProfileResponse", Actor = "WebClient" },
                "Moradora da Av. Paulista, 1578, Ap 42 (endereço fictício).", SinkType.PublicHttpResponse, ct),

            await RunAsync("Credencial a caminho da IA externa",
                new DataFlowContext { Source = "/api/security/remediation", Purpose = "ExternalAiPrompt", Actor = "InternalWorker" },
                "Chave de integração: api_key=sk-proj-94819482938491823948192384912384 (token fictício).", SinkType.ExternalAiService, ct),

            await RunAsync("Uso interno autorizado para gerar alerta",
                new DataFlowContext { Source = "/api/alerts/generate", Purpose = "RouteAlertGeneration", Actor = "AlertEngine", IsAuthorized = true },
                "Trecho monitorado: -23.5614,-46.6559", SinkType.InternalHttpResponse, ct)
        };

        return new DemoScenariosResult
        {
            Summary = "Os 4 cenários foram executados e gravados na auditoria. Bloqueios e mascaramentos geraram incidentes.",
            Scenarios = outcomes
        };
    }

    private async Task<DemoScenarioOutcome> RunAsync(
        string scenario, DataFlowContext context, string content, SinkType sink, CancellationToken ct)
    {
        var tainted = _taintTracker.TaintByContent(content, context);
        var result = await _taintTracker.TryDeliverAsync(tainted, sink, context, ct);
        return new DemoScenarioOutcome(
            scenario, context.Source, sink.ToString(), tainted.Metadata.Category.ToString(),
            result.Decision.ToString(), result.ReleasedValue);
    }

    private static IReadOnlyDictionary<string, int> CountBy(IEnumerable<IncidentCount> groups, Func<IncidentCount, string> key) =>
        groups.GroupBy(key).ToDictionary(g => g.Key, g => g.Sum(x => x.Count));
}

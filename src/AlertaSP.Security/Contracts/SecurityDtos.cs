using AlertaSP.Core.Entities;
using AlertaSP.Core.Interfaces.Security;

namespace AlertaSP.Security.Contracts;

/// <summary>Página de resultados com o total de registros, para a API montar a paginação.</summary>
public sealed record PageOf<T>(IReadOnlyList<T> Items, int TotalCount);

public sealed class SecurityIncidentDto
{
    public int Id { get; init; }
    public string FlowId { get; init; } = string.Empty;
    public DateTime Timestamp { get; init; }
    public string Category { get; init; } = string.Empty;
    public string Sensitivity { get; init; } = string.Empty;
    public string SinkType { get; init; } = string.Empty;
    public string Decision { get; init; } = string.Empty;
    public string Result { get; init; } = string.Empty;
    public string RuleApplied { get; init; } = string.Empty;
    public string Summary { get; init; } = string.Empty;
    public string? Remediation { get; init; }
    public string? RemediationOrigin { get; init; }

    public static SecurityIncidentDto From(SecurityIncident incident) => new()
    {
        Id = incident.Id,
        FlowId = incident.FlowId,
        Timestamp = incident.Timestamp,
        Category = incident.Category.ToString(),
        Sensitivity = incident.Sensitivity.ToString(),
        SinkType = incident.SinkType.ToString(),
        Decision = incident.Decision.ToString(),
        Result = incident.Result.ToString(),
        RuleApplied = incident.RuleApplied,
        Summary = incident.Summary,
        Remediation = incident.Remediation,
        RemediationOrigin = incident.RemediationOrigin?.ToString()
    };
}

public sealed class AuditEventDto
{
    public int Id { get; init; }
    public string FlowId { get; init; } = string.Empty;
    public DateTime Timestamp { get; init; }
    public string Source { get; init; } = string.Empty;
    public string SinkType { get; init; } = string.Empty;
    public string Category { get; init; } = string.Empty;
    public string Decision { get; init; } = string.Empty;
    public string RuleApplied { get; init; } = string.Empty;
    public string Summary { get; init; } = string.Empty;

    public static AuditEventDto From(AuditEvent auditEvent) => new()
    {
        Id = auditEvent.Id,
        FlowId = auditEvent.FlowId,
        Timestamp = auditEvent.Timestamp,
        Source = auditEvent.Source,
        SinkType = auditEvent.SinkType.ToString(),
        Category = auditEvent.Category.ToString(),
        Decision = auditEvent.Decision.ToString(),
        RuleApplied = auditEvent.RuleApplied,
        Summary = auditEvent.Summary
    };
}

public sealed class PiiAnalysisResult
{
    public int TotalDetections { get; init; }
    public bool HasPii { get; init; }
    public IReadOnlyList<PiiDetection> Detections { get; init; } = Array.Empty<PiiDetection>();
    public string MaskedContent { get; init; } = string.Empty;
}

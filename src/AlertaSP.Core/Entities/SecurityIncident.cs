using AlertaSP.Core.Enums;

namespace AlertaSP.Core.Entities;

/// <summary>
/// Tentativa de levar um dado sensível a um destino inseguro, registrada quando a política bloqueia ou
/// sanitiza. Alimenta o indicador Risco Cidadão. Assim como a auditoria, não guarda o valor original.
/// </summary>
public class SecurityIncident
{
    public int Id { get; private set; }
    public string FlowId { get; private set; } = string.Empty;
    public DateTime Timestamp { get; private set; }
    public DataCategory Category { get; private set; }
    public DataSensitivity Sensitivity { get; private set; }
    public SinkType SinkType { get; private set; }
    public PolicyDecision Decision { get; private set; }
    public IncidentResult Result { get; private set; }
    public string RuleApplied { get; private set; } = string.Empty;
    public string Summary { get; private set; } = string.Empty;
    public string? Remediation { get; private set; }
    public RemediationOrigin? RemediationOrigin { get; private set; }

    private SecurityIncident() { }

    public static SecurityIncident Create(
        string flowId, DataCategory category, DataSensitivity sensitivity,
        SinkType sinkType, PolicyDecision decision, IncidentResult result,
        string ruleApplied, string summary)
    {
        return new SecurityIncident
        {
            FlowId = flowId,
            Timestamp = DateTime.UtcNow,
            Category = category,
            Sensitivity = sensitivity,
            SinkType = sinkType,
            Decision = decision,
            Result = result,
            RuleApplied = ruleApplied,
            Summary = summary
        };
    }

    public void SetRemediation(string remediation, RemediationOrigin origin)
    {
        if (string.IsNullOrWhiteSpace(remediation))
            throw new ArgumentException("A tradução do incidente não pode ser vazia.", nameof(remediation));

        Remediation = remediation;
        RemediationOrigin = origin;
    }
}

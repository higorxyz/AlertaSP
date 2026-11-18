using AlertaSP.Core.Enums;

namespace AlertaSP.Core.Entities;

/// <summary>
/// Registro de uma decisão da política de segurança: de onde o dado veio, para onde ia e o que foi decidido.
/// Não guarda o valor sensível; o resumo cita apenas categoria, origem e destino.
/// </summary>
public class AuditEvent
{
    public int Id { get; private set; }
    public string FlowId { get; private set; } = string.Empty;
    public DateTime Timestamp { get; private set; }
    public string Source { get; private set; } = string.Empty;
    public SinkType SinkType { get; private set; }
    public DataCategory Category { get; private set; }
    public DataSensitivity Sensitivity { get; private set; }
    public PolicyDecision Decision { get; private set; }
    public string RuleApplied { get; private set; } = string.Empty;
    public string Summary { get; private set; } = string.Empty;

    private AuditEvent() { }

    public static AuditEvent Create(
        string flowId, string source, SinkType sinkType,
        DataCategory category, DataSensitivity sensitivity,
        PolicyDecision decision, string ruleApplied, string summary)
    {
        return new AuditEvent
        {
            FlowId = flowId,
            Timestamp = DateTime.UtcNow,
            Source = source,
            SinkType = sinkType,
            Category = category,
            Sensitivity = sensitivity,
            Decision = decision,
            RuleApplied = ruleApplied,
            Summary = summary
        };
    }
}

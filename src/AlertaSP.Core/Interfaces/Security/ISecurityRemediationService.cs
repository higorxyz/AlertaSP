using AlertaSP.Core.Entities;
using AlertaSP.Core.Enums;

namespace AlertaSP.Core.Interfaces.Security;

/// <summary>Traduz um incidente técnico em uma mensagem que o cidadão entende.</summary>
public interface ISecurityRemediationService
{
    Task<RemediationResult> TranslateIncidentAsync(SecurityIncident incident, CancellationToken ct = default);
}

public class RemediationResult
{
    public string Message { get; init; } = string.Empty;
    public RemediationOrigin Origin { get; init; }
}

using AlertaSP.Core.Interfaces.Security;
using AlertaSP.Security.Contracts;

namespace AlertaSP.Security.Incidents;

public interface ISecurityIncidentService
{
    Task<PageOf<SecurityIncidentDto>> GetIncidentsAsync(int page, int pageSize, CancellationToken ct = default);
    Task<SecurityIncidentDto?> GetIncidentAsync(int id, CancellationToken ct = default);

    /// <summary>Traduz o incidente para o cidadão e guarda a tradução com a origem (IA ou texto de reserva). Nulo se o incidente não existe.</summary>
    Task<RemediationResult?> TranslateAsync(int id, CancellationToken ct = default);

    Task<PageOf<AuditEventDto>> GetAuditTrailAsync(int page, int pageSize, CancellationToken ct = default);
}

public class SecurityIncidentService : ISecurityIncidentService
{
    private readonly ISecurityIncidentRepository _incidents;
    private readonly IAuditSink _audit;
    private readonly ISecurityRemediationService _remediation;

    public SecurityIncidentService(
        ISecurityIncidentRepository incidents,
        IAuditSink audit,
        ISecurityRemediationService remediation)
    {
        _incidents = incidents;
        _audit = audit;
        _remediation = remediation;
    }

    public async Task<PageOf<SecurityIncidentDto>> GetIncidentsAsync(int page, int pageSize, CancellationToken ct = default)
    {
        var total = await _incidents.CountAsync(ct);
        var items = await _incidents.GetAllAsync(page, pageSize, ct);
        return new PageOf<SecurityIncidentDto>(items.Select(SecurityIncidentDto.From).ToList(), total);
    }

    public async Task<SecurityIncidentDto?> GetIncidentAsync(int id, CancellationToken ct = default)
    {
        var incident = await _incidents.GetByIdAsync(id, ct);
        return incident == null ? null : SecurityIncidentDto.From(incident);
    }

    public async Task<RemediationResult?> TranslateAsync(int id, CancellationToken ct = default)
    {
        var incident = await _incidents.GetByIdAsync(id, ct);
        if (incident == null)
            return null;

        var result = await _remediation.TranslateIncidentAsync(incident, ct);
        incident.SetRemediation(result.Message, result.Origin);
        await _incidents.UpdateAsync(incident, ct);
        return result;
    }

    public async Task<PageOf<AuditEventDto>> GetAuditTrailAsync(int page, int pageSize, CancellationToken ct = default)
    {
        var total = await _audit.CountAsync(ct);
        var items = await _audit.GetEventsAsync(page, pageSize, ct);
        return new PageOf<AuditEventDto>(items.Select(AuditEventDto.From).ToList(), total);
    }
}

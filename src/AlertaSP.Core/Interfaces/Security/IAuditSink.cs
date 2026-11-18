using AlertaSP.Core.Entities;
using AlertaSP.Core.Enums;

namespace AlertaSP.Core.Interfaces.Security;

/// <summary>Destino dos eventos de auditoria gerados pelo rastreador.</summary>
public interface IAuditSink
{
    Task RecordAsync(AuditEvent auditEvent, CancellationToken ct = default);
    Task<IReadOnlyList<AuditEvent>> GetEventsAsync(int page, int pageSize, CancellationToken ct = default);
    Task<int> CountAsync(CancellationToken ct = default);

    /// <summary>
    /// Eventos do período agrupados pela decisão da política (liberado, mascarado, bloqueado).
    /// Decisões sem eventos no período não aparecem no dicionário.
    /// </summary>
    Task<IReadOnlyDictionary<PolicyDecision, int>> CountByDecisionAsync(DateTime from, DateTime to, CancellationToken ct = default);
}

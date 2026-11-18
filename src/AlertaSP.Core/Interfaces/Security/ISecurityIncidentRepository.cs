using AlertaSP.Core.Entities;
using AlertaSP.Core.Enums;

namespace AlertaSP.Core.Interfaces.Security;

public interface ISecurityIncidentRepository
{
    Task<SecurityIncident?> GetByIdAsync(int id, CancellationToken ct = default);
    Task<IReadOnlyList<SecurityIncident>> GetAllAsync(int page, int pageSize, CancellationToken ct = default);
    Task<SecurityIncident> AddAsync(SecurityIncident incident, CancellationToken ct = default);
    Task UpdateAsync(SecurityIncident incident, CancellationToken ct = default);
    Task<int> CountAsync(CancellationToken ct = default);

    /// <summary>Incidentes do período agrupados por categoria, sensibilidade e resultado (base do Risco Cidadão).</summary>
    Task<IReadOnlyList<IncidentCount>> CountByGroupAsync(DateTime from, DateTime to, CancellationToken ct = default);

    /// <summary>
    /// Incidentes do período agrupados por dia no fuso indicado por <paramref name="utcOffsetHours"/>,
    /// do mais antigo para o mais recente.
    /// </summary>
    Task<IReadOnlyList<DailyIncidentCount>> CountByDayAsync(DateTime from, DateTime to, int utcOffsetHours, CancellationToken ct = default);
}

public sealed record IncidentCount(DataCategory Category, DataSensitivity Sensitivity, IncidentResult Result, int Count);

public sealed record DailyIncidentCount(DateOnly Day, int Total, int Blocked, int Sanitized);

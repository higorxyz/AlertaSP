using AlertaSP.Core.Entities;

namespace AlertaSP.Core.Interfaces;

public interface IAlertRepository
{
    Task<Alert?> GetByIdAsync(int id, CancellationToken ct = default);
    Task<IReadOnlyList<Alert>> GetAllAsync(int page, int pageSize, CancellationToken ct = default);
    Task<IReadOnlyList<Alert>> GetByCitizenIdAsync(int citizenId, int page, int pageSize, CancellationToken ct = default);
    Task<IReadOnlySet<int>> GetExistingOccurrenceIdsAsync(int routeId, IReadOnlyCollection<int> occurrenceIds, CancellationToken ct = default);
    Task<Alert> AddAsync(Alert alert, CancellationToken ct = default);
    Task UpdateAsync(Alert alert, CancellationToken ct = default);
    Task<int> CountAsync(CancellationToken ct = default);
    Task<int> CountByCitizenIdAsync(int citizenId, CancellationToken ct = default);
}

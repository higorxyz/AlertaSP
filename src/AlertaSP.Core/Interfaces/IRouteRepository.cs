using AlertaSP.Core.Entities;

namespace AlertaSP.Core.Interfaces;

public interface IRouteRepository
{
    Task<Route?> GetByIdAsync(int id, CancellationToken ct = default);
    Task<IReadOnlyList<Route>> GetAllAsync(int page, int pageSize, CancellationToken ct = default);
    Task<IReadOnlyList<Route>> GetByCitizenIdAsync(int citizenId, CancellationToken ct = default);
    Task<IReadOnlyList<Route>> GetActiveMonitoringRoutesAsync(CancellationToken ct = default);
    Task<IReadOnlyDictionary<int, string>> GetNamesByIdsAsync(IReadOnlyCollection<int> ids, CancellationToken ct = default);
    Task<Route> AddAsync(Route route, CancellationToken ct = default);
    Task UpdateAsync(Route route, CancellationToken ct = default);
    Task DeleteAsync(Route route, CancellationToken ct = default);
    Task<int> CountAsync(CancellationToken ct = default);
}

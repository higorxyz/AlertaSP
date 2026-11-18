using AlertaSP.Core.Entities;
using AlertaSP.Core.Enums;

namespace AlertaSP.Core.Interfaces;

public interface IFloodOccurrenceRepository
{
    Task<FloodOccurrence?> GetByIdAsync(int id, CancellationToken ct = default);
    Task<IReadOnlyList<FloodOccurrence>> GetAllAsync(int page, int pageSize,
        Severity? severity = null, OccurrenceStatus? status = null, CancellationToken ct = default);
    Task<IReadOnlyList<FloodOccurrence>> GetInBoundingBoxAsync(
        double minLat, double maxLat, double minLon, double maxLon,
        OccurrenceStatus? status = null, CancellationToken ct = default);
    Task<FloodOccurrence> AddAsync(FloodOccurrence occurrence, CancellationToken ct = default);
    Task UpdateAsync(FloodOccurrence occurrence, CancellationToken ct = default);
    Task<int> CountAsync(Severity? severity = null, OccurrenceStatus? status = null, CancellationToken ct = default);
}

using AlertaSP.Application.DTOs.Common;
using AlertaSP.Application.DTOs.FloodOccurrences;
using AlertaSP.Core.Enums;

namespace AlertaSP.Application.Interfaces;

public interface IFloodOccurrenceService
{
    Task<FloodOccurrenceResponse> RegisterAsync(CreateFloodOccurrenceRequest request, CancellationToken ct = default);
    Task<FloodOccurrenceResponse?> GetByIdAsync(int id, CancellationToken ct = default);
    Task<PagedResult<FloodOccurrenceResponse>> GetAllAsync(
        int page = 1, int pageSize = 10,
        Severity? severity = null, OccurrenceStatus? status = null,
        CancellationToken ct = default);
    Task<FloodOccurrenceResponse> UpdateStatusAsync(int id, OccurrenceStatus status, CancellationToken ct = default);
    Task<IReadOnlyList<NearbyOccurrenceResponse>> GetNearbyAsync(double latitude, double longitude, double? radiusMeters = null, CancellationToken ct = default);
}

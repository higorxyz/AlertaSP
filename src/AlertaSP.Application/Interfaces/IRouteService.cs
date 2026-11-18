using AlertaSP.Application.DTOs.Common;
using AlertaSP.Application.DTOs.FloodOccurrences;
using AlertaSP.Application.DTOs.Routes;

namespace AlertaSP.Application.Interfaces;

public interface IRouteService
{
    Task<RouteResponse> CreateAsync(CreateRouteRequest request, CancellationToken ct = default);
    Task<RouteResponse?> GetByIdAsync(int id, CancellationToken ct = default);
    Task<PagedResult<RouteResponse>> GetAllAsync(int page = 1, int pageSize = 10, CancellationToken ct = default);
    Task<IReadOnlyList<RouteResponse>> GetByCitizenIdAsync(int citizenId, CancellationToken ct = default);
    Task<RouteResponse> UpdateAsync(int id, UpdateRouteRequest request, CancellationToken ct = default);
    Task<RouteResponse> SetMonitoringAsync(int id, bool isActive, CancellationToken ct = default);
    Task DeleteAsync(int id, CancellationToken ct = default);

    /// <summary>
    /// Ocorrências ativas a até <paramref name="radiusMeters"/> do segmento origem → destino (sem valor,
    /// usa o raio padrão). Lança EntityNotFoundException se o trajeto não existe.
    /// </summary>
    Task<RouteRiskAnalysisResponse> AnalyzeRiskAsync(int id, double? radiusMeters = null, CancellationToken ct = default);
}

using AlertaSP.Application.DTOs.Alerts;
using AlertaSP.Application.DTOs.Common;

namespace AlertaSP.Application.Interfaces;

public interface IAlertService
{
    /// <summary>
    /// Gera alertas para os trajetos com monitoramento ativo. Sem raio informado, usa o padrão da
    /// configuração. Um par trajeto/ocorrência nunca gera dois alertas.
    /// </summary>
    Task<GenerateAlertsResult> GenerateRouteAlertsAsync(double? radiusMeters = null, CancellationToken ct = default);
    Task<AlertResponse?> GetByIdAsync(int id, CancellationToken ct = default);
    Task<PagedResult<AlertResponse>> GetAllAsync(int page = 1, int pageSize = 10, CancellationToken ct = default);
    Task<PagedResult<AlertResponse>> GetByCitizenIdAsync(int citizenId, int page = 1, int pageSize = 10, CancellationToken ct = default);
    Task MarkAsReadAsync(int id, CancellationToken ct = default);
}

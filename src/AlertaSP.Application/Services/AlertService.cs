using AlertaSP.Application.DTOs.Alerts;
using AlertaSP.Application.DTOs.Common;
using AlertaSP.Application.Interfaces;
using AlertaSP.Application.Proximity;
using AlertaSP.Core.Entities;
using AlertaSP.Core.Exceptions;
using AlertaSP.Core.Interfaces;
using AlertaSP.Core.Interfaces.Security;

namespace AlertaSP.Application.Services;

public class AlertService : IAlertService
{
    private readonly IAlertRepository _alertRepository;
    private readonly IRouteRepository _routeRepository;
    private readonly INearbyOccurrenceFinder _finder;
    private readonly ITaintTracker _taintTracker;
    private readonly RouteLocationProtector _protector;

    public AlertService(
        IAlertRepository alertRepository,
        IRouteRepository routeRepository,
        INearbyOccurrenceFinder finder,
        ITaintTracker taintTracker,
        RouteLocationProtector protector)
    {
        _protector = protector;
        _alertRepository = alertRepository;
        _routeRepository = routeRepository;
        _finder = finder;
        _taintTracker = taintTracker;
    }

    public async Task<GenerateAlertsResult> GenerateRouteAlertsAsync(double? radiusMeters = null, CancellationToken ct = default)
    {
        var radius = _finder.ResolveRadius(radiusMeters);
        var routes = await _routeRepository.GetActiveMonitoringRoutesAsync(ct);

        var context = new DataFlowContext
        {
            Source = "/api/alerts/generate",
            Purpose = "RouteAlertGeneration",
            Actor = "AlertEngine",
            IsAuthorized = true
        };
        var segments = await _taintTracker.ReleaseForInternalUseAsync(routes.Select(_protector.Unprotect).ToList(), context, ct);

        var generated = new List<AlertResponse>();
        var evaluated = 0;

        for (var i = 0; i < routes.Count; i++)
        {
            var nearby = await _finder.FindAsync(segments[i], radius, ct);
            evaluated += nearby.Count;
            if (nearby.Count == 0)
                continue;

            var alreadyAlerted = await _alertRepository.GetExistingOccurrenceIdsAsync(
                routes[i].Id, nearby.Select(n => n.Occurrence.Id).ToList(), ct);

            foreach (var match in nearby.Where(n => !alreadyAlerted.Contains(n.Occurrence.Id)))
            {
                var alert = Alert.For(routes[i], match.Occurrence, match.DistanceMeters);
                await _alertRepository.AddAsync(alert, ct);
                generated.Add(AlertResponse.From(alert, routes[i].Name));
            }
        }

        return new GenerateAlertsResult
        {
            AlertsGenerated = generated.Count,
            RoutesMonitored = routes.Count,
            OccurrencesWithinRadius = evaluated,
            RadiusMeters = radius,
            GeneratedAlerts = generated
        };
    }

    public async Task<AlertResponse?> GetByIdAsync(int id, CancellationToken ct = default)
    {
        var alert = await _alertRepository.GetByIdAsync(id, ct);
        if (alert == null)
            return null;

        var names = await _routeRepository.GetNamesByIdsAsync(new[] { alert.RouteId }, ct);
        return AlertResponse.From(alert, names.GetValueOrDefault(alert.RouteId, "Trajeto"));
    }

    public async Task<PagedResult<AlertResponse>> GetAllAsync(int page = 1, int pageSize = 10, CancellationToken ct = default)
    {
        var total = await _alertRepository.CountAsync(ct);
        var alerts = await _alertRepository.GetAllAsync(page, pageSize, ct);
        return new PagedResult<AlertResponse>(await WithRouteNamesAsync(alerts, ct), total, page, pageSize);
    }

    public async Task<PagedResult<AlertResponse>> GetByCitizenIdAsync(int citizenId, int page = 1, int pageSize = 10, CancellationToken ct = default)
    {
        var total = await _alertRepository.CountByCitizenIdAsync(citizenId, ct);
        var alerts = await _alertRepository.GetByCitizenIdAsync(citizenId, page, pageSize, ct);
        return new PagedResult<AlertResponse>(await WithRouteNamesAsync(alerts, ct), total, page, pageSize);
    }

    public async Task MarkAsReadAsync(int id, CancellationToken ct = default)
    {
        var alert = await _alertRepository.GetByIdAsync(id, ct)
            ?? throw new EntityNotFoundException("Alerta", id);

        alert.MarkAsRead();
        await _alertRepository.UpdateAsync(alert, ct);
    }

    /// <summary>Busca os nomes dos trajetos da página numa única consulta.</summary>
    private async Task<List<AlertResponse>> WithRouteNamesAsync(IReadOnlyList<Alert> alerts, CancellationToken ct)
    {
        var names = await _routeRepository.GetNamesByIdsAsync(alerts.Select(a => a.RouteId).Distinct().ToList(), ct);
        return alerts.Select(a => AlertResponse.From(a, names.GetValueOrDefault(a.RouteId, "Trajeto"))).ToList();
    }
}

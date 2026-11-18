using AlertaSP.Application.Common;
using AlertaSP.Application.DTOs.Common;
using AlertaSP.Application.DTOs.FloodOccurrences;
using AlertaSP.Application.DTOs.Routes;
using AlertaSP.Application.Interfaces;
using AlertaSP.Application.Proximity;
using AlertaSP.Core.Entities;
using AlertaSP.Core.Enums;
using AlertaSP.Core.Exceptions;
using AlertaSP.Core.Interfaces;
using AlertaSP.Core.Interfaces.Security;

namespace AlertaSP.Application.Services;

public class RouteService : IRouteService
{
    private const string Source = "/api/routes";
    private const int FieldsPerRoute = 6;

    private readonly IRouteRepository _routeRepository;
    private readonly ICitizenRepository _citizenRepository;
    private readonly INearbyOccurrenceFinder _finder;
    private readonly ITaintTracker _taintTracker;

    public RouteService(
        IRouteRepository routeRepository,
        ICitizenRepository citizenRepository,
        INearbyOccurrenceFinder finder,
        ITaintTracker taintTracker)
    {
        _routeRepository = routeRepository;
        _citizenRepository = citizenRepository;
        _finder = finder;
        _taintTracker = taintTracker;
    }

    public async Task<RouteResponse> CreateAsync(CreateRouteRequest request, CancellationToken ct = default)
    {
        if (await _citizenRepository.GetByIdAsync(request.CitizenId, ct) == null)
            throw new EntityNotFoundException("Cidadão", request.CitizenId);

        // Endereços e coordenadas do trajeto são Location: revelam onde a pessoa mora e trabalha.
        var input = SensitiveFlow.Input(Source, "RouteRegistration", $"Citizen:{request.CitizenId}");
        var stored = await ReleaseForStorageAsync(_taintTracker.TaintAnnotatedFields(request, input), input, ct);

        var route = Route.Create(
            request.CitizenId, request.Name,
            stored.Origin, stored.Destination,
            stored.OriginLatitude, stored.OriginLongitude,
            stored.DestinationLatitude, stored.DestinationLongitude);

        await _routeRepository.AddAsync(route, ct);
        return (await ToPublicResponsesAsync(new[] { route }, input, ct))[0];
    }

    public async Task<RouteResponse?> GetByIdAsync(int id, CancellationToken ct = default)
    {
        var route = await _routeRepository.GetByIdAsync(id, ct);
        if (route == null)
            return null;

        var input = SensitiveFlow.Input(Source, "RouteLookup", "PublicUser");
        return (await ToPublicResponsesAsync(new[] { route }, input, ct))[0];
    }

    public async Task<PagedResult<RouteResponse>> GetAllAsync(int page = 1, int pageSize = 10, CancellationToken ct = default)
    {
        var total = await _routeRepository.CountAsync(ct);
        var routes = await _routeRepository.GetAllAsync(page, pageSize, ct);
        var input = SensitiveFlow.Input(Source, "RouteListing", "PublicUser");
        return new PagedResult<RouteResponse>(await ToPublicResponsesAsync(routes, input, ct), total, page, pageSize);
    }

    public async Task<IReadOnlyList<RouteResponse>> GetByCitizenIdAsync(int citizenId, CancellationToken ct = default)
    {
        var routes = await _routeRepository.GetByCitizenIdAsync(citizenId, ct);
        var input = SensitiveFlow.Input(Source, "RouteListing", $"Citizen:{citizenId}");
        return await ToPublicResponsesAsync(routes, input, ct);
    }

    public async Task<RouteResponse> UpdateAsync(int id, UpdateRouteRequest request, CancellationToken ct = default)
    {
        var route = await FindAsync(id, ct);

        var input = SensitiveFlow.Input(Source, "RouteUpdate", $"Citizen:{route.CitizenId}");
        var stored = await ReleaseForStorageAsync(_taintTracker.TaintAnnotatedFields(request, input), input, ct);

        route.Update(
            request.Name,
            stored.Origin, stored.Destination,
            stored.OriginLatitude, stored.OriginLongitude,
            stored.DestinationLatitude, stored.DestinationLongitude);

        await _routeRepository.UpdateAsync(route, ct);
        return (await ToPublicResponsesAsync(new[] { route }, input, ct))[0];
    }

    public async Task<RouteResponse> SetMonitoringAsync(int id, bool isActive, CancellationToken ct = default)
    {
        var route = await FindAsync(id, ct);

        if (isActive)
            route.ActivateMonitoring();
        else
            route.DeactivateMonitoring();

        await _routeRepository.UpdateAsync(route, ct);

        var input = SensitiveFlow.Input(Source, "RouteMonitoring", $"Citizen:{route.CitizenId}");
        return (await ToPublicResponsesAsync(new[] { route }, input, ct))[0];
    }

    public async Task DeleteAsync(int id, CancellationToken ct = default)
    {
        await _routeRepository.DeleteAsync(await FindAsync(id, ct), ct);
    }

    public async Task<RouteRiskAnalysisResponse> AnalyzeRiskAsync(int id, double? radiusMeters = null, CancellationToken ct = default)
    {
        var route = await FindAsync(id, ct);
        var radius = _finder.ResolveRadius(radiusMeters);

        var context = new DataFlowContext
        {
            Source = $"{Source}/{{id}}/risk",
            Purpose = "RouteRiskAnalysis",
            Actor = "RiskEngine",
            IsAuthorized = true
        };
        var segment = (await _taintTracker.ReleaseForInternalUseAsync(new[] { route }, context, ct))[0];

        var nearby = (await _finder.FindAsync(segment, radius, ct))
            .Select(NearbyOccurrenceResponse.From)
            .ToList();

        // A ausência de registro não garante que o caminho esteja livre: a mensagem diz só o que se sabe.
        var message = nearby.Count == 0
            ? $"Nenhuma ocorrência ativa registrada a até {radius:0} m deste trajeto. Isso reflete apenas os registros existentes e não garante que o caminho esteja livre de alagamento."
            : $"{nearby.Count} {(nearby.Count == 1 ? "ocorrência ativa registrada" : "ocorrências ativas registradas")} a até {radius:0} m deste trajeto. " +
              $"Maior severidade: {SeverityText.Of(nearby.Max(n => n.Severity))}.";

        return new RouteRiskAnalysisResponse
        {
            RouteId = route.Id,
            RouteName = route.Name,
            RadiusMeters = radius,
            StatusMessage = message,
            NearbyOccurrences = nearby
        };
    }

    private async Task<Route> FindAsync(int id, CancellationToken ct) =>
        await _routeRepository.GetByIdAsync(id, ct) ?? throw new EntityNotFoundException("Trajeto", id);

    private sealed record StoredRoute(
        string Origin, string Destination,
        double OriginLatitude, double OriginLongitude,
        double DestinationLatitude, double DestinationLongitude);

    /// <summary>Entrega os campos rotulados ao destino Database e devolve só o que a política liberou.</summary>
    private async Task<StoredRoute> ReleaseForStorageAsync(
        IReadOnlyDictionary<string, Tainted<string>> fields, DataFlowContext input, CancellationToken ct)
    {
        var names = new[]
        {
            nameof(CreateRouteRequest.Origin), nameof(CreateRouteRequest.Destination),
            nameof(CreateRouteRequest.OriginLatitude), nameof(CreateRouteRequest.OriginLongitude),
            nameof(CreateRouteRequest.DestinationLatitude), nameof(CreateRouteRequest.DestinationLongitude)
        };

        var released = await _taintTracker.ReleaseManyAsync(
            names.Select(n => fields[n]).ToList(), SinkType.Database, SensitiveFlow.Persistence(input), ct);

        return new StoredRoute(
            released[0], released[1],
            RouteCoordinates.Parse(released[2]), RouteCoordinates.Parse(released[3]),
            RouteCoordinates.Parse(released[4]), RouteCoordinates.Parse(released[5]));
    }

    /// <summary>
    /// Na resposta pública, endereços e coordenadas saem generalizados: endereço sem logradouro e
    /// coordenadas com 2 casas decimais (cerca de 1 km). O valor exato fica só no banco.
    /// </summary>
    private async Task<List<RouteResponse>> ToPublicResponsesAsync(
        IReadOnlyList<Route> routes, DataFlowContext input, CancellationToken ct)
    {
        if (routes.Count == 0)
            return new List<RouteResponse>();

        var tainted = routes
            .SelectMany(r => new[]
            {
                r.Origin, r.Destination,
                RouteCoordinates.Format(r.OriginLatitude), RouteCoordinates.Format(r.OriginLongitude),
                RouteCoordinates.Format(r.DestinationLatitude), RouteCoordinates.Format(r.DestinationLongitude)
            })
            .Select(value => _taintTracker.Taint(value, input, DataCategory.Location, DataSensitivity.Medium))
            .ToList();

        var released = await _taintTracker.ReleaseManyAsync(
            tainted, SinkType.PublicHttpResponse, SensitiveFlow.PublicResponse(input), ct);

        return routes.Select((route, i) =>
        {
            var o = i * FieldsPerRoute;
            return new RouteResponse
            {
                Id = route.Id,
                CitizenId = route.CitizenId,
                Name = route.Name,
                Origin = released[o],
                Destination = released[o + 1],
                OriginLatitude = RouteCoordinates.Parse(released[o + 2]),
                OriginLongitude = RouteCoordinates.Parse(released[o + 3]),
                DestinationLatitude = RouteCoordinates.Parse(released[o + 4]),
                DestinationLongitude = RouteCoordinates.Parse(released[o + 5]),
                IsMonitoringActive = route.IsMonitoringActive,
                CreatedAt = route.CreatedAt
            };
        }).ToList();
    }
}

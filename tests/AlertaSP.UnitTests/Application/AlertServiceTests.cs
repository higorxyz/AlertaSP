using AlertaSP.Application.Proximity;
using AlertaSP.Application.Services;
using AlertaSP.Core.Entities;
using AlertaSP.Core.Enums;
using AlertaSP.Core.Exceptions;
using AlertaSP.Infrastructure.Repositories;
using AlertaSP.UnitTests.Support;
using Microsoft.Extensions.Options;

namespace AlertaSP.UnitTests.Application;

public class AlertServiceTests : IDisposable
{
    // Trajeto Liberdade → Consolação, aproximado por um segmento reto.
    private const double OriginLat = -23.565, OriginLon = -46.640, DestLat = -23.555, DestLon = -46.660;

    private readonly SqliteTestDatabase _db = new();
    private readonly FakeAuditSink _audit = new();
    private readonly FakeIncidentRepository _incidents = new();
    private readonly AlertService _service;
    private readonly int _citizenId;

    public AlertServiceTests()
    {
        var finder = new NearbyOccurrenceFinder(
            new FloodOccurrenceRepository(_db.Context), Options.Create(new ProximityOptions { NearbyRadiusMeters = 500 }));

        _service = new AlertService(
            new AlertRepository(_db.Context),
            new RouteRepository(_db.Context),
            finder,
            TestSecurity.CreateTracker(_audit, _incidents));

        var citizen = Citizen.Create("Cidadã Teste", "enc_cpf", "hash_cpf", "enc_email", "enc_address");
        _db.Context.Citizens.Add(citizen);
        _db.Context.SaveChanges();
        _citizenId = citizen.Id;
    }

    public void Dispose() => _db.Dispose();

    private Route AddRoute(string name = "Casa -> Trabalho", bool monitored = true)
    {
        var route = Route.Create(_citizenId, name, "Liberdade", "Consolação", OriginLat, OriginLon, DestLat, DestLon);
        if (!monitored)
            route.DeactivateMonitoring();

        _db.Context.Routes.Add(route);
        _db.Context.SaveChanges();
        return route;
    }

    private FloodOccurrence AddOccurrence(double lat, double lon, bool resolved = false)
    {
        var occurrence = FloodOccurrence.Create("Trecho de teste", lat, lon, "Via alagada", Severity.Alto);
        if (resolved)
            occurrence.Resolve();

        _db.Context.FloodOccurrences.Add(occurrence);
        _db.Context.SaveChanges();
        return occurrence;
    }

    [Fact]
    public async Task Generate_AlertsOnlyMonitoredRoutesNearActiveOccurrences()
    {
        var monitored = AddRoute();
        AddRoute("Casa -> Faculdade", monitored: false);
        var onTheRoute = AddOccurrence(-23.560, -46.650);
        AddOccurrence(-23.561, -46.649, resolved: true);

        var result = await _service.GenerateRouteAlertsAsync();

        var alert = Assert.Single(result.GeneratedAlerts);
        Assert.Equal(monitored.Id, alert.RouteId);
        Assert.Equal(onTheRoute.Id, alert.OccurrenceId);
        Assert.Equal(1, result.RoutesMonitored);
        Assert.Equal(500, result.RadiusMeters);
    }

    [Fact]
    public async Task Generate_RunTwice_DoesNotDuplicateAlerts()
    {
        AddRoute();
        AddOccurrence(-23.560, -46.650);

        var first = await _service.GenerateRouteAlertsAsync();
        var second = await _service.GenerateRouteAlertsAsync();

        Assert.Equal(1, first.AlertsGenerated);
        Assert.Equal(0, second.AlertsGenerated);
        Assert.Equal(1, _db.Context.Alerts.Count());
    }

    [Fact]
    public async Task Generate_UsesTheConfiguredRadiusUnlessOneIsGiven()
    {
        AddRoute();
        AddOccurrence(OriginLat - 0.0072, OriginLon); // cerca de 800 m ao sul da origem

        var withDefault = await _service.GenerateRouteAlertsAsync();
        var withWiderRadius = await _service.GenerateRouteAlertsAsync(radiusMeters: 1000);

        Assert.Equal(0, withDefault.AlertsGenerated);
        Assert.Equal(1, withWiderRadius.AlertsGenerated);
        Assert.Contains("a cerca de 80", withWiderRadius.GeneratedAlerts[0].Message);
    }

    [Fact]
    public async Task Generate_ReadsRouteCoordinatesAsAuditedInternalUse()
    {
        AddRoute();
        AddRoute("Casa -> Faculdade");

        await _service.GenerateRouteAlertsAsync();

        var audit = Assert.Single(_audit.RecordedEvents);
        Assert.Equal("/api/alerts/generate", audit.Source);
        Assert.Equal(SinkType.InternalHttpResponse, audit.SinkType);
        Assert.Equal(DataCategory.Location, audit.Category);
        Assert.Equal(PolicyDecision.Allow, audit.Decision);
        Assert.Contains("Quantidade: 8", audit.Summary);
        Assert.Empty(_incidents.RecordedIncidents);
    }

    [Fact]
    public async Task MarkAsRead_UnknownAlert_ThrowsNotFound()
    {
        await Assert.ThrowsAsync<EntityNotFoundException>(() => _service.MarkAsReadAsync(999));
    }
}

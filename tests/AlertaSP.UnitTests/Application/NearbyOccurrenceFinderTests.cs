using AlertaSP.Application.Proximity;
using AlertaSP.Core.Entities;
using AlertaSP.Core.Enums;
using AlertaSP.Infrastructure.Repositories;
using AlertaSP.UnitTests.Support;
using Microsoft.Extensions.Options;

namespace AlertaSP.UnitTests.Application;

public class NearbyOccurrenceFinderTests : IDisposable
{
    private static readonly GeoSegment Route = new(-23.565, -46.640, -23.555, -46.660);

    private readonly SqliteTestDatabase _db = new();
    private readonly NearbyOccurrenceFinder _finder;

    public NearbyOccurrenceFinderTests()
    {
        _finder = new NearbyOccurrenceFinder(
            new FloodOccurrenceRepository(_db.Context), Options.Create(new ProximityOptions { NearbyRadiusMeters = 500 }));
    }

    public void Dispose() => _db.Dispose();

    private FloodOccurrence Add(string location, double lat, double lon, bool resolved = false)
    {
        var occurrence = FloodOccurrence.Create(location, lat, lon, "Teste", Severity.Moderado);
        if (resolved)
            occurrence.Resolve();
        _db.Context.FloodOccurrences.Add(occurrence);
        _db.Context.SaveChanges();
        return occurrence;
    }

    [Fact]
    public async Task Find_ReturnsActiveOccurrencesInsideTheRadius_NearestFirst()
    {
        Add("Perto do fim", -23.5550, -46.6580); // fora do segmento, a menos de 200 m dele
        Add("Sobre o meio", -23.5600, -46.6500);
        Add("Resolvida", -23.5600, -46.6501, resolved: true);
        Add("Longe", -23.6000, -46.7000);

        var result = await _finder.FindAsync(Route, 500);

        Assert.Equal(new[] { "Sobre o meio", "Perto do fim" }, result.Select(r => r.Occurrence.Location));
        Assert.True(result[0].DistanceMeters <= result[1].DistanceMeters);
    }

    [Fact]
    public async Task Find_PointInsideTheBoundingBoxButOutsideTheRadius_IsDiscarded()
    {
        // A caixa delimitadora é um retângulo; este ponto fica no canto dela, a mais de 500 m do segmento.
        var (_, maxLat, minLon, _) = GeoDistanceCalculator.GetSegmentBoundingBox(-23.565, -46.640, -23.555, -46.660, 500);
        Add("Canto da caixa", maxLat - 0.0001, minLon + 0.0001);

        var result = await _finder.FindAsync(Route, 500);

        Assert.Empty(result);
    }

    [Fact]
    public async Task Find_AroundAPoint_UsesTheSameRules()
    {
        Add("Ao lado", -23.5601, -46.6501);

        var result = await _finder.FindAsync(GeoSegment.Point(-23.5600, -46.6500), 100);

        var match = Assert.Single(result);
        Assert.InRange(match.DistanceMeters, 0, 20);
    }

    [Theory]
    [InlineData(null, 500.0)]
    [InlineData(1200.0, 1200.0)]
    public void ResolveRadius_FallsBackToTheConfiguredDefault(double? requested, double expected)
    {
        Assert.Equal(expected, _finder.ResolveRadius(requested));
    }
}

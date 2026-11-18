using AlertaSP.Application.Proximity;
using Xunit;

namespace AlertaSP.UnitTests.Application;

public class GeoDistanceCalculatorTests
{
    // Coordenadas reais de São Paulo para teste
    // Ponto A: MASP (Av. Paulista, -23.5614, -46.6559)
    // Ponto B: Faria Lima / Rebouças (-23.5714, -46.6890)
    private const double MaspLat = -23.5614;
    private const double MaspLon = -46.6559;
    private const double FariaLimaLat = -23.5714;
    private const double FariaLimaLon = -46.6890;

    [Fact]
    public void DistanceBetweenPoints_SamePoint_ReturnsZero()
    {
        double dist = GeoDistanceCalculator.DistanceBetweenPointsMeters(MaspLat, MaspLon, MaspLat, MaspLon);
        Assert.True(dist < 0.01);
    }

    [Fact]
    public void DistanceBetweenPoints_KnownDistance_ReturnsRealisticValue()
    {
        // Distância MASP até Faria Lima em linha reta é aproximadamente 3.5 km (+/- 300m)
        double dist = GeoDistanceCalculator.DistanceBetweenPointsMeters(MaspLat, MaspLon, FariaLimaLat, FariaLimaLon);
        Assert.InRange(dist, 3200, 3800);
    }

    [Fact]
    public void DistancePointToSegment_PointDirectlyOnSegment_ReturnsZero()
    {
        // Ponto C exatamente no ponto médio entre A e B
        double midLat = (MaspLat + FariaLimaLat) / 2.0;
        double midLon = (MaspLon + FariaLimaLon) / 2.0;

        double dist = GeoDistanceCalculator.DistancePointToSegmentMeters(
            midLat, midLon,
            MaspLat, MaspLon,
            FariaLimaLat, FariaLimaLon
        );

        Assert.True(dist < 1.0); // Praticamente 0 metros
    }

    [Fact]
    public void DistancePointToSegment_PointNearSegment_ReturnsAccurateDistance()
    {
        // Ponto deslocado ~200 metros para o norte do meio do trajeto
        double midLat = (MaspLat + FariaLimaLat) / 2.0 + 0.0018; // ~200m
        double midLon = (MaspLon + FariaLimaLon) / 2.0;

        double dist = GeoDistanceCalculator.DistancePointToSegmentMeters(
            midLat, midLon,
            MaspLat, MaspLon,
            FariaLimaLat, FariaLimaLon
        );

        Assert.InRange(dist, 180, 220);
    }

    [Fact]
    public void DistancePointToSegment_PointFarAway_ReturnsLargeDistance()
    {
        // Ponto na Zona Norte (Marginal Tietê, -23.5150, -46.6250)
        double dist = GeoDistanceCalculator.DistancePointToSegmentMeters(
            -23.5150, -46.6250,
            MaspLat, MaspLon,
            FariaLimaLat, FariaLimaLon
        );

        // Mais de 5 km de distância
        Assert.True(dist > 5000);
    }

    [Fact]
    public void GetSegmentBoundingBox_ContainsBothEndpointsPlusMargin()
    {
        var (minLat, maxLat, minLon, maxLon) = GeoDistanceCalculator.GetSegmentBoundingBox(
            MaspLat, MaspLon, FariaLimaLat, FariaLimaLon, 500
        );

        Assert.True(minLat < Math.Min(MaspLat, FariaLimaLat));
        Assert.True(maxLat > Math.Max(MaspLat, FariaLimaLat));
        Assert.True(minLon < Math.Min(MaspLon, FariaLimaLon));
        Assert.True(maxLon > Math.Max(MaspLon, FariaLimaLon));
    }
}

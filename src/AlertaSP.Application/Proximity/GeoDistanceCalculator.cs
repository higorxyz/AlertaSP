namespace AlertaSP.Application.Proximity;

/// <summary>
/// Distâncias em metros com projeção equiretangular local (plano tangente na latitude média, raio
/// terrestre de 6.371 km). O erro é desprezível nas distâncias de uma cidade; para centenas de
/// quilômetros seria preciso usar a fórmula de haversine.
/// </summary>
public static class GeoDistanceCalculator
{
    private const double EarthRadiusMeters = 6_371_000.0;
    private const double DegToRad = Math.PI / 180.0;

    /// <summary>Converte (lat, lon) em metros num plano centrado na latitude de referência.</summary>
    public static (double x, double y) ToCartesianMeters(double lat, double lon, double refLatRad)
    {
        double x = lon * DegToRad * EarthRadiusMeters * Math.Cos(refLatRad);
        double y = lat * DegToRad * EarthRadiusMeters;
        return (x, y);
    }

    public static double DistanceBetweenPointsMeters(double lat1, double lon1, double lat2, double lon2)
    {
        double refLatRad = ((lat1 + lat2) / 2.0) * DegToRad;
        var (x1, y1) = ToCartesianMeters(lat1, lon1, refLatRad);
        var (x2, y2) = ToCartesianMeters(lat2, lon2, refLatRad);
        return Math.Sqrt((x2 - x1) * (x2 - x1) + (y2 - y1) * (y2 - y1));
    }

    /// <summary>
    /// Menor distância do ponto P ao segmento AB. Se a projeção de P cair fora do segmento, a distância
    /// é até a extremidade mais próxima.
    /// </summary>
    public static double DistancePointToSegmentMeters(
        double pointLat, double pointLon,
        double segStartLat, double segStartLon,
        double segEndLat, double segEndLon)
    {
        double refLatRad = ((pointLat + segStartLat + segEndLat) / 3.0) * DegToRad;

        var (px, py) = ToCartesianMeters(pointLat, pointLon, refLatRad);
        var (ax, ay) = ToCartesianMeters(segStartLat, segStartLon, refLatRad);
        var (bx, by) = ToCartesianMeters(segEndLat, segEndLon, refLatRad);

        double abx = bx - ax;
        double aby = by - ay;
        double lengthSquared = abx * abx + aby * aby;

        // Origem e destino no mesmo ponto: vira distância entre dois pontos.
        if (lengthSquared < 1e-6)
            return Math.Sqrt((px - ax) * (px - ax) + (py - ay) * (py - ay));

        // t = (AP · AB) / |AB|², limitado a [0, 1] para ficar dentro do segmento.
        double t = Math.Clamp(((px - ax) * abx + (py - ay) * aby) / lengthSquared, 0.0, 1.0);

        double dx = px - (ax + t * abx);
        double dy = py - (ay + t * aby);
        return Math.Sqrt(dx * dx + dy * dy);
    }

    /// <summary>
    /// Caixa (minLat, maxLat, minLon, maxLon) que envolve o segmento com uma margem em metros. Serve de
    /// filtro barato no banco antes do cálculo exato.
    /// </summary>
    public static (double minLat, double maxLat, double minLon, double maxLon) GetSegmentBoundingBox(
        double lat1, double lon1, double lat2, double lon2, double marginMeters)
    {
        double latDelta = (marginMeters / EarthRadiusMeters) * (180.0 / Math.PI);
        double cosLat = Math.Max(0.01, Math.Cos(((lat1 + lat2) / 2.0) * DegToRad));
        double lonDelta = (marginMeters / (EarthRadiusMeters * cosLat)) * (180.0 / Math.PI);

        return (
            Math.Min(lat1, lat2) - latDelta,
            Math.Max(lat1, lat2) + latDelta,
            Math.Min(lon1, lon2) - lonDelta,
            Math.Max(lon1, lon2) + lonDelta);
    }
}

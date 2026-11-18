using AlertaSP.Core.Entities;
using AlertaSP.Core.Enums;
using AlertaSP.Core.Interfaces;
using Microsoft.Extensions.Options;

namespace AlertaSP.Application.Proximity;

/// <summary>Trecho reto entre dois pontos; é como o trajeto é modelado no cálculo de proximidade.</summary>
public readonly record struct GeoSegment(double StartLatitude, double StartLongitude, double EndLatitude, double EndLongitude)
{
    public static GeoSegment Point(double latitude, double longitude) => new(latitude, longitude, latitude, longitude);
}

public sealed record NearbyOccurrence(FloodOccurrence Occurrence, double DistanceMeters);

public interface INearbyOccurrenceFinder
{
    /// <summary>Raio pedido ou, se nulo, o padrão da configuração.</summary>
    double ResolveRadius(double? requestedMeters);

    /// <summary>Ocorrências ativas a até <paramref name="radiusMeters"/> do segmento, da mais próxima para a mais distante.</summary>
    Task<IReadOnlyList<NearbyOccurrence>> FindAsync(GeoSegment segment, double radiusMeters, CancellationToken ct = default);
}

/// <summary>
/// Busca em duas etapas: uma caixa delimitadora filtra os candidatos no banco (consulta LINQ traduzida
/// para SQL) e a distância ponto–segmento é calculada só para eles, em memória.
/// </summary>
public class NearbyOccurrenceFinder : INearbyOccurrenceFinder
{
    private readonly IFloodOccurrenceRepository _occurrences;
    private readonly double _defaultRadius;

    public NearbyOccurrenceFinder(IFloodOccurrenceRepository occurrences, IOptions<ProximityOptions> options)
    {
        _occurrences = occurrences;
        _defaultRadius = options.Value.NearbyRadiusMeters;
    }

    public double ResolveRadius(double? requestedMeters) => requestedMeters ?? _defaultRadius;

    public async Task<IReadOnlyList<NearbyOccurrence>> FindAsync(GeoSegment segment, double radiusMeters, CancellationToken ct = default)
    {
        var (minLat, maxLat, minLon, maxLon) = GeoDistanceCalculator.GetSegmentBoundingBox(
            segment.StartLatitude, segment.StartLongitude, segment.EndLatitude, segment.EndLongitude, radiusMeters);

        var candidates = await _occurrences.GetInBoundingBoxAsync(minLat, maxLat, minLon, maxLon, OccurrenceStatus.Ativa, ct);

        return candidates
            .Select(occurrence => new NearbyOccurrence(occurrence, GeoDistanceCalculator.DistancePointToSegmentMeters(
                occurrence.Latitude, occurrence.Longitude,
                segment.StartLatitude, segment.StartLongitude,
                segment.EndLatitude, segment.EndLongitude)))
            .Where(n => n.DistanceMeters <= radiusMeters)
            .OrderBy(n => n.DistanceMeters)
            .ToList();
    }
}

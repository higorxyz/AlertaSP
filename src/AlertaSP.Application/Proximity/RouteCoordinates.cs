using System.Globalization;
using AlertaSP.Core.Enums;
using AlertaSP.Core.Interfaces.Security;

namespace AlertaSP.Application.Proximity;

/// <summary>
/// As coordenadas exatas de um trajeto revelam a rotina do cidadão. Depois de decifradas, elas passam pelo
/// rastreador como uso interno: a política só libera com ator autorizado e finalidade declarada, e a decisão
/// fica na trilha de auditoria.
/// </summary>
internal static class RouteCoordinates
{
    public static async Task<IReadOnlyList<GeoSegment>> ReleaseForInternalUseAsync(
        this ITaintTracker tracker, IReadOnlyList<RouteLocation> locations, DataFlowContext context, CancellationToken ct)
    {
        if (locations.Count == 0)
            return Array.Empty<GeoSegment>();

        var tainted = locations
            .Select(l => l.Segment)
            .SelectMany(s => new[] { s.StartLatitude, s.StartLongitude, s.EndLatitude, s.EndLongitude })
            .Select(value => tracker.Taint(Format(value), context, DataCategory.Location, DataSensitivity.Medium))
            .ToList();

        var released = await tracker.ReleaseManyAsync(tainted, SinkType.InternalHttpResponse, context, ct);

        return Enumerable.Range(0, locations.Count)
            .Select(i => new GeoSegment(
                Parse(released[i * 4]), Parse(released[i * 4 + 1]),
                Parse(released[i * 4 + 2]), Parse(released[i * 4 + 3])))
            .ToList();
    }

    public static string Format(double value) => value.ToString("R", CultureInfo.InvariantCulture);

    public static double Parse(string value) => double.Parse(value, NumberStyles.Float, CultureInfo.InvariantCulture);
}

using System.Globalization;
using AlertaSP.Core.Entities;
using AlertaSP.Core.Exceptions;
using AlertaSP.Core.Interfaces;

namespace AlertaSP.Application.Proximity;

/// <summary>Origem, destino e coordenadas do trajeto em claro. Só existe em memória, durante o caso de uso.</summary>
public sealed record RouteLocation(string Origin, string Destination, GeoSegment Segment)
{
    public static RouteLocation Create(string origin, string destination,
        double originLat, double originLon, double destLat, double destLon)
    {
        if (string.IsNullOrWhiteSpace(origin) || string.IsNullOrWhiteSpace(destination))
            throw new DomainException("Origem e destino do trajeto são obrigatórios.");

        Coordinates.EnsureValid(originLat, originLon, "origem");
        Coordinates.EnsureValid(destLat, destLon, "destino");

        return new RouteLocation(origin.Trim(), destination.Trim(), new GeoSegment(originLat, originLon, destLat, destLon));
    }
}

/// <summary>
/// Cifra a localização do trajeto antes de gravar e decifra ao ler. As quatro coordenadas vão juntas num
/// único valor cifrado; a busca por proximidade não filtra trajetos por coordenada no banco, então elas
/// não precisam ficar em claro.
/// </summary>
public class RouteLocationProtector
{
    private const char Separator = ';';

    private readonly ICryptoService _crypto;

    public RouteLocationProtector(ICryptoService crypto)
    {
        _crypto = crypto;
    }

    public EncryptedRouteLocation Protect(RouteLocation location)
    {
        var s = location.Segment;
        var coordinates = string.Join(Separator,
            new[] { s.StartLatitude, s.StartLongitude, s.EndLatitude, s.EndLongitude }
                .Select(v => v.ToString("R", CultureInfo.InvariantCulture)));

        return new EncryptedRouteLocation(
            _crypto.Encrypt(location.Origin),
            _crypto.Encrypt(location.Destination),
            _crypto.Encrypt(coordinates));
    }

    public RouteLocation Unprotect(Route route)
    {
        var parts = _crypto.Decrypt(route.EncryptedCoordinates).Split(Separator);
        if (parts.Length != 4)
            throw new InvalidOperationException($"Coordenadas do trajeto {route.Id} em formato inesperado.");

        var v = parts.Select(p => double.Parse(p, NumberStyles.Float, CultureInfo.InvariantCulture)).ToArray();
        return new RouteLocation(
            _crypto.Decrypt(route.EncryptedOrigin),
            _crypto.Decrypt(route.EncryptedDestination),
            new GeoSegment(v[0], v[1], v[2], v[3]));
    }
}

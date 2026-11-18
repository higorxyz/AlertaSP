using AlertaSP.Core.Exceptions;

namespace AlertaSP.Core.Entities;

/// <summary>
/// Trajeto do cidadão (ex.: Casa → Trabalho). Para o cálculo de proximidade, o trajeto é aproximado
/// por um segmento reto entre origem e destino.
/// </summary>
public class Route
{
    public int Id { get; private set; }
    public int CitizenId { get; private set; }
    public string Name { get; private set; } = string.Empty;
    public string Origin { get; private set; } = string.Empty;
    public string Destination { get; private set; } = string.Empty;
    public double OriginLatitude { get; private set; }
    public double OriginLongitude { get; private set; }
    public double DestinationLatitude { get; private set; }
    public double DestinationLongitude { get; private set; }
    public bool IsMonitoringActive { get; private set; }
    public DateTime CreatedAt { get; private set; }

    public Citizen Citizen { get; private set; } = null!;

    private Route() { }

    public static Route Create(
        int citizenId, string name,
        string origin, string destination,
        double originLat, double originLon,
        double destLat, double destLon)
    {
        if (citizenId <= 0)
            throw new DomainException("O trajeto precisa pertencer a um cidadão.");

        var route = new Route
        {
            CitizenId = citizenId,
            IsMonitoringActive = true,
            CreatedAt = DateTime.UtcNow
        };
        route.Update(name, origin, destination, originLat, originLon, destLat, destLon);
        return route;
    }

    public void Update(string name, string origin, string destination,
        double originLat, double originLon, double destLat, double destLon)
    {
        if (string.IsNullOrWhiteSpace(name))
            throw new DomainException("O nome do trajeto é obrigatório.");
        if (string.IsNullOrWhiteSpace(origin) || string.IsNullOrWhiteSpace(destination))
            throw new DomainException("Origem e destino do trajeto são obrigatórios.");

        Coordinates.EnsureValid(originLat, originLon, "origem");
        Coordinates.EnsureValid(destLat, destLon, "destino");

        Name = name.Trim();
        Origin = origin.Trim();
        Destination = destination.Trim();
        OriginLatitude = originLat;
        OriginLongitude = originLon;
        DestinationLatitude = destLat;
        DestinationLongitude = destLon;
    }

    public void ActivateMonitoring() => IsMonitoringActive = true;
    public void DeactivateMonitoring() => IsMonitoringActive = false;
}

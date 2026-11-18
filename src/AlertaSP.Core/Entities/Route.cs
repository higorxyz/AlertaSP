using AlertaSP.Core.Exceptions;

namespace AlertaSP.Core.Entities;

/// <summary>
/// Trajeto do cidadão (ex.: Casa → Trabalho). Origem, destino e coordenadas revelam onde a pessoa mora e
/// trabalha, por isso chegam aqui já cifrados (<see cref="EncryptedRouteLocation"/>), como CPF e endereço
/// em <see cref="Citizen"/>. A entidade nunca vê esses valores em claro.
/// </summary>
public class Route
{
    public int Id { get; private set; }
    public int CitizenId { get; private set; }
    public string Name { get; private set; } = string.Empty;
    public string EncryptedOrigin { get; private set; } = string.Empty;
    public string EncryptedDestination { get; private set; } = string.Empty;
    public string EncryptedCoordinates { get; private set; } = string.Empty;
    public bool IsMonitoringActive { get; private set; }
    public DateTime CreatedAt { get; private set; }

    public Citizen Citizen { get; private set; } = null!;

    private Route() { }

    public static Route Create(int citizenId, string name, EncryptedRouteLocation location)
    {
        if (citizenId <= 0)
            throw new DomainException("O trajeto precisa pertencer a um cidadão.");

        var route = new Route
        {
            CitizenId = citizenId,
            IsMonitoringActive = true,
            CreatedAt = DateTime.UtcNow
        };
        route.Update(name, location);
        return route;
    }

    public void Update(string name, EncryptedRouteLocation location)
    {
        ArgumentNullException.ThrowIfNull(location);

        if (string.IsNullOrWhiteSpace(name))
            throw new DomainException("O nome do trajeto é obrigatório.");

        Name = name.Trim();
        EncryptedOrigin = location.Origin;
        EncryptedDestination = location.Destination;
        EncryptedCoordinates = location.Coordinates;
    }

    public EncryptedRouteLocation Location => new(EncryptedOrigin, EncryptedDestination, EncryptedCoordinates);

    public void ActivateMonitoring() => IsMonitoringActive = true;
    public void DeactivateMonitoring() => IsMonitoringActive = false;
}

/// <summary>Origem, destino e coordenadas do trajeto, já cifrados para gravação.</summary>
public sealed record EncryptedRouteLocation
{
    public string Origin { get; }
    public string Destination { get; }
    public string Coordinates { get; }

    public EncryptedRouteLocation(string origin, string destination, string coordinates)
    {
        if (string.IsNullOrWhiteSpace(origin) || string.IsNullOrWhiteSpace(destination) || string.IsNullOrWhiteSpace(coordinates))
            throw new DomainException("Origem, destino e coordenadas do trajeto são obrigatórios.");

        Origin = origin;
        Destination = destination;
        Coordinates = coordinates;
    }
}

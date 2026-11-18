using AlertaSP.Core.Enums;
using AlertaSP.Core.Exceptions;

namespace AlertaSP.Core.Entities;

public class FloodOccurrence
{
    public int Id { get; private set; }
    public string Location { get; private set; } = string.Empty;
    public double Latitude { get; private set; }
    public double Longitude { get; private set; }
    public string Description { get; private set; } = string.Empty;
    public Severity Severity { get; private set; }
    public DateTime OccurredAt { get; private set; }
    public OccurrenceStatus Status { get; private set; }

    /// <summary>Marca ocorrências criadas só para demonstração, para separá-las de registros reais.</summary>
    public bool IsDemo { get; private set; }

    private FloodOccurrence() { }

    public static FloodOccurrence Create(
        string location, double latitude, double longitude,
        string description, Severity severity, bool isDemo = false)
    {
        if (string.IsNullOrWhiteSpace(location))
            throw new DomainException("A localização da ocorrência é obrigatória.");
        if (string.IsNullOrWhiteSpace(description))
            throw new DomainException("A descrição da ocorrência é obrigatória.");
        if (!Enum.IsDefined(severity))
            throw new DomainException("Severidade inválida.");

        Coordinates.EnsureValid(latitude, longitude, "ocorrência");

        return new FloodOccurrence
        {
            Location = location.Trim(),
            Latitude = latitude,
            Longitude = longitude,
            Description = description.Trim(),
            Severity = severity,
            OccurredAt = DateTime.UtcNow,
            Status = OccurrenceStatus.Ativa,
            IsDemo = isDemo
        };
    }

    public bool IsActive => Status == OccurrenceStatus.Ativa;

    public void Resolve() => Status = OccurrenceStatus.Resolvida;
    public void Reactivate() => Status = OccurrenceStatus.Ativa;
}

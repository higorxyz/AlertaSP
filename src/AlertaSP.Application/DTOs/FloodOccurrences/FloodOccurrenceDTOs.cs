using System.ComponentModel.DataAnnotations;
using AlertaSP.Application.Proximity;
using AlertaSP.Core.Entities;
using AlertaSP.Core.Enums;

namespace AlertaSP.Application.DTOs.FloodOccurrences;

public class CreateFloodOccurrenceRequest
{
    [Required(ErrorMessage = "A localização é obrigatória.")]
    [StringLength(500, MinimumLength = 3, ErrorMessage = "A localização deve ter entre 3 e 500 caracteres.")]
    public string Location { get; set; } = string.Empty;

    [Range(-90.0, 90.0, ErrorMessage = "A latitude deve estar entre -90 e 90.")]
    public double Latitude { get; set; }

    [Range(-180.0, 180.0, ErrorMessage = "A longitude deve estar entre -180 e 180.")]
    public double Longitude { get; set; }

    [Required(ErrorMessage = "A descrição é obrigatória.")]
    [StringLength(2000, MinimumLength = 5, ErrorMessage = "A descrição deve ter entre 5 e 2000 caracteres.")]
    public string Description { get; set; } = string.Empty;

    [EnumDataType(typeof(Severity), ErrorMessage = "Severidade inválida. Use Baixo, Moderado, Alto ou Critico.")]
    public Severity Severity { get; set; }

    public bool IsDemo { get; set; }
}

public class UpdateOccurrenceStatusRequest
{
    [EnumDataType(typeof(OccurrenceStatus), ErrorMessage = "Status inválido. Use Ativa ou Resolvida.")]
    public OccurrenceStatus Status { get; set; }
}

public class FloodOccurrenceResponse
{
    public int Id { get; init; }
    public string Location { get; init; } = string.Empty;
    public double Latitude { get; init; }
    public double Longitude { get; init; }
    public string Description { get; init; } = string.Empty;
    public Severity Severity { get; init; }
    public OccurrenceStatus Status { get; init; }
    public DateTime OccurredAt { get; init; }
    public bool IsDemo { get; init; }

    public static FloodOccurrenceResponse From(FloodOccurrence occurrence) => new()
    {
        Id = occurrence.Id,
        Location = occurrence.Location,
        Latitude = occurrence.Latitude,
        Longitude = occurrence.Longitude,
        Description = occurrence.Description,
        Severity = occurrence.Severity,
        Status = occurrence.Status,
        OccurredAt = occurrence.OccurredAt,
        IsDemo = occurrence.IsDemo
    };
}

public class NearbyOccurrenceResponse
{
    public int OccurrenceId { get; init; }
    public string Location { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public Severity Severity { get; init; }
    public double DistanceMeters { get; init; }
    public string Recommendation { get; init; } = string.Empty;

    public static NearbyOccurrenceResponse From(NearbyOccurrence nearby) => new()
    {
        OccurrenceId = nearby.Occurrence.Id,
        Location = nearby.Occurrence.Location,
        Description = nearby.Occurrence.Description,
        Severity = nearby.Occurrence.Severity,
        DistanceMeters = Math.Round(nearby.DistanceMeters, 1),
        Recommendation = OccurrenceRecommendation.For(nearby.Occurrence.Severity)
    };
}

public class RouteRiskAnalysisResponse
{
    public int RouteId { get; init; }
    public string RouteName { get; init; } = string.Empty;
    public double RadiusMeters { get; init; }
    public bool HasNearbyOccurrences => NearbyOccurrences.Count > 0;
    public string StatusMessage { get; init; } = string.Empty;
    public IReadOnlyList<NearbyOccurrenceResponse> NearbyOccurrences { get; init; } = Array.Empty<NearbyOccurrenceResponse>();
}

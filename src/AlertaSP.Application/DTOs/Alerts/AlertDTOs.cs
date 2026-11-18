using AlertaSP.Core.Entities;
using AlertaSP.Core.Enums;

namespace AlertaSP.Application.DTOs.Alerts;

public class GenerateAlertsResult
{
    public int AlertsGenerated { get; init; }
    public int RoutesMonitored { get; init; }
    public int OccurrencesWithinRadius { get; init; }
    public double RadiusMeters { get; init; }
    public IReadOnlyList<AlertResponse> GeneratedAlerts { get; init; } = Array.Empty<AlertResponse>();
}

public class AlertResponse
{
    public int Id { get; init; }
    public int CitizenId { get; init; }
    public int RouteId { get; init; }
    public string RouteName { get; init; } = string.Empty;
    public int OccurrenceId { get; init; }
    public string Message { get; init; } = string.Empty;
    public Severity Severity { get; init; }
    public DateTime CreatedAt { get; init; }
    public bool IsRead { get; init; }

    public static AlertResponse From(Alert alert, string routeName) => new()
    {
        Id = alert.Id,
        CitizenId = alert.CitizenId,
        RouteId = alert.RouteId,
        RouteName = routeName,
        OccurrenceId = alert.OccurrenceId,
        Message = alert.Message,
        Severity = alert.Severity,
        CreatedAt = alert.CreatedAt,
        IsRead = alert.IsRead
    };
}

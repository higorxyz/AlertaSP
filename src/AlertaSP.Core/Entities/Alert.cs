using AlertaSP.Core.Enums;
using AlertaSP.Core.Exceptions;

namespace AlertaSP.Core.Entities;

/// <summary>
/// Aviso gerado quando uma ocorrência ativa fica perto de um trajeto monitorado. O par
/// (RouteId, OccurrenceId) é único: a mesma ocorrência não gera dois alertas para o mesmo trajeto.
/// A mensagem cita o trajeto pelo nome e nunca inclui dados pessoais do cidadão.
/// </summary>
public class Alert
{
    public int Id { get; private set; }
    public int CitizenId { get; private set; }
    public int RouteId { get; private set; }
    public int OccurrenceId { get; private set; }
    public string Message { get; private set; } = string.Empty;
    public Severity Severity { get; private set; }
    public DateTime CreatedAt { get; private set; }
    public bool IsRead { get; private set; }

    public Citizen Citizen { get; private set; } = null!;
    public Route Route { get; private set; } = null!;
    public FloodOccurrence Occurrence { get; private set; } = null!;

    private Alert() { }

    public static Alert For(Route route, FloodOccurrence occurrence, double distanceMeters)
    {
        ArgumentNullException.ThrowIfNull(route);
        ArgumentNullException.ThrowIfNull(occurrence);

        if (!route.IsMonitoringActive)
            throw new DomainException("Só trajetos com monitoramento ativo recebem alertas.");
        if (!occurrence.IsActive)
            throw new DomainException("Ocorrências resolvidas não geram alertas.");

        var message =
            $"Foi registrada uma ocorrência de alagamento de severidade {SeverityText.Of(occurrence.Severity)} a cerca de " +
            $"{Math.Round(distanceMeters):0} m do trajeto '{route.Name}'. Recomendamos atenção antes de iniciar o deslocamento.";

        return new Alert
        {
            CitizenId = route.CitizenId,
            RouteId = route.Id,
            OccurrenceId = occurrence.Id,
            Message = message,
            Severity = occurrence.Severity,
            CreatedAt = DateTime.UtcNow,
            IsRead = false
        };
    }

    public void MarkAsRead() => IsRead = true;
}

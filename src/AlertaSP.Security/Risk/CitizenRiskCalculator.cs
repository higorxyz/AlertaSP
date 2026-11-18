using AlertaSP.Core.Enums;
using AlertaSP.Core.Interfaces.Security;
using Microsoft.Extensions.Options;

namespace AlertaSP.Security.Risk;

public interface ICitizenRiskCalculator
{
    CitizenRiskScore Calculate(IReadOnlyCollection<IncidentCount> incidents);
}

public class CitizenRiskScore
{
    public double RawExposure { get; init; }
    public int Score { get; init; }
    public string Classification { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public double KFactor { get; init; }
    public int IncidentCount { get; init; }
}

/// <summary>
/// Risco Cidadão = round(100 × (1 − e^(−exposição/K))), com exposição = Σ severidade × categoria × resultado.
/// Começa em 0, nunca diminui quando entra um incidente novo na janela e se aproxima de 100 sem passar.
/// Incidentes bloqueados pesam menos que exposições efetivas.
/// </summary>
public class CitizenRiskCalculator : ICitizenRiskCalculator
{
    private readonly double _k;

    public CitizenRiskCalculator(IOptions<CitizenRiskOptions> options)
    {
        _k = options.Value.CitizenRiskK;
    }

    public CitizenRiskScore Calculate(IReadOnlyCollection<IncidentCount> incidents)
    {
        var total = incidents.Sum(i => i.Count);
        var exposure = incidents.Sum(i => i.Count * Weight(i));
        var score = Math.Clamp((int)Math.Round(100.0 * (1.0 - Math.Exp(-exposure / _k))), 0, 100);

        return new CitizenRiskScore
        {
            RawExposure = Math.Round(exposure, 2),
            Score = score,
            Classification = Classify(score),
            Description = total == 0
                ? "Nenhum incidente de segurança na janela de análise."
                : $"Calculado a partir de {total} {(total == 1 ? "incidente" : "incidentes")} na janela de análise.",
            KFactor = _k,
            IncidentCount = total
        };
    }

    private static double Weight(IncidentCount incident) =>
        SeverityWeight(incident.Sensitivity) * CategoryWeight(incident.Category) * ResultWeight(incident.Result);

    private static double SeverityWeight(DataSensitivity sensitivity) => sensitivity switch
    {
        DataSensitivity.Medium => 2.0,
        DataSensitivity.High => 4.0,
        DataSensitivity.Critical => 8.0,
        _ => 1.0
    };

    private static double CategoryWeight(DataCategory category) => category switch
    {
        DataCategory.PersonalData => 1.2,
        DataCategory.HealthData => 1.3,
        DataCategory.Credentials => 1.5,
        _ => 1.0
    };

    private static double ResultWeight(IncidentResult result) => result switch
    {
        IncidentResult.Blocked => 0.3,
        IncidentResult.AllowedWithViolation => 1.0,
        _ => 0.5
    };

    /// <summary>Faixas do documento: 0–20, 21–40, 41–60, 61–80 e 81–100.</summary>
    public static string Classify(int score) => score switch
    {
        <= 20 => "Muito baixo",
        <= 40 => "Baixo",
        <= 60 => "Moderado",
        <= 80 => "Alto",
        _ => "Crítico"
    };
}

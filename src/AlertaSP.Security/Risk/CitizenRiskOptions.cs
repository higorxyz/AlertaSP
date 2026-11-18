namespace AlertaSP.Security.Risk;

/// <summary>Parâmetros do indicador Risco Cidadão (seção <c>Risk</c> da configuração).</summary>
public sealed class CitizenRiskOptions
{
    public const string SectionName = "Risk";

    /// <summary>Constante de saturação: com exposição igual a K, o risco fica em 63.</summary>
    public double CitizenRiskK { get; set; } = 30.0;

    /// <summary>Quantos dias de incidentes entram no cálculo.</summary>
    public int AnalysisWindowDays { get; set; } = 7;

    /// <summary>Fuso usado para agrupar incidentes por dia. São Paulo não tem horário de verão desde 2019.</summary>
    public int ReportingUtcOffsetHours { get; set; } = -3;
}

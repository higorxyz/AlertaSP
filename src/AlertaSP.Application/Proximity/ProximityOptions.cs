namespace AlertaSP.Application.Proximity;

/// <summary>Parâmetros da busca de ocorrências próximas (seção <c>Risk</c> da configuração).</summary>
public sealed class ProximityOptions
{
    public const string SectionName = "Risk";
    public const double MaxRadiusMeters = 10_000;

    /// <summary>Raio usado quando a requisição não informa um.</summary>
    public double NearbyRadiusMeters { get; set; } = 500;
}

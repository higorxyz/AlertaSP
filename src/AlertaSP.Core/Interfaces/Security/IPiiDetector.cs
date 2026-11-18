using AlertaSP.Core.Enums;

namespace AlertaSP.Core.Interfaces.Security;

public class PiiDetection
{
    public DataCategory Category { get; init; }
    public string Rule { get; init; } = string.Empty;
    public int Start { get; init; }
    public int Length { get; init; }
    public DataSensitivity Sensitivity { get; init; }
    public double Confidence { get; init; }
    public RecommendedAction RecommendedAction { get; init; }
    /// <summary>False para candidatos que têm o formato mas não passam na validação (ex.: CPF com dígitos errados).</summary>
    public bool IsValid { get; init; } = true;

    /// <summary>Trecho detectado. Uso interno: fica fora da serialização para não voltar na resposta da API.</summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public string? MatchedValue { get; init; }
}

/// <summary>Motor de detecção de PII: aplica todas as regras registradas e devolve as detecções ordenadas por posição.</summary>
public interface IPiiDetector
{
    IReadOnlyList<PiiDetection> Analyze(string content);
}

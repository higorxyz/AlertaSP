namespace AlertaSP.Security.Remediation;

/// <summary>
/// Configuração do provedor de IA (seção <c>AiRemediation</c>). Qualquer API compatível com
/// Chat Completions da OpenAI funciona. Sem <see cref="ApiKey"/>, o texto de reserva é usado.
/// </summary>
public sealed class AiRemediationOptions
{
    public const string SectionName = "AiRemediation";

    public string Endpoint { get; set; } = "https://api.openai.com/v1/chat/completions";
    public string ApiKey { get; set; } = string.Empty;
    public string Model { get; set; } = "gpt-4o-mini";
    public int TimeoutSeconds { get; set; } = 10;
    public int MaxAttempts { get; set; } = 2;
    public int RetryDelayMs { get; set; } = 300;

    /// <summary>Modelos de raciocínio (ex.: gpt-oss) gastam tokens pensando; com limite baixo a resposta vem vazia.</summary>
    public int MaxTokens { get; set; } = 200;

    /// <summary>Enviado como <c>reasoning_effort</c> só quando preenchido (ex.: "low").</summary>
    public string? ReasoningEffort { get; set; }

    public bool IsValid() =>
        Uri.TryCreate(Endpoint, UriKind.Absolute, out _)
        && TimeoutSeconds >= 1 && MaxAttempts >= 1 && RetryDelayMs >= 0 && MaxTokens >= 16;
}

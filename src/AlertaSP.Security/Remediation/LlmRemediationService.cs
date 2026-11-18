using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.RegularExpressions;
using AlertaSP.Core.Entities;
using AlertaSP.Core.Enums;
using AlertaSP.Core.Interfaces.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AlertaSP.Security.Remediation;

/// <summary>
/// Traduz incidentes para o cidadão com um LLM. A IA só escreve o texto: a decisão de bloquear ou
/// mascarar já foi tomada pela política. O prompt leva apenas descritores do incidente, passa pelo
/// rastreador com destino <see cref="SinkType.ExternalAiService"/> e não é enviado se contiver PII.
/// A resposta é tratada como conteúdo não confiável. Em qualquer falha, usa o texto de reserva.
/// </summary>
public class LlmRemediationService : ISecurityRemediationService
{
    public const string HttpClientName = "AiRemediationClient";

    private const int MaxResponseLength = 1000;
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(250);
    private static readonly HttpStatusCode[] RetryableStatusCodes =
    {
        HttpStatusCode.RequestTimeout,
        HttpStatusCode.TooManyRequests,
        HttpStatusCode.InternalServerError,
        HttpStatusCode.BadGateway,
        HttpStatusCode.ServiceUnavailable,
        HttpStatusCode.GatewayTimeout
    };

    private const string SystemPrompt =
        "Você explica incidentes de segurança do AlertaSP, um serviço de alertas de alagamento, para cidadãos " +
        "sem conhecimento técnico. Escreva em português do Brasil, em texto simples, sem markdown, links ou código.";

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IPiiDetector _piiDetector;
    private readonly ITaintTracker _taintTracker;
    private readonly DeterministicRemediationService _fallback;
    private readonly ILogger<LlmRemediationService> _logger;
    private readonly AiRemediationOptions _options;

    public LlmRemediationService(
        IHttpClientFactory httpClientFactory,
        IPiiDetector piiDetector,
        ITaintTracker taintTracker,
        DeterministicRemediationService fallback,
        IOptions<AiRemediationOptions> options,
        ILogger<LlmRemediationService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _piiDetector = piiDetector;
        _taintTracker = taintTracker;
        _fallback = fallback;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<RemediationResult> TranslateIncidentAsync(SecurityIncident incident, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(_options.ApiKey))
        {
            _logger.LogInformation("Chave do LLM não configurada; usando o texto de reserva.");
            return await _fallback.TranslateIncidentAsync(incident, ct);
        }

        var prompt = BuildPrompt(incident);
        if (!await IsPromptAllowedAsync(prompt, incident.FlowId, ct))
            return await _fallback.TranslateIncidentAsync(incident, ct);

        var answer = await RequestWithRetryAsync(prompt, ct);
        return answer != null
            ? new RemediationResult { Message = answer, Origin = RemediationOrigin.Llm }
            : await _fallback.TranslateIncidentAsync(incident, ct);
    }

    /// <summary>Somente descritores do incidente; o resumo interno e qualquer conteúdo original ficam de fora.</summary>
    private static string BuildPrompt(SecurityIncident incident) =>
        "Explique ao cidadão, em no máximo 3 frases curtas, o que o sistema impediu e por que isso protege os dados dele. " +
        "Não cite os termos técnicos em inglês nem o nome da regra, não atribua a tentativa a uma pessoa e não invente detalhes. " +
        "Informações do incidente:\n" +
        $"- Tipo de dado: {incident.Category} ({IncidentWording.DataKind(incident.Category)})\n" +
        $"- Destino da tentativa: {incident.SinkType} ({IncidentWording.Sink(incident.SinkType)})\n" +
        $"- Ação do sistema: {incident.Decision} ({IncidentWording.Decision(incident.Decision)})\n" +
        $"- Regra aplicada: {incident.RuleApplied}";

    /// <summary>
    /// O prompt é um dado saindo para um serviço externo: passa pelo rastreador como qualquer outro.
    /// Qualquer detecção, mesmo que só mascarável, cancela o envio.
    /// </summary>
    private async Task<bool> IsPromptAllowedAsync(string prompt, string flowId, CancellationToken ct)
    {
        var context = new DataFlowContext
        {
            FlowId = flowId,
            Source = "SecurityRemediation",
            Purpose = "IncidentTranslation",
            Actor = nameof(LlmRemediationService)
        };

        var delivery = await _taintTracker.TryDeliverAsync(
            _taintTracker.TaintByContent(prompt, context), SinkType.ExternalAiService, context, ct);

        if (delivery.Decision == PolicyDecision.Allow && _piiDetector.Analyze(prompt).Count == 0)
            return true;

        _logger.LogWarning("Prompt para o LLM barrado pela política (decisão {Decision}).", delivery.Decision);
        return false;
    }

    private async Task<string?> RequestWithRetryAsync(string prompt, CancellationToken ct)
    {
        for (var attempt = 1; attempt <= _options.MaxAttempts; attempt++)
        {
            try
            {
                var outcome = await SendAsync(prompt, ct);
                if (outcome.Content != null)
                {
                    var safe = ValidateResponse(outcome.Content);
                    if (safe == null)
                        _logger.LogWarning("Resposta do LLM rejeitada pela validação de conteúdo.");
                    return safe;
                }

                if (!outcome.Retryable)
                    return null;

                _logger.LogWarning("Falha transitória do LLM (tentativa {Attempt}/{Max}).", attempt, _options.MaxAttempts);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                _logger.LogWarning("Timeout do LLM (tentativa {Attempt}/{Max}).", attempt, _options.MaxAttempts);
            }
            catch (HttpRequestException ex)
            {
                _logger.LogWarning(ex, "Falha de rede com o LLM (tentativa {Attempt}/{Max}).", attempt, _options.MaxAttempts);
            }
            catch (JsonException ex)
            {
                _logger.LogWarning(ex, "Resposta do LLM não é JSON válido.");
                return null;
            }

            if (attempt < _options.MaxAttempts && _options.RetryDelayMs > 0)
                await Task.Delay(_options.RetryDelayMs * attempt, ct);
        }

        return null;
    }

    private async Task<SendOutcome> SendAsync(string prompt, CancellationToken ct)
    {
        using var client = _httpClientFactory.CreateClient(HttpClientName);
        client.Timeout = TimeSpan.FromSeconds(_options.TimeoutSeconds);

        var body = new Dictionary<string, object>
        {
            ["model"] = _options.Model,
            ["messages"] = new[]
            {
                new { role = "system", content = SystemPrompt },
                new { role = "user", content = prompt }
            },
            ["max_tokens"] = _options.MaxTokens,
            ["temperature"] = 0.3
        };
        if (!string.IsNullOrWhiteSpace(_options.ReasoningEffort))
            body["reasoning_effort"] = _options.ReasoningEffort.Trim();

        using var request = new HttpRequestMessage(HttpMethod.Post, _options.Endpoint)
        {
            Content = JsonContent.Create(body)
        };
        request.Headers.Add("Authorization", $"Bearer {_options.ApiKey}");

        using var response = await client.SendAsync(request, ct);
        if (!response.IsSuccessStatusCode)
        {
            // O corpo de erro do provedor ajuda a diagnosticar modelo ou chave errados e não contém a chave.
            var detail = await response.Content.ReadAsStringAsync(ct);
            _logger.LogWarning("LLM respondeu {StatusCode}: {Detail}", (int)response.StatusCode, detail.Length > 300 ? detail[..300] : detail);
            return new SendOutcome(null, RetryableStatusCodes.Contains(response.StatusCode));
        }

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        var root = document.RootElement;

        if (root.TryGetProperty("choices", out var choices)
            && choices.ValueKind == JsonValueKind.Array
            && choices.GetArrayLength() > 0
            && choices[0].TryGetProperty("message", out var message)
            && message.TryGetProperty("content", out var content)
            && content.ValueKind == JsonValueKind.String)
        {
            return new SendOutcome(content.GetString() ?? string.Empty, false);
        }

        _logger.LogWarning("Resposta do LLM fora do formato esperado.");
        return new SendOutcome(string.Empty, false);
    }

    /// <summary>Devolve o texto pronto para exibir ou null se a resposta for recusada.</summary>
    private string? ValidateResponse(string content)
    {
        // Bloco de código é verificado antes de remover a marcação, que apagaria as crases.
        if (content.Contains("```", StringComparison.Ordinal))
            return null;

        var text = StripMarkdown(content).Trim();
        if (text.Length == 0)
            return null;

        if (text.Length > MaxResponseLength)
            text = text[..MaxResponseLength];

        if (_piiDetector.Analyze(text).Count > 0 || ContainsLinkOrCommand(text))
            return null;

        return text;
    }

    /// <summary>
    /// Remove negrito, títulos, marcadores de lista e crases. O painel mostra texto puro, e o modelo às
    /// vezes devolve "**O que aconteceu:**" mesmo quando se pede texto simples.
    /// </summary>
    internal static string StripMarkdown(string text)
    {
        try
        {
            var cleaned = Regex.Replace(text, @"(\*\*|__|`)", string.Empty, RegexOptions.None, RegexTimeout);
            cleaned = Regex.Replace(cleaned, @"(?m)^\s{0,3}(#{1,6}\s+|[*\-+]\s+)", string.Empty, RegexOptions.None, RegexTimeout);
            return Regex.Replace(cleaned, @"[ \t]{2,}", " ", RegexOptions.None, RegexTimeout);
        }
        catch (RegexMatchTimeoutException)
        {
            return text;
        }
    }

    /// <summary>Links e pedidos para executar algo são recusados; estouro de tempo do regex também.</summary>
    private static bool ContainsLinkOrCommand(string text)
    {
        try
        {
            return Regex.IsMatch(text, @"https?://|www\.", RegexOptions.IgnoreCase, RegexTimeout)
                || Regex.IsMatch(text, @"(?i)\b(?:execute|executar|comando|curl|powershell|instrução|instrucoes)\b", RegexOptions.None, RegexTimeout);
        }
        catch (RegexMatchTimeoutException)
        {
            return true;
        }
    }

    /// <param name="Content">Texto da resposta; null quando a requisição falhou.</param>
    /// <param name="Retryable">Se vale tentar de novo (só faz sentido quando Content é null).</param>
    private sealed record SendOutcome(string? Content, bool Retryable);
}

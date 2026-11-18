using System.Text.RegularExpressions;

namespace AlertaSP.Api.Middleware;

/// <summary>
/// Garante um identificador de correlação por requisição (cabeçalho <c>X-Correlation-ID</c>).
/// Um valor recebido só é aceito se for curto e composto por caracteres seguros; caso contrário é
/// substituído por um novo GUID (evita injeção de conteúdo em logs e cabeçalhos).
/// </summary>
public sealed partial class CorrelationIdMiddleware
{
    public const string HeaderName = "X-Correlation-ID";

    private readonly RequestDelegate _next;
    private readonly ILogger<CorrelationIdMiddleware> _logger;

    public CorrelationIdMiddleware(RequestDelegate next, ILogger<CorrelationIdMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var incoming = context.Request.Headers[HeaderName].ToString();
        var correlationId = IsSafe(incoming) ? incoming : Guid.NewGuid().ToString("N");

        context.TraceIdentifier = correlationId;
        context.Response.OnStarting(() =>
        {
            context.Response.Headers[HeaderName] = correlationId;
            return Task.CompletedTask;
        });

        using (_logger.BeginScope(new Dictionary<string, object> { ["CorrelationId"] = correlationId }))
        {
            await _next(context);
        }
    }

    internal static bool IsSafe(string value) => !string.IsNullOrEmpty(value) && SafeId().IsMatch(value);

    [GeneratedRegex(@"^[A-Za-z0-9\-_]{1,64}$", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 100)]
    private static partial Regex SafeId();
}

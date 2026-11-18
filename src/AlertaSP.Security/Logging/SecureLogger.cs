using System.Text;
using System.Text.RegularExpressions;
using AlertaSP.Core.Enums;
using AlertaSP.Core.Interfaces.Security;
using Microsoft.Extensions.Logging;

namespace AlertaSP.Security.Logging;

/// <summary>
/// Log que só escreve o que a política liberou. Cada argumento passa pelo <see cref="ITaintTracker"/> com
/// destino <see cref="SinkType.Log"/>: valores <see cref="Tainted{T}"/> seguem a política, textos comuns são
/// rotulados por conteúdo, e um valor bloqueado vira um marcador, sem derrubar a escrita do log.
/// </summary>
public class SecureLogger : ISecureLogger
{
    private static readonly Regex PlaceholderRegex = new(
        @"\{(?<name>[A-Za-z_][A-Za-z0-9_]*)\}",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(250));

    private readonly ITaintTracker _tracker;
    private readonly ILogger<SecureLogger> _logger;

    public SecureLogger(ITaintTracker tracker, ILogger<SecureLogger> logger)
    {
        _tracker = tracker;
        _logger = logger;
    }

    public async Task LogAsync(
        SecureLogLevel level,
        string messageTemplate,
        DataFlowContext context,
        IReadOnlyDictionary<string, object?>? arguments = null,
        CancellationToken ct = default)
    {
        var rendered = new Dictionary<string, string>();

        if (arguments != null)
        {
            foreach (var (name, value) in arguments)
                rendered[name] = await RenderArgumentAsync(value, context, ct);
        }

        var message = PlaceholderRegex.Replace(
            messageTemplate,
            m => rendered.TryGetValue(m.Groups["name"].Value, out var text) ? text : m.Value);

        _logger.Log(ToLogLevel(level), "{SecureMessage}", message);
    }

    private async Task<string> RenderArgumentAsync(object? value, DataFlowContext context, CancellationToken ct)
    {
        switch (value)
        {
            case null:
                return "null";

            case Tainted<string> tainted:
                return await DeliverAsync(tainted, context, ct);

            case string text:
                return await DeliverAsync(_tracker.TaintByContent(text, context), context, ct);

            default:
                // Números, ids e datas não têm texto livre, mas um ToString() customizado pode ter:
                // por isso também passam pela detecção.
                var asText = Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty;
                return await DeliverAsync(_tracker.TaintByContent(asText, context), context, ct);
        }
    }

    private async Task<string> DeliverAsync(Tainted<string> tainted, DataFlowContext context, CancellationToken ct)
    {
        var result = await _tracker.TryDeliverAsync(tainted, SinkType.Log, context, ct);
        return result.Allowed
            ? result.ReleasedValue ?? string.Empty
            : $"[BLOQUEADO:{tainted.Metadata.Category}]";
    }

    private static LogLevel ToLogLevel(SecureLogLevel level) => level switch
    {
        SecureLogLevel.Warning => LogLevel.Warning,
        SecureLogLevel.Error => LogLevel.Error,
        _ => LogLevel.Information
    };
}

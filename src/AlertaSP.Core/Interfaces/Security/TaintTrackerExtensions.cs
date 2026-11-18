using AlertaSP.Core.Enums;
using AlertaSP.Core.Exceptions;

namespace AlertaSP.Core.Interfaces.Security;

/// <summary>
/// Atalhos para o caso comum: entregar o valor e usar só o que a política liberou.
/// Quando a política bloqueia, lançam <see cref="SecurityViolationException"/>.
/// </summary>
public static class TaintTrackerExtensions
{
    /// <summary>Concatena dois valores contaminados; o resultado herda a maior sensibilidade.</summary>
    public static Tainted<string> Concat(
        this ITaintTracker tracker,
        Tainted<string> left,
        Tainted<string> right,
        string separator = "")
        => tracker.Combine(new[] { left, right }, separator);

    public static async Task<string> ReleaseAsync(
        this ITaintTracker tracker,
        Tainted<string> data,
        SinkType sink,
        DataFlowContext context,
        CancellationToken ct = default)
    {
        var result = await tracker.TryDeliverAsync(data, sink, context, ct);
        return EnsureAllowed(result, data, sink);
    }

    public static async Task<IReadOnlyList<string>> ReleaseManyAsync(
        this ITaintTracker tracker,
        IReadOnlyList<Tainted<string>> items,
        SinkType sink,
        DataFlowContext context,
        CancellationToken ct = default)
    {
        if (items.Count == 0)
            return Array.Empty<string>();

        var results = await tracker.TryDeliverManyAsync(items, sink, context, ct);
        var values = new List<string>(items.Count);
        for (var i = 0; i < items.Count; i++)
            values.Add(EnsureAllowed(results[i], items[i], sink));

        return values;
    }

    private static string EnsureAllowed(SinkResult result, Tainted<string> data, SinkType sink)
    {
        if (!result.Allowed)
        {
            throw new SecurityViolationException(
                $"A política de segurança bloqueou a entrega de dado [{data.Metadata.Category}] ao destino [{sink}].");
        }

        return result.ReleasedValue ?? string.Empty;
    }
}

using AlertaSP.Core.Enums;

namespace AlertaSP.Core.Interfaces.Security;

/// <summary>Metadados que acompanham um valor contaminado da origem até o destino.</summary>
public class TaintedData
{
    public string FlowId { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;

    /// <summary>Categoria que decide a política: a mais grave entre as presentes.</summary>
    public DataCategory Category { get; set; }

    /// <summary>Todas as categorias presentes no valor (texto livre e concatenações podem ter mais de uma).</summary>
    public HashSet<DataCategory> Categories { get; set; } = new();

    public DataSensitivity Sensitivity { get; set; }
    public List<string> PropagationHistory { get; set; } = new();
    public SinkType? IntendedSink { get; set; }
    public bool IsSanitized { get; set; }

    /// <summary>
    /// Texto livre rotulado por detecção de conteúdo. Na sanitização, só os trechos detectados são
    /// mascarados; um campo rotulado (ex.: CPF) é mascarado por inteiro conforme a categoria.
    /// </summary>
    public bool IsFreeText { get; set; }
}

/// <summary>
/// Valor contaminado. O valor bruto é <c>internal</c>: código de aplicação só o obtém depois de uma
/// decisão da política (<see cref="SinkResult.ReleasedValue"/>) ou de uma revelação auditada.
/// </summary>
public class Tainted<T>
{
    private readonly T _value;
    public TaintedData Metadata { get; }

    public Tainted(T value, TaintedData metadata)
    {
        _value = value;
        Metadata = metadata ?? throw new ArgumentNullException(nameof(metadata));
    }

    /// <summary>Não revela o valor, para que interpolações e logs acidentais não vazem o dado.</summary>
    public override string ToString() => $"[TAINTED:{Metadata.Category}]";

    internal T GetValueInternal() => _value;
}

/// <summary>Quem está movendo o dado, de onde e com que finalidade. A política decide com base nisso.</summary>
public class DataFlowContext
{
    public string FlowId { get; set; } = Guid.NewGuid().ToString("N");
    public string Source { get; set; } = string.Empty;
    public string Purpose { get; set; } = string.Empty;
    public string Actor { get; set; } = string.Empty;
    public bool IsAuthorized { get; set; }

    /// <summary>
    /// Saída de rotina do sistema (resposta pública com CPF mascarado, gravação cifrada). A decisão é
    /// auditada, mas não vira incidente: nada vazou. Fluxos de vazamento deixam este valor em false.
    /// </summary>
    public bool IsRoutineOutput { get; set; }
}

public class SinkResult
{
    public PolicyDecision Decision { get; init; }

    /// <summary>Preenchido apenas quando a decisão é <see cref="PolicyDecision.AllowSanitized"/>.</summary>
    public string? SanitizedValue { get; init; }

    /// <summary>O que pode seguir para o destino: o original (Allow), o sanitizado (AllowSanitized) ou nulo (Block).</summary>
    public string? ReleasedValue { get; init; }

    public string RuleApplied { get; init; } = string.Empty;
    public bool Allowed => Decision is PolicyDecision.Allow or PolicyDecision.AllowSanitized;
}

public interface ITaintTracker
{
    Tainted<string> Taint(string value, DataFlowContext context, DataCategory category, DataSensitivity sensitivity);

    /// <summary>Fonte rotulada: contamina as propriedades marcadas com <c>[Sensitive]</c>, indexadas pelo nome.</summary>
    IReadOnlyDictionary<string, Tainted<string>> TaintAnnotatedFields(object source, DataFlowContext context);

    /// <summary>
    /// Detecção por conteúdo: o texto passa pelo detector de PII e recebe a categoria e a sensibilidade
    /// da detecção mais grave (ou None, se nada for encontrado).
    /// </summary>
    Tainted<string> TaintByContent(string value, DataFlowContext context);

    Tainted<string> Propagate(Tainted<string> source, string operation, string? transformedValue = null);
    Tainted<string> Sanitize(Tainted<string> source, string sanitizedValue);

    /// <summary>
    /// Concatena valores. O resultado herda a maior sensibilidade, reúne categorias e históricos de todas
    /// as partes e só conta como sanitizado se todas as partes sensíveis já estiverem sanitizadas.
    /// </summary>
    Tainted<string> Combine(IReadOnlyList<Tainted<string>> parts, string separator = "");

    Task<SinkResult> TryDeliverAsync(Tainted<string> data, SinkType sink, DataFlowContext context, CancellationToken ct = default);

    /// <summary>
    /// Entrega vários valores ao mesmo destino. A política decide valor a valor; decisões iguais
    /// viram um único evento de auditoria.
    /// </summary>
    Task<IReadOnlyList<SinkResult>> TryDeliverManyAsync(IReadOnlyList<Tainted<string>> items, SinkType sink, DataFlowContext context, CancellationToken ct = default);

    /// <summary>Acesso ao valor bruto: exige ator autorizado, finalidade igual à do contexto e gera auditoria.</summary>
    Task<string> RevealAsync(Tainted<string> data, string purpose, DataFlowContext context, CancellationToken ct = default);
}

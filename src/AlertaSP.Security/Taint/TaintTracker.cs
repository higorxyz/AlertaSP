using System.Globalization;
using System.Reflection;
using AlertaSP.Core.Attributes;
using AlertaSP.Core.Entities;
using AlertaSP.Core.Enums;
using AlertaSP.Core.Interfaces.Security;

namespace AlertaSP.Security.Taint;

/// <summary>
/// Acompanha dados sensíveis da origem (campo rotulado ou conteúdo detectado) até o destino (sink).
/// Quem decide a entrega é a <see cref="ISecurityPolicy"/>; o valor só sai por
/// <see cref="SinkResult.ReleasedValue"/>, já na forma aprovada (original, sanitizado ou nenhum).
/// </summary>
public class TaintTracker : ITaintTracker
{
    private readonly ISecurityPolicy _policy;
    private readonly IAuditSink _auditSink;
    private readonly ISecurityIncidentRepository _incidentRepository;
    private readonly IPiiMaskingService _maskingService;
    private readonly IPiiDetector _detector;

    public TaintTracker(
        ISecurityPolicy policy,
        IAuditSink auditSink,
        ISecurityIncidentRepository incidentRepository,
        IPiiMaskingService maskingService,
        IPiiDetector detector)
    {
        _policy = policy;
        _auditSink = auditSink;
        _incidentRepository = incidentRepository;
        _maskingService = maskingService;
        _detector = detector;
    }

    public Tainted<string> Taint(string value, DataFlowContext context, DataCategory category, DataSensitivity sensitivity)
    {
        var metadata = new TaintedData
        {
            FlowId = context.FlowId,
            Source = context.Source,
            Category = category,
            Categories = category == DataCategory.None ? new() : new() { category },
            Sensitivity = sensitivity,
            PropagationHistory = new List<string> { $"Taint(Category:{category}, Sensitivity:{sensitivity}, Source:{context.Source})" },
            IsSanitized = false
        };

        return new Tainted<string>(value, metadata);
    }

    public IReadOnlyDictionary<string, Tainted<string>> TaintAnnotatedFields(object source, DataFlowContext context)
    {
        ArgumentNullException.ThrowIfNull(source);

        var result = new Dictionary<string, Tainted<string>>();

        foreach (var property in source.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            var attribute = property.GetCustomAttribute<SensitiveAttribute>();
            if (attribute == null || property.GetIndexParameters().Length > 0)
                continue;

            var raw = property.GetValue(source);
            var text = raw switch
            {
                null => null,
                string s => s,
                IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
                _ => raw.ToString()
            };

            if (text == null)
                continue;

            var tainted = Taint(text, context, attribute.Category, DefaultSensitivity(attribute.Category));
            tainted.Metadata.PropagationHistory.Add($"Field({property.Name})");
            result[property.Name] = tainted;
        }

        return result;
    }

    public Tainted<string> TaintByContent(string value, DataFlowContext context)
    {
        // Candidatos com IsValid = false (ex.: CPF com dígitos errados) não contaminam o valor.
        var detections = _detector.Analyze(value ?? string.Empty)
            .Where(d => d.IsValid)
            .ToList();

        var metadata = new TaintedData
        {
            FlowId = context.FlowId,
            Source = context.Source,
            IsFreeText = true,
            IsSanitized = false
        };

        if (detections.Count == 0)
        {
            metadata.Category = DataCategory.None;
            metadata.Sensitivity = DataSensitivity.None;
            metadata.PropagationHistory.Add($"TaintByContent(None, Source:{context.Source})");
        }
        else
        {
            var top = detections
                .OrderByDescending(d => d.Sensitivity)
                .ThenBy(d => CategoryRank(d.Category))
                .First();

            metadata.Category = top.Category;
            metadata.Categories = detections.Select(d => d.Category).ToHashSet();
            metadata.Sensitivity = top.Sensitivity;
            metadata.PropagationHistory.Add(
                $"TaintByContent(Category:{top.Category}, Rule:{top.Rule}, Detections:{detections.Count}, Source:{context.Source})");
        }

        return new Tainted<string>(value ?? string.Empty, metadata);
    }

    public Tainted<string> Propagate(Tainted<string> source, string operation, string? transformedValue = null)
    {
        var newHistory = new List<string>(source.Metadata.PropagationHistory)
        {
            $"{operation} at {DateTime.UtcNow:O}"
        };

        var metadata = new TaintedData
        {
            FlowId = source.Metadata.FlowId,
            Source = source.Metadata.Source,
            Category = source.Metadata.Category,
            Categories = new(source.Metadata.Categories),
            Sensitivity = source.Metadata.Sensitivity,
            PropagationHistory = newHistory,
            IntendedSink = source.Metadata.IntendedSink,
            IsSanitized = source.Metadata.IsSanitized,
            IsFreeText = source.Metadata.IsFreeText
        };

        var value = transformedValue ?? source.GetValueInternal();
        return new Tainted<string>(value, metadata);
    }

    public Tainted<string> Combine(IReadOnlyList<Tainted<string>> parts, string separator = "")
    {
        ArgumentNullException.ThrowIfNull(parts);
        if (parts.Count == 0)
            throw new ArgumentException("É preciso informar ao menos uma parte para combinar.", nameof(parts));

        // A parte mais sensível define a política: maior sensibilidade e, em empate, a categoria mais grave.
        var dominant = parts
            .OrderByDescending(p => p.Metadata.Sensitivity)
            .ThenBy(p => CategoryRank(p.Metadata.Category))
            .First();

        var history = new List<string>();
        foreach (var part in parts)
        {
            foreach (var step in part.Metadata.PropagationHistory)
            {
                if (!history.Contains(step))
                    history.Add(step);
            }
        }

        history.Add(
            $"Combine(Parts:{parts.Count}, Category:{dominant.Metadata.Category}, Sensitivity:{dominant.Metadata.Sensitivity}) at {DateTime.UtcNow:O}");

        var metadata = new TaintedData
        {
            FlowId = dominant.Metadata.FlowId,
            Source = dominant.Metadata.Source,
            Category = dominant.Metadata.Category,
            Categories = parts.SelectMany(p => p.Metadata.Categories).ToHashSet(),
            Sensitivity = dominant.Metadata.Sensitivity,
            PropagationHistory = history,
            IsSanitized = parts.Any(p => p.Metadata.IsSanitized) && parts.Where(IsSensitive).All(p => p.Metadata.IsSanitized),
            IsFreeText = parts.Any(p => p.Metadata.IsFreeText)
        };

        var value = string.Join(separator ?? string.Empty, parts.Select(p => p.GetValueInternal()));
        return new Tainted<string>(value, metadata);
    }

    public Tainted<string> Sanitize(Tainted<string> source, string sanitizedValue)
    {
        var newHistory = new List<string>(source.Metadata.PropagationHistory)
        {
            $"Sanitize({source.Metadata.Category}) at {DateTime.UtcNow:O}"
        };

        var metadata = new TaintedData
        {
            FlowId = source.Metadata.FlowId,
            Source = source.Metadata.Source,
            Category = source.Metadata.Category,
            Categories = new(source.Metadata.Categories),
            Sensitivity = DataSensitivity.Low,
            PropagationHistory = newHistory,
            IsSanitized = true,
            IsFreeText = source.Metadata.IsFreeText
        };

        return new Tainted<string>(sanitizedValue, metadata);
    }

    public async Task<SinkResult> TryDeliverAsync(
        Tainted<string> data,
        SinkType sink,
        DataFlowContext context,
        CancellationToken ct = default)
    {
        var results = await TryDeliverManyAsync(new[] { data }, sink, context, ct);
        return results[0];
    }

    public async Task<IReadOnlyList<SinkResult>> TryDeliverManyAsync(
        IReadOnlyList<Tainted<string>> items,
        SinkType sink,
        DataFlowContext context,
        CancellationToken ct = default)
    {
        var results = new SinkResult[items.Count];
        var outcomes = new List<Outcome>(items.Count);

        for (var i = 0; i < items.Count; i++)
        {
            var data = items[i];
            data.Metadata.IntendedSink = sink;

            // Nada sensível: libera sem gravar auditoria, para não encher a trilha de eventos vazios.
            if (data.Metadata.Category == DataCategory.None || data.Metadata.Sensitivity == DataSensitivity.None)
            {
                results[i] = new SinkResult
                {
                    Decision = PolicyDecision.Allow,
                    ReleasedValue = data.GetValueInternal(),
                    RuleApplied = "Policy:NoSensitiveData"
                };
                continue;
            }

            var raw = data.GetValueInternal();
            PolicyDecision decision;
            string rule;

            // Dado marcado como sanitizado só é liberado direto se uma nova varredura não achar nada.
            if (data.Metadata.IsSanitized && _detector.Analyze(raw).Count == 0)
            {
                decision = PolicyDecision.Allow;
                rule = $"Policy:AlreadySanitized:{data.Metadata.Category}->{sink}";
            }
            else
            {
                decision = _policy.Evaluate(data.Metadata.Category, data.Metadata.Sensitivity, sink, context);
                rule = $"Policy:{data.Metadata.Category}->{sink}";
            }

            string? sanitized = decision == PolicyDecision.AllowSanitized ? SanitizeValue(data) : null;

            results[i] = new SinkResult
            {
                Decision = decision,
                SanitizedValue = sanitized,
                ReleasedValue = decision switch
                {
                    PolicyDecision.Allow => raw,
                    PolicyDecision.AllowSanitized => sanitized,
                    _ => null
                },
                RuleApplied = rule
            };

            outcomes.Add(new Outcome(data.Metadata, decision, rule));
        }

        await RecordAsync(outcomes, sink, context, ct);
        return results;
    }

    public async Task<string> RevealAsync(
        Tainted<string> data,
        string purpose,
        DataFlowContext context,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(purpose) ||
            !context.IsAuthorized ||
            !string.Equals(context.Purpose, purpose, StringComparison.Ordinal))
        {
            throw new UnauthorizedAccessException("Revelação de dado sensível exige autorização e finalidade correspondente.");
        }

        var decision = _policy.Evaluate(
            data.Metadata.Category,
            data.Metadata.Sensitivity,
            SinkType.InternalHttpResponse,
            context);

        if (decision != PolicyDecision.Allow)
        {
            throw new UnauthorizedAccessException("A política de segurança bloqueou a revelação do dado sensível.");
        }

        var audit = AuditEvent.Create(
            flowId: data.Metadata.FlowId,
            source: data.Metadata.Source,
            sinkType: SinkType.InternalHttpResponse,
            category: data.Metadata.Category,
            sensitivity: data.Metadata.Sensitivity,
            decision: PolicyDecision.Allow,
            ruleApplied: "ExplicitRevealWithPurpose",
            summary: $"Valor sensível [{data.Metadata.Category}] revelado para propósito explícito: '{purpose}' por ator: '{context.Actor}'."
        );
        await _auditSink.RecordAsync(audit, ct);

        return data.GetValueInternal();
    }

    /// <summary>
    /// Grava um evento de auditoria por grupo de decisões iguais e um incidente para cada bloqueio ou
    /// sanitização. Sanitização de saída de rotina (<see cref="DataFlowContext.IsRoutineOutput"/>) é
    /// auditada, mas não vira incidente. O resumo não inclui o valor original.
    /// </summary>
    private async Task RecordAsync(
        List<Outcome> outcomes,
        SinkType sink,
        DataFlowContext context,
        CancellationToken ct)
    {
        var groups = outcomes.GroupBy(o => new
        {
            o.Metadata.FlowId,
            o.Metadata.Source,
            o.Metadata.Category,
            o.Metadata.Sensitivity,
            o.Decision,
            o.Rule
        });

        foreach (var group in groups)
        {
            var key = group.Key;
            var count = group.Count();
            var quantity = count > 1 ? $" Quantidade: {count}." : string.Empty;
            var others = group.SelectMany(o => o.Metadata.Categories).Where(c => c != key.Category).Distinct().ToList();
            var alsoPresent = others.Count > 0 ? $" Também presente: {string.Join(", ", others)}." : string.Empty;
            var summary =
                $"Tentativa de entrega de dado [{key.Category}] originado em [{key.Source}] para o destino [{sink}]. Decisão: [{key.Decision}].{quantity}{alsoPresent}";

            await _auditSink.RecordAsync(AuditEvent.Create(
                flowId: key.FlowId,
                source: key.Source,
                sinkType: sink,
                category: key.Category,
                sensitivity: key.Sensitivity,
                decision: key.Decision,
                ruleApplied: key.Rule,
                summary: summary), ct);

            var isBlock = key.Decision == PolicyDecision.Block;
            var isSanitized = key.Decision == PolicyDecision.AllowSanitized;
            if (!isBlock && !(isSanitized && !context.IsRoutineOutput))
                continue;

            await _incidentRepository.AddAsync(SecurityIncident.Create(
                flowId: key.FlowId,
                category: key.Category,
                sensitivity: key.Sensitivity,
                sinkType: sink,
                decision: key.Decision,
                result: isBlock ? IncidentResult.Blocked : IncidentResult.Sanitized,
                ruleApplied: key.Rule,
                summary: summary), ct);
        }
    }

    private string SanitizeValue(Tainted<string> data)
    {
        var raw = data.GetValueInternal();

        if (data.Metadata.IsFreeText)
            return _maskingService.MaskContent(raw);

        return data.Metadata.Category switch
        {
            DataCategory.PersonalData => raw.Contains('@') ? _maskingService.MaskEmail(raw) : _maskingService.MaskCpf(raw),
            DataCategory.Location when double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out _)
                => _maskingService.MaskCoordinate(raw),
            DataCategory.Location => _maskingService.MaskAddress(raw),
            DataCategory.Credentials => _maskingService.MaskCredential(raw),
            _ => "[DADO SENSÍVEL SANITIZADO]"
        };
    }

    private static bool IsSensitive(Tainted<string> part) =>
        part.Metadata.Category != DataCategory.None && part.Metadata.Sensitivity != DataSensitivity.None;

    private static DataSensitivity DefaultSensitivity(DataCategory category) => category switch
    {
        DataCategory.Credentials => DataSensitivity.Critical,
        DataCategory.PersonalData => DataSensitivity.High,
        DataCategory.HealthData => DataSensitivity.High,
        DataCategory.Location => DataSensitivity.Medium,
        _ => DataSensitivity.None
    };

    private static int CategoryRank(DataCategory category) => category switch
    {
        DataCategory.Credentials => 0,
        DataCategory.HealthData => 1,
        DataCategory.PersonalData => 2,
        DataCategory.Location => 3,
        _ => 4
    };

    private sealed record Outcome(TaintedData Metadata, PolicyDecision Decision, string Rule);
}

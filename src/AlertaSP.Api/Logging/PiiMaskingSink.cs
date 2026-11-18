using Serilog.Core;
using Serilog.Events;
using Serilog.Parsing;

namespace AlertaSP.Api.Logging;

/// <summary>
/// Defesa em profundidade do Serilog: qualquer evento de log (inclusive dos componentes do framework e
/// de código que não usa o <c>ISecureLogger</c>) tem o texto e as propriedades mascarados pelo motor PII
/// antes de chegar ao sink real. O texto do modelo é mascarado só nos trechos literais, preservando os
/// marcadores <c>{Nome}</c>.
/// Limitação: a mensagem de uma exceção anexada ao evento não é reescrita.
/// </summary>
public sealed class PiiMaskingSink : ILogEventSink
{
    private readonly ILogEventSink _inner;
    private readonly Func<string, string> _mask;
    private readonly MessageTemplateParser _parser = new();

    public PiiMaskingSink(ILogEventSink inner, Func<string, string> mask)
    {
        _inner = inner;
        _mask = mask;
    }

    public void Emit(LogEvent logEvent)
    {
        var properties = logEvent.Properties
            .Select(p => new LogEventProperty(p.Key, MaskValue(p.Value)))
            .ToList();

        var templateText = string.Concat(logEvent.MessageTemplate.Tokens.Select(token =>
            token is TextToken text ? _mask(text.Text) : token.ToString()));

        var masked = new LogEvent(
            logEvent.Timestamp,
            logEvent.Level,
            logEvent.Exception,
            _parser.Parse(templateText),
            properties);

        _inner.Emit(masked);
    }

    private LogEventPropertyValue MaskValue(LogEventPropertyValue value) => value switch
    {
        ScalarValue { Value: string text } => new ScalarValue(_mask(text)),
        StructureValue structure => new StructureValue(
            structure.Properties.Select(p => new LogEventProperty(p.Name, MaskValue(p.Value))),
            structure.TypeTag),
        SequenceValue sequence => new SequenceValue(sequence.Elements.Select(MaskValue)),
        DictionaryValue dictionary => new DictionaryValue(
            dictionary.Elements.Select(e => new KeyValuePair<ScalarValue, LogEventPropertyValue>(e.Key, MaskValue(e.Value)))),
        _ => value
    };
}

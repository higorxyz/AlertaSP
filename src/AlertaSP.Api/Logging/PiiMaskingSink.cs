using Serilog.Core;
using Serilog.Events;
using Serilog.Parsing;

namespace AlertaSP.Api.Logging;

/// <summary>
/// Defesa em profundidade do Serilog: qualquer evento de log (inclusive dos componentes do framework e
/// de código que não usa o <c>ISecureLogger</c>) tem o texto e as propriedades mascarados pelo motor PII
/// antes de chegar ao sink real. O texto do modelo é mascarado só nos trechos literais, preservando os
/// marcadores <c>{Nome}</c>. Uma exceção anexada ao evento é trocada por uma cópia com mensagem e stack
/// trace mascarados, porque mensagens de exceção às vezes carregam o valor que causou o erro.
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
            logEvent.Exception is null ? null : new MaskedException(logEvent.Exception, _mask),
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

/// <summary>
/// Cópia de uma exceção com o texto já mascarado. O sink de console imprime <see cref="ToString"/>, que aqui
/// devolve o tipo, a mensagem e o stack trace originais depois de passarem pelo motor de PII.
/// </summary>
public sealed class MaskedException : Exception
{
    private readonly string _text;
    private readonly string? _stackTrace;

    public MaskedException(Exception original, Func<string, string> mask)
        : base(mask(original.Message))
    {
        _text = mask(original.ToString());
        _stackTrace = original.StackTrace is null ? null : mask(original.StackTrace);
    }

    public override string? StackTrace => _stackTrace;

    public override string ToString() => _text;
}

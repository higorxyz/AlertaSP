using AlertaSP.Api.Logging;
using AlertaSP.Security.Pii;
using AlertaSP.Security.Pii.Rules;
using AlertaSP.Core.Interfaces.Security;
using Serilog;
using Serilog.Core;
using Serilog.Events;

namespace AlertaSP.UnitTests.Api;

public class PiiMaskingSinkTests
{
    private sealed class CapturingSink : ILogEventSink
    {
        public List<LogEvent> Events { get; } = new();
        public void Emit(LogEvent logEvent) => Events.Add(logEvent);
    }

    private static (ILogger Logger, CapturingSink Sink) CreateLogger()
    {
        var detector = new PiiDetectionService(new IPiiRule[]
        {
            new CpfPiiRule(), new CredentialsPiiRule(), new HealthDataPiiRule(),
            new LocationPiiRule(), new CoordinatesPiiRule(), new EmailPiiRule()
        });
        var sink = new CapturingSink();
        var logger = new LoggerConfiguration()
            .WriteTo.Sink(new PiiMaskingSink(sink, new PiiMaskingService(detector).MaskContent))
            .CreateLogger();
        return (logger, sink);
    }

    [Fact]
    public void MessageAndProperties_AreMasked()
    {
        var (logger, sink) = CreateLogger();

        logger.Information("Cadastro do CPF 529.982.247-25 para {Email}", "maria@exemplo.com");

        var rendered = Assert.Single(sink.Events).RenderMessage();
        Assert.DoesNotContain("529.982.247-25", rendered);
        Assert.DoesNotContain("maria@exemplo.com", rendered);
        Assert.Contains("***.***.***-25", rendered);
    }

    [Fact]
    public void ExceptionMessage_IsMaskedBeforeReachingTheSink()
    {
        var (logger, sink) = CreateLogger();
        Exception thrown;
        try
        {
            throw new InvalidOperationException("Falha ao gravar o CPF 529.982.247-25 com senha=Abc12345");
        }
        catch (Exception ex)
        {
            thrown = ex;
        }

        logger.Error(thrown, "Erro no cadastro");

        var exception = Assert.Single(sink.Events).Exception!;
        Assert.IsType<MaskedException>(exception);
        Assert.DoesNotContain("529.982.247-25", exception.ToString());
        Assert.DoesNotContain("Abc12345", exception.ToString());
        Assert.DoesNotContain("Abc12345", exception.Message);
        Assert.Contains(nameof(InvalidOperationException), exception.ToString());
        Assert.Contains(nameof(ExceptionMessage_IsMaskedBeforeReachingTheSink), exception.StackTrace);
    }
}

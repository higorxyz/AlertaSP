using AlertaSP.Core.Enums;
using AlertaSP.Core.Interfaces.Security;
using AlertaSP.Security.Logging;
using AlertaSP.SecurityTests.Support;
using Xunit;

namespace AlertaSP.SecurityTests.Logging;

public class SecureLoggerTests
{
    private const string RawCpf = "529.982.247-25";

    private readonly FakeAuditSink _audit = new();
    private readonly FakeIncidentRepository _incidents = new();
    private readonly CapturingLogger<SecureLogger> _output = new();
    private readonly ITaintTracker _tracker;
    private readonly SecureLogger _logger;

    public SecureLoggerTests()
    {
        _tracker = TestSecurity.CreateTracker(_audit, _incidents);
        _logger = new SecureLogger(_tracker, _output);
    }

    [Fact]
    public async Task TaintedCpfArgument_IsWrittenMaskedAndAudited()
    {
        var context = new DataFlowContext { Source = "/api/citizens", Purpose = "Log", IsRoutineOutput = true };
        var cpf = _tracker.Taint(RawCpf, context, DataCategory.PersonalData, DataSensitivity.High);

        await _logger.LogAsync(
            SecureLogLevel.Information,
            "Cidadão cadastrado. Id={Id}, Cpf={Cpf}",
            context,
            new Dictionary<string, object?> { ["Id"] = 7, ["Cpf"] = cpf });

        var line = Assert.Single(_output.Messages);
        Assert.Equal("Cidadão cadastrado. Id=7, Cpf=***.***.***-25", line);
        Assert.DoesNotContain(RawCpf, line);
        var audit = Assert.Single(_audit.RecordedEvents);
        Assert.Equal(SinkType.Log, audit.SinkType);
    }

    [Fact]
    public async Task PlainStringWithCredential_IsBlockedInsteadOfWritten()
    {
        var context = new DataFlowContext { Source = "/api/test", Purpose = "Log" };

        await _logger.LogAsync(
            SecureLogLevel.Warning,
            "Falha ao autenticar: {Detail}",
            context,
            new Dictionary<string, object?> { ["Detail"] = "senha=MinhaSenhaSecreta1" });

        var line = Assert.Single(_output.Messages);
        Assert.Equal("Falha ao autenticar: [BLOQUEADO:Credentials]", line);
        Assert.DoesNotContain("MinhaSenhaSecreta1", line);
        Assert.Single(_incidents.RecordedIncidents);
    }

    [Fact]
    public async Task PlainStringWithCpf_IsMaskedByContent()
    {
        var context = new DataFlowContext { Source = "/api/test", Purpose = "Log" };

        await _logger.LogAsync(
            SecureLogLevel.Information,
            "Consulta: {Text}",
            context,
            new Dictionary<string, object?> { ["Text"] = $"cidadão {RawCpf} consultado" });

        Assert.Equal("Consulta: cidadão ***.***.***-25 consultado", Assert.Single(_output.Messages));
    }

    [Fact]
    public async Task ArgumentsWithoutSensitiveContent_PassThroughWithoutAuditNoise()
    {
        var context = new DataFlowContext { Source = "/api/test", Purpose = "Log" };

        await _logger.LogAsync(
            SecureLogLevel.Information,
            "Trajeto {RouteId} ativado em {When}",
            context,
            new Dictionary<string, object?> { ["RouteId"] = 12, ["When"] = new DateTime(2026, 11, 15, 10, 0, 0, DateTimeKind.Utc) });

        var line = Assert.Single(_output.Messages);
        Assert.StartsWith("Trajeto 12 ativado em ", line);
        Assert.Empty(_audit.RecordedEvents);
    }

    [Fact]
    public async Task UnknownPlaceholders_AreKeptAsWritten()
    {
        var context = new DataFlowContext { Source = "/api/test", Purpose = "Log" };

        await _logger.LogAsync(SecureLogLevel.Error, "Erro em {Operation}", context);

        Assert.Equal("Erro em {Operation}", Assert.Single(_output.Messages));
    }
}

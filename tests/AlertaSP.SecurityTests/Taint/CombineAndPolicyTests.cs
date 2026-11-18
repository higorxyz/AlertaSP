using System.Diagnostics;
using AlertaSP.Core.Entities;
using AlertaSP.Core.Enums;
using AlertaSP.Core.Interfaces.Security;
using AlertaSP.Security.Dashboard;
using AlertaSP.Security.Pii.Rules;
using AlertaSP.Security.Risk;
using AlertaSP.Security.Taint;
using AlertaSP.SecurityTests.Support;
using Microsoft.Extensions.Options;
using Xunit;

namespace AlertaSP.SecurityTests.Taint;

/// <summary>
/// Propagação por concatenação (Combine/Concat), exigência de finalidade na política
/// e contagem de operações permitidas/bloqueadas no dashboard.
/// </summary>
public class CombineAndPolicyTests
{
    private const string RawCpf = "529.982.247-25";

    private readonly ITaintTracker _tracker;
    private readonly FakeAuditSink _audit = new();
    private readonly FakeIncidentRepository _incidents = new();

    public CombineAndPolicyTests()
    {
        _tracker = TestSecurity.CreateTracker(_audit, _incidents);
    }

    private static DataFlowContext Ctx(string purpose = "CombineTest", bool authorized = false) => new()
    {
        Source = "/api/test",
        Purpose = purpose,
        IsAuthorized = authorized
    };

    // ---------- Combine / Concat ----------

    [Fact]
    public async Task Concat_PublicPlusCpf_InheritsCpfSensitivityAndIsMaskedOnLog()
    {
        var context = Ctx();
        var publicPart = _tracker.Taint("Cidadão: ", context, DataCategory.None, DataSensitivity.None);
        var cpfPart = _tracker.Taint(RawCpf, context, DataCategory.PersonalData, DataSensitivity.High);

        var combined = _tracker.Concat(publicPart, cpfPart);

        Assert.Equal(DataCategory.PersonalData, combined.Metadata.Category);
        Assert.Equal(DataSensitivity.High, combined.Metadata.Sensitivity);
        Assert.DoesNotContain(RawCpf, combined.ToString());

        var result = await _tracker.TryDeliverAsync(combined, SinkType.Log, context);

        Assert.Equal(PolicyDecision.AllowSanitized, result.Decision);
        Assert.DoesNotContain(RawCpf, result.ReleasedValue);
    }

    [Fact]
    public void Combine_DominantPartIsTheMostSensitiveAndHistoryIsMerged()
    {
        var context = Ctx();
        var location = _tracker.Taint("Av. Paulista, 1000", context, DataCategory.Location, DataSensitivity.Medium);
        var token = _tracker.Taint("segredo", context, DataCategory.Credentials, DataSensitivity.Critical);

        var combined = _tracker.Combine(new[] { location, token }, " | ");

        Assert.Equal(DataCategory.Credentials, combined.Metadata.Category);
        Assert.Equal(DataSensitivity.Critical, combined.Metadata.Sensitivity);
        Assert.Contains(combined.Metadata.PropagationHistory, h => h.StartsWith("Combine(Parts:2"));
        Assert.True(combined.Metadata.PropagationHistory.Count > location.Metadata.PropagationHistory.Count);
    }

    [Fact]
    public async Task Combine_CredentialsPart_IsBlockedOnPublicResponse()
    {
        var context = Ctx();
        var a = _tracker.Taint("usuário", context, DataCategory.None, DataSensitivity.None);
        var b = _tracker.Taint("sk-proj-94819482938491823948192384912384", context, DataCategory.Credentials, DataSensitivity.Critical);

        var combined = _tracker.Concat(a, b, ":");
        var result = await _tracker.TryDeliverAsync(combined, SinkType.PublicHttpResponse, context);

        Assert.Equal(PolicyDecision.Block, result.Decision);
        Assert.Null(result.ReleasedValue);
    }

    [Fact]
    public void Combine_EmptyList_Throws()
    {
        Assert.Throws<ArgumentException>(() => _tracker.Combine(Array.Empty<Tainted<string>>()));
    }

    [Fact]
    public void Combine_SanitizedFlagOnlyWhenEverySensitivePartWasSanitized()
    {
        var context = Ctx();
        var cpf = _tracker.Taint(RawCpf, context, DataCategory.PersonalData, DataSensitivity.High);
        var maskedCpf = _tracker.Sanitize(cpf, "***.***.***-25");
        var location = _tracker.Taint("Rua das Flores, 10", context, DataCategory.Location, DataSensitivity.Medium);

        var partial = _tracker.Combine(new[] { maskedCpf, location });
        var full = _tracker.Combine(new[] { maskedCpf, _tracker.Sanitize(location, "Rua ***") });

        Assert.False(partial.Metadata.IsSanitized);
        Assert.True(full.Metadata.IsSanitized);
    }

    // ---------- Finalidade obrigatória na política ----------

    [Theory]
    [InlineData(DataCategory.PersonalData)]
    [InlineData(DataCategory.Location)]
    public void Policy_InternalResponse_RequiresAuthorizationAndPurpose(DataCategory category)
    {
        var policy = new SecurityPolicy();

        var authorizedWithPurpose = new DataFlowContext { Purpose = "RouteAlertGeneration", IsAuthorized = true };
        var authorizedNoPurpose = new DataFlowContext { Purpose = "  ", IsAuthorized = true };
        var purposeNoAuthorization = new DataFlowContext { Purpose = "RouteAlertGeneration", IsAuthorized = false };

        Assert.Equal(PolicyDecision.Allow,
            policy.Evaluate(category, DataSensitivity.High, SinkType.InternalHttpResponse, authorizedWithPurpose));
        Assert.NotEqual(PolicyDecision.Allow,
            policy.Evaluate(category, DataSensitivity.High, SinkType.InternalHttpResponse, authorizedNoPurpose));
        Assert.NotEqual(PolicyDecision.Allow,
            policy.Evaluate(category, DataSensitivity.High, SinkType.InternalHttpResponse, purposeNoAuthorization));
    }

    // ---------- Dashboard: operações permitidas × bloqueadas ----------

    [Fact]
    public async Task Dashboard_CountsAllowedSanitizedAndBlockedOperations()
    {
        var allowCtx = Ctx("RouteAlertGeneration", authorized: true);
        var okLocation = _tracker.Taint("-23.5614,-46.6559", allowCtx, DataCategory.Location, DataSensitivity.Medium);
        await _tracker.TryDeliverAsync(okLocation, SinkType.InternalHttpResponse, allowCtx);

        var ctx = Ctx("SystemLogging");
        await _tracker.TryDeliverAsync(
            _tracker.Taint(RawCpf, ctx, DataCategory.PersonalData, DataSensitivity.High), SinkType.Log, ctx);
        await _tracker.TryDeliverAsync(
            _tracker.Taint("sk-proj-94819482938491823948192384912384", ctx, DataCategory.Credentials, DataSensitivity.Critical),
            SinkType.Log, ctx);

        var options = Options.Create(new CitizenRiskOptions());
        var service = new SecurityDashboardService(
            _incidents, _audit, new CitizenRiskCalculator(options), _tracker, options);

        var metrics = await service.GetDashboardMetricsAsync();

        Assert.Equal(1, metrics.AllowedOperations);
        Assert.Equal(1, metrics.SanitizedOperations);
        Assert.Equal(1, metrics.BlockedOperations);
    }

    // ---------- Regex com timeout ----------

    [Fact]
    public void CpfAndLocationRules_HandleLongHostileInputWithinTimeBudget()
    {
        var hostile = new string('9', 200_000) + " " + string.Concat(Enumerable.Repeat("Rua ", 20_000));
        var sw = Stopwatch.StartNew();

        try
        {
            new CpfPiiRule().Detect(hostile);
            new LocationPiiRule().Detect(hostile);
        }
        catch (System.Text.RegularExpressions.RegexMatchTimeoutException)
        {
            // Aceitável: a regra estourou o limite de 250 ms e o PiiDetectionService trata isso como fail-closed.
        }

        sw.Stop();
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5), $"Regras levaram {sw.Elapsed.TotalSeconds:F1}s");
    }
}

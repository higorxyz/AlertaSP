using AlertaSP.Core.Attributes;
using AlertaSP.Core.Enums;
using AlertaSP.Core.Exceptions;
using AlertaSP.Core.Interfaces.Security;
using AlertaSP.SecurityTests.Support;
using Xunit;

namespace AlertaSP.SecurityTests.Taint;

public class TaintAnalysisTests
{
    private const string RawCpf = "529.982.247-25";
    private const string RawToken = "sk-proj-94819482938491823948192384912384";

    private readonly ITaintTracker _tracker;
    private readonly FakeAuditSink _audit = new();
    private readonly FakeIncidentRepository _incidents = new();

    public TaintAnalysisTests()
    {
        _tracker = TestSecurity.CreateTracker(_audit, _incidents);
    }

    // ---------- Cenários obrigatórios (5.2) ----------

    [Fact]
    public async Task Scenario1_CpfToLog_AllowsSanitizedAndRecordsAudit()
    {
        var context = new DataFlowContext { Source = "/api/citizens", Purpose = "SystemLogging", Actor = "BackendApp" };
        var tainted = _tracker.Taint(RawCpf, context, DataCategory.PersonalData, DataSensitivity.High);

        var result = await _tracker.TryDeliverAsync(tainted, SinkType.Log, context);

        Assert.Equal(PolicyDecision.AllowSanitized, result.Decision);
        Assert.Equal("***.***.***-25", result.SanitizedValue);
        Assert.Equal("***.***.***-25", result.ReleasedValue);
        Assert.Contains(_audit.RecordedEvents, e => e.Category == DataCategory.PersonalData && e.Decision == PolicyDecision.AllowSanitized);
    }

    [Fact]
    public async Task Scenario1_CpfInsideFreeText_IsDetectedByContentAndMasked()
    {
        var context = new DataFlowContext { Source = "/api/citizens", Purpose = "SystemLogging" };
        var tainted = _tracker.TaintByContent($"Cadastro do CPF {RawCpf} concluído", context);

        Assert.Equal(DataCategory.PersonalData, tainted.Metadata.Category);

        var result = await _tracker.TryDeliverAsync(tainted, SinkType.Log, context);

        Assert.Equal(PolicyDecision.AllowSanitized, result.Decision);
        Assert.Equal("Cadastro do CPF ***.***.***-25 concluído", result.ReleasedValue);
        Assert.DoesNotContain(RawCpf, result.ReleasedValue);
    }

    [Fact]
    public async Task Scenario2_AddressToPublicResponse_AllowsSanitizedAndCreatesIncident()
    {
        var context = new DataFlowContext { Source = "/api/routes", Purpose = "PublicProfileView", Actor = "AnonymousClient" };
        var tainted = _tracker.Taint("Av. Paulista, 1000", context, DataCategory.Location, DataSensitivity.Medium);

        var result = await _tracker.TryDeliverAsync(tainted, SinkType.PublicHttpResponse, context);

        Assert.Equal(PolicyDecision.AllowSanitized, result.Decision);
        Assert.DoesNotContain("1000", result.ReleasedValue);
        Assert.Contains(_incidents.RecordedIncidents, i => i.Category == DataCategory.Location && i.Result == IncidentResult.Sanitized);
    }

    [Fact]
    public async Task Scenario3_CredentialsToExternalAiService_BlocksDeliveryAndCreatesCriticalIncident()
    {
        var context = new DataFlowContext { Source = "/api/security/analyze", Purpose = "AiCompletion", Actor = "AiAgent" };
        var tainted = _tracker.Taint(RawToken, context, DataCategory.Credentials, DataSensitivity.Critical);

        var result = await _tracker.TryDeliverAsync(tainted, SinkType.ExternalAiService, context);

        Assert.Equal(PolicyDecision.Block, result.Decision);
        Assert.False(result.Allowed);
        Assert.Null(result.ReleasedValue);
        var incident = Assert.Single(_incidents.RecordedIncidents, i => i.Category == DataCategory.Credentials);
        Assert.Equal(IncidentResult.Blocked, incident.Result);
        Assert.Equal(DataSensitivity.Critical, incident.Sensitivity);
    }

    [Fact]
    public async Task Scenario3_CredentialInsideFreeText_IsDetectedByContentAndBlocked()
    {
        var context = new DataFlowContext { Source = "/api/security/analyze", Purpose = "AiCompletion" };
        var tainted = _tracker.TaintByContent($"config: api_key={RawToken}", context);

        Assert.Equal(DataCategory.Credentials, tainted.Metadata.Category);
        Assert.Equal(DataSensitivity.Critical, tainted.Metadata.Sensitivity);

        var result = await _tracker.TryDeliverAsync(tainted, SinkType.ExternalAiService, context);

        Assert.Equal(PolicyDecision.Block, result.Decision);
        Assert.Null(result.ReleasedValue);
        Assert.Single(_incidents.RecordedIncidents);
        Assert.DoesNotContain(RawToken, _audit.RecordedEvents.Single().Summary);
    }

    [Fact]
    public async Task Scenario4_AuthorizedInternalFlow_AllowsAccessToGenerateAlerts()
    {
        var context = new DataFlowContext
        {
            Source = "/api/alerts/generate",
            Purpose = "RouteAlertGeneration",
            Actor = "InternalAlertEngine",
            IsAuthorized = true
        };
        var tainted = _tracker.Taint("-23.5614,-46.6559", context, DataCategory.Location, DataSensitivity.Medium);

        var result = await _tracker.TryDeliverAsync(tainted, SinkType.InternalHttpResponse, context);

        Assert.Equal(PolicyDecision.Allow, result.Decision);
        Assert.True(result.Allowed);
        Assert.Equal("-23.5614,-46.6559", result.ReleasedValue);
        Assert.Empty(_incidents.RecordedIncidents);
    }

    // ---------- Origem: fonte rotulada e detecção por conteúdo ----------

    private sealed class SampleRequest
    {
        public string Name { get; set; } = "Maria";

        [Sensitive(DataCategory.PersonalData)]
        public string Cpf { get; set; } = RawCpf;

        [Sensitive(DataCategory.Location)]
        public double Latitude { get; set; } = -23.5612;

        [Sensitive(DataCategory.Location)]
        public string? Complement { get; set; }
    }

    [Fact]
    public void AnnotatedFields_TaintOnlyPropertiesMarkedAsSensitive()
    {
        var context = new DataFlowContext { Source = "/api/test" };

        var fields = _tracker.TaintAnnotatedFields(new SampleRequest(), context);

        Assert.Equal(new[] { "Cpf", "Latitude" }, fields.Keys.OrderBy(k => k).ToArray());
        Assert.Equal(DataCategory.PersonalData, fields["Cpf"].Metadata.Category);
        Assert.Equal(DataCategory.Location, fields["Latitude"].Metadata.Category);
        Assert.Contains(fields["Cpf"].Metadata.PropagationHistory, h => h.Contains("Field(Cpf)"));
    }

    [Fact]
    public async Task AnnotatedNumericField_IsGeneralizedWhenSentToPublicSink()
    {
        var context = new DataFlowContext { Source = "/api/test", IsRoutineOutput = true };
        var fields = _tracker.TaintAnnotatedFields(new SampleRequest(), context);

        var result = await _tracker.TryDeliverAsync(fields["Latitude"], SinkType.PublicHttpResponse, context);

        Assert.Equal(PolicyDecision.AllowSanitized, result.Decision);
        Assert.Equal("-23.56", result.ReleasedValue);
    }

    [Fact]
    public async Task TaintByContent_TextWithoutPii_IsNotSensitiveAndFlowsWithoutAuditNoise()
    {
        var context = new DataFlowContext { Source = "/api/flood-occurrences" };
        var tainted = _tracker.TaintByContent("Alagamento na avenida, pista esquerda interditada", context);

        var result = await _tracker.TryDeliverAsync(tainted, SinkType.PublicHttpResponse, context);

        Assert.Equal(DataCategory.None, tainted.Metadata.Category);
        Assert.Equal(PolicyDecision.Allow, result.Decision);
        Assert.Equal("Alagamento na avenida, pista esquerda interditada", result.ReleasedValue);
        Assert.Empty(_audit.RecordedEvents);
        Assert.Empty(_incidents.RecordedIncidents);
    }

    [Fact]
    public void TaintByContent_InvalidCpfCandidate_IsNotClassifiedAsCpf()
    {
        var context = new DataFlowContext { Source = "/api/test" };

        var tainted = _tracker.TaintByContent("tentativa com 123.456.789-99 no formulário", context);

        Assert.Equal(DataCategory.None, tainted.Metadata.Category);
    }

    [Fact]
    public void TaintByContent_MixedContent_UsesMostSevereCategory()
    {
        var context = new DataFlowContext { Source = "/api/test" };

        var tainted = _tracker.TaintByContent($"CPF {RawCpf} e senha=SegredoForte123", context);

        Assert.Equal(DataCategory.Credentials, tainted.Metadata.Category);
    }

    // ---------- Propagação ----------

    [Fact]
    public void Tainted_ToString_NeverRevealsRawSensitiveValue()
    {
        var context = new DataFlowContext { Source = "Test" };
        var tainted = _tracker.Taint("SUPER_SECRET_PASSWORD_123", context, DataCategory.Credentials, DataSensitivity.Critical);

        var text = tainted.ToString();

        Assert.DoesNotContain("SUPER_SECRET_PASSWORD_123", text);
        Assert.Equal("[TAINTED:Credentials]", text);
    }

    [Fact]
    public void Propagation_TracksOperationHistory()
    {
        var context = new DataFlowContext { Source = "SourceEndpoint" };
        var tainted = _tracker.Taint("InitialData", context, DataCategory.PersonalData, DataSensitivity.High);
        var propagated = _tracker.Propagate(tainted, "TransformedToUpperCase", "INITIALDATA");

        Assert.Contains(propagated.Metadata.PropagationHistory, h => h.Contains("TransformedToUpperCase"));
        Assert.Equal(DataCategory.PersonalData, propagated.Metadata.Category);
        Assert.Equal(DataSensitivity.High, propagated.Metadata.Sensitivity);
        Assert.Equal(tainted.Metadata.FlowId, propagated.Metadata.FlowId);
    }

    [Fact]
    public async Task PropagatedValue_KeepsTaintAndIsStillBlockedAtTheSink()
    {
        var context = new DataFlowContext { Source = "/api/test", Purpose = "Debug" };
        var tainted = _tracker.Taint("MinhaSenhaSecreta!", context, DataCategory.Credentials, DataSensitivity.Critical);

        var upper = _tracker.Propagate(tainted, "Map(ToUpper)", "MINHASENHASECRETA!");
        var concatenated = _tracker.Propagate(upper, "Concat", "senha=MINHASENHASECRETA!");

        var result = await _tracker.TryDeliverAsync(concatenated, SinkType.Log, context);

        Assert.Equal(PolicyDecision.Block, result.Decision);
        Assert.Contains(concatenated.Metadata.PropagationHistory, h => h.StartsWith("Map(ToUpper)"));
        Assert.Contains(concatenated.Metadata.PropagationHistory, h => h.StartsWith("Concat"));
    }

    [Fact]
    public async Task Sanitized_WhenNoDetectionRemains_FlowsToPublicSink()
    {
        var context = new DataFlowContext { Source = "/api/citizens", Purpose = "PublicView" };
        var tainted = _tracker.Taint(RawCpf, context, DataCategory.PersonalData, DataSensitivity.High);
        var sanitized = _tracker.Sanitize(tainted, "***.***.***-25");

        var result = await _tracker.TryDeliverAsync(sanitized, SinkType.PublicHttpResponse, context);

        Assert.Equal(PolicyDecision.Allow, result.Decision);
        Assert.Contains("AlreadySanitized", result.RuleApplied);
        Assert.Equal("***.***.***-25", result.ReleasedValue);
        Assert.Empty(_incidents.RecordedIncidents);
    }

    [Fact]
    public async Task Sanitized_WhenSensitiveContentRemains_IsStillSanitizedByPolicy()
    {
        var context = new DataFlowContext { Source = "/api/citizens", Purpose = "PublicView" };
        var tainted = _tracker.Taint(RawCpf, context, DataCategory.PersonalData, DataSensitivity.High);
        var badlySanitized = _tracker.Sanitize(tainted, RawCpf);

        var result = await _tracker.TryDeliverAsync(badlySanitized, SinkType.PublicHttpResponse, context);

        Assert.Equal(PolicyDecision.AllowSanitized, result.Decision);
        Assert.Equal("***.***.***-25", result.ReleasedValue);
    }

    // ---------- Auditoria e incidentes ----------

    [Fact]
    public async Task AuditEvents_NeverContainRawSensitiveDataInSummary()
    {
        var context = new DataFlowContext { Source = "/api/citizens", Purpose = "TestingAudit" };
        var tainted = _tracker.Taint(RawCpf, context, DataCategory.PersonalData, DataSensitivity.High);
        await _tracker.TryDeliverAsync(tainted, SinkType.Log, context);

        var auditEvent = Assert.Single(_audit.RecordedEvents);
        Assert.DoesNotContain(RawCpf, auditEvent.Summary);
        Assert.DoesNotContain("52998224725", auditEvent.Summary);
        Assert.All(_incidents.RecordedIncidents, i => Assert.DoesNotContain(RawCpf, i.Summary));
    }

    [Fact]
    public async Task RoutineOutput_Sanitization_IsAuditedButIsNotAnIncident()
    {
        var context = new DataFlowContext { Source = "/api/citizens", Purpose = "CitizenResponse", IsRoutineOutput = true };
        var tainted = _tracker.Taint(RawCpf, context, DataCategory.PersonalData, DataSensitivity.High);

        var result = await _tracker.TryDeliverAsync(tainted, SinkType.PublicHttpResponse, context);

        Assert.Equal(PolicyDecision.AllowSanitized, result.Decision);
        Assert.Single(_audit.RecordedEvents);
        Assert.Empty(_incidents.RecordedIncidents);
    }

    [Fact]
    public async Task RoutineOutput_DoesNotHideBlocks()
    {
        var context = new DataFlowContext { Source = "/api/test", Purpose = "Response", IsRoutineOutput = true };
        var tainted = _tracker.Taint("senha=abc12345", context, DataCategory.Credentials, DataSensitivity.Critical);

        var result = await _tracker.TryDeliverAsync(tainted, SinkType.PublicHttpResponse, context);

        Assert.Equal(PolicyDecision.Block, result.Decision);
        Assert.Single(_incidents.RecordedIncidents);
    }

    [Fact]
    public async Task TryDeliverMany_GroupsEqualDecisionsInOneAuditEventAndKeepsOrder()
    {
        var context = new DataFlowContext { Source = "/api/citizens", Purpose = "Listing" };
        var items = new[]
        {
            _tracker.Taint("529.982.247-25", context, DataCategory.PersonalData, DataSensitivity.High),
            _tracker.Taint("384.920.184-88", context, DataCategory.PersonalData, DataSensitivity.High),
            _tracker.Taint("111.444.777-35", context, DataCategory.PersonalData, DataSensitivity.High)
        };

        var results = await _tracker.TryDeliverManyAsync(items, SinkType.PublicHttpResponse, context);

        Assert.Equal(new[] { "***.***.***-25", "***.***.***-88", "***.***.***-35" }, results.Select(r => r.ReleasedValue).ToArray());
        var audit = Assert.Single(_audit.RecordedEvents);
        Assert.Contains("Quantidade: 3", audit.Summary);
        Assert.Single(_incidents.RecordedIncidents);
    }

    [Fact]
    public async Task ReleaseAsync_ThrowsSecurityViolationWithoutLeakingTheValue_WhenPolicyBlocks()
    {
        var context = new DataFlowContext { Source = "/api/test", Purpose = "Debug" };
        var tainted = _tracker.Taint("senha=MinhaSenha!", context, DataCategory.Credentials, DataSensitivity.Critical);

        var exception = await Assert.ThrowsAsync<SecurityViolationException>(
            () => _tracker.ReleaseAsync(tainted, SinkType.Log, context));

        Assert.DoesNotContain("MinhaSenha", exception.Message);
        Assert.Contains("Credentials", exception.Message);
    }

    [Fact]
    public async Task ReleaseAsync_ReturnsSanitizedValue_WhenPolicySanitizes()
    {
        var context = new DataFlowContext { Source = "/api/test", Purpose = "Debug" };
        var tainted = _tracker.Taint("maria.silva@exemplo.com", context, DataCategory.PersonalData, DataSensitivity.High);

        var released = await _tracker.ReleaseAsync(tainted, SinkType.Log, context);

        Assert.Equal("ma***@exemplo.com", released);
    }

    // ---------- Reveal ----------

    [Fact]
    public async Task Reveal_RequiresAuthorizedMatchingPurpose()
    {
        var context = new DataFlowContext
        {
            Source = "/api/citizens",
            Purpose = "CitizenRegistration",
            IsAuthorized = false
        };
        var tainted = _tracker.Taint(RawCpf, context, DataCategory.PersonalData, DataSensitivity.High);

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            _tracker.RevealAsync(tainted, "CitizenRegistration", context));

        context.IsAuthorized = true;
        Assert.Equal(RawCpf, await _tracker.RevealAsync(tainted, "CitizenRegistration", context));
        Assert.Contains(_audit.RecordedEvents, e => e.RuleApplied == "ExplicitRevealWithPurpose");
    }

    // ---------- Matriz de política (5.2) ----------

    [Theory]
    [InlineData(DataCategory.Credentials, SinkType.Log, PolicyDecision.Block)]
    [InlineData(DataCategory.Credentials, SinkType.PublicHttpResponse, PolicyDecision.Block)]
    [InlineData(DataCategory.Credentials, SinkType.ExternalAiService, PolicyDecision.Block)]
    [InlineData(DataCategory.Credentials, SinkType.Report, PolicyDecision.Block)]
    [InlineData(DataCategory.Credentials, SinkType.Export, PolicyDecision.Block)]
    [InlineData(DataCategory.PersonalData, SinkType.Log, PolicyDecision.AllowSanitized)]
    [InlineData(DataCategory.PersonalData, SinkType.PublicHttpResponse, PolicyDecision.AllowSanitized)]
    [InlineData(DataCategory.PersonalData, SinkType.ExternalAiService, PolicyDecision.AllowSanitized)]
    [InlineData(DataCategory.PersonalData, SinkType.Report, PolicyDecision.AllowSanitized)]
    [InlineData(DataCategory.PersonalData, SinkType.Export, PolicyDecision.AllowSanitized)]
    [InlineData(DataCategory.PersonalData, SinkType.Database, PolicyDecision.Allow)]
    [InlineData(DataCategory.Location, SinkType.Log, PolicyDecision.AllowSanitized)]
    [InlineData(DataCategory.Location, SinkType.PublicHttpResponse, PolicyDecision.AllowSanitized)]
    [InlineData(DataCategory.Location, SinkType.ExternalAiService, PolicyDecision.AllowSanitized)]
    [InlineData(DataCategory.HealthData, SinkType.Log, PolicyDecision.Block)]
    [InlineData(DataCategory.HealthData, SinkType.PublicHttpResponse, PolicyDecision.Block)]
    [InlineData(DataCategory.HealthData, SinkType.ExternalAiService, PolicyDecision.Block)]
    [InlineData(DataCategory.HealthData, SinkType.Export, PolicyDecision.Block)]
    public async Task PolicyMatrix_UnauthorizedFlow_FollowsTheDocumentedDecision(
        DataCategory category, SinkType sink, PolicyDecision expected)
    {
        var context = new DataFlowContext { Source = "/api/test", Purpose = "Matrix", IsAuthorized = false };
        var tainted = _tracker.Taint("valor-de-teste-123", context, category, DataSensitivity.High);

        var result = await _tracker.TryDeliverAsync(tainted, sink, context);

        Assert.Equal(expected, result.Decision);
    }

    [Fact]
    public async Task HealthData_IsAllowedOnlyForAuthorizedInternalFlowWithHealthPurpose()
    {
        var context = new DataFlowContext
        {
            Source = "/api/test",
            Purpose = "HealthRecordReview",
            IsAuthorized = true
        };
        var tainted = _tracker.Taint("diagnóstico de diabetes", context, DataCategory.HealthData, DataSensitivity.High);

        var internalResult = await _tracker.TryDeliverAsync(tainted, SinkType.InternalHttpResponse, context);
        var publicResult = await _tracker.TryDeliverAsync(tainted, SinkType.PublicHttpResponse, context);

        Assert.Equal(PolicyDecision.Allow, internalResult.Decision);
        Assert.Equal(PolicyDecision.Block, publicResult.Decision);
    }
}

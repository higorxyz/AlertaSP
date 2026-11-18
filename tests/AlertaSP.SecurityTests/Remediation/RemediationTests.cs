using System.Net;
using System.Text;
using AlertaSP.Core.Entities;
using AlertaSP.Core.Enums;
using AlertaSP.Core.Interfaces.Security;
using AlertaSP.Security.Remediation;
using AlertaSP.SecurityTests.Support;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace AlertaSP.SecurityTests.Remediation;

public class RemediationTests
{
    private readonly DeterministicRemediationService _deterministicService = new();
    private readonly FakeAuditSink _audit = new();
    private readonly FakeIncidentRepository _incidents = new();

    // ---------- Fallback determinístico ----------

    [Fact]
    public async Task DeterministicFallback_LabelsOriginAsFallback()
    {
        var result = await _deterministicService.TranslateIncidentAsync(CreateIncident());

        Assert.Equal(RemediationOrigin.Fallback, result.Origin);
        Assert.NotEmpty(result.Message);
        Assert.Contains("credenciais", result.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task DeterministicFallback_PersonalData_ProvidesClearCitizenMessage()
    {
        var incident = SecurityIncident.Create(
            "flow-test-cpf", DataCategory.PersonalData, DataSensitivity.High,
            SinkType.PublicHttpResponse, PolicyDecision.AllowSanitized, IncidentResult.Sanitized,
            "Rule_CPF", "Sanitização de CPF");

        var result = await _deterministicService.TranslateIncidentAsync(incident);

        Assert.Equal(RemediationOrigin.Fallback, result.Origin);
        Assert.Contains("dados pessoais", result.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("mascaramento", result.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(DataCategory.PersonalData)]
    [InlineData(DataCategory.Location)]
    [InlineData(DataCategory.Credentials)]
    [InlineData(DataCategory.HealthData)]
    public async Task DeterministicFallback_TranslatesEveryCategory(DataCategory category)
    {
        var incident = SecurityIncident.Create(
            "flow", category, DataSensitivity.High, SinkType.PublicHttpResponse,
            PolicyDecision.Block, IncidentResult.Blocked, "Rule", "Resumo");

        var result = await _deterministicService.TranslateIncidentAsync(incident);

        Assert.Equal(RemediationOrigin.Fallback, result.Origin);
        Assert.True(result.Message.Length > 40);
    }

    // ---------- Configuração ausente ----------

    [Fact]
    public async Task WithoutApiKey_UsesLabeledFallbackAndNeverCallsTheNetwork()
    {
        var handler = new RecordingHandler((_, _) => throw new InvalidOperationException("não deveria chamar a rede"));
        var service = CreateLlmService(handler, apiKey: string.Empty);

        var result = await service.TranslateIncidentAsync(CreateIncident());

        Assert.Equal(RemediationOrigin.Fallback, result.Origin);
        Assert.Equal(0, handler.CallCount);
    }

    // ---------- Resposta válida ----------

    [Fact]
    public async Task ValidLlmResponse_IsReturnedWithLlmOrigin()
    {
        var handler = RecordingHandler.Responding(LlmJson("Tentamos enviar uma senha para fora do sistema, mas bloqueamos a operação para proteger você."));
        var service = CreateLlmService(handler);

        var result = await service.TranslateIncidentAsync(CreateIncident());

        Assert.Equal(RemediationOrigin.Llm, result.Origin);
        Assert.Contains("bloqueamos", result.Message);
        Assert.Equal(1, handler.CallCount);
    }

    [Fact]
    public async Task LlmResponseWithMarkdown_IsReturnedAsPlainText()
    {
        var handler = RecordingHandler.Responding(LlmJson("**O que aconteceu:** tentamos enviar uma senha para fora. \n- **O que fizemos:** bloqueamos o envio."));
        var service = CreateLlmService(handler);

        var result = await service.TranslateIncidentAsync(CreateIncident());

        Assert.Equal(RemediationOrigin.Llm, result.Origin);
        Assert.DoesNotContain("**", result.Message);
        Assert.DoesNotContain("- ", result.Message.TrimStart().Substring(0, 2));
        Assert.Contains("O que aconteceu: tentamos enviar uma senha", result.Message);
        Assert.Contains("bloqueamos o envio", result.Message);
    }

    // ---------- Prompt sem PII (10.4) ----------

    [Fact]
    public async Task PromptSentToTheLlm_ContainsOnlyDescriptorsAndNoSensitiveContent()
    {
        var incident = SecurityIncident.Create(
            "flow-1", DataCategory.Credentials, DataSensitivity.Critical, SinkType.ExternalAiService,
            PolicyDecision.Block, IncidentResult.Blocked, "Policy:Credentials->ExternalAiService",
            "Resumo interno com CPF 529.982.247-25 e senha=NaoDeveSair123");
        var handler = RecordingHandler.Responding(LlmJson("Bloqueamos o envio de uma credencial."));
        var service = CreateLlmService(handler);

        await service.TranslateIncidentAsync(incident);

        var body = Assert.Single(handler.Bodies);
        Assert.DoesNotContain("529.982.247-25", body);
        Assert.DoesNotContain("NaoDeveSair123", body);
        Assert.DoesNotContain("Resumo interno", body);
        Assert.Contains("Credentials", body);
        Assert.Contains("ExternalAiService", body);
        Assert.Empty(TestSecurity.Detector().Analyze(body));
    }

    [Fact]
    public async Task PromptContainingPii_IsCancelledBeforeAnyRequestAndRecordedAsBlockedFlow()
    {
        // Uma regra violada que carrega um CPF faz o prompt conter PII: o envio deve ser cancelado.
        var incident = SecurityIncident.Create(
            "flow-2", DataCategory.PersonalData, DataSensitivity.High, SinkType.PublicHttpResponse,
            PolicyDecision.AllowSanitized, IncidentResult.Sanitized, "Policy:529.982.247-25", "Resumo");
        var handler = RecordingHandler.Responding(LlmJson("não deveria ser usado"));
        var service = CreateLlmService(handler);

        var result = await service.TranslateIncidentAsync(incident);

        Assert.Equal(RemediationOrigin.Fallback, result.Origin);
        Assert.Equal(0, handler.CallCount);
        Assert.Contains(_audit.RecordedEvents, e => e.SinkType == SinkType.ExternalAiService);
    }

    [Fact]
    public async Task PromptContainingCredential_IsBlockedByThePolicyAndNeverSent()
    {
        var incident = SecurityIncident.Create(
            "flow-3", DataCategory.Credentials, DataSensitivity.Critical, SinkType.ExternalAiService,
            PolicyDecision.Block, IncidentResult.Blocked, "senha=SuperSecreta123", "Resumo");
        var handler = RecordingHandler.Responding(LlmJson("não deveria ser usado"));
        var service = CreateLlmService(handler);

        var result = await service.TranslateIncidentAsync(incident);

        Assert.Equal(RemediationOrigin.Fallback, result.Origin);
        Assert.Equal(0, handler.CallCount);
        var blocked = Assert.Single(_incidents.RecordedIncidents);
        Assert.Equal(IncidentResult.Blocked, blocked.Result);
        Assert.Equal(SinkType.ExternalAiService, blocked.SinkType);
    }

    // ---------- Resposta não confiável ----------

    [Theory]
    [InlineData("Veja https://malicious.example para detalhes")]
    [InlineData("Acesse www.golpe.example agora")]
    [InlineData("Rode ```curl http://x``` no terminal")]
    [InlineData("Por favor execute este comando agora")]
    [InlineData("Seu CPF 529.982.247-25 foi exposto")]
    [InlineData("A senha=Vazada12345 foi enviada")]
    public async Task UnsafeLlmResponse_IsRejectedAndUsesLabeledFallback(string content)
    {
        var service = CreateLlmService(RecordingHandler.Responding(LlmJson(content)));

        var result = await service.TranslateIncidentAsync(CreateIncident());

        Assert.Equal(RemediationOrigin.Fallback, result.Origin);
    }

    [Fact]
    public async Task OversizedLlmResponse_IsTruncated()
    {
        var service = CreateLlmService(RecordingHandler.Responding(LlmJson(new string('a', 5000))));

        var result = await service.TranslateIncidentAsync(CreateIncident());

        Assert.Equal(RemediationOrigin.Llm, result.Origin);
        Assert.Equal(1000, result.Message.Length);
    }

    [Theory]
    [InlineData("""{"choices":[]}""")]
    [InlineData("""{"unexpected":true}""")]
    [InlineData("""{"choices":[{"message":{"content":""}}]}""")]
    [InlineData("isto não é json")]
    public async Task MalformedLlmResponse_UsesLabeledFallback(string body)
    {
        var service = CreateLlmService(RecordingHandler.Responding(body));

        var result = await service.TranslateIncidentAsync(CreateIncident());

        Assert.Equal(RemediationOrigin.Fallback, result.Origin);
    }

    // ---------- Indisponibilidade, timeout e retry limitado ----------

    [Fact]
    public async Task TransientServerError_IsRetriedOnceAndThenFallsBack()
    {
        var handler = new RecordingHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)));
        var service = CreateLlmService(handler, maxAttempts: 2);

        var result = await service.TranslateIncidentAsync(CreateIncident());

        Assert.Equal(RemediationOrigin.Fallback, result.Origin);
        Assert.Equal(2, handler.CallCount);
    }

    [Fact]
    public async Task TransientFailureFollowedBySuccess_ReturnsTheLlmAnswer()
    {
        var handler = new RecordingHandler((_, call) => Task.FromResult(call == 1
            ? new HttpResponseMessage(HttpStatusCode.BadGateway)
            : Json(LlmJson("Bloqueamos a operação para proteger seus dados."))));
        var service = CreateLlmService(handler, maxAttempts: 2);

        var result = await service.TranslateIncidentAsync(CreateIncident());

        Assert.Equal(RemediationOrigin.Llm, result.Origin);
        Assert.Equal(2, handler.CallCount);
    }

    [Fact]
    public async Task ClientError_IsNotRetried()
    {
        var handler = new RecordingHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.Unauthorized)));
        var service = CreateLlmService(handler, maxAttempts: 3);

        var result = await service.TranslateIncidentAsync(CreateIncident());

        Assert.Equal(RemediationOrigin.Fallback, result.Origin);
        Assert.Equal(1, handler.CallCount);
    }

    [Fact]
    public async Task NetworkFailure_UsesLabeledFallbackAfterTheAttemptLimit()
    {
        var handler = new RecordingHandler((_, _) => throw new HttpRequestException("rede indisponível"));
        var service = CreateLlmService(handler, maxAttempts: 2);

        var result = await service.TranslateIncidentAsync(CreateIncident());

        Assert.Equal(RemediationOrigin.Fallback, result.Origin);
        Assert.Equal(2, handler.CallCount);
    }

    [Fact]
    public async Task Timeout_UsesLabeledFallback()
    {
        var handler = new RecordingHandler((_, _) => throw new TaskCanceledException("timeout simulado"));
        var service = CreateLlmService(handler, maxAttempts: 1);

        var result = await service.TranslateIncidentAsync(CreateIncident());

        Assert.Equal(RemediationOrigin.Fallback, result.Origin);
    }

    [Fact]
    public async Task CallerCancellation_IsNotSwallowed()
    {
        using var cts = new CancellationTokenSource();
        var handler = new RecordingHandler((_, _) =>
        {
            cts.Cancel();
            throw new OperationCanceledException(cts.Token);
        });
        var service = CreateLlmService(handler, maxAttempts: 2);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => service.TranslateIncidentAsync(CreateIncident(), cts.Token));
    }

    // ---------- Infraestrutura de teste ----------

    private static SecurityIncident CreateIncident() =>
        SecurityIncident.Create(
            "flow-test", DataCategory.Credentials, DataSensitivity.Critical,
            SinkType.ExternalAiService, PolicyDecision.Block, IncidentResult.Blocked,
            "Rule_Creds", "Bloqueio de credencial");

    private static string LlmJson(string content) =>
        System.Text.Json.JsonSerializer.Serialize(new
        {
            choices = new[] { new { message = new { content } } }
        });

    private static HttpResponseMessage Json(string body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private LlmRemediationService CreateLlmService(RecordingHandler handler, string apiKey = "test-key", int maxAttempts = 2)
    {
        var options = Options.Create(new AiRemediationOptions
        {
            ApiKey = apiKey,
            Endpoint = "https://llm.test",
            TimeoutSeconds = 2,
            MaxAttempts = maxAttempts,
            RetryDelayMs = 0
        });

        var detector = TestSecurity.Detector();
        return new LlmRemediationService(
            new FakeHttpClientFactory(handler),
            detector,
            TestSecurity.CreateTracker(_audit, _incidents),
            new DeterministicRemediationService(),
            options,
            NullLogger<LlmRemediationService>.Instance);
    }

    private sealed class FakeHttpClientFactory : IHttpClientFactory
    {
        private readonly RecordingHandler _handler;

        public FakeHttpClientFactory(RecordingHandler handler) => _handler = handler;

        // disposeHandler: false, pois o mesmo handler atende as tentativas de retry.
        public HttpClient CreateClient(string name) => new(_handler, disposeHandler: false);
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, int, Task<HttpResponseMessage>> _respond;
        private int _calls;

        public RecordingHandler(Func<HttpRequestMessage, int, Task<HttpResponseMessage>> respond) => _respond = respond;

        public static RecordingHandler Responding(string body) =>
            new((_, _) => Task.FromResult(Json(body)));

        public int CallCount => _calls;
        public List<string> Bodies { get; } = new();

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var call = Interlocked.Increment(ref _calls);
            if (request.Content != null)
                Bodies.Add(await request.Content.ReadAsStringAsync(cancellationToken));

            return await _respond(request, call);
        }
    }
}

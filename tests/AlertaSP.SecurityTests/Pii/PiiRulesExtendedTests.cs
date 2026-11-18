using AlertaSP.Core.Enums;
using AlertaSP.Core.Interfaces.Security;
using AlertaSP.Security.Pii;
using AlertaSP.Security.Pii.Rules;
using AlertaSP.SecurityTests.Support;
using Xunit;

namespace AlertaSP.SecurityTests.Pii;

public class PiiRulesExtendedTests
{
    private readonly IPiiDetector _detector = TestSecurity.Detector();
    private readonly IPiiMaskingService _masker;

    public PiiRulesExtendedTests()
    {
        _masker = TestSecurity.Masker(_detector);
    }

    // ---------- Credenciais ----------

    [Fact]
    public void Credentials_OpenAiProjectToken_IsDetectedByPrefix()
    {
        var detections = _detector.Analyze("token vazado: sk-proj-94819482938491823948192384912384 no chat");

        Assert.Contains(detections, d => d.Rule == "CREDENTIAL_PREFIX_TOKEN" && d.Category == DataCategory.Credentials);
    }

    [Theory]
    [InlineData("ghp_abcdefghijklmnopqrstuvwxyz0123456789")]
    [InlineData("AKIAIOSFODNN7EXAMPLE")]
    public void Credentials_OtherVendorTokens_AreDetectedByPrefix(string token)
    {
        var detections = _detector.Analyze($"chave: {token}");

        Assert.Contains(detections, d => d.Category == DataCategory.Credentials);
    }

    [Fact]
    public void Credentials_OpaqueBearerToken_IsDetected()
    {
        var detections = _detector.Analyze("Authorization: Bearer 8f3a9c1d27be4410");

        Assert.Contains(detections, d => d.Rule == "CREDENTIAL_BEARER_TOKEN");
    }

    [Fact]
    public void Credentials_BasicAuthorizationHeader_IsDetected()
    {
        var detections = _detector.Analyze("Authorization: Basic dXNlcjpwYXNzd29yZDEyMw==");

        Assert.Contains(detections, d => d.Rule == "CREDENTIAL_BASIC_AUTH");
    }

    [Fact]
    public void Credentials_WordBearerInPlainText_IsNotADetection()
    {
        var detections = _detector.Analyze("O bearer certificate foi emitido pelo cartório.");

        Assert.DoesNotContain(detections, d => d.Category == DataCategory.Credentials);
    }

    [Fact]
    public void Credentials_HighEntropyValueAssignedToSecretLikeKey_IsDetected()
    {
        var detections = _detector.Analyze("client_token=Zk3pQ9vL2xR8mT5wY1nB7dF4");

        Assert.Contains(detections, d => d.Rule == "CREDENTIAL_HIGH_ENTROPY");
    }

    [Fact]
    public void Credentials_LowEntropyValueAssignedToSecretLikeKey_IsNotADetection()
    {
        var detections = _detector.Analyze("token_name=aaaaaaaaaaaaaaaaaaaaaaaa1");

        Assert.DoesNotContain(detections, d => d.Category == DataCategory.Credentials);
    }

    [Fact]
    public void Credentials_JsonPasswordField_IsDetected()
    {
        var detections = _detector.Analyze("""{"user":"maria","password":"Abc!2345xyz"}""");

        Assert.Contains(detections, d => d.Rule == "CREDENTIAL_KEY_VALUE");
    }

    [Fact]
    public void Credentials_AssignmentWithOverlappingRules_IsMaskedOnceWithoutCorruption()
    {
        var masked = _masker.MaskContent("api_key=sk-proj-94819482938491823948192384912384");

        Assert.Equal("[REDACTED]", masked);
    }

    // ---------- Saúde (regras configuráveis) ----------

    [Theory]
    [InlineData("O hospital fica na avenida principal.")]
    [InlineData("Campanha de conscientização sobre diabetes no bairro.")]
    [InlineData("A clínica abre às 8h.")]
    public void Health_IsolatedClinicalTerms_DoNotReachTheThreshold(string text)
    {
        Assert.DoesNotContain(_detector.Analyze(text), d => d.Category == DataCategory.HealthData);
    }

    [Theory]
    [InlineData("O paciente tem diabetes e está em acompanhamento")]
    [InlineData("Consta CID J45 no cadastro")]
    [InlineData("Ele é portador de hipertensão desde 2019")]
    [InlineData("Está em tratamento de depressão")]
    public void Health_CombinedSignals_AreDetected(string text)
    {
        Assert.Contains(_detector.Analyze(text), d => d.Category == DataCategory.HealthData);
    }

    [Fact]
    public void Health_CriticalCondition_HasCriticalSensitivity()
    {
        var detection = Assert.Single(_detector.Analyze("O morador é soropositivo"), d => d.Category == DataCategory.HealthData);

        Assert.Equal(DataSensitivity.Critical, detection.Sensitivity);
        Assert.Equal(RecommendedAction.Block, detection.RecommendedAction);
    }

    [Fact]
    public void Health_RulesCanBeReplacedByJsonWithoutChangingTheService()
    {
        const string json = """
            { "threshold": 3, "terms": [ { "name": "enxaqueca", "pattern": "enxaqueca", "weight": 3 } ] }
            """;
        var custom = new PiiDetectionService(new IPiiRule[] { new HealthDataPiiRule(HealthRuleSet.Parse(json)) });

        Assert.Contains(custom.Analyze("Ela sofre de enxaqueca crônica"), d => d.Category == DataCategory.HealthData);
        Assert.Empty(custom.Analyze("O paciente tem diabetes e está em acompanhamento"));
    }

    [Fact]
    public void Health_DefaultCatalogIsEmbeddedAndLoads()
    {
        var rules = HealthRuleSet.LoadDefault();

        Assert.True(rules.Threshold > 0);
        Assert.NotEmpty(rules.Terms);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("""{ "terms": [] }""")]
    [InlineData("""{ "terms": [ { "name": "x", "pattern": "", "weight": 2 } ] }""")]
    public void Health_InvalidCatalog_IsRejected(string json)
    {
        Assert.Throws<InvalidOperationException>(() => HealthRuleSet.Parse(json));
    }

    [Fact]
    public void Health_DetectionSpan_PointsAtTheClinicalText()
    {
        const string text = "Anotação: o paciente tem diabetes. Fim.";

        var detection = Assert.Single(_detector.Analyze(text), d => d.Category == DataCategory.HealthData);

        Assert.Equal(detection.MatchedValue, text.Substring(detection.Start, detection.Length));
    }

    // ---------- E-mail e coordenadas ----------

    [Fact]
    public void Email_IsDetectedAndMasked()
    {
        const string text = "Contato: maria.silva@exemplo.com.br para retorno";

        var detection = Assert.Single(_detector.Analyze(text), d => d.Rule == "PII_EMAIL");

        Assert.Equal(DataCategory.PersonalData, detection.Category);
        Assert.Equal("Contato: ma***@exemplo.com.br para retorno", _masker.MaskContent(text));
    }

    [Theory]
    [InlineData("Ponto em -23.5614,-46.6559 alagado")]
    [InlineData("coord -23.561423; -46.655912")]
    public void Coordinates_WithEnoughPrecision_AreDetectedAsLocation(string text)
    {
        Assert.Contains(_detector.Analyze(text), d => d.Rule == "LOCATION_COORDINATES" && d.Category == DataCategory.Location);
    }

    [Theory]
    [InlineData("Nota 1.5, 2.5 no teste")]
    [InlineData("lat 95.1234, 10.1234")]
    public void Coordinates_WithLowPrecisionOrOutOfRange_AreNotDetected(string text)
    {
        Assert.DoesNotContain(_detector.Analyze(text), d => d.Rule == "LOCATION_COORDINATES");
    }

    // ---------- Mascaramento ----------

    [Fact]
    public void MaskContent_MultipleCategories_ReplacesEachOneAndKeepsTheRest()
    {
        const string text = "CPF 529.982.247-25, e-mail ana@exemplo.com, senha=Abc12345! e ponto -23.5614,-46.6559.";

        var masked = _masker.MaskContent(text);

        Assert.DoesNotContain("529.982.247-25", masked);
        Assert.DoesNotContain("ana@exemplo.com", masked);
        Assert.DoesNotContain("Abc12345!", masked);
        Assert.DoesNotContain("-23.5614", masked);
        Assert.Contains("***.***.***-25", masked);
        Assert.Contains("an***@exemplo.com", masked);
        Assert.Contains("[REDACTED]", masked);
        Assert.Contains("[COORDENADA PROTEGIDA]", masked);
    }

    [Fact]
    public void MaskContent_TextWithoutPii_IsReturnedUnchanged()
    {
        const string text = "Alagamento na pista, sem feridos.";

        Assert.Equal(text, _masker.MaskContent(text));
    }

    [Theory]
    [InlineData("Rua A, 10 - Centro, Suzano - SP", "*** - Centro, Suzano - SP")]
    [InlineData("Av. Paulista, 1000", "[ENDEREÇO PROTEGIDO]")]
    [InlineData("", "[ENDEREÇO OMITIDO]")]
    public void MaskAddress_GeneralizesOrOmits(string address, string expected)
    {
        Assert.Equal(expected, _masker.MaskAddress(address));
    }

    [Fact]
    public void MaskCoordinate_RoundsToTwoDecimals()
    {
        Assert.Equal("-23.56", _masker.MaskCoordinate("-23.5612"));
        Assert.Equal("[COORDENADA PROTEGIDA]", _masker.MaskCoordinate("não-numérico"));
    }

    // ---------- Extensibilidade e entradas hostis ----------

    private sealed class AlwaysDetectsRule : IPiiRule
    {
        public IReadOnlyList<PiiDetection> Detect(string content) => new[]
        {
            new PiiDetection { Category = DataCategory.PersonalData, Rule = "CUSTOM_RULE", Start = 0, Length = 1 }
        };
    }

    [Fact]
    public void NewRules_CanBeAddedWithoutChangingTheService()
    {
        var detector = new PiiDetectionService(new IPiiRule[] { new AlwaysDetectsRule() });

        Assert.Contains(detector.Analyze("x"), d => d.Rule == "CUSTOM_RULE");
    }

    private sealed class TimingOutRule : IPiiRule
    {
        public IReadOnlyList<PiiDetection> Detect(string content) =>
            throw new System.Text.RegularExpressions.RegexMatchTimeoutException();
    }

    [Fact]
    public void RuleTimeout_FailsClosedInsteadOfLettingContentThrough()
    {
        var detector = new PiiDetectionService(new IPiiRule[] { new TimingOutRule() });

        var detection = Assert.Single(detector.Analyze("conteúdo qualquer"));

        Assert.Equal("ANALYSIS_TIMEOUT_FAIL_CLOSED", detection.Rule);
        Assert.Equal(RecommendedAction.Block, detection.RecommendedAction);
    }

    [Fact]
    public void LongPathologicalInput_FinishesQuickly()
    {
        var input = new string('a', 20000) + "=" + new string('b', 20000);

        var started = DateTime.UtcNow;
        _ = _detector.Analyze(input);

        Assert.True(DateTime.UtcNow - started < TimeSpan.FromSeconds(5));
    }
}

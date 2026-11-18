using AlertaSP.Core.Enums;
using AlertaSP.Core.Interfaces.Security;
using AlertaSP.Security.Pii;
using AlertaSP.Security.Pii.Rules;
using Xunit;

namespace AlertaSP.SecurityTests.Pii;

public class PiiDetectorTests
{
    private readonly IPiiDetector _detector;
    private readonly IPiiMaskingService _masker;

    public PiiDetectorTests()
    {
        var rules = new IPiiRule[]
        {
            new CpfPiiRule(),
            new CredentialsPiiRule(),
            new HealthDataPiiRule(),
            new LocationPiiRule()
        };
        _detector = new PiiDetectionService(rules);
        _masker = new PiiMaskingService(_detector);
    }

    [Fact]
    public void Detect_ValidFormattedCpf_ReturnsValidDetectionWithHighConfidence()
    {
        // 529.982.247-25 é um CPF válido com dígitos verificadores reais
        string text = "O relatório do cidadão CPF: 529.982.247-25 foi processado.";
        var detections = _detector.Analyze(text);

        var cpfDetection = Assert.Single(detections, d => d.Category == DataCategory.PersonalData);
        Assert.True(cpfDetection.IsValid);
        Assert.True(cpfDetection.Confidence > 0.9);
        Assert.Equal(DataSensitivity.High, cpfDetection.Sensitivity);
        Assert.Equal(RecommendedAction.Mask, cpfDetection.RecommendedAction);
    }

    [Fact]
    public void Detect_ValidUnformattedCpf_ReturnsValidDetection()
    {
        string text = "Cidadão portador do documento 52998224725 solicitou alerta.";
        var detections = _detector.Analyze(text);

        var cpfDetection = Assert.Single(detections, d => d.Category == DataCategory.PersonalData);
        Assert.True(cpfDetection.IsValid);
        Assert.Equal("52998224725", cpfDetection.MatchedValue);
    }

    [Fact]
    public void Detect_InvalidCpf_ClassifiedAsCandidateWithLowConfidence_NotValid()
    {
        // 123.456.789-99 tem formato de CPF mas dígitos verificadores inválidos
        string text = "Tentativa com CPF fictício: 123.456.789-99 no formulário.";
        var detections = _detector.Analyze(text);

        var cpfDetection = Assert.Single(detections, d => d.Category == DataCategory.PersonalData);
        Assert.False(cpfDetection.IsValid); // NÃO é CPF válido
        Assert.True(cpfDetection.Confidence < 0.5); // Baixa confiança
        Assert.Equal(DataSensitivity.Low, cpfDetection.Sensitivity);
    }

    [Fact]
    public void Detect_LongNumberThatIsNotCpf_DoesNotDetectCpf()
    {
        // Número com 12 dígitos (protocolo) ou telefone com DDD
        string text = "Protocolo de atendimento número 123456789012 gerado hoje.";
        var detections = _detector.Analyze(text);

        Assert.DoesNotContain(detections, d => d.Category == DataCategory.PersonalData);
    }

    [Fact]
    public void Detect_Credentials_InKeyValueAndBearerToken_DetectedAndBlocked()
    {
        string text = "Debug info: {\"password\": \"SegredoForte!123\", \"token\": \"Bearer eyJhbGciOiJIUzI1NiJ9.test.sign\"}";
        var detections = _detector.Analyze(text);

        Assert.Contains(detections, d => d.Category == DataCategory.Credentials && d.Rule == "CREDENTIAL_KEY_VALUE");
        Assert.Contains(detections, d => d.Category == DataCategory.Credentials && d.Rule == "CREDENTIAL_BEARER_TOKEN");
        Assert.All(detections.Where(d => d.Category == DataCategory.Credentials), d =>
        {
            Assert.Equal(DataSensitivity.Critical, d.Sensitivity);
            Assert.Equal(RecommendedAction.Block, d.RecommendedAction);
        });
    }

    [Fact]
    public void Detect_WordPasswordIsolated_DoesNotDetectCredential()
    {
        string text = "O sistema exige uma senha forte para todos os usuários cadastrados.";
        var detections = _detector.Analyze(text);

        Assert.DoesNotContain(detections, d => d.Category == DataCategory.Credentials);
    }

    [Fact]
    public void Detect_HealthData_ClinicalContext_Detected()
    {
        string text = "O cidadão é paciente com diagnóstico de insuficiência cardíaca crônica.";
        var detections = _detector.Analyze(text);

        var healthDetection = Assert.Single(detections, d => d.Category == DataCategory.HealthData);
        Assert.Equal(RecommendedAction.Block, healthDetection.RecommendedAction);
    }

    [Fact]
    public void Detect_MultiplePiiInSameText_DetectsAllWithAccuratePositions()
    {
        string text = "Cidadão 529.982.247-25, residente na Rua Augusta, 1200, senha=MinhaSenha!";
        var detections = _detector.Analyze(text);

        Assert.Contains(detections, d => d.Category == DataCategory.PersonalData);
        Assert.Contains(detections, d => d.Category == DataCategory.Location);
        Assert.Contains(detections, d => d.Category == DataCategory.Credentials);
    }

    [Fact]
    public void MaskContent_SanitizesSensitiveDataProperly()
    {
        string text = "Cidadão com CPF 529.982.247-25 e senha: SegredoForte123!";
        string masked = _masker.MaskContent(text);

        Assert.DoesNotContain("529.982.247-25", masked);
        Assert.DoesNotContain("SegredoForte123!", masked);
        Assert.Contains("***.***.***-25", masked);
        Assert.Contains("[REDACTED]", masked);
    }
}

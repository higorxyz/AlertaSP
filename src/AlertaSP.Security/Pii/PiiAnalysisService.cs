using AlertaSP.Core.Interfaces.Security;
using AlertaSP.Security.Contracts;

namespace AlertaSP.Security.Pii;

public interface IPiiAnalysisService
{
    PiiAnalysisResult Analyze(string content);
}

/// <summary>
/// Ferramenta de inspeção usada por <c>POST /api/security/analyze</c>: mostra o que o motor encontra e
/// como o texto ficaria mascarado. Não move o dado para nenhum destino, por isso não gera auditoria.
/// </summary>
public class PiiAnalysisService : IPiiAnalysisService
{
    private readonly IPiiDetector _detector;
    private readonly IPiiMaskingService _masking;

    public PiiAnalysisService(IPiiDetector detector, IPiiMaskingService masking)
    {
        _detector = detector;
        _masking = masking;
    }

    public PiiAnalysisResult Analyze(string content)
    {
        var detections = _detector.Analyze(content);
        return new PiiAnalysisResult
        {
            TotalDetections = detections.Count,
            HasPii = detections.Any(d => d.IsValid),
            Detections = detections,
            MaskedContent = _masking.MaskContent(content)
        };
    }
}

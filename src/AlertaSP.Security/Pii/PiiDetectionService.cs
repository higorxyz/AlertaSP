using System.Text.RegularExpressions;
using AlertaSP.Core.Enums;
using AlertaSP.Core.Interfaces.Security;

namespace AlertaSP.Security.Pii;

public class PiiDetectionService : IPiiDetector
{
    private readonly IEnumerable<IPiiRule> _rules;

    public PiiDetectionService(IEnumerable<IPiiRule> rules)
    {
        _rules = rules;
    }

    public IReadOnlyList<PiiDetection> Analyze(string content)
    {
        if (string.IsNullOrWhiteSpace(content))
            return Array.Empty<PiiDetection>();

        var allDetections = new List<PiiDetection>();

        foreach (var rule in _rules)
        {
            try
            {
                var detections = rule.Detect(content);
                if (detections != null && detections.Count > 0)
                    allDetections.AddRange(detections);
            }
            catch (RegexMatchTimeoutException)
            {
                // Falha fechada: texto que estoura o tempo de uma regra (possível ReDoS) é tratado como
                // sensível em vez de passar sem análise.
                allDetections.Add(new PiiDetection
                {
                    Category = DataCategory.Credentials,
                    Rule = "ANALYSIS_TIMEOUT_FAIL_CLOSED",
                    Start = 0,
                    Length = content.Length,
                    Sensitivity = DataSensitivity.Critical,
                    Confidence = 0.5,
                    RecommendedAction = RecommendedAction.Block,
                    IsValid = true,
                    MatchedValue = null
                });
            }
        }

        return allDetections.OrderBy(d => d.Start).ToList();
    }
}

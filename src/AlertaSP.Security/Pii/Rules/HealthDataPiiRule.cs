using System.Text.RegularExpressions;
using AlertaSP.Core.Enums;
using AlertaSP.Core.Interfaces.Security;

namespace AlertaSP.Security.Pii.Rules;

/// <summary>
/// Detecção de dados de saúde por combinação de sinais. O texto é dividido em trechos (sentenças) e
/// cada trecho é pontuado pelos termos do <see cref="HealthRuleSet"/>. Um termo clínico isolado
/// (por exemplo "hospital" ou "diabetes" sozinhos) não atinge o limiar e não gera detecção.
/// </summary>
public class HealthDataPiiRule : IPiiRule
{
    private static readonly Regex SegmentRegex = new(
        @"[^.;!?\n]+",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(250));

    private readonly HealthRuleSet _ruleSet;

    public HealthDataPiiRule() : this(HealthRuleSet.LoadDefault()) { }

    public HealthDataPiiRule(HealthRuleSet ruleSet)
    {
        _ruleSet = ruleSet;
    }

    public IReadOnlyList<PiiDetection> Detect(string content)
    {
        if (string.IsNullOrWhiteSpace(content))
            return Array.Empty<PiiDetection>();

        var list = new List<PiiDetection>();

        foreach (Match segment in SegmentRegex.Matches(content))
        {
            var score = 0;
            var critical = false;
            var first = int.MaxValue;
            var last = -1;

            foreach (var term in _ruleSet.Terms)
            {
                var match = term.Pattern.Match(segment.Value);
                if (!match.Success)
                    continue;

                score += term.Weight;
                critical |= term.IsCritical;
                first = Math.Min(first, match.Index);
                last = Math.Max(last, match.Index + match.Length);
            }

            if (score < _ruleSet.Threshold)
                continue;

            list.Add(new PiiDetection
            {
                Category = DataCategory.HealthData,
                Rule = critical ? "HEALTH_SENSITIVE_CONDITION" : "HEALTH_CLINICAL_CONTEXT",
                Start = segment.Index + first,
                Length = last - first,
                Sensitivity = critical ? DataSensitivity.Critical : DataSensitivity.High,
                Confidence = Math.Min(0.97, 0.5 + score * 0.05),
                RecommendedAction = RecommendedAction.Block,
                IsValid = true,
                MatchedValue = content.Substring(segment.Index + first, last - first)
            });
        }

        return list;
    }
}

using System.Text.RegularExpressions;
using AlertaSP.Core.Enums;
using AlertaSP.Core.Interfaces.Security;

namespace AlertaSP.Security.Pii.Rules;

public class EmailPiiRule : IPiiRule
{
    private static readonly Regex EmailRegex = new(
        @"(?<![\w.+\-])[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(250));

    public IReadOnlyList<PiiDetection> Detect(string content)
    {
        if (string.IsNullOrWhiteSpace(content))
            return Array.Empty<PiiDetection>();

        return EmailRegex.Matches(content)
            .Select(m => new PiiDetection
            {
                Category = DataCategory.PersonalData,
                Rule = "PII_EMAIL",
                Start = m.Index,
                Length = m.Length,
                Sensitivity = DataSensitivity.Medium,
                Confidence = 0.95,
                RecommendedAction = RecommendedAction.Mask,
                IsValid = true,
                MatchedValue = m.Value
            })
            .ToList();
    }
}

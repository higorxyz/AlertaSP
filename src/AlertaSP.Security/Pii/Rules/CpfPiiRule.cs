using System.Text.RegularExpressions;
using AlertaSP.Core.Enums;
using AlertaSP.Core.Interfaces.Security;
using AlertaSP.Core.Utils;

namespace AlertaSP.Security.Pii.Rules;

public class CpfPiiRule : IPiiRule
{
    // Captura padrão formatado (123.456.789-00) ou 11 dígitos com fronteiras não-numéricas
    private static readonly Regex CpfRegex = new(
        @"(?<!\d)(?<cpf>\d{3}\.\d{3}\.\d{3}-\d{2}|\d{11})(?!\d)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(250));

    public IReadOnlyList<PiiDetection> Detect(string content)
    {
        if (string.IsNullOrWhiteSpace(content))
            return Array.Empty<PiiDetection>();

        var list = new List<PiiDetection>();
        var matches = CpfRegex.Matches(content);

        foreach (Match match in matches)
        {
            var rawValue = match.Value;
            var digitsOnly = CpfValidator.Normalize(rawValue);

            if (digitsOnly.Length != 11)
                continue;

            bool isValid = CpfValidator.IsValid(digitsOnly);

            list.Add(new PiiDetection
            {
                Category = DataCategory.PersonalData,
                Rule = "PII_CPF",
                Start = match.Index,
                Length = match.Length,
                Sensitivity = isValid ? DataSensitivity.High : DataSensitivity.Low,
                Confidence = isValid ? 0.98 : 0.35,
                RecommendedAction = RecommendedAction.Mask,
                IsValid = isValid,
                MatchedValue = rawValue
            });
        }

        return list;
    }
}

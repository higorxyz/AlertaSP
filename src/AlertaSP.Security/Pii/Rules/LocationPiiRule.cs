using System.Text.RegularExpressions;
using AlertaSP.Core.Enums;
using AlertaSP.Core.Interfaces.Security;

namespace AlertaSP.Security.Pii.Rules;

public class LocationPiiRule : IPiiRule
{
    // CEP no formato 00000-000, com ou sem o prefixo "CEP"
    private static readonly Regex CepRegex = new(
        @"(?i)(?:cep\s*[:=]?\s*)?(?<!\d)(?<cep>\d{5}-\d{3})(?!\d)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(250));

    // Endereço residencial com número (ex: Rua Augusta, 1500 / Av. Paulista, 100)
    private static readonly Regex StreetAddressRegex = new(
        @"(?i)\b(?:rua|avenida|av\.?|alameda|al\.?|travessa|rodovia|pra[çc]a)\s+[^,\n]{3,40},\s*(?:n[º°]?\s*)?\d+",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(250));

    public IReadOnlyList<PiiDetection> Detect(string content)
    {
        if (string.IsNullOrWhiteSpace(content))
            return Array.Empty<PiiDetection>();

        var list = new List<PiiDetection>();

        foreach (Match match in CepRegex.Matches(content))
        {
            list.Add(new PiiDetection
            {
                Category = DataCategory.Location,
                Rule = "LOCATION_CEP",
                Start = match.Index,
                Length = match.Length,
                Sensitivity = DataSensitivity.Medium,
                Confidence = 0.90,
                RecommendedAction = RecommendedAction.Mask,
                IsValid = true,
                MatchedValue = match.Value
            });
        }

        foreach (Match match in StreetAddressRegex.Matches(content))
        {
            list.Add(new PiiDetection
            {
                Category = DataCategory.Location,
                Rule = "LOCATION_STREET_NUMBER",
                Start = match.Index,
                Length = match.Length,
                Sensitivity = DataSensitivity.Medium,
                Confidence = 0.88,
                RecommendedAction = RecommendedAction.Mask,
                IsValid = true,
                MatchedValue = match.Value
            });
        }

        return list;
    }
}

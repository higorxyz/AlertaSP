using System.Globalization;
using System.Text.RegularExpressions;
using AlertaSP.Core.Enums;
using AlertaSP.Core.Interfaces.Security;

namespace AlertaSP.Security.Pii.Rules;

/// <summary>
/// Pares latitude/longitude com ao menos 4 casas decimais (precisão de ~11 m), que revelam
/// endereços e rotinas. Valores com menos casas não são tratados como coordenada.
/// </summary>
public class CoordinatesPiiRule : IPiiRule
{
    private static readonly Regex PairRegex = new(
        @"(?<![\d.])(?<lat>-?\d{1,2}\.\d{4,})\s*[,;]\s*(?<lon>-?\d{1,3}\.\d{4,})(?![\d])",
        RegexOptions.Compiled | RegexOptions.CultureInvariant,
        TimeSpan.FromMilliseconds(250));

    public IReadOnlyList<PiiDetection> Detect(string content)
    {
        if (string.IsNullOrWhiteSpace(content))
            return Array.Empty<PiiDetection>();

        var list = new List<PiiDetection>();
        foreach (Match m in PairRegex.Matches(content))
        {
            if (!double.TryParse(m.Groups["lat"].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var lat) ||
                !double.TryParse(m.Groups["lon"].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var lon) ||
                Math.Abs(lat) > 90 || Math.Abs(lon) > 180)
            {
                continue;
            }

            list.Add(new PiiDetection
            {
                Category = DataCategory.Location,
                Rule = "LOCATION_COORDINATES",
                Start = m.Index,
                Length = m.Length,
                Sensitivity = DataSensitivity.Medium,
                Confidence = 0.90,
                RecommendedAction = RecommendedAction.Mask,
                IsValid = true,
                MatchedValue = m.Value
            });
        }

        return list;
    }
}

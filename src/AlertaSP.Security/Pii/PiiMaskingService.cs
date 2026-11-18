using System.Globalization;
using System.Text;
using AlertaSP.Core.Enums;
using AlertaSP.Core.Interfaces.Security;
using AlertaSP.Core.Utils;

namespace AlertaSP.Security.Pii;

public class PiiMaskingService : IPiiMaskingService
{
    private readonly IPiiDetector _piiDetector;

    public PiiMaskingService(IPiiDetector piiDetector)
    {
        _piiDetector = piiDetector;
    }

    public string MaskCpf(string cpf) => CpfValidator.Mask(cpf);

    public string MaskEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email) || !email.Contains('@'))
            return "***@***.***";

        var separator = email.IndexOf('@');
        var user = email[..separator];
        var domain = email[(separator + 1)..];
        var visibleLen = Math.Min(2, user.Length);
        return $"{user[..visibleLen]}***@{domain}";
    }

    /// <summary>
    /// Generaliza o endereço: mantém apenas o que vem depois de " - " (bairro, cidade, UF) quando
    /// existir; caso contrário, omite por completo.
    /// </summary>
    public string MaskAddress(string address)
    {
        if (string.IsNullOrWhiteSpace(address))
            return "[ENDEREÇO OMITIDO]";

        const string separator = " - ";
        var index = address.IndexOf(separator, StringComparison.Ordinal);
        if (index >= 0 && index + separator.Length < address.Length)
            return $"*** - {address[(index + separator.Length)..].Trim()}";

        return "[ENDEREÇO PROTEGIDO]";
    }

    /// <summary>Generaliza uma coordenada para 2 casas decimais (~1,1 km).</summary>
    public string MaskCoordinate(string coordinate)
    {
        if (!double.TryParse(coordinate, NumberStyles.Float, CultureInfo.InvariantCulture, out var value))
            return "[COORDENADA PROTEGIDA]";

        return Math.Round(value, 2).ToString("0.00", CultureInfo.InvariantCulture);
    }

    public string MaskCredential(string credential) => "[REDACTED]";

    public string MaskContent(string content)
    {
        if (string.IsNullOrWhiteSpace(content))
            return string.Empty;

        // Candidatos inválidos (ex.: CPF com dígitos errados) não são PII e ficam como estão.
        var detections = _piiDetector.Analyze(content).Where(d => d.IsValid).ToList();
        if (detections.Count == 0)
            return content;

        var sb = new StringBuilder();
        var cursor = 0;

        foreach (var span in MergeOverlapping(detections))
        {
            if (span.Start < cursor || span.End > content.Length)
                continue;

            sb.Append(content, cursor, span.Start - cursor);
            sb.Append(ReplacementFor(span));
            cursor = span.End;
        }

        sb.Append(content, cursor, content.Length - cursor);
        return sb.ToString();
    }

    private string ReplacementFor(MaskSpan span) => span.Category switch
    {
        DataCategory.Credentials => "[REDACTED]",
        DataCategory.HealthData => "[DADO DE SAÚDE SUPRIMIDO]",
        DataCategory.PersonalData when span.Rule == "PII_EMAIL" => MaskEmail(span.Value),
        DataCategory.PersonalData => MaskCpf(span.Value),
        DataCategory.Location when span.Rule == "LOCATION_COORDINATES" => "[COORDENADA PROTEGIDA]",
        DataCategory.Location => "[ENDEREÇO PROTEGIDO]",
        _ => "[DADO SENSÍVEL]"
    };

    /// <summary>
    /// Une detecções sobrepostas (ex.: "api_key=sk-..." casa duas regras) num só trecho, com a categoria da
    /// mais sensível. Substituir trechos que se cruzam separadamente corromperia o texto.
    /// </summary>
    private static List<MaskSpan> MergeOverlapping(IReadOnlyList<PiiDetection> detections)
    {
        var ordered = detections
            .OrderBy(d => d.Start)
            .ThenByDescending(d => d.Length)
            .ToList();

        var result = new List<MaskSpan>();
        MaskSpan? current = null;

        foreach (var d in ordered)
        {
            var end = d.Start + d.Length;
            if (current is not null && d.Start < current.End)
            {
                current.End = Math.Max(current.End, end);
                if (d.Sensitivity > current.Sensitivity)
                {
                    current.Sensitivity = d.Sensitivity;
                    current.Category = d.Category;
                    current.Rule = d.Rule;
                    current.Value = d.MatchedValue ?? string.Empty;
                }
                continue;
            }

            current = new MaskSpan
            {
                Start = d.Start,
                End = end,
                Category = d.Category,
                Rule = d.Rule,
                Sensitivity = d.Sensitivity,
                Value = d.MatchedValue ?? string.Empty
            };
            result.Add(current);
        }

        return result;
    }

    private sealed class MaskSpan
    {
        public int Start { get; set; }
        public int End { get; set; }
        public DataCategory Category { get; set; }
        public string Rule { get; set; } = string.Empty;
        public DataSensitivity Sensitivity { get; set; }
        public string Value { get; set; } = string.Empty;
    }
}

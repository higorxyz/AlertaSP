using System.Text.RegularExpressions;
using AlertaSP.Core.Enums;
using AlertaSP.Core.Interfaces.Security;

namespace AlertaSP.Security.Pii.Rules;

/// <summary>
/// Detecta credenciais pela estrutura: pares chave/valor, cabeçalhos de autorização, tokens com
/// prefixo de fornecedor e valores de alta entropia atribuídos a chaves com nome de segredo.
/// A palavra "senha" isolada, sem valor associado, não gera detecção.
/// </summary>
public class CredentialsPiiRule : IPiiRule
{
    private static readonly TimeSpan Timeout = TimeSpan.FromMilliseconds(250);
    private const RegexOptions Options = RegexOptions.Compiled | RegexOptions.CultureInvariant;

    // Pares chave-valor / JSON (ex.: "password": "...", password=..., senha: ...)
    private static readonly Regex KeyValueRegex = new(
        @"(?i)(?<key>""?(?:password|senha|passwd|pwd|access_token|refresh_token|id_token|api_key|apikey|x-api-key|client_secret|secret_key|private_key)""?)\s*[:=]\s*[""']?(?<value>[^""'\s,;]{3,})[""']?",
        Options, Timeout);

    // Authorization: Bearer <token> (JWT ou opaco). O token precisa ter dígito ou pontuação,
    // para não capturar a palavra "bearer" em texto corrido.
    private static readonly Regex BearerRegex = new(
        @"(?i)\bbearer\s+(?=[A-Za-z0-9\-._~+/]*[\d.\-_/+])(?<token>[A-Za-z0-9\-._~+/]{8,}=*)",
        Options, Timeout);

    // Authorization: Basic <base64>
    private static readonly Regex BasicAuthRegex = new(
        @"(?i)authorization\s*[:=]\s*basic\s+(?<token>[A-Za-z0-9+/]{8,}={0,2})",
        Options, Timeout);

    // Tokens conhecidos por prefixo (OpenAI sk-/sk-proj-, GitHub, AWS, Slack, Google)
    private static readonly Regex PrefixTokenRegex = new(
        @"(?<![A-Za-z0-9])(?<token>sk-[A-Za-z0-9_\-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9\-]{10,}|AIza[0-9A-Za-z_\-]{35})(?![A-Za-z0-9])",
        Options, Timeout);

    // Atribuição a uma chave com nome de segredo (candidata a alta entropia)
    private static readonly Regex AssignmentRegex = new(
        @"(?i)(?<![\w\-])(?<key>(?:[A-Za-z_][\w\-]{0,30}?)?(?:key|token|secret|auth|credential|pass)[\w\-]{0,30})\s*[:=]\s*[""']?(?<value>[A-Za-z0-9+/=_\-]{20,})[""']?",
        Options, Timeout);

    private const double MinEntropyBitsPerChar = 3.5;

    public IReadOnlyList<PiiDetection> Detect(string content)
    {
        if (string.IsNullOrWhiteSpace(content))
            return Array.Empty<PiiDetection>();

        var list = new List<PiiDetection>();

        foreach (Match match in KeyValueRegex.Matches(content))
        {
            if (match.Groups["value"].Length >= 3)
                list.Add(Create("CREDENTIAL_KEY_VALUE", match, 0.95));
        }

        foreach (Match match in BearerRegex.Matches(content))
            list.Add(Create("CREDENTIAL_BEARER_TOKEN", match, 0.99));

        foreach (Match match in BasicAuthRegex.Matches(content))
            list.Add(Create("CREDENTIAL_BASIC_AUTH", match, 0.97));

        foreach (Match match in PrefixTokenRegex.Matches(content))
            list.Add(Create("CREDENTIAL_PREFIX_TOKEN", match, 0.99));

        foreach (Match match in AssignmentRegex.Matches(content))
        {
            var value = match.Groups["value"].Value;
            if (!LooksLikeSecret(value) || Overlaps(list, match.Index, match.Length))
                continue;

            list.Add(Create("CREDENTIAL_HIGH_ENTROPY", match, 0.80));
        }

        return list;
    }

    /// <summary>Entropia de Shannon, em bits por caractere.</summary>
    internal static double ShannonEntropy(string value)
    {
        if (string.IsNullOrEmpty(value))
            return 0;

        var total = (double)value.Length;
        return value
            .GroupBy(c => c)
            .Select(g => g.Count() / total)
            .Sum(p => -p * Math.Log2(p));
    }

    private static bool LooksLikeSecret(string value) =>
        value.Any(char.IsDigit) &&
        value.Any(char.IsLetter) &&
        ShannonEntropy(value) >= MinEntropyBitsPerChar;

    private static bool Overlaps(List<PiiDetection> existing, int start, int length) =>
        existing.Any(d => start < d.Start + d.Length && d.Start < start + length);

    private static PiiDetection Create(string rule, Match match, double confidence) => new()
    {
        Category = DataCategory.Credentials,
        Rule = rule,
        Start = match.Index,
        Length = match.Length,
        Sensitivity = DataSensitivity.Critical,
        Confidence = confidence,
        RecommendedAction = RecommendedAction.Block,
        IsValid = true,
        MatchedValue = match.Value
    };
}

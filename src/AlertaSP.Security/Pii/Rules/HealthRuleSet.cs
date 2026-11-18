using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Configuration;

namespace AlertaSP.Security.Pii.Rules;

/// <summary>Um termo do catálogo de saúde: expressão, peso e indicação de gravidade crítica.</summary>
public sealed class HealthTerm
{
    public string Name { get; }
    public Regex Pattern { get; }
    public int Weight { get; }
    public bool IsCritical { get; }

    public HealthTerm(string name, Regex pattern, int weight, bool isCritical)
    {
        Name = name;
        Pattern = pattern;
        Weight = weight;
        IsCritical = isCritical;
    }
}

/// <summary>
/// Catálogo configurável de regras de saúde. Carregado de um JSON (embutido no assembly por padrão,
/// ou de um arquivo indicado em <c>Pii:HealthRulesPath</c>). Cada trecho de texto recebe uma pontuação
/// pela soma dos pesos dos termos distintos encontrados; só pontuação &gt;= limiar gera detecção.
/// </summary>
public sealed class HealthRuleSet
{
    private const string EmbeddedResourceName = "health-rules.json";
    private static readonly TimeSpan PatternTimeout = TimeSpan.FromMilliseconds(250);

    public int Threshold { get; }
    public IReadOnlyList<HealthTerm> Terms { get; }

    public HealthRuleSet(int threshold, IReadOnlyList<HealthTerm> terms)
    {
        if (threshold <= 0)
            throw new ArgumentOutOfRangeException(nameof(threshold), "O limiar deve ser positivo.");

        Threshold = threshold;
        Terms = terms;
    }

    public static HealthRuleSet LoadDefault()
    {
        using var stream = typeof(HealthRuleSet).Assembly.GetManifestResourceStream(EmbeddedResourceName)
            ?? throw new InvalidOperationException($"Recurso embutido '{EmbeddedResourceName}' não encontrado.");
        using var reader = new StreamReader(stream);
        return Parse(reader.ReadToEnd());
    }

    public static HealthRuleSet Load(IConfiguration configuration)
    {
        var path = configuration["Pii:HealthRulesPath"];
        return string.IsNullOrWhiteSpace(path) ? LoadDefault() : LoadFromFile(path);
    }

    public static HealthRuleSet LoadFromFile(string path)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException($"Arquivo de regras de saúde não encontrado: {path}", path);

        return Parse(File.ReadAllText(path));
    }

    public static HealthRuleSet Parse(string json)
    {
        var document = JsonSerializer.Deserialize<HealthRuleDocument>(json, new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true
        }) ?? throw new InvalidOperationException("Arquivo de regras de saúde vazio ou inválido.");

        if (document.Terms == null || document.Terms.Count == 0)
            throw new InvalidOperationException("O arquivo de regras de saúde não define nenhum termo.");

        var terms = document.Terms.Select(t =>
        {
            if (string.IsNullOrWhiteSpace(t.Pattern) || t.Weight <= 0)
                throw new InvalidOperationException($"Termo de saúde inválido: '{t.Name}'.");

            var regex = new Regex(
                t.Pattern,
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled,
                PatternTimeout);

            return new HealthTerm(t.Name ?? t.Pattern, regex, t.Weight, t.Critical);
        }).ToList();

        return new HealthRuleSet(document.Threshold > 0 ? document.Threshold : 4, terms);
    }

    private sealed class HealthRuleDocument
    {
        public int Threshold { get; set; }
        public List<HealthTermDocument>? Terms { get; set; }
    }

    private sealed class HealthTermDocument
    {
        public string? Name { get; set; }
        public string? Pattern { get; set; }
        public int Weight { get; set; }
        public bool Critical { get; set; }
    }
}

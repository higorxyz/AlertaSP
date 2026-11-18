namespace AlertaSP.Core.Enums;

/// <summary>Rótulo em português, com acento, para mensagens exibidas ao cidadão.</summary>
public static class SeverityText
{
    public static string Of(Severity severity) => severity switch
    {
        Severity.Baixo => "baixa",
        Severity.Moderado => "moderada",
        Severity.Alto => "alta",
        Severity.Critico => "crítica",
        _ => severity.ToString()
    };
}

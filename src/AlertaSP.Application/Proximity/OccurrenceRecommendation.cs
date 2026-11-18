using AlertaSP.Core.Enums;

namespace AlertaSP.Application.Proximity;

public static class OccurrenceRecommendation
{
    public static string For(Severity severity) => severity switch
    {
        Severity.Critico => "Alagamento intenso registrado. Evite passar pela região.",
        Severity.Alto => "Alagamento de grande porte registrado. Procure outro caminho ou adie o deslocamento.",
        Severity.Moderado => "Acúmulo de água registrado. Reduza a velocidade e redobre a atenção.",
        _ => "Acúmulo leve de água registrado. Acompanhe a situação antes de sair."
    };
}

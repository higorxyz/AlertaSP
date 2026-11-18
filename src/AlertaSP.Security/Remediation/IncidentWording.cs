using AlertaSP.Core.Enums;

namespace AlertaSP.Security.Remediation;

/// <summary>Descrições em português dos campos de um incidente, usadas no texto de reserva e no prompt da IA.</summary>
internal static class IncidentWording
{
    public static string DataKind(DataCategory category) => category switch
    {
        DataCategory.Credentials => "credenciais de acesso (senha, token ou chave)",
        DataCategory.HealthData => "informações de saúde",
        DataCategory.PersonalData => "dados pessoais, como CPF ou e-mail",
        DataCategory.Location => "endereço ou localização",
        _ => "dados"
    };

    public static string Sink(SinkType sink) => sink switch
    {
        SinkType.Log => "um registro de log",
        SinkType.PublicHttpResponse => "uma resposta pública da API",
        SinkType.InternalHttpResponse => "uma consulta interna",
        SinkType.ExternalAiService => "um serviço de IA externo",
        SinkType.Report => "um relatório",
        SinkType.Export => "uma exportação de dados",
        SinkType.Database => "o banco de dados",
        _ => "um destino não identificado"
    };

    public static string Decision(PolicyDecision decision) => decision switch
    {
        PolicyDecision.Block => "bloqueado",
        PolicyDecision.AllowSanitized => "liberado apenas em versão mascarada",
        PolicyDecision.Allow => "liberado",
        _ => decision.ToString()
    };
}

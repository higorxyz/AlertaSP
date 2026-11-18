using AlertaSP.Core.Entities;
using AlertaSP.Core.Enums;
using AlertaSP.Core.Interfaces.Security;

namespace AlertaSP.Security.Remediation;

/// <summary>
/// Texto de reserva, usado quando não há chave de IA, a rede falha ou a resposta do modelo é rejeitada.
/// O resultado sai sempre com <see cref="RemediationOrigin.Fallback"/>, para não ser confundido com IA.
/// </summary>
public class DeterministicRemediationService : ISecurityRemediationService
{
    public Task<RemediationResult> TranslateIncidentAsync(SecurityIncident incident, CancellationToken ct = default)
    {
        return Task.FromResult(new RemediationResult
        {
            Message = Translate(incident),
            Origin = RemediationOrigin.Fallback
        });
    }

    private static string Translate(SecurityIncident incident)
    {
        var sink = IncidentWording.Sink(incident.SinkType);
        var blocked = incident.Decision == PolicyDecision.Block;

        return incident.Category switch
        {
            DataCategory.Credentials =>
                $"Credenciais de acesso (senha, token ou chave) iam ser enviadas para {sink}. " +
                "O AlertaSP bloqueou o envio e a credencial não saiu do sistema.",

            DataCategory.HealthData =>
                $"Uma informação de saúde ia ser enviada para {sink}. O envio foi bloqueado: " +
                "dados de saúde só circulam em atendimentos autorizados.",

            DataCategory.PersonalData when blocked =>
                $"Dados pessoais iam ser usados em {sink} sem autorização. O acesso foi bloqueado.",

            DataCategory.PersonalData =>
                $"Dados pessoais, como CPF ou e-mail, iam aparecer em {sink}. O sistema aplicou mascaramento " +
                "e mostrou só uma parte (por exemplo, ***.***.***-25). O dado completo continua cifrado no banco.",

            DataCategory.Location when blocked =>
                $"Um endereço ou localização ia ser usado em {sink} sem autorização. O acesso foi bloqueado.",

            DataCategory.Location =>
                $"Um endereço ou localização ia aparecer em {sink}. O sistema omitiu o endereço e arredondou as " +
                "coordenadas para não revelar a rotina de ninguém.",

            _ =>
                $"Um evento de segurança envolvendo {IncidentWording.DataKind(incident.Category)} foi registrado. " +
                $"O envio para {sink} foi {IncidentWording.Decision(incident.Decision)}."
        };
    }
}

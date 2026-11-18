using AlertaSP.Core.Enums;
using AlertaSP.Core.Interfaces.Security;

namespace AlertaSP.Security.Taint;

/// <summary>
/// Matriz de decisão por categoria e destino (ver docs/taint-analysis.md). A decisão é determinística:
/// nenhuma IA participa dela.
/// </summary>
public class SecurityPolicy : ISecurityPolicy
{
    public PolicyDecision Evaluate(DataCategory category, DataSensitivity sensitivity, SinkType sink, DataFlowContext context)
    {
        if (category == DataCategory.None || sensitivity == DataSensitivity.None)
            return PolicyDecision.Allow;

        return category switch
        {
            // Credencial não tem uso legítimo fora do próprio mecanismo de autenticação.
            DataCategory.Credentials => PolicyDecision.Block,
            DataCategory.HealthData => EvaluateHealth(sink, context),
            DataCategory.PersonalData or DataCategory.Location => EvaluatePersonal(sink, context),
            _ => PolicyDecision.Block
        };
    }

    /// <summary>Saúde só circula em resposta interna autorizada cuja finalidade seja de saúde.</summary>
    private static PolicyDecision EvaluateHealth(SinkType sink, DataFlowContext context) =>
        sink == SinkType.InternalHttpResponse
        && context.IsAuthorized
        && context.Purpose.Contains("Health", StringComparison.OrdinalIgnoreCase)
            ? PolicyDecision.Allow
            : PolicyDecision.Block;

    /// <summary>
    /// CPF, e-mail, endereço e coordenadas: em claro só no uso interno autorizado e com finalidade;
    /// uso interno sem justificativa é bloqueado; destinos externos recebem a versão mascarada.
    /// </summary>
    private static PolicyDecision EvaluatePersonal(SinkType sink, DataFlowContext context) => sink switch
    {
        SinkType.InternalHttpResponse => IsAuthorizedWithPurpose(context) ? PolicyDecision.Allow : PolicyDecision.Block,
        SinkType.Database => PolicyDecision.Allow, // gravado cifrado pela camada de infraestrutura
        SinkType.Log or SinkType.PublicHttpResponse or SinkType.ExternalAiService
            or SinkType.Report or SinkType.Export => PolicyDecision.AllowSanitized,
        _ => PolicyDecision.Block
    };

    /// <summary>Autorização sem finalidade declarada não libera o dado.</summary>
    private static bool IsAuthorizedWithPurpose(DataFlowContext context) =>
        context.IsAuthorized && !string.IsNullOrWhiteSpace(context.Purpose);
}

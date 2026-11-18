using AlertaSP.Core.Enums;
using AlertaSP.Core.Interfaces.Security;

namespace AlertaSP.Application.Common;

/// <summary>
/// Contextos de fluxo dos serviços. Entrada, gravação e resposta de um mesmo caso de uso compartilham
/// o FlowId, o que permite seguir o dado de ponta a ponta na trilha de auditoria.
/// </summary>
internal static class SensitiveFlow
{
    public static DataFlowContext Input(string source, string purpose, string actor) => new()
    {
        Source = source,
        Purpose = purpose,
        Actor = actor,
        IsAuthorized = false
    };

    /// <summary>Resposta pública do mesmo fluxo. O mascaramento aqui é rotina e não vira incidente.</summary>
    public static DataFlowContext PublicResponse(DataFlowContext input) => new()
    {
        FlowId = input.FlowId,
        Source = input.Source,
        Purpose = $"{input.Purpose}Response",
        Actor = input.Actor,
        IsAuthorized = false,
        IsRoutineOutput = true
    };

    /// <summary>Gravação no banco do mesmo fluxo. Os campos sensíveis são cifrados antes de gravar.</summary>
    public static DataFlowContext Persistence(DataFlowContext input) => new()
    {
        FlowId = input.FlowId,
        Source = input.Source,
        Purpose = $"{input.Purpose}Persistence",
        Actor = input.Actor,
        IsAuthorized = true,
        IsRoutineOutput = true
    };
}

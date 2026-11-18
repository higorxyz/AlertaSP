using AlertaSP.Core.Enums;

namespace AlertaSP.Core.Interfaces.Security;

/// <summary>
/// Sink de log que só aceita valores aprovados pela política. Argumentos <see cref="Tainted{T}"/>
/// passam pelo rastreador (sink Log); strings comuns são mascaradas por conteúdo.
/// </summary>
public interface ISecureLogger
{
    /// <param name="messageTemplate">Modelo com marcadores <c>{Nome}</c>.</param>
    /// <param name="arguments">Valores dos marcadores, indexados pelo nome.</param>
    Task LogAsync(
        SecureLogLevel level,
        string messageTemplate,
        DataFlowContext context,
        IReadOnlyDictionary<string, object?>? arguments = null,
        CancellationToken ct = default);
}

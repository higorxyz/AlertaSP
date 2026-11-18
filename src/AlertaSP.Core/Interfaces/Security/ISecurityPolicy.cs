using AlertaSP.Core.Enums;

namespace AlertaSP.Core.Interfaces.Security;

/// <summary>Decide se um dado de determinada categoria pode chegar a um destino, e em que forma.</summary>
public interface ISecurityPolicy
{
    PolicyDecision Evaluate(DataCategory category, DataSensitivity sensitivity, SinkType sink, DataFlowContext context);
}

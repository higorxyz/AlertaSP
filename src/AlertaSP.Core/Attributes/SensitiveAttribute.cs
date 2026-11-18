using AlertaSP.Core.Enums;

namespace AlertaSP.Core.Attributes;

/// <summary>
/// Marca um campo de DTO como contendo dados sensíveis.
/// O Taint Tracker utiliza este atributo para rotular automaticamente os valores na entrada.
/// </summary>
[AttributeUsage(AttributeTargets.Property | AttributeTargets.Parameter, AllowMultiple = false)]
public class SensitiveAttribute : Attribute
{
    public DataCategory Category { get; }

    public SensitiveAttribute(DataCategory category)
    {
        Category = category;
    }
}

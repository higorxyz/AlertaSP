namespace AlertaSP.Core.Interfaces.Security;

/// <summary>
/// Uma regra de detecção. Novas regras entram no motor só com o registro no contêiner de DI,
/// sem alterar o <see cref="IPiiDetector"/>.
/// </summary>
public interface IPiiRule
{
    IReadOnlyList<PiiDetection> Detect(string content);
}

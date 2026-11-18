namespace AlertaSP.Core.Exceptions;

/// <summary>
/// Lançada quando a política de segurança bloqueia a entrega de um dado a um destino.
/// A mensagem nunca contém o valor sensível, apenas a categoria e o destino.
/// </summary>
public class SecurityViolationException : DomainException
{
    public SecurityViolationException(string message) : base(message) { }
}

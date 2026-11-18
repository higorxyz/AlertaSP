namespace AlertaSP.Core.Exceptions;

public class DuplicateEntityException : DomainException
{
    public DuplicateEntityException(string entity, string field)
        : base($"Já existe um registro de {entity} com o mesmo {field}.") { }
}

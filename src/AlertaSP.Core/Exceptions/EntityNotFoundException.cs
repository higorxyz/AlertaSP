namespace AlertaSP.Core.Exceptions;

public class EntityNotFoundException : DomainException
{
    public EntityNotFoundException(string entity, object id)
        : base($"{entity} com identificador '{id}' não encontrado(a).") { }
}

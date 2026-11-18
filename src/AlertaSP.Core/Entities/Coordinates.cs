using AlertaSP.Core.Exceptions;

namespace AlertaSP.Core.Entities;

internal static class Coordinates
{
    public static void EnsureValid(double latitude, double longitude, string label)
    {
        if (!double.IsFinite(latitude) || latitude < -90 || latitude > 90)
            throw new DomainException($"A latitude de {label} deve estar entre -90 e 90.");
        if (!double.IsFinite(longitude) || longitude < -180 || longitude > 180)
            throw new DomainException($"A longitude de {label} deve estar entre -180 e 180.");
    }
}

using AlertaSP.Application.Proximity;
using AlertaSP.Core.Entities;
using AlertaSP.Core.Exceptions;
using AlertaSP.UnitTests.Support;

namespace AlertaSP.UnitTests.Application;

public class RouteLocationTests
{
    private readonly RouteLocationProtector _protector = new(new FakeCryptoService());

    [Theory]
    [InlineData(95.0, 0.0)]
    [InlineData(0.0, -185.0)]
    [InlineData(double.NaN, 0.0)]
    public void Create_InvalidCoordinates_AreRejected(double lat, double lon)
    {
        Assert.Throws<DomainException>(() => RouteLocation.Create("Origem", "Destino", lat, lon, 0, 0));
    }

    [Fact]
    public void Create_WithoutOriginOrDestination_IsRejected()
    {
        Assert.Throws<DomainException>(() => RouteLocation.Create(" ", "Destino", 0, 0, 0, 0));
        Assert.Throws<DomainException>(() => RouteLocation.Create("Origem", "", 0, 0, 0, 0));
    }

    [Fact]
    public void Protect_EncryptsEveryField_AndUnprotectRestoresTheExactValues()
    {
        var location = RouteLocation.Create(" Rua Augusta, 1200 ", "Av. Paulista, 1578", -23.5612, -46.6401, -23.5559, -46.6602);

        var encrypted = _protector.Protect(location);
        var route = Route.Create(1, "Casa -> Trabalho", encrypted);
        var restored = _protector.Unprotect(route);

        Assert.Equal("ENC_Rua Augusta, 1200", encrypted.Origin);
        Assert.Equal("ENC_Av. Paulista, 1578", encrypted.Destination);
        Assert.StartsWith("ENC_", encrypted.Coordinates);
        Assert.Equal("Rua Augusta, 1200", restored.Origin);
        Assert.Equal(new GeoSegment(-23.5612, -46.6401, -23.5559, -46.6602), restored.Segment);
    }
}

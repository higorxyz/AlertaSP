using AlertaSP.Core.Entities;
using AlertaSP.Core.Enums;
using AlertaSP.Core.Exceptions;
using Xunit;

namespace AlertaSP.UnitTests.Core;

public class EntityTests
{
    private static EncryptedRouteLocation EncryptedLocation() => new("enc_origem", "enc_destino", "enc_coordenadas");

    private static Route NewRoute() => Route.Create(1, "Casa -> Trabalho", EncryptedLocation());

    private static FloodOccurrence NewOccurrence(Severity severity = Severity.Alto) =>
        FloodOccurrence.Create("Rua da Consolação", -23.560, -46.650, "Via alagada", severity);

    [Fact]
    public void Citizen_Create_KeepsEncryptedValuesAndTrimsName()
    {
        var citizen = Citizen.Create("  Maria Teste ", "enc_cpf", "hash_cpf", "enc_email", "enc_address");

        Assert.Equal("Maria Teste", citizen.Name);
        Assert.Equal("enc_cpf", citizen.EncryptedCpf);
        Assert.Equal("hash_cpf", citizen.CpfHash);
        Assert.Equal(DateTimeKind.Utc, citizen.CreatedAt.Kind);
    }

    [Theory]
    [InlineData("   ", "hash")]
    [InlineData("Maria", "")]
    public void Citizen_Create_WithoutNameOrCpf_IsRejected(string name, string cpfHash)
    {
        Assert.Throws<DomainException>(() => Citizen.Create(name, "enc_cpf", cpfHash, "enc_email", "enc_addr"));
    }

    [Fact]
    public void Route_KeepsOnlyEncryptedLocation()
    {
        var route = NewRoute();

        Assert.Equal("enc_origem", route.EncryptedOrigin);
        Assert.Equal("enc_destino", route.EncryptedDestination);
        Assert.Equal("enc_coordenadas", route.EncryptedCoordinates);
    }

    [Fact]
    public void Route_Update_KeepsTheSameRulesAsCreate()
    {
        var route = NewRoute();

        Assert.Throws<DomainException>(() => route.Update(" ", EncryptedLocation()));
        Assert.Throws<DomainException>(() => new EncryptedRouteLocation("enc", "", "enc"));
        Assert.Throws<DomainException>(() => Route.Create(0, "Rota", EncryptedLocation()));
        Assert.Equal("Casa -> Trabalho", route.Name);
    }

    [Fact]
    public void Route_StartsMonitoredAndTogglesMonitoring()
    {
        var route = NewRoute();
        Assert.True(route.IsMonitoringActive);

        route.DeactivateMonitoring();
        Assert.False(route.IsMonitoringActive);

        route.ActivateMonitoring();
        Assert.True(route.IsMonitoringActive);
    }

    [Fact]
    public void FloodOccurrence_ResolveAndReactivate_ChangeStatus()
    {
        var occurrence = NewOccurrence();
        Assert.True(occurrence.IsActive);

        occurrence.Resolve();
        Assert.Equal(OccurrenceStatus.Resolvida, occurrence.Status);

        occurrence.Reactivate();
        Assert.Equal(OccurrenceStatus.Ativa, occurrence.Status);
    }

    [Fact]
    public void FloodOccurrence_UndefinedSeverity_IsRejected()
    {
        Assert.Throws<DomainException>(() => NewOccurrence((Severity)99));
    }

    [Fact]
    public void Alert_For_UsesRouteAndOccurrenceWithoutPersonalData()
    {
        var alert = Alert.For(NewRoute(), NewOccurrence(Severity.Critico), 123.4);

        Assert.Equal(1, alert.CitizenId);
        Assert.Equal(Severity.Critico, alert.Severity);
        Assert.False(alert.IsRead);
        Assert.Contains("crítica", alert.Message);
        Assert.Contains("123 m", alert.Message);
        Assert.Contains("Casa -> Trabalho", alert.Message);
    }

    [Fact]
    public void Alert_For_RouteWithoutMonitoring_IsRejected()
    {
        var route = NewRoute();
        route.DeactivateMonitoring();

        Assert.Throws<DomainException>(() => Alert.For(route, NewOccurrence(), 10));
    }

    [Fact]
    public void Alert_For_ResolvedOccurrence_IsRejected()
    {
        var occurrence = NewOccurrence();
        occurrence.Resolve();

        Assert.Throws<DomainException>(() => Alert.For(NewRoute(), occurrence, 10));
    }

    [Fact]
    public void Alert_MarkAsRead_SetsIsRead()
    {
        var alert = Alert.For(NewRoute(), NewOccurrence(), 10);

        alert.MarkAsRead();

        Assert.True(alert.IsRead);
    }
}

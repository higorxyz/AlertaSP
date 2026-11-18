using AlertaSP.Core.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AlertaSP.Infrastructure.Data.Configurations;

public class RouteConfiguration : IEntityTypeConfiguration<Route>
{
    public void Configure(EntityTypeBuilder<Route> builder)
    {
        builder.ToTable("Routes");
        builder.HasKey(r => r.Id);

        builder.Property(r => r.Name)
            .IsRequired()
            .HasMaxLength(200);

        // Cifrados com Data Protection antes de chegar à entidade (ver RouteLocationProtector).
        builder.Property(r => r.EncryptedOrigin).IsRequired();
        builder.Property(r => r.EncryptedDestination).IsRequired();
        builder.Property(r => r.EncryptedCoordinates).IsRequired();
        builder.Ignore(r => r.Location);

        builder.HasOne(r => r.Citizen)
            .WithMany()
            .HasForeignKey(r => r.CitizenId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasIndex(r => r.CitizenId);
    }
}

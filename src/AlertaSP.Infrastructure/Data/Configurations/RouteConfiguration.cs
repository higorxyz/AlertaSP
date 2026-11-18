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

        builder.Property(r => r.Origin).HasMaxLength(500);
        builder.Property(r => r.Destination).HasMaxLength(500);

        builder.HasOne(r => r.Citizen)
            .WithMany()
            .HasForeignKey(r => r.CitizenId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasIndex(r => r.CitizenId);
    }
}

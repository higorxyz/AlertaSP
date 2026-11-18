using AlertaSP.Core.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AlertaSP.Infrastructure.Data.Configurations;

public class AlertConfiguration : IEntityTypeConfiguration<Alert>
{
    public void Configure(EntityTypeBuilder<Alert> builder)
    {
        builder.ToTable("Alerts");
        builder.HasKey(a => a.Id);

        builder.Property(a => a.Message)
            .IsRequired()
            .HasMaxLength(1000);

        builder.Property(a => a.Severity)
            .HasConversion<string>()
            .HasMaxLength(20);

        builder.HasOne(a => a.Citizen)
            .WithMany()
            .HasForeignKey(a => a.CitizenId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasOne(a => a.Route)
            .WithMany()
            .HasForeignKey(a => a.RouteId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasOne(a => a.Occurrence)
            .WithMany()
            .HasForeignKey(a => a.OccurrenceId)
            .OnDelete(DeleteBehavior.Cascade);

        // Índice único: um alerta por par (RouteId, OccurrenceId)
        builder.HasIndex(a => new { a.RouteId, a.OccurrenceId })
            .IsUnique();

        builder.HasIndex(a => a.CitizenId);
    }
}

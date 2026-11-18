using AlertaSP.Core.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AlertaSP.Infrastructure.Data.Configurations;

public class FloodOccurrenceConfiguration : IEntityTypeConfiguration<FloodOccurrence>
{
    public void Configure(EntityTypeBuilder<FloodOccurrence> builder)
    {
        builder.ToTable("FloodOccurrences");
        builder.HasKey(f => f.Id);

        builder.Property(f => f.Location).HasMaxLength(500);
        builder.Property(f => f.Description).HasMaxLength(2000);

        builder.Property(f => f.Severity)
            .HasConversion<string>()
            .HasMaxLength(20);

        builder.Property(f => f.Status)
            .HasConversion<string>()
            .HasMaxLength(20);

        builder.HasIndex(f => f.Severity);
        builder.HasIndex(f => f.Status);
        builder.HasIndex(f => new { f.Latitude, f.Longitude });
    }
}

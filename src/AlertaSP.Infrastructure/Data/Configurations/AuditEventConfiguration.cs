using AlertaSP.Core.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AlertaSP.Infrastructure.Data.Configurations;

public class AuditEventConfiguration : IEntityTypeConfiguration<AuditEvent>
{
    public void Configure(EntityTypeBuilder<AuditEvent> builder)
    {
        builder.ToTable("AuditEvents");
        builder.HasKey(a => a.Id);

        builder.Property(a => a.FlowId).HasMaxLength(64);
        builder.Property(a => a.Source).HasMaxLength(200);
        builder.Property(a => a.RuleApplied).HasMaxLength(200);
        builder.Property(a => a.Summary).HasMaxLength(2000);

        builder.Property(a => a.SinkType)
            .HasConversion<string>()
            .HasMaxLength(30);

        builder.Property(a => a.Category)
            .HasConversion<string>()
            .HasMaxLength(30);

        builder.Property(a => a.Sensitivity)
            .HasConversion<string>()
            .HasMaxLength(20);

        builder.Property(a => a.Decision)
            .HasConversion<string>()
            .HasMaxLength(20);

        builder.HasIndex(a => a.Timestamp);
        builder.HasIndex(a => a.FlowId);
    }
}

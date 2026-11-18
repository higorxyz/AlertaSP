using AlertaSP.Core.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AlertaSP.Infrastructure.Data.Configurations;

public class SecurityIncidentConfiguration : IEntityTypeConfiguration<SecurityIncident>
{
    public void Configure(EntityTypeBuilder<SecurityIncident> builder)
    {
        builder.ToTable("SecurityIncidents");
        builder.HasKey(s => s.Id);

        builder.Property(s => s.FlowId).HasMaxLength(64);
        builder.Property(s => s.Summary).HasMaxLength(2000);
        builder.Property(s => s.RuleApplied).HasMaxLength(200);
        builder.Property(s => s.Remediation).HasMaxLength(4000);

        builder.Property(s => s.Category)
            .HasConversion<string>()
            .HasMaxLength(30);

        builder.Property(s => s.Sensitivity)
            .HasConversion<string>()
            .HasMaxLength(20);

        builder.Property(s => s.SinkType)
            .HasConversion<string>()
            .HasMaxLength(30);

        builder.Property(s => s.Decision)
            .HasConversion<string>()
            .HasMaxLength(20);

        builder.Property(s => s.Result)
            .HasConversion<string>()
            .HasMaxLength(30);

        builder.Property(s => s.RemediationOrigin)
            .HasConversion<string?>()
            .HasMaxLength(20);

        builder.HasIndex(s => s.Timestamp);
        builder.HasIndex(s => s.Category);
    }
}

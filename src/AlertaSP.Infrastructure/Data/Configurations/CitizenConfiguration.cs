using AlertaSP.Core.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AlertaSP.Infrastructure.Data.Configurations;

public class CitizenConfiguration : IEntityTypeConfiguration<Citizen>
{
    public void Configure(EntityTypeBuilder<Citizen> builder)
    {
        builder.ToTable("Citizens");
        builder.HasKey(c => c.Id);

        builder.Property(c => c.Name)
            .IsRequired()
            .HasMaxLength(200);

        builder.Property(c => c.EncryptedCpf)
            .IsRequired();

        builder.Property(c => c.CpfHash)
            .IsRequired()
            .HasMaxLength(128);

        builder.HasIndex(c => c.CpfHash)
            .IsUnique();

        builder.Property(c => c.EncryptedEmail)
            .IsRequired();

        builder.Property(c => c.EncryptedAddress)
            .IsRequired();

        builder.Property(c => c.CreatedAt)
            .IsRequired();
    }
}

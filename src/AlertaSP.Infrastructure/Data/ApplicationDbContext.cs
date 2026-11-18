using AlertaSP.Core.Entities;
using Microsoft.EntityFrameworkCore;

namespace AlertaSP.Infrastructure.Data;

public class ApplicationDbContext : DbContext
{
    public DbSet<Citizen> Citizens => Set<Citizen>();
    public DbSet<Route> Routes => Set<Route>();
    public DbSet<FloodOccurrence> FloodOccurrences => Set<FloodOccurrence>();
    public DbSet<Alert> Alerts => Set<Alert>();
    public DbSet<SecurityIncident> SecurityIncidents => Set<SecurityIncident>();
    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();

    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
    {
    }

    /// <summary>
    /// Todas as datas são gravadas em UTC, mas o SQLite não guarda o fuso e devolve DateTimeKind.Unspecified.
    /// Sem isto, a API serializa "2026-11-17T22:30:00" (sem "Z") e o cliente lê como horário local.
    /// </summary>
    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
    {
        configurationBuilder.Properties<DateTime>().HaveConversion<UtcDateTimeConverter>();
    }

    private sealed class UtcDateTimeConverter : Microsoft.EntityFrameworkCore.Storage.ValueConversion.ValueConverter<DateTime, DateTime>
    {
        public UtcDateTimeConverter()
            : base(
                v => v.Kind == DateTimeKind.Utc ? v : v.ToUniversalTime(),
                v => DateTime.SpecifyKind(v, DateTimeKind.Utc))
        {
        }
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(ApplicationDbContext).Assembly);
    }
}

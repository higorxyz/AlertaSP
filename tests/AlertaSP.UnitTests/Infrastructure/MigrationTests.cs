using AlertaSP.Core.Entities;
using AlertaSP.Infrastructure.Data;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace AlertaSP.UnitTests.Infrastructure;

public class MigrationTests : IDisposable
{
    private readonly SqliteConnection _connection = new("DataSource=:memory:");
    private readonly ApplicationDbContext _context;

    public MigrationTests()
    {
        _connection.Open();
        _context = new ApplicationDbContext(new DbContextOptionsBuilder<ApplicationDbContext>().UseSqlite(_connection).Options);
    }

    public void Dispose()
    {
        _context.Dispose();
        _connection.Dispose();
    }

    [Fact]
    public void Migrations_MatchTheCurrentModel()
    {
        // Falha se alguém mudar uma entidade ou configuração sem gerar a migração correspondente.
        Assert.False(_context.Database.HasPendingModelChanges());
    }

    [Fact]
    public async Task Migrate_CreatesTheSchemaOnAnEmptyDatabase()
    {
        await _context.Database.MigrateAsync();

        Assert.Empty(await _context.Database.GetPendingMigrationsAsync());
        Assert.Contains("20261115004946_InitialCreate", await _context.Database.GetAppliedMigrationsAsync());

        _context.Citizens.Add(Citizen.Create("Teste", "enc", "hash", "enc", "enc"));
        await _context.SaveChangesAsync();
        Assert.Equal(1, await _context.Citizens.CountAsync());
    }

    [Fact]
    public async Task DatesReadFromTheDatabase_AreUtc()
    {
        await _context.Database.MigrateAsync();
        _context.Citizens.Add(Citizen.Create("Teste", "enc", "hash", "enc", "enc"));
        await _context.SaveChangesAsync();
        _context.ChangeTracker.Clear();

        var stored = await _context.Citizens.SingleAsync();

        Assert.Equal(DateTimeKind.Utc, stored.CreatedAt.Kind);
    }
}

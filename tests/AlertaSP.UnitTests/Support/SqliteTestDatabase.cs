using AlertaSP.Infrastructure.Data;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace AlertaSP.UnitTests.Support;

/// <summary>
/// Banco SQLite em memória com o esquema real. As consultas LINQ dos repositórios rodam traduzidas para
/// SQL, como em produção, e cada teste começa com um banco vazio.
/// </summary>
public sealed class SqliteTestDatabase : IDisposable
{
    private readonly SqliteConnection _connection = new("DataSource=:memory:");

    public ApplicationDbContext Context { get; }

    public SqliteTestDatabase()
    {
        _connection.Open();
        Context = new ApplicationDbContext(new DbContextOptionsBuilder<ApplicationDbContext>().UseSqlite(_connection).Options);
        Context.Database.EnsureCreated();
    }

    public void Dispose()
    {
        Context.Dispose();
        _connection.Dispose();
    }
}

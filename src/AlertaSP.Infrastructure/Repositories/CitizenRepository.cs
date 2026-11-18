using AlertaSP.Core.Entities;
using AlertaSP.Core.Exceptions;
using AlertaSP.Core.Interfaces;
using AlertaSP.Infrastructure.Data;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace AlertaSP.Infrastructure.Repositories;

public class CitizenRepository : ICitizenRepository
{
    private readonly ApplicationDbContext _context;

    public CitizenRepository(ApplicationDbContext context)
    {
        _context = context;
    }

    public async Task<Citizen?> GetByIdAsync(int id, CancellationToken ct = default)
        => await _context.Citizens.FindAsync(new object[] { id }, ct);

    public async Task<IReadOnlyList<Citizen>> GetAllAsync(int page, int pageSize, CancellationToken ct = default)
        => await _context.Citizens
            .OrderBy(c => c.Id)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(ct);

    public async Task<bool> ExistsByCpfHashAsync(string cpfHash, CancellationToken ct = default)
        => await _context.Citizens.AnyAsync(c => c.CpfHash == cpfHash, ct);

    public async Task<Citizen> AddAsync(Citizen citizen, CancellationToken ct = default)
    {
        _context.Citizens.Add(citizen);
        try
        {
            await _context.SaveChangesAsync(ct);
        }
        catch (DbUpdateException ex) when (IsUniqueConstraintViolation(ex))
        {
            // Duas requisições simultâneas com o mesmo CPF passam pela checagem prévia; o índice único do
            // CpfHash barra a segunda, que deve virar 409 e não 500.
            _context.Entry(citizen).State = EntityState.Detached;
            throw new DuplicateEntityException("Cidadão", "CPF");
        }

        return citizen;
    }

    public async Task UpdateAsync(Citizen citizen, CancellationToken ct = default)
    {
        _context.Citizens.Update(citizen);
        await _context.SaveChangesAsync(ct);
    }

    public async Task DeleteAsync(Citizen citizen, CancellationToken ct = default)
    {
        _context.Citizens.Remove(citizen);
        await _context.SaveChangesAsync(ct);
    }

    public async Task<int> CountAsync(CancellationToken ct = default)
        => await _context.Citizens.CountAsync(ct);

    private const int SqliteConstraintUnique = 2067;

    private static bool IsUniqueConstraintViolation(DbUpdateException ex)
        => ex.InnerException is SqliteException { SqliteExtendedErrorCode: SqliteConstraintUnique };
}

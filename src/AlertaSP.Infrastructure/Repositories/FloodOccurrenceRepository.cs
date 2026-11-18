using AlertaSP.Core.Entities;
using AlertaSP.Core.Enums;
using AlertaSP.Core.Interfaces;
using AlertaSP.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace AlertaSP.Infrastructure.Repositories;

public class FloodOccurrenceRepository : IFloodOccurrenceRepository
{
    private readonly ApplicationDbContext _context;

    public FloodOccurrenceRepository(ApplicationDbContext context)
    {
        _context = context;
    }

    public async Task<FloodOccurrence?> GetByIdAsync(int id, CancellationToken ct = default)
        => await _context.FloodOccurrences.FindAsync(new object[] { id }, ct);

    public async Task<IReadOnlyList<FloodOccurrence>> GetAllAsync(int page, int pageSize,
        Severity? severity = null, OccurrenceStatus? status = null, CancellationToken ct = default)
    {
        var query = _context.FloodOccurrences.AsQueryable();

        if (severity.HasValue)
            query = query.Where(f => f.Severity == severity.Value);

        if (status.HasValue)
            query = query.Where(f => f.Status == status.Value);

        return await query
            .OrderByDescending(f => f.OccurredAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(ct);
    }

    public async Task<IReadOnlyList<FloodOccurrence>> GetInBoundingBoxAsync(
        double minLat, double maxLat, double minLon, double maxLon,
        OccurrenceStatus? status = null, CancellationToken ct = default)
    {
        var query = _context.FloodOccurrences
            .Where(f => f.Latitude >= minLat && f.Latitude <= maxLat
                     && f.Longitude >= minLon && f.Longitude <= maxLon);

        if (status.HasValue)
            query = query.Where(f => f.Status == status.Value);

        return await query.ToListAsync(ct);
    }

    public async Task<FloodOccurrence> AddAsync(FloodOccurrence occurrence, CancellationToken ct = default)
    {
        _context.FloodOccurrences.Add(occurrence);
        await _context.SaveChangesAsync(ct);
        return occurrence;
    }

    public async Task UpdateAsync(FloodOccurrence occurrence, CancellationToken ct = default)
    {
        _context.FloodOccurrences.Update(occurrence);
        await _context.SaveChangesAsync(ct);
    }

    public async Task<int> CountAsync(Severity? severity = null, OccurrenceStatus? status = null, CancellationToken ct = default)
    {
        var query = _context.FloodOccurrences.AsQueryable();

        if (severity.HasValue)
            query = query.Where(f => f.Severity == severity.Value);

        if (status.HasValue)
            query = query.Where(f => f.Status == status.Value);

        return await query.CountAsync(ct);
    }
}

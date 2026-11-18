using AlertaSP.Core.Entities;
using AlertaSP.Core.Interfaces;
using AlertaSP.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace AlertaSP.Infrastructure.Repositories;

public class AlertRepository : IAlertRepository
{
    private readonly ApplicationDbContext _context;

    public AlertRepository(ApplicationDbContext context)
    {
        _context = context;
    }

    public async Task<Alert?> GetByIdAsync(int id, CancellationToken ct = default)
        => await _context.Alerts.FindAsync(new object[] { id }, ct);

    public async Task<IReadOnlyList<Alert>> GetAllAsync(int page, int pageSize, CancellationToken ct = default)
        => await _context.Alerts
            .OrderByDescending(a => a.CreatedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(ct);

    public async Task<IReadOnlyList<Alert>> GetByCitizenIdAsync(int citizenId, int page, int pageSize, CancellationToken ct = default)
        => await _context.Alerts
            .Where(a => a.CitizenId == citizenId)
            .OrderByDescending(a => a.CreatedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(ct);

    public async Task<IReadOnlySet<int>> GetExistingOccurrenceIdsAsync(int routeId, IReadOnlyCollection<int> occurrenceIds, CancellationToken ct = default)
    {
        if (occurrenceIds.Count == 0)
            return new HashSet<int>();

        var ids = await _context.Alerts
            .Where(a => a.RouteId == routeId && occurrenceIds.Contains(a.OccurrenceId))
            .Select(a => a.OccurrenceId)
            .ToListAsync(ct);

        return ids.ToHashSet();
    }

    public async Task<Alert> AddAsync(Alert alert, CancellationToken ct = default)
    {
        _context.Alerts.Add(alert);
        await _context.SaveChangesAsync(ct);
        return alert;
    }

    public async Task UpdateAsync(Alert alert, CancellationToken ct = default)
    {
        _context.Alerts.Update(alert);
        await _context.SaveChangesAsync(ct);
    }

    public async Task<int> CountAsync(CancellationToken ct = default)
        => await _context.Alerts.CountAsync(ct);

    public async Task<int> CountByCitizenIdAsync(int citizenId, CancellationToken ct = default)
        => await _context.Alerts.CountAsync(a => a.CitizenId == citizenId, ct);
}

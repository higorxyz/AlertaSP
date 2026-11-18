using AlertaSP.Core.Entities;
using AlertaSP.Core.Interfaces;
using AlertaSP.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace AlertaSP.Infrastructure.Repositories;

public class RouteRepository : IRouteRepository
{
    private readonly ApplicationDbContext _context;

    public RouteRepository(ApplicationDbContext context)
    {
        _context = context;
    }

    public async Task<Route?> GetByIdAsync(int id, CancellationToken ct = default)
        => await _context.Routes.FindAsync(new object[] { id }, ct);

    public async Task<IReadOnlyList<Route>> GetAllAsync(int page, int pageSize, CancellationToken ct = default)
        => await _context.Routes
            .OrderBy(r => r.Id)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(ct);

    public async Task<IReadOnlyList<Route>> GetByCitizenIdAsync(int citizenId, CancellationToken ct = default)
        => await _context.Routes
            .Where(r => r.CitizenId == citizenId)
            .OrderBy(r => r.Id)
            .ToListAsync(ct);

    public async Task<IReadOnlyList<Route>> GetActiveMonitoringRoutesAsync(CancellationToken ct = default)
        => await _context.Routes
            .Where(r => r.IsMonitoringActive)
            .ToListAsync(ct);

    public async Task<IReadOnlyDictionary<int, string>> GetNamesByIdsAsync(IReadOnlyCollection<int> ids, CancellationToken ct = default)
    {
        if (ids.Count == 0)
            return new Dictionary<int, string>();

        return await _context.Routes
            .Where(r => ids.Contains(r.Id))
            .ToDictionaryAsync(r => r.Id, r => r.Name, ct);
    }

    public async Task<Route> AddAsync(Route route, CancellationToken ct = default)
    {
        _context.Routes.Add(route);
        await _context.SaveChangesAsync(ct);
        return route;
    }

    public async Task UpdateAsync(Route route, CancellationToken ct = default)
    {
        _context.Routes.Update(route);
        await _context.SaveChangesAsync(ct);
    }

    public async Task DeleteAsync(Route route, CancellationToken ct = default)
    {
        _context.Routes.Remove(route);
        await _context.SaveChangesAsync(ct);
    }

    public async Task<int> CountAsync(CancellationToken ct = default)
        => await _context.Routes.CountAsync(ct);
}

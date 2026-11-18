using AlertaSP.Core.Entities;
using AlertaSP.Core.Enums;
using AlertaSP.Core.Interfaces.Security;
using AlertaSP.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace AlertaSP.Infrastructure.Repositories;

public class SecurityIncidentRepository : ISecurityIncidentRepository
{
    private readonly ApplicationDbContext _context;

    public SecurityIncidentRepository(ApplicationDbContext context)
    {
        _context = context;
    }

    public async Task<SecurityIncident?> GetByIdAsync(int id, CancellationToken ct = default)
        => await _context.SecurityIncidents.FindAsync(new object[] { id }, ct);

    public async Task<IReadOnlyList<SecurityIncident>> GetAllAsync(int page, int pageSize, CancellationToken ct = default)
        => await _context.SecurityIncidents
            .AsNoTracking()
            .OrderByDescending(s => s.Timestamp)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(ct);

    public async Task<SecurityIncident> AddAsync(SecurityIncident incident, CancellationToken ct = default)
    {
        _context.SecurityIncidents.Add(incident);
        await _context.SaveChangesAsync(ct);
        return incident;
    }

    public async Task UpdateAsync(SecurityIncident incident, CancellationToken ct = default)
    {
        _context.SecurityIncidents.Update(incident);
        await _context.SaveChangesAsync(ct);
    }

    public async Task<int> CountAsync(CancellationToken ct = default)
        => await _context.SecurityIncidents.CountAsync(ct);

    public async Task<IReadOnlyList<IncidentCount>> CountByGroupAsync(DateTime from, DateTime to, CancellationToken ct = default)
        => await _context.SecurityIncidents
            .Where(s => s.Timestamp >= from && s.Timestamp <= to)
            .GroupBy(s => new { s.Category, s.Sensitivity, s.Result })
            .Select(g => new IncidentCount(g.Key.Category, g.Key.Sensitivity, g.Key.Result, g.Count()))
            .ToListAsync(ct);

    public async Task<IReadOnlyList<DailyIncidentCount>> CountByDayAsync(
        DateTime from, DateTime to, int utcOffsetHours, CancellationToken ct = default)
    {
        var rows = await _context.SecurityIncidents
            .Where(s => s.Timestamp >= from && s.Timestamp <= to)
            .GroupBy(s => s.Timestamp.AddHours(utcOffsetHours).Date)
            .Select(g => new
            {
                Day = g.Key,
                Total = g.Count(),
                Blocked = g.Count(s => s.Result == IncidentResult.Blocked),
                Sanitized = g.Count(s => s.Result == IncidentResult.Sanitized)
            })
            .OrderBy(r => r.Day)
            .ToListAsync(ct);

        return rows
            .Select(r => new DailyIncidentCount(DateOnly.FromDateTime(r.Day), r.Total, r.Blocked, r.Sanitized))
            .ToList();
    }
}

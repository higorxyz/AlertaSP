using AlertaSP.Core.Entities;
using AlertaSP.Core.Enums;
using AlertaSP.Core.Interfaces.Security;
using AlertaSP.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace AlertaSP.Infrastructure.Repositories;

public class AuditEventRepository : IAuditSink
{
    private readonly ApplicationDbContext _context;

    public AuditEventRepository(ApplicationDbContext context)
    {
        _context = context;
    }

    public async Task RecordAsync(AuditEvent auditEvent, CancellationToken ct = default)
    {
        _context.AuditEvents.Add(auditEvent);
        await _context.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<AuditEvent>> GetEventsAsync(int page, int pageSize, CancellationToken ct = default)
        => await _context.AuditEvents
            .OrderByDescending(a => a.Timestamp)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync(ct);

    public async Task<int> CountAsync(CancellationToken ct = default)
        => await _context.AuditEvents.CountAsync(ct);

    public async Task<IReadOnlyDictionary<PolicyDecision, int>> CountByDecisionAsync(
        DateTime from, DateTime to, CancellationToken ct = default)
    {
        var groups = await _context.AuditEvents
            .Where(a => a.Timestamp >= from && a.Timestamp <= to)
            .GroupBy(a => a.Decision)
            .Select(g => new { Decision = g.Key, Count = g.Count() })
            .ToListAsync(ct);

        return groups.ToDictionary(g => g.Decision, g => g.Count);
    }
}

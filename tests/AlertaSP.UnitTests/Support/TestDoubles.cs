using AlertaSP.Core.Entities;
using AlertaSP.Core.Enums;
using AlertaSP.Core.Interfaces.Security;
using AlertaSP.Security.Pii;
using AlertaSP.Security.Pii.Rules;
using AlertaSP.Security.Taint;
using Microsoft.Extensions.Logging;

namespace AlertaSP.UnitTests.Support;

public sealed class FakeAuditSink : IAuditSink
{
    public List<AuditEvent> RecordedEvents { get; } = new();

    public Task RecordAsync(AuditEvent auditEvent, CancellationToken ct = default)
    {
        RecordedEvents.Add(auditEvent);
        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<AuditEvent>> GetEventsAsync(int page, int pageSize, CancellationToken ct = default)
        => Task.FromResult<IReadOnlyList<AuditEvent>>(RecordedEvents);

    public Task<int> CountAsync(CancellationToken ct = default) => Task.FromResult(RecordedEvents.Count);

    public Task<IReadOnlyDictionary<PolicyDecision, int>> CountByDecisionAsync(DateTime from, DateTime to, CancellationToken ct = default)
    {
        var counts = RecordedEvents
            .Where(e => e.Timestamp >= from && e.Timestamp <= to)
            .GroupBy(e => e.Decision)
            .ToDictionary(g => g.Key, g => g.Count());
        return Task.FromResult<IReadOnlyDictionary<PolicyDecision, int>>(counts);
    }
}

public sealed class FakeIncidentRepository : ISecurityIncidentRepository
{
    public List<SecurityIncident> RecordedIncidents { get; } = new();

    public Task<SecurityIncident?> GetByIdAsync(int id, CancellationToken ct = default) => Task.FromResult<SecurityIncident?>(null);

    public Task<IReadOnlyList<SecurityIncident>> GetAllAsync(int page, int pageSize, CancellationToken ct = default)
        => Task.FromResult<IReadOnlyList<SecurityIncident>>(RecordedIncidents);

    public Task<SecurityIncident> AddAsync(SecurityIncident incident, CancellationToken ct = default)
    {
        RecordedIncidents.Add(incident);
        return Task.FromResult(incident);
    }

    public Task UpdateAsync(SecurityIncident incident, CancellationToken ct = default) => Task.CompletedTask;

    public Task<int> CountAsync(CancellationToken ct = default) => Task.FromResult(RecordedIncidents.Count);

    public Task<IReadOnlyList<IncidentCount>> CountByGroupAsync(DateTime from, DateTime to, CancellationToken ct = default)
        => Task.FromResult<IReadOnlyList<IncidentCount>>(RecordedIncidents
            .Where(i => i.Timestamp >= from && i.Timestamp <= to)
            .GroupBy(i => (i.Category, i.Sensitivity, i.Result))
            .Select(g => new IncidentCount(g.Key.Category, g.Key.Sensitivity, g.Key.Result, g.Count()))
            .ToList());

    public Task<IReadOnlyList<DailyIncidentCount>> CountByDayAsync(DateTime from, DateTime to, int utcOffsetHours, CancellationToken ct = default)
        => Task.FromResult<IReadOnlyList<DailyIncidentCount>>(RecordedIncidents
            .Where(i => i.Timestamp >= from && i.Timestamp <= to)
            .GroupBy(i => DateOnly.FromDateTime(i.Timestamp.AddHours(utcOffsetHours)))
            .OrderBy(g => g.Key)
            .Select(g => new DailyIncidentCount(g.Key, g.Count(),
                g.Count(i => i.Result == IncidentResult.Blocked), g.Count(i => i.Result == IncidentResult.Sanitized)))
            .ToList());
}

public sealed class CapturingLogger<T> : ILogger<T>
{
    public List<string> Messages { get; } = new();

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        => Messages.Add(formatter(state, exception));
}

public static class TestSecurity
{
    public static TaintTracker CreateTracker(FakeAuditSink audit, FakeIncidentRepository incidents)
    {
        var detector = new PiiDetectionService(new IPiiRule[]
        {
            new CpfPiiRule(),
            new CredentialsPiiRule(),
            new HealthDataPiiRule(),
            new LocationPiiRule(),
            new CoordinatesPiiRule(),
            new EmailPiiRule()
        });

        return new TaintTracker(new SecurityPolicy(), audit, incidents, new PiiMaskingService(detector), detector);
    }
}

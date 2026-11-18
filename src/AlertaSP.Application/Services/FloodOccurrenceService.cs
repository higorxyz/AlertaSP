using AlertaSP.Application.Common;
using AlertaSP.Application.DTOs.Common;
using AlertaSP.Application.DTOs.FloodOccurrences;
using AlertaSP.Application.Interfaces;
using AlertaSP.Application.Proximity;
using AlertaSP.Core.Entities;
using AlertaSP.Core.Enums;
using AlertaSP.Core.Exceptions;
using AlertaSP.Core.Interfaces;
using AlertaSP.Core.Interfaces.Security;

namespace AlertaSP.Application.Services;

public class FloodOccurrenceService : IFloodOccurrenceService
{
    private const string Source = "/api/flood-occurrences";

    private readonly IFloodOccurrenceRepository _occurrenceRepository;
    private readonly INearbyOccurrenceFinder _finder;
    private readonly ITaintTracker _taintTracker;

    public FloodOccurrenceService(
        IFloodOccurrenceRepository occurrenceRepository,
        INearbyOccurrenceFinder finder,
        ITaintTracker taintTracker)
    {
        _occurrenceRepository = occurrenceRepository;
        _finder = finder;
        _taintTracker = taintTracker;
    }

    public async Task<FloodOccurrenceResponse> RegisterAsync(CreateFloodOccurrenceRequest request, CancellationToken ct = default)
    {
        // Local e descrição são texto livre e ficam visíveis a qualquer pessoa nas consultas de proximidade.
        // Por isso passam pelo destino PublicHttpResponse antes de gravar: credencial ou dado de saúde
        // faz o cadastro ser recusado; CPF, e-mail e endereço são gravados já mascarados.
        var input = SensitiveFlow.Input(Source, "OccurrenceRegistration", "PublicReporter");
        var published = await _taintTracker.ReleaseManyAsync(
            new[]
            {
                _taintTracker.TaintByContent(request.Location, input),
                _taintTracker.TaintByContent(request.Description, input)
            },
            SinkType.PublicHttpResponse,
            SensitiveFlow.PublicResponse(input),
            ct);

        var occurrence = FloodOccurrence.Create(
            location: published[0],
            latitude: request.Latitude,
            longitude: request.Longitude,
            description: published[1],
            severity: request.Severity,
            isDemo: request.IsDemo);

        await _occurrenceRepository.AddAsync(occurrence, ct);
        return FloodOccurrenceResponse.From(occurrence);
    }

    public async Task<FloodOccurrenceResponse?> GetByIdAsync(int id, CancellationToken ct = default)
    {
        var occurrence = await _occurrenceRepository.GetByIdAsync(id, ct);
        return occurrence == null ? null : FloodOccurrenceResponse.From(occurrence);
    }

    public async Task<PagedResult<FloodOccurrenceResponse>> GetAllAsync(
        int page = 1, int pageSize = 10,
        Severity? severity = null, OccurrenceStatus? status = null,
        CancellationToken ct = default)
    {
        var total = await _occurrenceRepository.CountAsync(severity, status, ct);
        var occurrences = await _occurrenceRepository.GetAllAsync(page, pageSize, severity, status, ct);
        return new PagedResult<FloodOccurrenceResponse>(
            occurrences.Select(FloodOccurrenceResponse.From).ToList(), total, page, pageSize);
    }

    public async Task<FloodOccurrenceResponse> UpdateStatusAsync(int id, OccurrenceStatus status, CancellationToken ct = default)
    {
        var occurrence = await _occurrenceRepository.GetByIdAsync(id, ct)
            ?? throw new EntityNotFoundException("Ocorrência de alagamento", id);

        if (status == OccurrenceStatus.Resolvida)
            occurrence.Resolve();
        else
            occurrence.Reactivate();

        await _occurrenceRepository.UpdateAsync(occurrence, ct);
        return FloodOccurrenceResponse.From(occurrence);
    }

    public async Task<IReadOnlyList<NearbyOccurrenceResponse>> GetNearbyAsync(
        double latitude, double longitude, double? radiusMeters = null, CancellationToken ct = default)
    {
        var nearby = await _finder.FindAsync(
            GeoSegment.Point(latitude, longitude), _finder.ResolveRadius(radiusMeters), ct);
        return nearby.Select(NearbyOccurrenceResponse.From).ToList();
    }
}

using System.ComponentModel.DataAnnotations;
using AlertaSP.Application.DTOs.Common;
using AlertaSP.Application.DTOs.FloodOccurrences;
using AlertaSP.Application.Interfaces;
using AlertaSP.Application.Proximity;
using AlertaSP.Core.Enums;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace AlertaSP.Api.Controllers;

[ApiController]
[Route("api/flood-occurrences")]
public class FloodOccurrencesController : ControllerBase
{
    private readonly IFloodOccurrenceService _occurrenceService;

    public FloodOccurrencesController(IFloodOccurrenceService occurrenceService)
    {
        _occurrenceService = occurrenceService;
    }

    /// <summary>Registra uma ocorrência de alagamento.</summary>
    /// <remarks>
    /// Local e descrição são públicos, então passam pelo Taint Analysis antes de gravar: credencial ou dado
    /// de saúde fazem o cadastro ser recusado (400); CPF, e-mail e endereço são gravados mascarados.
    /// </remarks>
    [HttpPost]
    [ProducesResponseType(typeof(FloodOccurrenceResponse), StatusCodes.Status201Created)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<FloodOccurrenceResponse>> Register([FromBody] CreateFloodOccurrenceRequest request, CancellationToken ct)
    {
        var response = await _occurrenceService.RegisterAsync(request, ct);
        return CreatedAtAction(nameof(GetById), new { id = response.Id }, response);
    }

    /// <summary>Consulta uma ocorrência pelo identificador.</summary>
    [HttpGet("{id:int}")]
    [ProducesResponseType(typeof(FloodOccurrenceResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
    public async Task<ActionResult<FloodOccurrenceResponse>> GetById(int id, CancellationToken ct)
        => await _occurrenceService.GetByIdAsync(id, ct) is { } occurrence ? occurrence : NotFound();

    /// <summary>Lista ocorrências, com filtros opcionais por severidade e status.</summary>
    [HttpGet]
    [ProducesResponseType(typeof(PagedResult<FloodOccurrenceResponse>), StatusCodes.Status200OK)]
    public Task<PagedResult<FloodOccurrenceResponse>> GetAll(
        [FromQuery, Range(1, int.MaxValue)] int page = 1,
        [FromQuery, Range(1, Paging.MaxPageSize)] int pageSize = 10,
        [FromQuery] Severity? severity = null,
        [FromQuery] OccurrenceStatus? status = null,
        CancellationToken ct = default)
        => _occurrenceService.GetAllAsync(page, pageSize, severity, status, ct);

    /// <summary>Marca a ocorrência como Ativa ou Resolvida. Resolvidas deixam de gerar alertas.</summary>
    [HttpPatch("{id:int}/status")]
    [ProducesResponseType(typeof(FloodOccurrenceResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
    public Task<FloodOccurrenceResponse> UpdateStatus(int id, [FromBody] UpdateOccurrenceStatusRequest request, CancellationToken ct)
        => _occurrenceService.UpdateStatusAsync(id, request.Status, ct);

    /// <summary>Ocorrências ativas em volta de um ponto, da mais próxima para a mais distante.</summary>
    /// <param name="lat">Latitude, entre -90 e 90.</param>
    /// <param name="lon">Longitude, entre -180 e 180.</param>
    /// <param name="radiusMeters">Raio em metros (1 a 10.000). Sem valor, usa Risk:NearbyRadiusMeters (500 m).</param>
    /// <param name="ct">Cancelamento da requisição.</param>
    [HttpGet("nearby")]
    [ProducesResponseType(typeof(IReadOnlyList<NearbyOccurrenceResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    public Task<IReadOnlyList<NearbyOccurrenceResponse>> GetNearby(
        [FromQuery, BindRequired, Range(-90.0, 90.0)] double lat,
        [FromQuery, BindRequired, Range(-180.0, 180.0)] double lon,
        [FromQuery, Range(1, ProximityOptions.MaxRadiusMeters)] double? radiusMeters = null,
        CancellationToken ct = default)
        => _occurrenceService.GetNearbyAsync(lat, lon, radiusMeters, ct);
}

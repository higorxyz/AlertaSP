using System.ComponentModel.DataAnnotations;
using AlertaSP.Application.DTOs.Alerts;
using AlertaSP.Application.DTOs.Common;
using AlertaSP.Application.Interfaces;
using AlertaSP.Application.Proximity;
using Microsoft.AspNetCore.Mvc;

namespace AlertaSP.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AlertsController : ControllerBase
{
    private readonly IAlertService _alertService;

    public AlertsController(IAlertService alertService)
    {
        _alertService = alertService;
    }

    /// <summary>Lista todos os alertas, do mais recente para o mais antigo.</summary>
    [HttpGet]
    [ProducesResponseType(typeof(PagedResult<AlertResponse>), StatusCodes.Status200OK)]
    public Task<PagedResult<AlertResponse>> GetAll(
        [FromQuery, Range(1, int.MaxValue)] int page = 1,
        [FromQuery, Range(1, Paging.MaxPageSize)] int pageSize = 10,
        CancellationToken ct = default)
        => _alertService.GetAllAsync(page, pageSize, ct);

    /// <summary>Consulta um alerta pelo identificador.</summary>
    [HttpGet("{id:int}")]
    [ProducesResponseType(typeof(AlertResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
    public async Task<ActionResult<AlertResponse>> GetById(int id, CancellationToken ct)
        => await _alertService.GetByIdAsync(id, ct) is { } alert ? alert : NotFound();

    /// <summary>Alertas de um cidadão, do mais recente para o mais antigo.</summary>
    [HttpGet("citizen/{citizenId:int}")]
    [ProducesResponseType(typeof(PagedResult<AlertResponse>), StatusCodes.Status200OK)]
    public Task<PagedResult<AlertResponse>> GetByCitizenId(
        int citizenId,
        [FromQuery, Range(1, int.MaxValue)] int page = 1,
        [FromQuery, Range(1, Paging.MaxPageSize)] int pageSize = 10,
        CancellationToken ct = default)
        => _alertService.GetByCitizenIdAsync(citizenId, page, pageSize, ct);

    /// <summary>Gera alertas para os trajetos monitorados que têm ocorrência ativa por perto.</summary>
    /// <param name="radiusMeters">Raio em metros (1 a 10.000). Sem valor, usa Risk:NearbyRadiusMeters (500 m).</param>
    /// <param name="ct">Cancelamento da requisição.</param>
    /// <remarks>Rodar de novo não duplica alertas: cada par trajeto/ocorrência gera no máximo um.</remarks>
    [HttpPost("generate")]
    [ProducesResponseType(typeof(GenerateAlertsResult), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    public Task<GenerateAlertsResult> Generate(
        [FromQuery, Range(1, ProximityOptions.MaxRadiusMeters)] double? radiusMeters = null,
        CancellationToken ct = default)
        => _alertService.GenerateRouteAlertsAsync(radiusMeters, ct);

    /// <summary>Marca o alerta como lido.</summary>
    [HttpPatch("{id:int}/read")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> MarkAsRead(int id, CancellationToken ct)
    {
        await _alertService.MarkAsReadAsync(id, ct);
        return NoContent();
    }
}

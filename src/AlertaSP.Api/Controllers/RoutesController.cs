using System.ComponentModel.DataAnnotations;
using AlertaSP.Application.DTOs.Common;
using AlertaSP.Application.DTOs.FloodOccurrences;
using AlertaSP.Application.DTOs.Routes;
using AlertaSP.Application.Interfaces;
using AlertaSP.Application.Proximity;
using Microsoft.AspNetCore.Mvc;

namespace AlertaSP.Api.Controllers;

/// <summary>Minhas Rotas: trajetos do cidadão e consulta de alagamentos perto deles.</summary>
[ApiController]
[Route("api/[controller]")]
public class RoutesController : ControllerBase
{
    private readonly IRouteService _routeService;

    public RoutesController(IRouteService routeService)
    {
        _routeService = routeService;
    }

    /// <summary>Cadastra um trajeto (ex.: Casa → Trabalho). O monitoramento já começa ativo.</summary>
    /// <remarks>Na resposta, o endereço sai omitido e as coordenadas com 2 casas decimais; o valor exato fica no banco.</remarks>
    [HttpPost]
    [ProducesResponseType(typeof(RouteResponse), StatusCodes.Status201Created)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
    public async Task<ActionResult<RouteResponse>> Create([FromBody] CreateRouteRequest request, CancellationToken ct)
    {
        var response = await _routeService.CreateAsync(request, ct);
        return CreatedAtAction(nameof(GetById), new { id = response.Id }, response);
    }

    /// <summary>Consulta um trajeto, com endereço omitido e coordenadas generalizadas.</summary>
    [HttpGet("{id:int}")]
    [ProducesResponseType(typeof(RouteResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
    public async Task<ActionResult<RouteResponse>> GetById(int id, CancellationToken ct)
        => await _routeService.GetByIdAsync(id, ct) is { } route ? route : NotFound();

    /// <summary>Lista os trajetos cadastrados.</summary>
    [HttpGet]
    [ProducesResponseType(typeof(PagedResult<RouteResponse>), StatusCodes.Status200OK)]
    public Task<PagedResult<RouteResponse>> GetAll(
        [FromQuery, Range(1, int.MaxValue)] int page = 1,
        [FromQuery, Range(1, Paging.MaxPageSize)] int pageSize = 10,
        CancellationToken ct = default)
        => _routeService.GetAllAsync(page, pageSize, ct);

    /// <summary>Trajetos de um cidadão.</summary>
    [HttpGet("citizen/{citizenId:int}")]
    [ProducesResponseType(typeof(IReadOnlyList<RouteResponse>), StatusCodes.Status200OK)]
    public Task<IReadOnlyList<RouteResponse>> GetByCitizenId(int citizenId, CancellationToken ct)
        => _routeService.GetByCitizenIdAsync(citizenId, ct);

    /// <summary>Atualiza nome, origem, destino e coordenadas do trajeto.</summary>
    [HttpPut("{id:int}")]
    [ProducesResponseType(typeof(RouteResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
    public Task<RouteResponse> Update(int id, [FromBody] UpdateRouteRequest request, CancellationToken ct)
        => _routeService.UpdateAsync(id, request, ct);

    /// <summary>Liga ou desliga o monitoramento. Só trajetos monitorados recebem alertas.</summary>
    [HttpPatch("{id:int}/monitoring")]
    [ProducesResponseType(typeof(RouteResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
    public Task<RouteResponse> SetMonitoring(int id, [FromBody] ToggleMonitoringRequest request, CancellationToken ct)
        => _routeService.SetMonitoringAsync(id, request.IsActive, ct);

    /// <summary>Ocorrências ativas perto do trajeto, da mais próxima para a mais distante.</summary>
    /// <param name="id">Identificador do trajeto.</param>
    /// <param name="radiusMeters">Raio em metros (1 a 10.000). Sem valor, usa Risk:NearbyRadiusMeters (500 m).</param>
    /// <param name="ct">Cancelamento da requisição.</param>
    /// <remarks>
    /// O trajeto é tratado como um segmento reto entre origem e destino. Sem ocorrências, a resposta diz que
    /// não há registro, e não que o caminho é seguro.
    /// </remarks>
    [HttpGet("{id:int}/risk")]
    [ProducesResponseType(typeof(RouteRiskAnalysisResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
    public Task<RouteRiskAnalysisResponse> GetRisk(
        int id,
        [FromQuery, Range(1, ProximityOptions.MaxRadiusMeters)] double? radiusMeters = null,
        CancellationToken ct = default)
        => _routeService.AnalyzeRiskAsync(id, radiusMeters, ct);

    /// <summary>Remove o trajeto e os alertas dele.</summary>
    [HttpDelete("{id:int}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Delete(int id, CancellationToken ct)
    {
        await _routeService.DeleteAsync(id, ct);
        return NoContent();
    }
}

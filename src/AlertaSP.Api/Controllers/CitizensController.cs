using System.ComponentModel.DataAnnotations;
using AlertaSP.Application.DTOs.Citizens;
using AlertaSP.Application.DTOs.Common;
using AlertaSP.Application.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace AlertaSP.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class CitizensController : ControllerBase
{
    private readonly ICitizenService _citizenService;

    public CitizensController(ICitizenService citizenService)
    {
        _citizenService = citizenService;
    }

    /// <summary>Cadastra um cidadão.</summary>
    /// <remarks>
    /// O CPF é validado pelos dígitos verificadores. CPF, e-mail e endereço são gravados cifrados e voltam
    /// mascarados. CPF já cadastrado retorna 409.
    /// </remarks>
    [HttpPost]
    [ProducesResponseType(typeof(CitizenResponse), StatusCodes.Status201Created)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status409Conflict)]
    public async Task<ActionResult<CitizenResponse>> Register([FromBody] RegisterCitizenRequest request, CancellationToken ct)
    {
        var response = await _citizenService.RegisterAsync(request, ct);
        return CreatedAtAction(nameof(GetById), new { id = response.Id }, response);
    }

    /// <summary>Consulta um cidadão. CPF, e-mail e endereço voltam mascarados.</summary>
    [HttpGet("{id:int}")]
    [ProducesResponseType(typeof(CitizenResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
    public async Task<ActionResult<CitizenResponse>> GetById(int id, CancellationToken ct)
        => await _citizenService.GetByIdAsync(id, ct) is { } citizen ? citizen : NotFound();

    /// <summary>Lista os cidadãos com dados mascarados.</summary>
    [HttpGet]
    [ProducesResponseType(typeof(PagedResult<CitizenResponse>), StatusCodes.Status200OK)]
    public Task<PagedResult<CitizenResponse>> GetAll(
        [FromQuery, Range(1, int.MaxValue)] int page = 1,
        [FromQuery, Range(1, Paging.MaxPageSize)] int pageSize = 10,
        CancellationToken ct = default)
        => _citizenService.GetAllAsync(page, pageSize, ct);

    /// <summary>Atualiza nome, e-mail e endereço. O CPF não muda.</summary>
    [HttpPut("{id:int}")]
    [ProducesResponseType(typeof(CitizenResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
    public Task<CitizenResponse> Update(int id, [FromBody] UpdateCitizenRequest request, CancellationToken ct)
        => _citizenService.UpdateAsync(id, request, ct);

    /// <summary>Remove o cidadão junto com seus trajetos e alertas.</summary>
    [HttpDelete("{id:int}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Delete(int id, CancellationToken ct)
    {
        await _citizenService.DeleteAsync(id, ct);
        return NoContent();
    }
}

using AlertaSP.Core.Exceptions;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace AlertaSP.Api.Middleware;

/// <summary>
/// Converte exceções em respostas <c>application/problem+json</c>. Erros de domínio viram 400/404/409 com a
/// mensagem da regra; qualquer outra exceção vira 500 com texto genérico, sem stack trace na resposta.
/// </summary>
public sealed class GlobalExceptionHandler : IExceptionHandler
{
    private readonly IProblemDetailsService _problemDetails;
    private readonly ILogger<GlobalExceptionHandler> _logger;

    public GlobalExceptionHandler(IProblemDetailsService problemDetails, ILogger<GlobalExceptionHandler> logger)
    {
        _problemDetails = problemDetails;
        _logger = logger;
    }

    public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
    {
        var (status, title, detail) = exception switch
        {
            DuplicateEntityException e => (StatusCodes.Status409Conflict, "Registro duplicado", e.Message),
            EntityNotFoundException e => (StatusCodes.Status404NotFound, "Recurso não encontrado", e.Message),
            SecurityViolationException e => (StatusCodes.Status400BadRequest, "Conteúdo bloqueado pela política de segurança", e.Message),
            DomainException e => (StatusCodes.Status400BadRequest, "Regra de negócio violada", e.Message),
            _ => (StatusCodes.Status500InternalServerError, "Erro interno", "Não foi possível processar a solicitação.")
        };

        if (status == StatusCodes.Status500InternalServerError)
            _logger.LogError(exception, "Erro não tratado em {Method} {Path}", httpContext.Request.Method, httpContext.Request.Path);
        else
            _logger.LogWarning("{Title}: {Detail}", title, detail);

        httpContext.Response.StatusCode = status;
        return await _problemDetails.TryWriteAsync(new ProblemDetailsContext
        {
            HttpContext = httpContext,
            ProblemDetails = new ProblemDetails
            {
                Status = status,
                Title = title,
                Detail = detail,
                Instance = httpContext.Request.Path
            }
        });
    }
}

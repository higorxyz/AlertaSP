using System.Reflection;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace AlertaSP.Api.Filters;

/// <summary>Marca no Swagger só as operações protegidas por <see cref="ApiKeyAuthAttribute"/>.</summary>
public sealed class ApiKeyOperationFilter : IOperationFilter
{
    public const string SchemeId = "ApiKey";

    public void Apply(OpenApiOperation operation, OperationFilterContext context)
    {
        var protectedEndpoint =
            context.MethodInfo.GetCustomAttribute<ApiKeyAuthAttribute>() != null ||
            context.MethodInfo.DeclaringType?.GetCustomAttribute<ApiKeyAuthAttribute>() != null;

        if (!protectedEndpoint)
            return;

        operation.Security.Add(new OpenApiSecurityRequirement
        {
            [new OpenApiSecurityScheme { Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = SchemeId } }]
                = Array.Empty<string>()
        });
        operation.Responses.TryAdd("401", new OpenApiResponse { Description = "Cabeçalho X-Api-Key ausente ou inválido." });
    }
}

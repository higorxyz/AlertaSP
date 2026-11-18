using System.Text.Json.Serialization;
using AlertaSP.Api.Filters;
using AlertaSP.Api.Logging;
using AlertaSP.Api.Middleware;
using AlertaSP.Application;
using AlertaSP.Core.Interfaces.Security;
using AlertaSP.Infrastructure;
using AlertaSP.Infrastructure.Data;
using AlertaSP.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

// Todo evento de log passa pelo motor de PII antes de chegar ao console. É uma segunda barreira:
// o código de negócio já escreve pelo ISecureLogger, mas o framework e bibliotecas não.
builder.Host.UseSerilog((context, services, logger) =>
{
    var console = new LoggerConfiguration().WriteTo.Console().CreateLogger();
    var masking = services.GetRequiredService<IPiiMaskingService>();

    logger
        .MinimumLevel.Information()
        .MinimumLevel.Override("Microsoft.AspNetCore", Serilog.Events.LogEventLevel.Warning)
        .MinimumLevel.Override("Microsoft.EntityFrameworkCore", Serilog.Events.LogEventLevel.Warning)
        .WriteTo.Sink(new PiiMaskingSink(console, masking.MaskContent));
});

builder.Services.AddRouting(o => o.LowercaseUrls = true);
builder.Services
    .AddControllers(o => o.OutputFormatters.RemoveType<Microsoft.AspNetCore.Mvc.Formatters.StringOutputFormatter>())
    .AddJsonOptions(o => o.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter()));

builder.Services.AddProblemDetails(o =>
    o.CustomizeProblemDetails = ctx => ctx.ProblemDetails.Extensions["traceId"] = ctx.HttpContext.TraceIdentifier);
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "AlertaSP API",
        Version = "v1",
        Description = "Alertas de alagamento para os trajetos do cidadão, com detecção de PII, Taint Analysis e tradução de incidentes por IA."
    });

    c.AddSecurityDefinition(ApiKeyOperationFilter.SchemeId, new OpenApiSecurityScheme
    {
        Description = "Chave exigida pelos endpoints /api/security/* (cabeçalho X-Api-Key).",
        Type = SecuritySchemeType.ApiKey,
        Name = "X-Api-Key",
        In = ParameterLocation.Header
    });
    c.OperationFilter<ApiKeyOperationFilter>();

    foreach (var xml in new[] { "AlertaSP.Api.xml", "AlertaSP.Application.xml" })
    {
        var path = Path.Combine(AppContext.BaseDirectory, xml);
        if (File.Exists(path))
            c.IncludeXmlComments(path);
    }
});

builder.Services.AddApplication(builder.Configuration);
builder.Services.AddInfrastructure(builder.Configuration);
builder.Services.AddSecurity(builder.Configuration);

var app = builder.Build();

var missingSettings = new[] { "Security:ApiKey", "Security:HmacSecret" }
    .Where(key => string.IsNullOrWhiteSpace(app.Configuration[key]))
    .ToList();
if (missingSettings.Count > 0)
{
    throw new InvalidOperationException(
        $"Configuração obrigatória ausente: {string.Join(", ", missingSettings)}. " +
        "Defina por variável de ambiente (Security__ApiKey, Security__HmacSecret) ou User Secrets. Veja o README.");
}

app.UseExceptionHandler();
app.UseStatusCodePages();
app.UseMiddleware<CorrelationIdMiddleware>();
app.UseMiddleware<SecurityHeadersMiddleware>();

if (app.Environment.IsDevelopment())
{
    using (var scope = app.Services.CreateScope())
        scope.ServiceProvider.GetRequiredService<ApplicationDbContext>().Database.Migrate();

    app.UseSwagger();
    app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "AlertaSP API v1"));
}

app.UseHttpsRedirection();
app.UseDefaultFiles();
app.UseStaticFiles();

app.MapControllers();

app.MapGet("/health", async (ApplicationDbContext db, CancellationToken ct) =>
    await db.Database.CanConnectAsync(ct)
        ? Results.Ok(new { status = "Healthy", database = "Healthy", timestamp = DateTime.UtcNow })
        : Results.Json(new { status = "Unhealthy", database = "Unavailable", timestamp = DateTime.UtcNow },
            statusCode: StatusCodes.Status503ServiceUnavailable))
    .WithTags("Health")
    .WithSummary("Disponibilidade da API e do banco de dados.");

app.Run();

/// <summary>Exposto para os testes de integração com WebApplicationFactory.</summary>
public partial class Program { }

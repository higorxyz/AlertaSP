using AlertaSP.Core.Interfaces;
using AlertaSP.Core.Interfaces.Security;
using AlertaSP.Infrastructure.Data;
using AlertaSP.Infrastructure.Repositories;
using AlertaSP.Infrastructure.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AlertaSP.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        var connectionString = configuration.GetConnectionString("DefaultConnection") ?? "Data Source=alertasp.db";

        services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlite(connectionString));

        // Chaves do Data Protection ficam no perfil do usuário (padrão do ASP.NET Core). Em produção
        // deveriam ir para um cofre de chaves; ver docs/security.md.
        services.AddDataProtection()
            .SetApplicationName("AlertaSP");

        services.AddScoped<ICitizenRepository, CitizenRepository>();
        services.AddScoped<IRouteRepository, RouteRepository>();
        services.AddScoped<IFloodOccurrenceRepository, FloodOccurrenceRepository>();
        services.AddScoped<IAlertRepository, AlertRepository>();

        services.AddScoped<ISecurityIncidentRepository, SecurityIncidentRepository>();
        services.AddScoped<IAuditSink, AuditEventRepository>();

        services.AddSingleton<ICryptoService, DataProtectionCryptoService>();

        return services;
    }
}

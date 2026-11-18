using AlertaSP.Application.Interfaces;
using AlertaSP.Application.Proximity;
using AlertaSP.Application.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AlertaSP.Application;

public static class DependencyInjection
{
    public static IServiceCollection AddApplication(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<ProximityOptions>()
            .Bind(configuration.GetSection(ProximityOptions.SectionName))
            .Validate(o => o.NearbyRadiusMeters > 0 && o.NearbyRadiusMeters <= ProximityOptions.MaxRadiusMeters,
                $"Risk:NearbyRadiusMeters deve estar entre 1 e {ProximityOptions.MaxRadiusMeters} metros.")
            .ValidateOnStart();

        services.AddScoped<INearbyOccurrenceFinder, NearbyOccurrenceFinder>();
        services.AddScoped<ICitizenService, CitizenService>();
        services.AddScoped<IRouteService, RouteService>();
        services.AddScoped<IFloodOccurrenceService, FloodOccurrenceService>();
        services.AddScoped<IAlertService, AlertService>();

        return services;
    }
}

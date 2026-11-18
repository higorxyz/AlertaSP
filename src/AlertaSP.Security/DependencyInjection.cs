using AlertaSP.Core.Interfaces.Security;
using AlertaSP.Security.Dashboard;
using AlertaSP.Security.Incidents;
using AlertaSP.Security.Logging;
using AlertaSP.Security.Pii;
using AlertaSP.Security.Pii.Rules;
using AlertaSP.Security.Remediation;
using AlertaSP.Security.Risk;
using AlertaSP.Security.Taint;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AlertaSP.Security;

public static class DependencyInjection
{
    public static IServiceCollection AddSecurity(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<CitizenRiskOptions>()
            .Bind(configuration.GetSection(CitizenRiskOptions.SectionName))
            .Validate(o => o.CitizenRiskK > 0 && o.AnalysisWindowDays > 0, "Risk:CitizenRiskK e Risk:AnalysisWindowDays devem ser positivos.")
            .ValidateOnStart();

        services.AddOptions<AiRemediationOptions>()
            .Bind(configuration.GetSection(AiRemediationOptions.SectionName))
            .Validate(o => o.IsValid(), "Configuração AiRemediation inválida (endpoint, timeout, tentativas ou tokens).")
            .ValidateOnStart();

        // Cada regra é uma implementação de IPiiRule; o detector recebe todas pelo contêiner.
        services.AddSingleton(sp => HealthRuleSet.Load(sp.GetRequiredService<IConfiguration>()));
        services.AddSingleton<IPiiRule, CpfPiiRule>();
        services.AddSingleton<IPiiRule, CredentialsPiiRule>();
        services.AddSingleton<IPiiRule, HealthDataPiiRule>();
        services.AddSingleton<IPiiRule, LocationPiiRule>();
        services.AddSingleton<IPiiRule, CoordinatesPiiRule>();
        services.AddSingleton<IPiiRule, EmailPiiRule>();
        services.AddSingleton<IPiiDetector, PiiDetectionService>();
        services.AddSingleton<IPiiMaskingService, PiiMaskingService>();
        services.AddSingleton<IPiiAnalysisService, PiiAnalysisService>();

        services.AddSingleton<ISecurityPolicy, SecurityPolicy>();
        services.AddScoped<ITaintTracker, TaintTracker>();
        services.AddScoped<ISecureLogger, SecureLogger>();

        services.AddHttpClient(LlmRemediationService.HttpClientName);
        services.AddSingleton<DeterministicRemediationService>();
        services.AddScoped<ISecurityRemediationService, LlmRemediationService>();

        services.AddSingleton<ICitizenRiskCalculator, CitizenRiskCalculator>();
        services.AddScoped<ISecurityDashboardService, SecurityDashboardService>();
        services.AddScoped<ISecurityIncidentService, SecurityIncidentService>();

        return services;
    }
}

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using AlertaSP.Application.DTOs.Alerts;
using AlertaSP.Application.DTOs.Citizens;
using AlertaSP.Application.DTOs.Common;
using AlertaSP.Application.DTOs.FloodOccurrences;
using AlertaSP.Application.DTOs.Routes;
using AlertaSP.Core.Enums;
using AlertaSP.Core.Interfaces.Security;
using AlertaSP.Infrastructure.Data;
using AlertaSP.Security.Dashboard;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AlertaSP.UnitTests.Integration;

public class ApiIntegrationTests : IClassFixture<WebApplicationFactory<Program>>, IDisposable
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly string _dbFileName;
    private const string ApiKey = "integration-test-api-key";

    // Mesmas regras da API: nomes em camelCase e enums como texto.
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() }
    };

    public ApiIntegrationTests(WebApplicationFactory<Program> factory)
    {
        _dbFileName = $"test_integration_{Guid.NewGuid():N}.db";

        // Cada teste usa o próprio arquivo SQLite, apagado no Dispose.
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("Security:ApiKey", ApiKey);
            builder.UseSetting("Security:HmacSecret", "integration-test-hmac-secret");

            builder.ConfigureServices(services =>
            {
                var registered = services.SingleOrDefault(d => d.ServiceType == typeof(DbContextOptions<ApplicationDbContext>));
                if (registered != null)
                    services.Remove(registered);

                services.AddDbContext<ApplicationDbContext>(options => options.UseSqlite($"Data Source={_dbFileName}"));
            });
        });
    }

    public void Dispose()
    {
        // O host precisa ser descartado e o pool de conexões esvaziado antes de apagar o arquivo,
        // senão o SQLite mantém o arquivo aberto.
        _factory.Dispose();
        SqliteConnection.ClearAllPools();
        foreach (var suffix in new[] { "", "-wal", "-shm" })
            File.Delete(_dbFileName + suffix);
    }

    [Fact]
    public async Task HealthEndpoint_Returns200AndHealthyStatus()
    {
        var client = _factory.CreateClient();
        var response = await client.GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var content = await response.Content.ReadAsStringAsync();
        Assert.Contains("Healthy", content);
    }

    [Fact]
    public async Task RegisterCitizen_ValidInput_Returns201AndMaskedCpf()
    {
        var client = _factory.CreateClient();
        var request = new RegisterCitizenRequest
        {
            Name = "Higor Batista",
            Cpf = "529.982.247-25", // CPF válido
            Email = "higor@fiap.com.br",
            Address = "Av. Paulista, 1106 - Bela Vista, São Paulo - SP"
        };

        var response = await client.PostAsJsonAsync("/api/citizens", request);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var citizen = await response.Content.ReadFromJsonAsync<CitizenResponse>(Json);
        Assert.NotNull(citizen);
        Assert.Equal("Higor Batista", citizen.Name);
        Assert.Equal("***.***.***-25", citizen.MaskedCpf);
    }

    [Fact]
    public async Task RegisterCitizen_InvalidCpf_Returns400BadRequest()
    {
        var client = _factory.CreateClient();
        var request = new RegisterCitizenRequest
        {
            Name = "Teste Inválido",
            Cpf = "111.222.333-99", // CPF inválido
            Email = "invalido@teste.com",
            Address = "Rua Teste, 100"
        };

        var response = await client.PostAsJsonAsync("/api/citizens", request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task SecurityDashboard_WithoutApiKey_Returns401Unauthorized()
    {
        var client = _factory.CreateClient();
        var response = await client.GetAsync("/api/security/dashboard");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task SecurityDashboard_WithValidApiKey_Returns200AndMetrics()
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Api-Key", ApiKey);

        var response = await client.GetAsync("/api/security/dashboard");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var metrics = await response.Content.ReadFromJsonAsync<SecurityDashboardMetrics>(Json);
        Assert.NotNull(metrics);
        Assert.NotNull(metrics.CitizenRisk);
        Assert.Contains("não uma previsão", metrics.Disclaimer);
    }

    [Fact]
    public async Task SecurityDemoScenarios_ExecutesAndRecordsAuditAndIncidents()
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Api-Key", ApiKey);

        var response = await client.PostAsync("/api/security/demo/scenarios", null);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await response.Content.ReadFromJsonAsync<DemoScenariosResult>(Json);
        Assert.NotNull(result);
        Assert.Equal(4, result.Scenarios.Count);

        // Verifica se os incidentes e o risco foram refletidos no dashboard
        var dashResponse = await client.GetAsync("/api/security/dashboard");
        var metrics = await dashResponse.Content.ReadFromJsonAsync<SecurityDashboardMetrics>(Json);
        Assert.NotNull(metrics);
        Assert.True(metrics.TotalIncidents >= 2);
        Assert.True(metrics.CitizenRisk.Score > 0);
    }

    [Fact]
    public async Task FullWorkflow_RegisterCitizen_CreateRoute_AddOccurrence_GenerateAlerts()
    {
        var client = _factory.CreateClient();

        var citizenReq = new RegisterCitizenRequest
        {
            Name = "Workflow User",
            Cpf = "52998224725",
            Email = "workflow@alerta.sp.gov.br",
            Address = "Rua Vergueiro, 1000 - Liberdade, São Paulo"
        };
        var citRes = await client.PostAsJsonAsync("/api/citizens", citizenReq);
        Assert.Equal(HttpStatusCode.Created, citRes.StatusCode);
        var citizen = await citRes.Content.ReadFromJsonAsync<CitizenResponse>(Json);

        var routeReq = new CreateRouteRequest
        {
            CitizenId = citizen!.Id,
            Name = "Casa -> Trabalho",
            Origin = "Liberdade",
            Destination = "Consolação",
            OriginLatitude = -23.5650,
            OriginLongitude = -46.6400,
            DestinationLatitude = -23.5550,
            DestinationLongitude = -46.6600
        };
        var routeRes = await client.PostAsJsonAsync("/api/routes", routeReq);
        Assert.Equal(HttpStatusCode.Created, routeRes.StatusCode);
        var route = await routeRes.Content.ReadFromJsonAsync<RouteResponse>(Json);

        // Ocorrência a cerca de 150 m da reta do trajeto.
        var occReq = new CreateFloodOccurrenceRequest
        {
            Location = "Av. Brigadeiro Luís Antônio x Av. Paulista",
            Latitude = -23.5610,
            Longitude = -46.6490,
            Description = "Ponto de alagamento transitável na via principal.",
            Severity = Severity.Alto
        };
        var occRes = await client.PostAsJsonAsync("/api/flood-occurrences", occReq);
        Assert.Equal(HttpStatusCode.Created, occRes.StatusCode);

        var alertGenRes = await client.PostAsync("/api/alerts/generate?radiusMeters=500", null);
        Assert.Equal(HttpStatusCode.OK, alertGenRes.StatusCode);
        var genResult = await alertGenRes.Content.ReadFromJsonAsync<GenerateAlertsResult>(Json);
        Assert.NotNull(genResult);
        Assert.True(genResult.AlertsGenerated >= 1);

        var citAlertsRes = await client.GetAsync($"/api/alerts/citizen/{citizen.Id}");
        Assert.Equal(HttpStatusCode.OK, citAlertsRes.StatusCode);
    }

    // ---------- Helpers ----------

    private HttpClient CreateSecurityClient()
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Api-Key", ApiKey);
        return client;
    }

    private static async Task<CitizenResponse> RegisterCitizenAsync(HttpClient client, string cpf = "529.982.247-25", string email = "higor@fiap.com.br")
    {
        var response = await client.PostAsJsonAsync("/api/citizens", new RegisterCitizenRequest
        {
            Name = "Higor Batista",
            Cpf = cpf,
            Email = email,
            Address = "Av. Paulista, 1106 - Bela Vista, São Paulo - SP"
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<CitizenResponse>(Json))!;
    }

    // ---------- Dados sensíveis: respostas e repouso ----------

    [Fact]
    public async Task Citizens_NeverExposeRawCpfEmailOrAddressInAnyResponse()
    {
        var client = _factory.CreateClient();
        var created = await RegisterCitizenAsync(client);

        var single = await client.GetStringAsync($"/api/citizens/{created.Id}");
        var list = await client.GetStringAsync("/api/citizens");

        foreach (var body in new[] { single, list })
        {
            Assert.DoesNotContain("529.982.247-25", body);
            Assert.DoesNotContain("52998224725", body);
            Assert.DoesNotContain("higor@fiap.com.br", body);
            Assert.DoesNotContain("Av. Paulista, 1106", body);
            Assert.Contains("***.***.***-25", body);
        }
    }

    [Fact]
    public async Task Citizens_AreStoredEncryptedAtRest()
    {
        var client = _factory.CreateClient();
        await RegisterCitizenAsync(client);

        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var stored = await db.Citizens.AsNoTracking().SingleAsync();

        Assert.DoesNotContain("52998224725", stored.EncryptedCpf);
        Assert.DoesNotContain("529.982.247-25", stored.EncryptedCpf);
        Assert.DoesNotContain("higor@fiap.com.br", stored.EncryptedEmail);
        Assert.DoesNotContain("Paulista", stored.EncryptedAddress);
        Assert.NotEqual("52998224725", stored.CpfHash);
    }

    [Fact]
    public async Task RegisterCitizen_DuplicateCpf_Returns409()
    {
        var client = _factory.CreateClient();
        await RegisterCitizenAsync(client);

        var second = await client.PostAsJsonAsync("/api/citizens", new RegisterCitizenRequest
        {
            Name = "Outra Pessoa",
            Cpf = "52998224725",
            Email = "outra@exemplo.com",
            Address = "Rua B, 20 - Centro, Suzano - SP"
        });

        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
    }

    [Fact]
    public async Task Route_PublicResponseIsGeneralized_AndTheExactLocationIsStoredEncrypted()
    {
        var client = _factory.CreateClient();
        var citizen = await RegisterCitizenAsync(client);

        var response = await client.PostAsJsonAsync("/api/routes", new CreateRouteRequest
        {
            CitizenId = citizen.Id,
            Name = "Casa -> Trabalho",
            Origin = "Rua Augusta, 1200",
            Destination = "Av. Paulista, 1578",
            OriginLatitude = -23.5612,
            OriginLongitude = -46.6401,
            DestinationLatitude = -23.5559,
            DestinationLongitude = -46.6602
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var route = (await response.Content.ReadFromJsonAsync<RouteResponse>(Json))!;

        Assert.Equal(-23.56, route.OriginLatitude);
        Assert.Equal(-46.64, route.OriginLongitude);
        Assert.Equal("[ENDEREÇO PROTEGIDO]", route.Origin);
        Assert.Equal("[ENDEREÇO PROTEGIDO]", route.Destination);

        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            var stored = await db.Routes.AsNoTracking().SingleAsync();
            Assert.DoesNotContain("Augusta", stored.EncryptedOrigin);
            Assert.DoesNotContain("Paulista", stored.EncryptedDestination);
            Assert.DoesNotContain("-23.5612", stored.EncryptedCoordinates);
        }

        // O valor exato continua disponível para o uso interno: a ocorrência sobre o trajeto é encontrada.
        await client.PostAsJsonAsync("/api/flood-occurrences", new CreateFloodOccurrenceRequest
        {
            Location = "Trecho monitorado", Latitude = -23.5612, Longitude = -46.6401,
            Description = "Ponto de alagamento na origem.", Severity = Severity.Alto
        });
        var risk = (await client.GetFromJsonAsync<RouteRiskAnalysisResponse>($"/api/routes/{route.Id}/risk", Json))!;
        Assert.Equal(0, Assert.Single(risk.NearbyOccurrences).DistanceMeters);
    }

    // Inspeciona o arquivo SQLite byte a byte: nenhum dado sensível de cidadão ou de trajeto pode
    // aparecer em texto claro, nem em colunas que o teste não conhece.
    [Fact]
    public async Task SqliteFile_ContainsNoPlainTextPersonalOrLocationData()
    {
        var client = _factory.CreateClient();
        var citizen = await RegisterCitizenAsync(client);
        var routeResponse = await client.PostAsJsonAsync("/api/routes", new CreateRouteRequest
        {
            CitizenId = citizen.Id,
            Name = "Casa -> Trabalho",
            Origin = "Rua Augusta, 1200",
            Destination = "Av. Paulista, 1578",
            OriginLatitude = -23.5612,
            OriginLongitude = -46.6401,
            DestinationLatitude = -23.5559,
            DestinationLongitude = -46.6602
        });
        Assert.Equal(HttpStatusCode.Created, routeResponse.StatusCode);

        var text = await ReadDatabaseFilesAsync();

        foreach (var secret in new[] { "52998224725", "529.982.247-25", "higor@fiap.com.br", "Av. Paulista, 1106", "Rua Augusta, 1200", "Av. Paulista, 1578", "-23.5612", "-46.6602" })
            Assert.DoesNotContain(secret, text);
        Assert.Contains("Casa -> Trabalho", text); // o nome do trajeto não é sensível e confirma que o arquivo foi lido
    }

    // A atualização segue o mesmo caminho do cadastro: liberação pelo rastreador, cifragem e resposta generalizada.
    [Fact]
    public async Task Route_Update_StoresTheNewLocationEncryptedAndUsesItInternally()
    {
        var client = _factory.CreateClient();
        var citizen = await RegisterCitizenAsync(client);
        var route = await CreateRouteAsync(client, citizen.Id);

        var update = await client.PutAsJsonAsync($"/api/routes/{route.Id}", new UpdateRouteRequest
        {
            Name = "Casa -> Faculdade",
            Origin = "Rua Vergueiro, 3185",
            Destination = "Av. Lins de Vasconcelos, 1222",
            OriginLatitude = -23.5891,
            OriginLongitude = -46.6342,
            DestinationLatitude = -23.5743,
            DestinationLongitude = -46.6235
        });
        var updated = (await update.Content.ReadFromJsonAsync<RouteResponse>(Json))!;

        Assert.Equal(HttpStatusCode.OK, update.StatusCode);
        Assert.Equal("[ENDEREÇO PROTEGIDO]", updated.Origin);
        Assert.Equal("[ENDEREÇO PROTEGIDO]", updated.Destination);
        Assert.Equal(-23.59, updated.OriginLatitude);

        using (var scope = _factory.Services.CreateScope())
        {
            var stored = await scope.ServiceProvider.GetRequiredService<ApplicationDbContext>().Routes.AsNoTracking().SingleAsync();
            Assert.DoesNotContain("Vergueiro", stored.EncryptedOrigin);
            Assert.DoesNotContain("Lins de Vasconcelos", stored.EncryptedDestination);
            Assert.DoesNotContain("-23.5891", stored.EncryptedCoordinates);
        }

        var text = await ReadDatabaseFilesAsync();
        foreach (var secret in new[] { "Rua Vergueiro, 3185", "Av. Lins de Vasconcelos, 1222", "-23.5891", "-46.6235" })
            Assert.DoesNotContain(secret, text);
        Assert.Contains("Casa -> Faculdade", text);

        // A consulta de risco usa a localização nova: a ocorrência na nova origem fica a 0 m.
        await CreateOccurrenceAsync(client, -23.5891, -46.6342);
        var risk = (await client.GetFromJsonAsync<RouteRiskAnalysisResponse>($"/api/routes/{route.Id}/risk", Json))!;
        Assert.Equal(0, Assert.Single(risk.NearbyOccurrences).DistanceMeters);
    }

    /// <summary>
    /// Conteúdo bruto do banco de teste. O EF Core cria o SQLite em modo WAL: as gravações recentes ficam no
    /// arquivo "-wal" até o checkpoint, por isso os dois arquivos são lidos.
    /// </summary>
    private async Task<string> ReadDatabaseFilesAsync()
    {
        var text = new System.Text.StringBuilder();
        foreach (var path in new[] { _dbFileName, _dbFileName + "-wal" }.Where(File.Exists))
        {
            await using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var raw = new byte[file.Length];
            await file.ReadExactlyAsync(raw);
            text.Append(System.Text.Encoding.UTF8.GetString(raw));
        }
        return text.ToString();
    }

    // ---------- Ocorrências: conteúdo livre passa pelo taint ----------

    [Fact]
    public async Task Occurrence_WithCredentialInDescription_IsRejectedAndRecordedAsBlockedIncident()
    {
        var client = CreateSecurityClient();

        var response = await client.PostAsJsonAsync("/api/flood-occurrences", new CreateFloodOccurrenceRequest
        {
            Location = "Av. Brigadeiro Luís Antônio",
            Latitude = -23.5610,
            Longitude = -46.6490,
            Description = "Alagamento forte, senha=MinhaSenha123 do portão",
            Severity = Severity.Alto
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("MinhaSenha123", body);

        var dashboard = await client.GetFromJsonAsync<SecurityDashboardMetrics>("/api/security/dashboard", Json);
        Assert.NotNull(dashboard);
        Assert.True(dashboard!.BlockedAttempts >= 1);
        Assert.True(dashboard.CredentialsDetectedCount >= 1);
        Assert.True(dashboard.CitizenRisk.Score > 0);

        var list = await client.GetFromJsonAsync<PagedResult<FloodOccurrenceResponse>>("/api/flood-occurrences", Json);
        Assert.Empty(list!.Items);
    }

    [Fact]
    public async Task Occurrence_WithCpfInDescription_IsStoredMasked()
    {
        var client = _factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/flood-occurrences", new CreateFloodOccurrenceRequest
        {
            Location = "Rua do Ouvidor",
            Latitude = -23.5610,
            Longitude = -46.6490,
            Description = "Relato enviado pelo CPF 529.982.247-25 no ponto de alagamento",
            Severity = Severity.Moderado
        });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var created = (await response.Content.ReadFromJsonAsync<FloodOccurrenceResponse>(Json))!;
        Assert.DoesNotContain("529.982.247-25", created.Description);
        Assert.Contains("***.***.***-25", created.Description);

        var fetched = await client.GetStringAsync($"/api/flood-occurrences/{created.Id}");
        Assert.DoesNotContain("529.982.247-25", fetched);
    }

    // ---------- Segurança: endpoints e ambiente ----------

    [Fact]
    public async Task SecurityAnalyze_DetectsAndMasksSensitiveContent()
    {
        var client = CreateSecurityClient();

        var response = await client.PostAsJsonAsync("/api/security/analyze", new
        {
            content = "CPF 529.982.247-25, e-mail ana@exemplo.com, senha=Abc12345 e ponto -23.5614,-46.6559"
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("Abc12345", body.Substring(body.IndexOf("maskedContent", StringComparison.OrdinalIgnoreCase)));
        Assert.Contains("PII_CPF", body);
        Assert.Contains("PII_EMAIL", body);
        Assert.Contains("CREDENTIAL_KEY_VALUE", body);
        Assert.Contains("LOCATION_COORDINATES", body);
    }

    [Fact]
    public async Task SecurityAnalyze_RejectsOversizedContent()
    {
        var client = CreateSecurityClient();

        var response = await client.PostAsJsonAsync("/api/security/analyze", new { content = new string('a', 20001) });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task SecurityEndpoints_WithWrongApiKey_Return401()
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Add("X-Api-Key", "chave-errada");

        var response = await client.GetAsync("/api/security/incidents");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task DemoScenarios_OutsideDevelopment_Return404()
    {
        var production = _factory.WithWebHostBuilder(builder => builder.UseEnvironment("Production"));
        var client = production.CreateClient();
        client.DefaultRequestHeaders.Add("X-Api-Key", ApiKey);

        var response = await client.PostAsync("/api/security/demo/scenarios", null);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Dashboard_RiskStartsAtZeroAndNeverDecreasesAfterNewIncidents()
    {
        var client = CreateSecurityClient();

        var before = (await client.GetFromJsonAsync<SecurityDashboardMetrics>("/api/security/dashboard", Json))!;
        Assert.Equal(0, before.CitizenRisk.Score);
        Assert.Equal(0, before.TotalIncidents);

        await client.PostAsync("/api/security/demo/scenarios", null);
        var afterFirst = (await client.GetFromJsonAsync<SecurityDashboardMetrics>("/api/security/dashboard", Json))!;
        await client.PostAsync("/api/security/demo/scenarios", null);
        var afterSecond = (await client.GetFromJsonAsync<SecurityDashboardMetrics>("/api/security/dashboard", Json))!;

        Assert.True(afterFirst.CitizenRisk.Score > before.CitizenRisk.Score);
        Assert.True(afterSecond.CitizenRisk.Score >= afterFirst.CitizenRisk.Score);
        Assert.True(afterSecond.TotalIncidents > afterFirst.TotalIncidents);
        Assert.True(afterSecond.BlockedAttempts >= 2);
    }

    [Fact]
    public async Task DemoScenarios_RecordTheFourDocumentedDecisions()
    {
        var client = CreateSecurityClient();

        var result = (await (await client.PostAsync("/api/security/demo/scenarios", null))
            .Content.ReadFromJsonAsync<DemoScenariosResult>(Json))!;

        var cpf = result.Scenarios[0];
        Assert.Equal(("Log", "PersonalData", "AllowSanitized"), (cpf.Sink, cpf.Category, cpf.Decision));
        Assert.Contains("***.***.***-88", cpf.ReleasedValue);
        Assert.DoesNotContain("384.920.184-88", cpf.ReleasedValue);

        var address = result.Scenarios[1];
        Assert.Equal(("PublicHttpResponse", "Location", "AllowSanitized"), (address.Sink, address.Category, address.Decision));
        Assert.DoesNotContain("Paulista, 1578", address.ReleasedValue);

        var credential = result.Scenarios[2];
        Assert.Equal(("ExternalAiService", "Credentials", "Block"), (credential.Sink, credential.Category, credential.Decision));
        Assert.Null(credential.ReleasedValue);

        var authorized = result.Scenarios[3];
        Assert.Equal(("InternalHttpResponse", "Location", "Allow"), (authorized.Sink, authorized.Category, authorized.Decision));

        var audit = await client.GetFromJsonAsync<PagedResult<AuditEventPayload>>("/api/security/audit?pageSize=50", Json);
        Assert.True(audit!.TotalCount >= 4);
        Assert.All(audit.Items, e =>
        {
            Assert.DoesNotContain("384.920.184-88", e.Summary);
            Assert.DoesNotContain("sk-proj-", e.Summary);
        });
    }

    private sealed class AuditEventPayload
    {
        public string Source { get; set; } = string.Empty;
        public string SinkType { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public string Decision { get; set; } = string.Empty;
        public string Summary { get; set; } = string.Empty;
    }

    // O SQLite não guarda o fuso: sem a conversão no DbContext, a data volta sem "Z" e o painel
    // exibe o horário UTC como se fosse o de Brasília (3 horas adiantado).
    [Fact]
    public async Task Timestamps_ReadBackFromDatabase_AreSerializedAsUtc()
    {
        var client = _factory.CreateClient();
        var citizen = await RegisterCitizenAsync(client);

        using var json = System.Text.Json.JsonDocument.Parse(await client.GetStringAsync($"/api/citizens/{citizen.Id}"));
        var createdAt = json.RootElement.GetProperty("createdAt").GetString()!;

        Assert.EndsWith("Z", createdAt);
    }

    // Cenário 4 no fluxo real: a geração de alertas usa as coordenadas do trajeto (Location) em fluxo
    // interno autorizado com finalidade RouteAlertGeneration -> Allow, auditado e sem incidente.
    [Fact]
    public async Task AlertGeneration_UsesRouteCoordinatesThroughTaintTracker_AsAuthorizedInternalFlow()
    {
        var client = _factory.CreateClient();
        var citizen = await RegisterCitizenAsync(client);
        await CreateRouteAsync(client, citizen.Id);

        var generation = await client.PostAsync("/api/alerts/generate?radiusMeters=500", null);
        Assert.Equal(HttpStatusCode.OK, generation.StatusCode);

        var security = CreateSecurityClient();
        var audit = (await security.GetFromJsonAsync<PagedResult<AuditEventPayload>>("/api/security/audit?pageSize=100", Json))!;

        var alertFlow = Assert.Single(audit.Items, e => e.Source == "/api/alerts/generate");
        Assert.Equal("InternalHttpResponse", alertFlow.SinkType);
        Assert.Equal("Location", alertFlow.Category);
        Assert.Equal("Allow", alertFlow.Decision);
        Assert.DoesNotContain("-23.565", alertFlow.Summary);
    }

    // ---------- Alertas: paginação correta, sem duplicidade ----------

    [Fact]
    public async Task Alerts_PaginationReportsTheRealTotal_AndGenerationIsIdempotent()
    {
        var client = _factory.CreateClient();
        var citizen = await RegisterCitizenAsync(client);

        var routeResponse = await client.PostAsJsonAsync("/api/routes", new CreateRouteRequest
        {
            CitizenId = citizen.Id,
            Name = "Casa -> Faculdade",
            Origin = "Liberdade",
            Destination = "Consolação",
            OriginLatitude = -23.5650,
            OriginLongitude = -46.6400,
            DestinationLatitude = -23.5550,
            DestinationLongitude = -46.6600
        });
        Assert.Equal(HttpStatusCode.Created, routeResponse.StatusCode);

        // Três ocorrências sobre o segmento do trajeto (t = 0,3 / 0,5 / 0,7)
        foreach (var (lat, lon) in new[] { (-23.5620, -46.6460), (-23.5600, -46.6500), (-23.5580, -46.6540) })
        {
            var occurrence = await client.PostAsJsonAsync("/api/flood-occurrences", new CreateFloodOccurrenceRequest
            {
                Location = "Trecho monitorado",
                Latitude = lat,
                Longitude = lon,
                Description = "Ponto de alagamento sobre o trajeto.",
                Severity = Severity.Alto
            });
            Assert.Equal(HttpStatusCode.Created, occurrence.StatusCode);
        }

        var first = (await (await client.PostAsync("/api/alerts/generate?radiusMeters=200", null))
            .Content.ReadFromJsonAsync<GenerateAlertsResult>(Json))!;
        Assert.Equal(3, first.AlertsGenerated);

        var second = (await (await client.PostAsync("/api/alerts/generate?radiusMeters=200", null))
            .Content.ReadFromJsonAsync<GenerateAlertsResult>(Json))!;
        Assert.Equal(0, second.AlertsGenerated);

        var page = (await client.GetFromJsonAsync<PagedResult<AlertResponse>>($"/api/alerts/citizen/{citizen.Id}?page=1&pageSize=2", Json))!;
        Assert.Equal(3, page.TotalCount);
        Assert.Equal(2, page.TotalPages);
        Assert.Equal(2, page.Items.Count);
        Assert.All(page.Items, a => Assert.Equal("Casa -> Faculdade", a.RouteName));
        Assert.All(page.Items, a => Assert.DoesNotContain("Higor", a.Message));
    }

    // ---------- Consulta de risco do trajeto, filtros e validações ----------

    private static async Task<RouteResponse> CreateRouteAsync(HttpClient client, int citizenId)
    {
        var response = await client.PostAsJsonAsync("/api/routes", new CreateRouteRequest
        {
            CitizenId = citizenId,
            Name = "Casa -> Trabalho",
            Origin = "Liberdade",
            Destination = "Consolação",
            OriginLatitude = -23.5650,
            OriginLongitude = -46.6400,
            DestinationLatitude = -23.5550,
            DestinationLongitude = -46.6600
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<RouteResponse>(Json))!;
    }

    [Fact]
    public async Task RouteRisk_WithoutOccurrences_SaysNoneRegisteredWithoutPromisingSafety()
    {
        var client = _factory.CreateClient();
        var citizen = await RegisterCitizenAsync(client);
        var route = await CreateRouteAsync(client, citizen.Id);

        var response = await client.GetAsync($"/api/routes/{route.Id}/risk");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var risk = (await response.Content.ReadFromJsonAsync<RouteRiskAnalysisResponse>(Json))!;
        Assert.False(risk.HasNearbyOccurrences);
        Assert.Empty(risk.NearbyOccurrences);
        Assert.Contains("Nenhuma ocorrência", risk.StatusMessage);
        Assert.Contains("não garante", risk.StatusMessage);
    }

    [Fact]
    public async Task RouteRisk_WithOccurrenceOnTheSegment_ListsItOrderedByDistance()
    {
        var client = _factory.CreateClient();
        var citizen = await RegisterCitizenAsync(client);
        var route = await CreateRouteAsync(client, citizen.Id);

        // Uma sobre o segmento (t = 0,5) e uma distante (fora do raio padrão de 500 m)
        foreach (var (lat, lon, severity) in new[]
                 {
                     (-23.5600, -46.6500, Severity.Alto),
                     (-23.5300, -46.6500, Severity.Critico)
                 })
        {
            var created = await client.PostAsJsonAsync("/api/flood-occurrences", new CreateFloodOccurrenceRequest
            {
                Location = "Trecho monitorado",
                Latitude = lat,
                Longitude = lon,
                Description = "Ponto de alagamento registrado.",
                Severity = severity
            });
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        }

        var risk = (await client.GetFromJsonAsync<RouteRiskAnalysisResponse>($"/api/routes/{route.Id}/risk", Json))!;

        Assert.True(risk.HasNearbyOccurrences);
        Assert.Single(risk.NearbyOccurrences);
        Assert.Equal(Severity.Alto, risk.NearbyOccurrences[0].Severity);
        Assert.True(risk.NearbyOccurrences[0].DistanceMeters <= 500);
    }

    [Fact]
    public async Task RouteRisk_UnknownRoute_Returns404ProblemDetails()
    {
        var client = _factory.CreateClient();

        var response = await client.GetAsync("/api/routes/999999/risk");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Theory]
    [InlineData("-1")]
    [InlineData("10001")]
    public async Task RouteRisk_InvalidRadius_Returns400(string radius)
    {
        var client = _factory.CreateClient();
        var citizen = await RegisterCitizenAsync(client);
        var route = await CreateRouteAsync(client, citizen.Id);

        var response = await client.GetAsync($"/api/routes/{route.Id}/risk?radiusMeters={radius}");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("-5")]
    [InlineData("50000")]
    public async Task Nearby_InvalidRadius_Returns400ProblemDetails(string radius)
    {
        var client = _factory.CreateClient();

        var response = await client.GetAsync($"/api/flood-occurrences/nearby?lat=-23.56&lon=-46.65&radiusMeters={radius}");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task Occurrences_ListTotalCountRespectsFilters()
    {
        var client = _factory.CreateClient();

        foreach (var severity in new[] { Severity.Alto, Severity.Alto, Severity.Baixo })
        {
            var created = await client.PostAsJsonAsync("/api/flood-occurrences", new CreateFloodOccurrenceRequest
            {
                Location = "Ponto de teste",
                Latitude = -23.55,
                Longitude = -46.63,
                Description = "Registro para teste de filtro.",
                Severity = severity
            });
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        }

        var all = (await client.GetFromJsonAsync<PagedResult<FloodOccurrenceResponse>>("/api/flood-occurrences?pageSize=50", Json))!;
        var onlyHigh = (await client.GetFromJsonAsync<PagedResult<FloodOccurrenceResponse>>("/api/flood-occurrences?severity=Alto&pageSize=1", Json))!;

        Assert.Equal(3, all.TotalCount);
        Assert.Equal(2, onlyHigh.TotalCount);
        Assert.Single(onlyHigh.Items);
        Assert.Equal(2, onlyHigh.TotalPages);
    }

    // ---------- Cabeçalhos de segurança e correlação ----------

    [Fact]
    public async Task Responses_IncludeBasicSecurityHeaders()
    {
        var client = _factory.CreateClient();

        var response = await client.GetAsync("/health");

        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());
    }

    [Fact]
    public async Task Correlation_EchoesSafeIdAndGeneratesOneWhenMissing()
    {
        var client = _factory.CreateClient();

        var request = new HttpRequestMessage(HttpMethod.Get, "/health");
        request.Headers.Add("X-Correlation-ID", "gs-2026_demo-01");
        var echoed = await client.SendAsync(request);
        Assert.Equal("gs-2026_demo-01", echoed.Headers.GetValues("X-Correlation-ID").Single());

        var generated = await client.GetAsync("/health");
        Assert.False(string.IsNullOrWhiteSpace(generated.Headers.GetValues("X-Correlation-ID").Single()));
    }

    [Fact]
    public async Task Correlation_ReplacesUnsafeIncomingId()
    {
        var client = _factory.CreateClient();

        var request = new HttpRequestMessage(HttpMethod.Get, "/health");
        request.Headers.TryAddWithoutValidation("X-Correlation-ID", "<script>alert(1)</script>");
        var response = await client.SendAsync(request);

        var value = response.Headers.GetValues("X-Correlation-ID").Single();
        Assert.DoesNotContain("<", value);
        Assert.Matches("^[A-Za-z0-9\\-_]{1,64}$", value);
    }

    // ---------- Endpoints de manutenção ----------

    [Fact]
    public async Task Citizen_UpdateReturnsMaskedData_AndDeleteRemovesIt()
    {
        var client = _factory.CreateClient();
        var citizen = await RegisterCitizenAsync(client);

        var update = await client.PutAsJsonAsync($"/api/citizens/{citizen.Id}", new UpdateCitizenRequest
        {
            Name = "Nome Atualizado",
            Email = "novo@exemplo.com",
            Address = "Rua Nova, 50 - Mooca, São Paulo - SP"
        });
        var updated = (await update.Content.ReadFromJsonAsync<CitizenResponse>(Json))!;

        Assert.Equal(HttpStatusCode.OK, update.StatusCode);
        Assert.Equal("Nome Atualizado", updated.Name);
        Assert.Equal("no***@exemplo.com", updated.MaskedEmail);
        Assert.Equal("*** - Mooca, São Paulo - SP", updated.MaskedAddress);

        Assert.Equal(HttpStatusCode.NoContent, (await client.DeleteAsync($"/api/citizens/{citizen.Id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync($"/api/citizens/{citizen.Id}")).StatusCode);
    }

    [Fact]
    public async Task Monitoring_TurnedOff_RouteStopsReceivingAlerts()
    {
        var client = _factory.CreateClient();
        var citizen = await RegisterCitizenAsync(client);
        var route = await CreateRouteAsync(client, citizen.Id);
        await CreateOccurrenceAsync(client, -23.5600, -46.6500);

        var toggle = await client.PatchAsJsonAsync($"/api/routes/{route.Id}/monitoring", new ToggleMonitoringRequest { IsActive = false });
        var toggled = (await toggle.Content.ReadFromJsonAsync<RouteResponse>(Json))!;
        var generated = (await (await client.PostAsync("/api/alerts/generate", null)).Content.ReadFromJsonAsync<GenerateAlertsResult>(Json))!;

        Assert.False(toggled.IsMonitoringActive);
        Assert.Equal(0, generated.RoutesMonitored);
        Assert.Equal(0, generated.AlertsGenerated);
    }

    [Fact]
    public async Task ResolvedOccurrence_NoLongerGeneratesAlerts()
    {
        var client = _factory.CreateClient();
        var citizen = await RegisterCitizenAsync(client);
        await CreateRouteAsync(client, citizen.Id);
        var occurrence = await CreateOccurrenceAsync(client, -23.5600, -46.6500);

        var patch = await client.PatchAsJsonAsync($"/api/flood-occurrences/{occurrence.Id}/status", new { status = "Resolvida" });
        var resolved = (await patch.Content.ReadFromJsonAsync<FloodOccurrenceResponse>(Json))!;
        var generated = (await (await client.PostAsync("/api/alerts/generate", null)).Content.ReadFromJsonAsync<GenerateAlertsResult>(Json))!;

        Assert.Equal(OccurrenceStatus.Resolvida, resolved.Status);
        Assert.Equal(0, generated.AlertsGenerated);
    }

    [Fact]
    public async Task Alert_CanBeReadByIdAndMarkedAsRead()
    {
        var client = _factory.CreateClient();
        var citizen = await RegisterCitizenAsync(client);
        await CreateRouteAsync(client, citizen.Id);
        await CreateOccurrenceAsync(client, -23.5600, -46.6500);
        var generated = (await (await client.PostAsync("/api/alerts/generate", null)).Content.ReadFromJsonAsync<GenerateAlertsResult>(Json))!;
        var alertId = generated.GeneratedAlerts.Single().Id;

        Assert.Equal(HttpStatusCode.NoContent, (await client.PatchAsync($"/api/alerts/{alertId}/read", null)).StatusCode);
        var alert = (await client.GetFromJsonAsync<AlertResponse>($"/api/alerts/{alertId}", Json))!;

        Assert.True(alert.IsRead);
        Assert.Equal(Severity.Alto, alert.Severity);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/api/alerts/999999")).StatusCode);
    }

    [Fact]
    public async Task Occurrence_SeverityIsAcceptedByNameAndReturnedAsText()
    {
        var client = _factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/flood-occurrences", new
        {
            location = "Av. do Estado",
            latitude = -23.55,
            longitude = -46.62,
            description = "Pista alagada",
            severity = "Critico"
        });
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal("Critico", body.RootElement.GetProperty("severity").GetString());
        Assert.Equal("Ativa", body.RootElement.GetProperty("status").GetString());
    }

    [Theory]
    [InlineData("Inexistente")]
    [InlineData(99)]
    public async Task Occurrence_UnknownSeverity_Returns400(object severity)
    {
        var client = _factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/flood-occurrences", new Dictionary<string, object>
        {
            ["location"] = "Av. do Estado",
            ["latitude"] = -23.55,
            ["longitude"] = -46.62,
            ["description"] = "Pista alagada",
            ["severity"] = severity
        });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Occurrence_WithHealthDataInDescription_IsBlocked()
    {
        var client = _factory.CreateClient();

        var response = await client.PostAsJsonAsync("/api/flood-occurrences", new CreateFloodOccurrenceRequest
        {
            Location = "Rua Teste",
            Latitude = -23.55,
            Longitude = -46.62,
            Description = "Morador da casa 3 é paciente diagnosticado com insuficiência cardíaca.",
            Severity = Severity.Moderado
        });
        var problem = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("política de segurança", problem);
        Assert.DoesNotContain("insuficiência", problem);
    }

    [Fact]
    public async Task UnknownRoute_Returns404AsProblemDetails()
    {
        var client = _factory.CreateClient();

        var response = await client.GetAsync("/api/routes/424242");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task InvalidPagination_Returns400()
    {
        var client = _factory.CreateClient();

        Assert.Equal(HttpStatusCode.BadRequest, (await client.GetAsync("/api/citizens?page=0")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.GetAsync("/api/alerts?pageSize=500")).StatusCode);
    }

    // ---------- Painel: histórico diário ----------

    [Fact]
    public async Task DashboardHistory_ListsEveryDayAndCountsTodaysIncidents()
    {
        var client = CreateSecurityClient();
        await client.PostAsync("/api/security/demo/scenarios", null);

        var history = (await client.GetFromJsonAsync<List<DailyIncidentCount>>("/api/security/dashboard/history?days=7", Json))!;
        var today = DateOnly.FromDateTime(DateTime.UtcNow.AddHours(-3));

        Assert.Equal(7, history.Count);
        Assert.Equal(today, history[^1].Day);
        Assert.Equal(3, history[^1].Total);
        Assert.Equal(1, history[^1].Blocked);
        Assert.Equal(2, history[^1].Sanitized);
        Assert.All(history.Take(6), d => Assert.Equal(0, d.Total));
    }

    // ---------- Documentação ----------

    [Fact]
    public async Task Swagger_DocumentsEndpointsAndRequiresApiKeyOnlyOnSecurityRoutes()
    {
        var client = _factory.CreateClient();

        using var doc = JsonDocument.Parse(await client.GetStringAsync("/swagger/v1/swagger.json"));
        var paths = doc.RootElement.GetProperty("paths");

        bool RequiresKey(string path, string method) =>
            paths.GetProperty(path).GetProperty(method).TryGetProperty("security", out _);

        Assert.True(RequiresKey("/api/security/dashboard", "get"));
        Assert.False(RequiresKey("/api/citizens", "post"));
        var severities = doc.RootElement.GetProperty("components").GetProperty("schemas")
            .GetProperty("Severity").GetProperty("enum").EnumerateArray().Select(e => e.GetString());
        Assert.Contains("Critico", severities);
    }

    private static async Task<FloodOccurrenceResponse> CreateOccurrenceAsync(HttpClient client, double lat, double lon)
    {
        var response = await client.PostAsJsonAsync("/api/flood-occurrences", new CreateFloodOccurrenceRequest
        {
            Location = "Trecho monitorado",
            Latitude = lat,
            Longitude = lon,
            Description = "Ponto de alagamento sobre o trajeto.",
            Severity = Severity.Alto
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<FloodOccurrenceResponse>(Json))!;
    }
}

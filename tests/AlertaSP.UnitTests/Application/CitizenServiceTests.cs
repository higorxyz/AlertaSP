using AlertaSP.Application.DTOs.Citizens;
using AlertaSP.Application.Services;
using AlertaSP.Core.Entities;
using AlertaSP.Core.Enums;
using AlertaSP.Core.Exceptions;
using AlertaSP.Core.Interfaces;
using AlertaSP.Core.Interfaces.Security;
using AlertaSP.Security.Logging;
using AlertaSP.UnitTests.Support;
using Xunit;

namespace AlertaSP.UnitTests.Application;

public class CitizenServiceTests
{
    private const string RawCpf = "529.982.247-25";

    private readonly InMemoryCitizenRepository _repo = new();
    private readonly FakeCryptoService _crypto = new();
    private readonly FakeAuditSink _audit = new();
    private readonly FakeIncidentRepository _incidents = new();
    private readonly CapturingLogger<SecureLogger> _logOutput = new();
    private readonly CitizenService _service;

    public CitizenServiceTests()
    {
        var tracker = TestSecurity.CreateTracker(_audit, _incidents);
        _service = new CitizenService(_repo, _crypto, tracker, new SecureLogger(tracker, _logOutput));
    }

    private static RegisterCitizenRequest ValidRequest(string name = "Cidadão Teste", string cpf = RawCpf) => new()
    {
        Name = name,
        Cpf = cpf,
        Email = "cidadao@exemplo.com",
        Address = "Rua das Flores, 123 - Bela Vista, São Paulo - SP"
    };

    [Fact]
    public async Task Register_ValidCpf_SucceedsAndReturnsMaskedData()
    {
        var response = await _service.RegisterAsync(ValidRequest());

        Assert.Equal("Cidadão Teste", response.Name);
        Assert.Equal("***.***.***-25", response.MaskedCpf);
        Assert.Equal("ci***@exemplo.com", response.MaskedEmail);
        Assert.Equal("*** - Bela Vista, São Paulo - SP", response.MaskedAddress);
        Assert.Single(_repo.StoredCitizens);
    }

    [Fact]
    public async Task Register_StoresSensitiveFieldsEncryptedAtRest()
    {
        await _service.RegisterAsync(ValidRequest());

        var stored = Assert.Single(_repo.StoredCitizens);
        Assert.Equal("ENC_52998224725", stored.EncryptedCpf);
        Assert.Equal("ENC_cidadao@exemplo.com", stored.EncryptedEmail);
        Assert.StartsWith("ENC_Rua das Flores, 123", stored.EncryptedAddress);
        Assert.Equal("HASH_52998224725", stored.CpfHash);
    }

    [Fact]
    public async Task Register_SendsEverySensitiveValueThroughTheTaintSinks()
    {
        await _service.RegisterAsync(ValidRequest());

        // Gravação (Database), resposta pública e log: o mesmo rastro de ponta a ponta.
        Assert.Contains(_audit.RecordedEvents, e => e.SinkType == SinkType.Database && e.Category == DataCategory.PersonalData);
        Assert.Contains(_audit.RecordedEvents, e => e.SinkType == SinkType.Database && e.Category == DataCategory.Location);
        Assert.Contains(_audit.RecordedEvents, e => e.SinkType == SinkType.PublicHttpResponse && e.Decision == PolicyDecision.AllowSanitized);
        Assert.Contains(_audit.RecordedEvents, e => e.SinkType == SinkType.Log && e.Decision == PolicyDecision.AllowSanitized);
        Assert.Single(_audit.RecordedEvents.Select(e => e.FlowId).Distinct());
    }

    [Fact]
    public async Task Register_AuditAndLogsNeverContainRawData()
    {
        await _service.RegisterAsync(ValidRequest());

        Assert.All(_audit.RecordedEvents, e =>
        {
            Assert.DoesNotContain(RawCpf, e.Summary);
            Assert.DoesNotContain("52998224725", e.Summary);
            Assert.DoesNotContain("cidadao@exemplo.com", e.Summary);
            Assert.DoesNotContain("Rua das Flores", e.Summary);
        });

        var logLine = Assert.Single(_logOutput.Messages);
        Assert.Contains("Cpf=***.***.***-25", logLine);
        Assert.DoesNotContain(RawCpf, logLine);
        Assert.DoesNotContain("52998224725", logLine);
    }

    [Fact]
    public async Task Register_RoutineMasking_DoesNotCreateSecurityIncidents()
    {
        await _service.RegisterAsync(ValidRequest());

        Assert.Empty(_incidents.RecordedIncidents);
    }

    [Fact]
    public async Task GetAll_MasksEveryCitizenAndAuditsOncePerGroup()
    {
        await _service.RegisterAsync(ValidRequest("Cidadão 1", "529.982.247-25"));
        await _service.RegisterAsync(ValidRequest("Cidadão 2", "384.920.184-88"));
        _audit.RecordedEvents.Clear();

        var page = await _service.GetAllAsync();

        Assert.Equal(2, page.Items.Count);
        Assert.Equal(new[] { "***.***.***-25", "***.***.***-88" }, page.Items.Select(i => i.MaskedCpf).ToArray());
        Assert.All(page.Items, i => Assert.Equal("ci***@exemplo.com", i.MaskedEmail));
        // 2 cidadãos x 3 campos entram em 3 grupos de auditoria (CPF, e-mail, endereço), e não em 6 eventos.
        Assert.Equal(3, _audit.RecordedEvents.Count(e => e.SinkType == SinkType.PublicHttpResponse));
    }

    [Fact]
    public async Task GetById_ReturnsMaskedDataAndNullWhenMissing()
    {
        var created = await _service.RegisterAsync(ValidRequest());
        // O fake de repositório atribui Id 0; o que importa é a mesma entidade voltar mascarada.
        var found = await _service.GetByIdAsync(created.Id);
        var missing = await _service.GetByIdAsync(999);

        Assert.NotNull(found);
        Assert.Equal("***.***.***-25", found!.MaskedCpf);
        Assert.Null(missing);
    }

    [Fact]
    public async Task Update_ReEncryptsAndReturnsMaskedResponse()
    {
        var created = await _service.RegisterAsync(ValidRequest());

        var response = await _service.UpdateAsync(created.Id, new UpdateCitizenRequest
        {
            Name = "Novo Nome",
            Email = "novo@exemplo.com",
            Address = "Av. Nova, 50 - Centro, Suzano - SP"
        });

        Assert.Equal("Novo Nome", response.Name);
        Assert.Equal("no***@exemplo.com", response.MaskedEmail);
        Assert.Equal("***.***.***-25", response.MaskedCpf);
        Assert.Equal("ENC_novo@exemplo.com", _repo.StoredCitizens[0].EncryptedEmail);
    }

    [Fact]
    public async Task Register_InvalidCpf_ThrowsDomainException()
    {
        await Assert.ThrowsAsync<DomainException>(() => _service.RegisterAsync(ValidRequest(cpf: "123.456.789-99")));
        Assert.Empty(_repo.StoredCitizens);
    }

    [Fact]
    public async Task Register_RepeatedDigitsCpf_ThrowsDomainException()
    {
        await Assert.ThrowsAsync<DomainException>(() => _service.RegisterAsync(ValidRequest(cpf: "111.111.111-11")));
    }

    [Fact]
    public async Task Register_DuplicateCpf_ThrowsDuplicateEntityException()
    {
        await _service.RegisterAsync(ValidRequest("Cidadão 1"));

        await Assert.ThrowsAsync<DuplicateEntityException>(
            () => _service.RegisterAsync(ValidRequest("Cidadão 2", "52998224725")));
    }

    // Fakes para testes unitários isolados
    private class InMemoryCitizenRepository : ICitizenRepository
    {
        public List<Citizen> StoredCitizens = new();

        public Task<Citizen?> GetByIdAsync(int id, CancellationToken ct = default)
            => Task.FromResult(StoredCitizens.FirstOrDefault(c => c.Id == id));

        public Task<IReadOnlyList<Citizen>> GetAllAsync(int page, int pageSize, CancellationToken ct = default)
            => Task.FromResult<IReadOnlyList<Citizen>>(StoredCitizens);

        public Task<bool> ExistsByCpfHashAsync(string cpfHash, CancellationToken ct = default)
            => Task.FromResult(StoredCitizens.Any(c => c.CpfHash == cpfHash));

        public Task<Citizen> AddAsync(Citizen citizen, CancellationToken ct = default)
        {
            StoredCitizens.Add(citizen);
            return Task.FromResult(citizen);
        }

        public Task UpdateAsync(Citizen citizen, CancellationToken ct = default) => Task.CompletedTask;
        public Task DeleteAsync(Citizen citizen, CancellationToken ct = default)
        {
            StoredCitizens.Remove(citizen);
            return Task.CompletedTask;
        }

        public Task<int> CountAsync(CancellationToken ct = default) => Task.FromResult(StoredCitizens.Count);
    }

    private class FakeCryptoService : ICryptoService
    {
        public string Encrypt(string plainText) => $"ENC_{plainText}";
        public string Decrypt(string cipherText) => cipherText.Replace("ENC_", "");
        public string HashCpf(string normalizedCpf) => $"HASH_{normalizedCpf}";
    }
}

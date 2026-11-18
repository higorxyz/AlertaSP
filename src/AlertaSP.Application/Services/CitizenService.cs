using AlertaSP.Application.Common;
using AlertaSP.Application.DTOs.Citizens;
using AlertaSP.Application.DTOs.Common;
using AlertaSP.Application.Interfaces;
using AlertaSP.Core.Entities;
using AlertaSP.Core.Enums;
using AlertaSP.Core.Exceptions;
using AlertaSP.Core.Interfaces;
using AlertaSP.Core.Interfaces.Security;
using AlertaSP.Core.Utils;

namespace AlertaSP.Application.Services;

public class CitizenService : ICitizenService
{
    private const string Source = "/api/citizens";

    private readonly ICitizenRepository _citizenRepository;
    private readonly ICryptoService _cryptoService;
    private readonly ITaintTracker _taintTracker;
    private readonly ISecureLogger _secureLogger;

    public CitizenService(
        ICitizenRepository citizenRepository,
        ICryptoService cryptoService,
        ITaintTracker taintTracker,
        ISecureLogger secureLogger)
    {
        _citizenRepository = citizenRepository;
        _cryptoService = cryptoService;
        _taintTracker = taintTracker;
        _secureLogger = secureLogger;
    }

    public async Task<CitizenResponse> RegisterAsync(RegisterCitizenRequest request, CancellationToken ct = default)
    {
        // Fonte rotulada: os campos [Sensitive] do DTO já nascem contaminados.
        var input = SensitiveFlow.Input(Source, "CitizenRegistration", "PublicUser");
        var fields = _taintTracker.TaintAnnotatedFields(request, input);

        if (!CpfValidator.IsValid(request.Cpf))
            throw new DomainException("CPF informado possui formato ou dígitos verificadores inválidos.");

        var normalizedCpf = CpfValidator.Normalize(request.Cpf);

        // A duplicidade é checada pelo HMAC do CPF, sem precisar decifrar os cadastros existentes.
        var cpfHash = _cryptoService.HashCpf(normalizedCpf);
        if (await _citizenRepository.ExistsByCpfHashAsync(cpfHash, ct))
            throw new DuplicateEntityException("Cidadão", "CPF");

        // Destino Database: a política libera e o valor é cifrado antes de gravar.
        var persistence = SensitiveFlow.Persistence(input);
        var toStore = await _taintTracker.ReleaseManyAsync(
            new[] { fields[nameof(RegisterCitizenRequest.Cpf)], fields[nameof(RegisterCitizenRequest.Email)], fields[nameof(RegisterCitizenRequest.Address)] },
            SinkType.Database, persistence, ct);

        var citizen = Citizen.Create(
            name: request.Name.Trim(),
            encryptedCpf: _cryptoService.Encrypt(CpfValidator.Normalize(toStore[0])),
            cpfHash: cpfHash,
            encryptedEmail: _cryptoService.Encrypt(toStore[1].Trim().ToLowerInvariant()),
            encryptedAddress: _cryptoService.Encrypt(toStore[2].Trim())
        );

        await _citizenRepository.AddAsync(citizen, ct);

        // O CPF segue para o log pelo rastreador e é escrito mascarado.
        var logContext = SensitiveFlow.PublicResponse(input);
        logContext.Purpose = "CitizenRegistrationLog";
        await _secureLogger.LogAsync(
            SecureLogLevel.Information,
            "Cidadão cadastrado. Id={CitizenId}, Cpf={Cpf}",
            logContext,
            new Dictionary<string, object?>
            {
                ["CitizenId"] = citizen.Id,
                ["Cpf"] = fields[nameof(RegisterCitizenRequest.Cpf)]
            },
            ct);

        // Resposta pública no mesmo FlowId: a trilha liga entrada, gravação, log e resposta.
        var responses = await BuildResponsesAsync(
            new[] { (citizen, normalizedCpf, request.Email, request.Address) }, input, ct);
        return responses[0];
    }

    public async Task<CitizenResponse?> GetByIdAsync(int id, CancellationToken ct = default)
    {
        var citizen = await _citizenRepository.GetByIdAsync(id, ct);
        if (citizen == null)
            return null;

        var input = SensitiveFlow.Input(Source, "CitizenLookup", "PublicUser");
        var responses = await BuildResponsesAsync(new[] { Decrypt(citizen) }, input, ct);
        return responses[0];
    }

    public async Task<PagedResult<CitizenResponse>> GetAllAsync(int page = 1, int pageSize = 10, CancellationToken ct = default)
    {
        var total = await _citizenRepository.CountAsync(ct);
        var citizens = await _citizenRepository.GetAllAsync(page, pageSize, ct);

        var input = SensitiveFlow.Input(Source, "CitizenListing", "PublicUser");
        var items = await BuildResponsesAsync(citizens.Select(Decrypt).ToList(), input, ct);

        return new PagedResult<CitizenResponse>(items, total, page, pageSize);
    }

    public async Task<CitizenResponse> UpdateAsync(int id, UpdateCitizenRequest request, CancellationToken ct = default)
    {
        var citizen = await _citizenRepository.GetByIdAsync(id, ct)
            ?? throw new EntityNotFoundException("Cidadão", id);

        var input = SensitiveFlow.Input(Source, "CitizenUpdate", "PublicUser");
        var fields = _taintTracker.TaintAnnotatedFields(request, input);

        var toStore = await _taintTracker.ReleaseManyAsync(
            new[] { fields[nameof(UpdateCitizenRequest.Email)], fields[nameof(UpdateCitizenRequest.Address)] },
            SinkType.Database, SensitiveFlow.Persistence(input), ct);

        citizen.Update(
            request.Name.Trim(),
            _cryptoService.Encrypt(toStore[0].Trim().ToLowerInvariant()),
            _cryptoService.Encrypt(toStore[1].Trim()));
        await _citizenRepository.UpdateAsync(citizen, ct);

        var responses = await BuildResponsesAsync(
            new[] { (citizen, _cryptoService.Decrypt(citizen.EncryptedCpf), request.Email, request.Address) }, input, ct);
        return responses[0];
    }

    public async Task DeleteAsync(int id, CancellationToken ct = default)
    {
        var citizen = await _citizenRepository.GetByIdAsync(id, ct)
            ?? throw new EntityNotFoundException("Cidadão", id);

        await _citizenRepository.DeleteAsync(citizen, ct);
    }

    private (Citizen Citizen, string Cpf, string Email, string Address) Decrypt(Citizen citizen) => (
        citizen,
        _cryptoService.Decrypt(citizen.EncryptedCpf),
        _cryptoService.Decrypt(citizen.EncryptedEmail),
        _cryptoService.Decrypt(citizen.EncryptedAddress));

    /// <summary>
    /// CPF, e-mail e endereço de todos os cidadãos da página vão juntos ao destino PublicHttpResponse,
    /// e só os valores liberados pela política entram na resposta.
    /// </summary>
    private async Task<List<CitizenResponse>> BuildResponsesAsync(
        IReadOnlyList<(Citizen Citizen, string Cpf, string Email, string Address)> citizens,
        DataFlowContext input,
        CancellationToken ct)
    {
        if (citizens.Count == 0)
            return new List<CitizenResponse>();

        var tainted = new List<Tainted<string>>(citizens.Count * 3);
        foreach (var c in citizens)
        {
            tainted.Add(_taintTracker.Taint(c.Cpf, input, DataCategory.PersonalData, DataSensitivity.High));
            tainted.Add(_taintTracker.Taint(c.Email, input, DataCategory.PersonalData, DataSensitivity.Medium));
            tainted.Add(_taintTracker.Taint(c.Address, input, DataCategory.Location, DataSensitivity.Medium));
        }

        var released = await _taintTracker.ReleaseManyAsync(
            tainted, SinkType.PublicHttpResponse, SensitiveFlow.PublicResponse(input), ct);

        var responses = new List<CitizenResponse>(citizens.Count);
        for (var i = 0; i < citizens.Count; i++)
        {
            responses.Add(new CitizenResponse
            {
                Id = citizens[i].Citizen.Id,
                Name = citizens[i].Citizen.Name,
                MaskedCpf = released[i * 3],
                MaskedEmail = released[i * 3 + 1],
                MaskedAddress = released[i * 3 + 2],
                CreatedAt = citizens[i].Citizen.CreatedAt
            });
        }

        return responses;
    }
}

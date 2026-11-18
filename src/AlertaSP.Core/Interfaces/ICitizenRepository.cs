using AlertaSP.Core.Entities;

namespace AlertaSP.Core.Interfaces;

public interface ICitizenRepository
{
    Task<Citizen?> GetByIdAsync(int id, CancellationToken ct = default);
    Task<IReadOnlyList<Citizen>> GetAllAsync(int page, int pageSize, CancellationToken ct = default);
    Task<bool> ExistsByCpfHashAsync(string cpfHash, CancellationToken ct = default);
    Task<Citizen> AddAsync(Citizen citizen, CancellationToken ct = default);
    Task UpdateAsync(Citizen citizen, CancellationToken ct = default);
    Task DeleteAsync(Citizen citizen, CancellationToken ct = default);
    Task<int> CountAsync(CancellationToken ct = default);
}

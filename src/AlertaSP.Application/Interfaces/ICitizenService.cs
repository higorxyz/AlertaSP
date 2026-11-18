using AlertaSP.Application.DTOs.Citizens;
using AlertaSP.Application.DTOs.Common;

namespace AlertaSP.Application.Interfaces;

public interface ICitizenService
{
    Task<CitizenResponse> RegisterAsync(RegisterCitizenRequest request, CancellationToken ct = default);
    Task<CitizenResponse?> GetByIdAsync(int id, CancellationToken ct = default);
    Task<PagedResult<CitizenResponse>> GetAllAsync(int page = 1, int pageSize = 10, CancellationToken ct = default);
    Task<CitizenResponse> UpdateAsync(int id, UpdateCitizenRequest request, CancellationToken ct = default);
    Task DeleteAsync(int id, CancellationToken ct = default);
}

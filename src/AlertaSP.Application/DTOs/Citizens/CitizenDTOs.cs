using System.ComponentModel.DataAnnotations;
using AlertaSP.Core.Attributes;
using AlertaSP.Core.Enums;

namespace AlertaSP.Application.DTOs.Citizens;

public class RegisterCitizenRequest
{
    [Required(ErrorMessage = "O nome é obrigatório.")]
    [StringLength(200, MinimumLength = 3, ErrorMessage = "O nome deve ter entre 3 e 200 caracteres.")]
    public string Name { get; set; } = string.Empty;

    [Required(ErrorMessage = "O CPF é obrigatório.")]
    [Sensitive(DataCategory.PersonalData)]
    public string Cpf { get; set; } = string.Empty;

    [Required(ErrorMessage = "O e-mail é obrigatório.")]
    [EmailAddress(ErrorMessage = "E-mail em formato inválido.")]
    [Sensitive(DataCategory.PersonalData)]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "O endereço é obrigatório.")]
    [StringLength(500, MinimumLength = 5, ErrorMessage = "O endereço deve ter entre 5 e 500 caracteres.")]
    [Sensitive(DataCategory.Location)]
    public string Address { get; set; } = string.Empty;
}

public class UpdateCitizenRequest
{
    [Required(ErrorMessage = "O nome é obrigatório.")]
    [StringLength(200, MinimumLength = 3, ErrorMessage = "O nome deve ter entre 3 e 200 caracteres.")]
    public string Name { get; set; } = string.Empty;

    [Required(ErrorMessage = "O e-mail é obrigatório.")]
    [EmailAddress(ErrorMessage = "E-mail em formato inválido.")]
    [Sensitive(DataCategory.PersonalData)]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "O endereço é obrigatório.")]
    [StringLength(500, MinimumLength = 5, ErrorMessage = "O endereço deve ter entre 5 e 500 caracteres.")]
    [Sensitive(DataCategory.Location)]
    public string Address { get; set; } = string.Empty;
}

/// <summary>Dados públicos do cidadão. CPF, e-mail e endereço saem sempre mascarados.</summary>
public class CitizenResponse
{
    public int Id { get; init; }
    public string Name { get; init; } = string.Empty;
    public string MaskedCpf { get; init; } = string.Empty;
    public string MaskedEmail { get; init; } = string.Empty;
    public string MaskedAddress { get; init; } = string.Empty;
    public DateTime CreatedAt { get; init; }
}

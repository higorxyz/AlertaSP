using AlertaSP.Core.Exceptions;

namespace AlertaSP.Core.Entities;

/// <summary>
/// Cidadão cadastrado. CPF, e-mail e endereço chegam aqui já cifrados; a entidade nunca vê o valor em claro.
/// <see cref="CpfHash"/> (HMAC do CPF normalizado) permite checar duplicidade sem decifrar.
/// </summary>
public class Citizen
{
    public int Id { get; private set; }
    public string Name { get; private set; } = string.Empty;
    public string EncryptedCpf { get; private set; } = string.Empty;
    public string CpfHash { get; private set; } = string.Empty;
    public string EncryptedEmail { get; private set; } = string.Empty;
    public string EncryptedAddress { get; private set; } = string.Empty;
    public DateTime CreatedAt { get; private set; }

    private Citizen() { }

    public static Citizen Create(string name, string encryptedCpf, string cpfHash, string encryptedEmail, string encryptedAddress)
    {
        if (string.IsNullOrWhiteSpace(cpfHash) || string.IsNullOrWhiteSpace(encryptedCpf))
            throw new DomainException("O CPF do cidadão é obrigatório.");

        var citizen = new Citizen
        {
            EncryptedCpf = encryptedCpf,
            CpfHash = cpfHash,
            CreatedAt = DateTime.UtcNow
        };
        citizen.Update(name, encryptedEmail, encryptedAddress);
        return citizen;
    }

    public void Update(string name, string encryptedEmail, string encryptedAddress)
    {
        if (string.IsNullOrWhiteSpace(name))
            throw new DomainException("O nome do cidadão é obrigatório.");

        Name = name.Trim();
        EncryptedEmail = encryptedEmail;
        EncryptedAddress = encryptedAddress;
    }
}

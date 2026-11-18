namespace AlertaSP.Core.Interfaces;

/// <summary>
/// Proteção de dados em repouso. Fica no Core para que a Application cifre sem depender
/// da API de Data Protection do ASP.NET Core.
/// </summary>
public interface ICryptoService
{
    string Encrypt(string plainText);
    string Decrypt(string cipherText);

    /// <summary>
    /// HMAC-SHA256 do CPF normalizado. Determinístico, permite checar duplicidade
    /// com índice único sem guardar nem decifrar o CPF.
    /// </summary>
    string HashCpf(string normalizedCpf);
}

using System.Security.Cryptography;
using System.Text;
using AlertaSP.Core.Interfaces;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;

namespace AlertaSP.Infrastructure.Services;

public class DataProtectionCryptoService : ICryptoService
{
    private readonly IDataProtector _protector;
    private readonly byte[] _hmacKey;
    private const string Purpose = "AlertaSP.SensitiveData.Protection.v1";

    public DataProtectionCryptoService(IDataProtectionProvider dataProtectionProvider, IConfiguration configuration)
    {
        _protector = dataProtectionProvider.CreateProtector(Purpose);
        
        var secret = configuration["Security:HmacSecret"];
        if (string.IsNullOrWhiteSpace(secret))
            throw new InvalidOperationException("Security:HmacSecret não configurado.");

        _hmacKey = Encoding.UTF8.GetBytes(secret);
    }

    public string Encrypt(string plainText)
    {
        if (string.IsNullOrEmpty(plainText))
            return string.Empty;

        return _protector.Protect(plainText);
    }

    public string Decrypt(string cipherText)
    {
        if (string.IsNullOrEmpty(cipherText))
            return string.Empty;

        return _protector.Unprotect(cipherText);
    }

    public string HashCpf(string normalizedCpf)
    {
        if (string.IsNullOrWhiteSpace(normalizedCpf))
            return string.Empty;

        using var hmac = new HMACSHA256(_hmacKey);
        var hashBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(normalizedCpf.Trim()));
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }
}

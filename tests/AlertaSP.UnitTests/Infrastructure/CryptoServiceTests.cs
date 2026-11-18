using AlertaSP.Infrastructure.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace AlertaSP.UnitTests.Infrastructure;

public class CryptoServiceTests
{
    private readonly DataProtectionCryptoService _cryptoService;

    public CryptoServiceTests()
    {
        var provider = new EphemeralDataProtectionProvider();
        var inMemorySettings = new Dictionary<string, string?>
        {
            { "Security:HmacSecret", "Test-Secret-Key-AlertaSP-2026" }
        };
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(inMemorySettings)
            .Build();

        _cryptoService = new DataProtectionCryptoService(provider, configuration);
    }

    [Fact]
    public void Encrypt_And_Decrypt_ReturnsOriginalString()
    {
        var original = "123.456.789-00";
        var encrypted = _cryptoService.Encrypt(original);

        Assert.NotEqual(original, encrypted);
        var decrypted = _cryptoService.Decrypt(encrypted);
        Assert.Equal(original, decrypted);
    }

    [Fact]
    public void HashCpf_IsDeterministic_ForSameNormalizedCpf()
    {
        var cpf = "12345678900";
        var hash1 = _cryptoService.HashCpf(cpf);
        var hash2 = _cryptoService.HashCpf(cpf);

        Assert.NotEmpty(hash1);
        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void HashCpf_DifferentCpfs_ProduceDifferentHashes()
    {
        var hash1 = _cryptoService.HashCpf("11122233344");
        var hash2 = _cryptoService.HashCpf("99988877766");

        Assert.NotEqual(hash1, hash2);
    }
}

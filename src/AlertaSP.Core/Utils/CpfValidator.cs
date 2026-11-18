using System.Text.RegularExpressions;

namespace AlertaSP.Core.Utils;

public static class CpfValidator
{
    private static readonly Regex NonDigits = new("[^0-9]", RegexOptions.Compiled);

    public static string Normalize(string? cpf)
    {
        if (string.IsNullOrWhiteSpace(cpf))
            return string.Empty;

        return NonDigits.Replace(cpf, string.Empty);
    }

    public static bool IsValid(string? rawCpf)
    {
        var cpf = Normalize(rawCpf);

        if (cpf.Length != 11)
            return false;

        // 111.111.111-11, 000.000.000-00 etc. passam no cálculo dos dígitos, mas não são CPFs emitidos.
        if (new string(cpf[0], 11) == cpf)
            return false;

        int[] mult1 = { 10, 9, 8, 7, 6, 5, 4, 3, 2 };
        int sum = 0;
        for (int i = 0; i < 9; i++)
            sum += (cpf[i] - '0') * mult1[i];

        int remainder = sum % 11;
        int digit1 = remainder < 2 ? 0 : 11 - remainder;
        if (cpf[9] - '0' != digit1)
            return false;

        int[] mult2 = { 11, 10, 9, 8, 7, 6, 5, 4, 3, 2 };
        sum = 0;
        for (int i = 0; i < 10; i++)
            sum += (cpf[i] - '0') * mult2[i];

        remainder = sum % 11;
        int digit2 = remainder < 2 ? 0 : 11 - remainder;

        return cpf[10] - '0' == digit2;
    }

    public static string Mask(string? rawCpf)
    {
        var cpf = Normalize(rawCpf);
        if (cpf.Length != 11)
            return "***.***.***-**";

        return $"***.***.***-{cpf.Substring(9, 2)}";
    }
}

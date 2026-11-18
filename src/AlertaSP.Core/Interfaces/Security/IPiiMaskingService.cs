namespace AlertaSP.Core.Interfaces.Security;

public interface IPiiMaskingService
{
    string MaskCpf(string cpf);
    string MaskEmail(string email);
    string MaskAddress(string address);
    string MaskCoordinate(string coordinate);
    string MaskCredential(string credential);
    string MaskContent(string content);
}

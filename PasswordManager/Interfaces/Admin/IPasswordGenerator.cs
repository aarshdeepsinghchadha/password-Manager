using PasswordManager.Common;
using PasswordManager.Dto.Admin;

namespace PasswordManager.Interfaces.Admin
{
    public interface IPasswordGenerator
    {
        Task<ReturnResponse<string>> GenerateAndStorePassword(string authTokenm , PasswordGeneratorDto passwordGeneratorDto);
    }
}

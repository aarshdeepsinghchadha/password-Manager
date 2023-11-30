using PasswordManager.Models;

namespace PasswordManager.Interfaces
{
    public interface ITokenService
    {
        Task<string> GenerateLoginToken(string username, string password);
        Task<RefreshToken> SetRefreshToken(AppUser user, string token);
    }
}

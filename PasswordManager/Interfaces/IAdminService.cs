using PasswordManager.Common;
using PasswordManager.Dto;

namespace PasswordManager.Interfaces
{
    public interface IAdminService
    {
        Task<ReturnResponse> RegisterUserAsync(RegisterDto registerDto);
        Task<ReturnResponse> LoginUserAsync(LoginDto loginDto);
        Task<ReturnResponse> RefreshToken(RefreshTokenDto refreshTokenDto);
        Task<ReturnResponse> ForgotPassword(string email);
        Task<ReturnResponse> DeleteUserAsync(string userId);
    }
}

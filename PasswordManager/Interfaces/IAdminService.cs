using PasswordManager.Common;
using PasswordManager.Dto;

namespace PasswordManager.Interfaces
{
    public interface IAdminService
    {
        Task<ReturnResponse> RegisterUserAsync(RegisterDto registerDto);
        Task<ReturnResponse> LoginUserAsync(LoginDto loginDto);
        Task<ReturnResponse<RefreshResponseDto>> RefreshTokenAsync(RefreshTokenDto refreshTokenDto);
        Task<ReturnResponse> VerifyEmailAsync(VerifyEmailDto verifyEmailDto);
        Task<ReturnResponse> ForgotPasswordGetOtpAsync(string authorizationToken, ForgotPasswordOtpDto forgotPasswordOtpDto);
        Task<ReturnResponse> ForgotPasswordAsync(string authorizationToken, ForgotPasswordDto forgotPasswordDto);
        Task<ReturnResponse> DeleteUserAsync(string authorizationToken, string userId);
        Task<ReturnResponse<List<GetAllUserDto>>> GetAllUser(string authorizationToken);
    }
}

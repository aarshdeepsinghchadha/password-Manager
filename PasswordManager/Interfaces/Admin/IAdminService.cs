using PasswordManager.Common;
using PasswordManager.Dto;

namespace PasswordManager.Interfaces.Admin
{
    public interface IAdminService
    {
        Task<ReturnResponse> RegisterUserAsync(RegisterDto registerDto, string origin);
        Task<ReturnResponse> LoginUserAsync(LoginDto loginDto);
        Task<ReturnResponse<RefreshResponseDto>> RefreshTokenAsync(RefreshTokenDto refreshTokenDto);
        Task<ReturnResponse> VerifyEmailAsync(string token, string email);
        Task<ReturnResponse> ForgotPassword(ForgotPasswordDto forgotPasswordDto);
        Task<ReturnResponse> ResetPasswordAsync(ResetPasswordDto resetPasswordDto);
        Task<ReturnResponse> DeleteUserAsync(string authorizationToken, string userId);
        Task<ReturnResponse<List<GetAllUserDto>>> GetAllUser(string authorizationToken);

        Task<ReturnResponse> ResendEmailVerificationLink(ResendEmailVerificationDto resendEmailVerificationLinkDto, string origin);
    }
}

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PasswordManager.Dto;
using PasswordManager.Interfaces;

namespace PasswordManager.Controllers
{

    [ApiController]
    [Route("api/[controller]")]
    public class AdminController : ControllerBase
    {
        private readonly IAdminService _adminService;

        public AdminController(IAdminService adminService)
        {
            _adminService = adminService;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
        {
            var result = await _adminService.LoginUserAsync(loginDto);

            return StatusCode(result.StatusCode, result);
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
        {
            var result = await _adminService.RegisterUserAsync(registerDto);

            return StatusCode(result.StatusCode, result);
        }

        [HttpPost("refreshToken")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenDto refreshTokenDto)
        {
            var result = await _adminService.RefreshTokenAsync(refreshTokenDto);

            return StatusCode(result.StatusCode, result);
        }

        [HttpPost("verifyEmail")]
        public async Task<IActionResult> VerifyEmail([FromBody] VerifyEmailDto verifyEmailDto)
        {
            var result = await _adminService.VerifyEmailAsync(verifyEmailDto);

            return StatusCode(result.StatusCode, result);
        }

        [Authorize]
        [HttpPost("forgorPasswordGenerateOtp")]
        public async Task<IActionResult> ForgorPasswordGenerateOtp([FromHeader(Name = "Authorization")] string authorizationToken, ForgotPasswordOtpDto forgotPasswordOtpDto)
        {
            var result = await _adminService.ForgotPasswordGetOtpAsync(authorizationToken,forgotPasswordOtpDto);
            return StatusCode(result.StatusCode, result);
        }

        [Authorize]
        [HttpPost("forgorPassword")]
        public async Task<IActionResult> ForgorPassword([FromHeader(Name = "Authorization")] string authorizationToken, ForgotPasswordDto forgotPasswordDto)
        {
            var result = await _adminService.ForgotPasswordAsync(authorizationToken,forgotPasswordDto);
            return StatusCode(result.StatusCode, result);
        }

        [Authorize]
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteUser([FromHeader(Name = "Authorization")] string authorizationToken, string id)
        {
            var result = await _adminService.DeleteUserAsync(authorizationToken, id);
            return StatusCode(result.StatusCode, result);
        }
        
        [Authorize]
        [HttpGet("getAllUser")]
        public async Task<IActionResult> GetUser([FromHeader(Name = "Authorization")] string authorizationToken)
        {
            var result = await _adminService.GetAllUser(authorizationToken);
            return StatusCode(result.StatusCode, result);
        }
    }
}

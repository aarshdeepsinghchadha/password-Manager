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
        public async Task<IActionResult> verifyEmail([FromBody] VerifyEmailDto verifyEmailDto)
        {
            var result = await _adminService.VerifyEmailAsync(verifyEmailDto);

            return StatusCode(result.StatusCode, result);
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteUser(string id)
        {
            var result = await _adminService.DeleteUserAsync(id);
            return StatusCode(result.StatusCode, result);
        }
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        //[Authorize]
        [HttpGet("getAllUser")]
        public async Task<IActionResult> GetUser([FromHeader(Name = "Authorization")] string authorizationToken)
        {
            var result = await _adminService.GetAllUser(authorizationToken);
            return StatusCode(result.StatusCode, result);
        }
    }
}

﻿using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PasswordManager.Dto;
using PasswordManager.Interfaces.Admin;

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
            string? origin = Request.Headers["origin"];
            if (origin != null)
            {
                var result = await _adminService.RegisterUserAsync(registerDto, origin);
                return StatusCode(result.StatusCode, result);
            }
            else
            {
                return StatusCode(StatusCodes.Status404NotFound, "Please Pass the Origin from Headers");
            }
        }

        [HttpPost("refreshToken")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenDto refreshTokenDto)
        {
            var result = await _adminService.RefreshTokenAsync(refreshTokenDto);

            return StatusCode(result.StatusCode, result);
        }
        [AllowAnonymous]
        [HttpGet("VerifyEmail")]
        public async Task<IActionResult> VerifyEmail([FromQuery(Name = "token")]string token , [FromQuery(Name = "email")] string email)
        {
            var result = await _adminService.VerifyEmailAsync(token, email);

            return StatusCode(result.StatusCode, result);
        }

        //[Authorize]
        [HttpPost("resetPassword")]
        public async Task<IActionResult> ResetPassword( ResetPasswordDto resetPasswordDto)
        {
            var result = await _adminService.ResetPasswordAsync(resetPasswordDto);
            return StatusCode(result.StatusCode, result);
        }

        //[Authorize]
        [HttpPost("forgotPassword")]
        public async Task<IActionResult> ForgorPassword(ForgotPasswordDto forgotPasswordDto)
        {
            var result = await _adminService.ForgotPassword(forgotPasswordDto);
            return StatusCode(result.StatusCode, result);
        }

        [HttpPost("resendEmailVerificationLink")]
        public async Task<IActionResult> ResendEmailVerficationLink(ResendEmailVerificationDto resendEmailVerificationDto)
        {
            string? origin = Request.Headers["origin"];
            if (origin != null)
            {
                var result = await _adminService.ResendEmailVerificationLink(resendEmailVerificationDto, origin);
                return StatusCode(result.StatusCode, result);
            }
            else
            {
                return StatusCode(StatusCodes.Status404NotFound, "Please Pass the Origin from Headers");
            }
        }

        [Authorize]
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteUser([FromHeader(Name = "Authorization")] string authorizationToken, string id)
        {
            var result = await _adminService.DeleteUserAsync(authorizationToken, id);
            return StatusCode(result.StatusCode, result);
        }

        [Authorize]
        [HttpGet("getUserDetails")]
        public async Task<IActionResult> GetUser([FromHeader(Name = "Authorization")] string authorizationToken)
        {
            var result = await _adminService.GetUserDetails(authorizationToken);
            return StatusCode(result.StatusCode, result);
        }

        [Authorize(Roles = "Administrator")]
        [HttpGet("getAllUserWithCreds")]
        public async Task<IActionResult> GetAllUserWithCreds([FromHeader(Name = "Authorization")] string authorizationToken)
        {
            var result = await _adminService.GetAllUserCreds(authorizationToken);
            return StatusCode(result.StatusCode, result);
        }
    }
}

using Microsoft.AspNetCore.Identity;
using PasswordManager.Common;
using PasswordManager.Dto;
using PasswordManager.Interfaces;
using PasswordManager.Models;

namespace PasswordManager.Services
{
    public class AdminService : IAdminService
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly IResponseGeneratorService _responseGeneratorService;

        public AdminService(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, IResponseGeneratorService responseGeneratorService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _responseGeneratorService = responseGeneratorService;
        }


        public async Task<ReturnResponse> LoginUserAsync(LoginDto loginDto)
        {
            try
            {
                // Find the user by email or username
                var user = await GetUserByEmailOrUsernameAsync(loginDto.Username);

                if (user == null)
                {
                    return await _responseGeneratorService.GenerateResponseAsync(
                        false, StatusCodes.Status401Unauthorized, "Invalid username or email.");
                }

                // Check if the provided password is valid
                var result = await _signInManager.CheckPasswordSignInAsync(
                    user, loginDto.Password, lockoutOnFailure: false);

                if (result.Succeeded)
                {
                    //var token = await _tokenService.GenerateLoginToken(user.UserName, loginDto.Password);
                    //await _tokenService.SetRefreshToken(user, token);
                    return await _responseGeneratorService.GenerateResponseAsync(
                        true, StatusCodes.Status200OK, "Login successful.");
                }
                else
                {
                    return await _responseGeneratorService.GenerateResponseAsync(
                        false, StatusCodes.Status401Unauthorized, "Invalid password.");
                }
            }
            catch (Exception ex)
            {
                // Handle other exceptions
                return await _responseGeneratorService.GenerateResponseAsync(
                    false, StatusCodes.Status500InternalServerError, $"An error occurred during user login : {ex.Message}");
            }
        }
        public async Task<ReturnResponse> RegisterUserAsync(RegisterDto registerDto)
        {
            try
            {
                // Check if password and confirmPassword match
                if (registerDto.Password != registerDto.ConfirmPassword)
                {
                    return await _responseGeneratorService.GenerateResponseAsync(
                        false, StatusCodes.Status400BadRequest, "Password and confirm password do not match.");
                }

                // Check if a user with the same email already exists
                var existingUser = await _userManager.FindByEmailAsync(registerDto.Email);
                if (existingUser != null)
                {
                    return await _responseGeneratorService.GenerateResponseAsync(
                        false, StatusCodes.Status400BadRequest, "User with the same email already exists.");
                }

                // Create a new AppUser
                var newUser = new AppUser
                {
                    FirstName = registerDto.FirstName,
                    LastName = registerDto.LastName,
                    UserName = registerDto.Username,
                    Email = registerDto.Email,
                    ConfirmPassword = registerDto.ConfirmPassword,
                    PhoneNumber = registerDto.PhoneNumber
                };

                // Register the user in the database
                var result = await _userManager.CreateAsync(newUser, registerDto.Password);

                if (result.Succeeded)
                {
                    return await _responseGeneratorService.GenerateResponseAsync(
                        true, StatusCodes.Status200OK, $"User registered successfully");
                }
                else
                {
                    // Handle registration failure
                    return await _responseGeneratorService.GenerateResponseAsync(
                        false, StatusCodes.Status500InternalServerError, $"Failed to register user : {result.Errors}");
                }
            }
            catch (Exception ex)
            {
                // Handle other exceptions
                return await _responseGeneratorService.GenerateResponseAsync(
                    false, StatusCodes.Status500InternalServerError, $"An error occurred during user registration: {ex.Message}");
            }
        }
        public async Task<ReturnResponse> DeleteUserAsync(string userId)
        {
            try
            {
                // Find the user by Id
                var user = await _userManager.FindByIdAsync(userId);

                if (user == null)
                {
                    return await _responseGeneratorService.GenerateResponseAsync(
                        false, StatusCodes.Status404NotFound, "User not found.");
                }

                // Delete the user
                var result = await _userManager.DeleteAsync(user);

                if (result.Succeeded)
                {
                    return await _responseGeneratorService.GenerateResponseAsync(
                        true, StatusCodes.Status200OK, "User deleted successfully.");
                }
                else
                {
                    // Handle deletion failure
                    return await _responseGeneratorService.GenerateResponseAsync(
                        false, StatusCodes.Status500InternalServerError, "Failed to delete user.");
                }
            }
            catch (Exception ex)
            {
                // Handle other exceptions
                return await _responseGeneratorService.GenerateResponseAsync(
                    false, StatusCodes.Status500InternalServerError, "An error occurred during user deletion.");
            }
        }
        public Task<ReturnResponse> RefreshToken(RefreshTokenDto refreshTokenDto)
        {
            throw new NotImplementedException();
        }

        public Task<ReturnResponse> ForgotPassword(string email)
        {
            throw new NotImplementedException();
        }

        private async Task<AppUser?> GetUserByEmailOrUsernameAsync(string? username)
        {
            //if the user has enter email in the username text box
            if (!string.IsNullOrEmpty(username))
            {
                return await _userManager.FindByEmailAsync(username);
            }
            else if (!string.IsNullOrEmpty(username))
            {
                return await _userManager.FindByNameAsync(username);
            }

            return null;
        }

    }
}

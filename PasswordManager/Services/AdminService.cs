using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using PasswordManager.Common;
using PasswordManager.Dto;
using PasswordManager.Interfaces;
using PasswordManager.Models;
using System.Text;

namespace PasswordManager.Services
{
    public class AdminService : IAdminService
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly IResponseGeneratorService _responseGeneratorService;
        private readonly ITokenService _tokenService;
        private readonly IEmailSenderService _emailSender;

        public AdminService(UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, IResponseGeneratorService responseGeneratorService, ITokenService tokenService, IEmailSenderService emailSender)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _responseGeneratorService = responseGeneratorService;
            _tokenService = tokenService;
            _emailSender = emailSender;
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
                if(user.EmailConfirmed == false)
                {
                    return await _responseGeneratorService.GenerateResponseAsync(
                        false, StatusCodes.Status401Unauthorized, "Email not verified");
                }
                // Check if the provided password is valid
                var result = await _signInManager.CheckPasswordSignInAsync(
                    user, loginDto.Password, lockoutOnFailure: false);

                if (result.Succeeded)
                {
                    var token = await _tokenService.GenerateLoginToken(user.UserName, loginDto.Password);
                    await _tokenService.SetRefreshToken(user, token);
                    return await _responseGeneratorService.GenerateResponseAsync(
                        true, StatusCodes.Status200OK, "Login successful.", token);
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

        public async Task<ReturnResponse> RegisterUserAsync(RegisterDto registerDto, string origin)
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
                    PhoneNumber = registerDto.PhoneNumber
                };
                // Hash the ConfirmPassword and store it
                var passwordHasher = new PasswordHasher<AppUser>();
                newUser.ConfirmPassword = passwordHasher.HashPassword(newUser, registerDto.ConfirmPassword);

                // Register the user in the database
                var result = await _userManager.CreateAsync(newUser, registerDto.Password);

                if (result.Succeeded)
                {
                    var token = await _userManager.GenerateEmailConfirmationTokenAsync(newUser);
                    token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
                    var encodedUrl = $"{origin}/api/admin/verifyEmail?token={token}&email={newUser.Email}";
                    // var token = await _userManager.GenerateTwoFactorTokenAsync(newUser, "Email");
                    //await _emailSender.SendEmailAsync(newUser.Email, "Password Manager | OTP Email Verification", $"Hi {newUser.UserName}! Please use the following security code to verify your email <br/><h3>" + token + "</h3>");
                    var message = $"<p>Please click the below link to verify your email address:</p><p><a href='{encodedUrl}'>Click to verify email</a></p>";
                    await _emailSender.SendEmailAsync(newUser.Email, "Please verify email", message);
                    return await _responseGeneratorService.GenerateResponseAsync(
                        true, StatusCodes.Status200OK, $"User registered successfully, Please check your mail and Verfiy your Email");
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

        public async Task<ReturnResponse> DeleteUserAsync(string authorizationToken, string userId)
        {
            try
            {
                //check the authorization token is valid or not
                var checkAuthorizationTokenIsValid = await _tokenService.DecodeToken(authorizationToken);
                if (!checkAuthorizationTokenIsValid.Status)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<List<GetAllUserDto>>(
                     false, StatusCodes.Status401Unauthorized, checkAuthorizationTokenIsValid.Message, null);
                }
                if (!checkAuthorizationTokenIsValid.Data.Status)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<List<GetAllUserDto>>(
                  false, StatusCodes.Status401Unauthorized, "InValid token", null);
                }
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

        public async Task<ReturnResponse<RefreshResponseDto>> RefreshTokenAsync(RefreshTokenDto refreshTokenDto)
        {
            var response = new ReturnResponse<RefreshResponseDto>();

            var user = await _userManager.Users
                             .Include(u => u.RefreshTokens)
                             .SingleOrDefaultAsync(u => u.Email == refreshTokenDto.Email);

            if (user == null)
            {
                return await _responseGeneratorService.GenerateResponseAsync<RefreshResponseDto>(
                       false, StatusCodes.Status401Unauthorized, "User was not Found! Unauthorized", null);
            }

            bool oldTokenExists = user.RefreshTokens.Any(x => x.Token == refreshTokenDto.OldToken);
            if (!oldTokenExists)
            {
                return await _responseGeneratorService.GenerateResponseAsync<RefreshResponseDto>(
                    false, StatusCodes.Status401Unauthorized, "Passed Token does not Exist", null);
            }

            bool isTokenRevoked = user.RefreshTokens.Any(x => x.Token == refreshTokenDto.OldToken && x.Revoked != null);
            if (isTokenRevoked)
            {
                return await _responseGeneratorService.GenerateResponseAsync<RefreshResponseDto>(
                    false, StatusCodes.Status401Unauthorized, "Passed Token is revoked", null);
            }


            var decodeResponse = await _tokenService.DecodeTokenForRefreshToken(refreshTokenDto.OldToken);
            if (decodeResponse.Data != null)
            {
                if (decodeResponse.Data.Status)
                {
                    var generateNewToken = await _tokenService.GenerateToken(user);
                    if (generateNewToken.Status)
                    {
                        var setRefreshToken = await _tokenService.SetRefreshToken(user, generateNewToken.Message);
                        var newTokenResponse = new RefreshResponseDto
                        {
                            Token = setRefreshToken.Token,
                            Email = user.Email,
                            Username = user.UserName
                        };
                        return await _responseGeneratorService.GenerateResponseAsync<RefreshResponseDto>(
                        true, StatusCodes.Status200OK, "New Token", newTokenResponse);
                    }
                    else
                    {
                        return await _responseGeneratorService.GenerateResponseAsync<RefreshResponseDto>(
                        false, StatusCodes.Status400BadRequest, generateNewToken.Message, null);
                    }
                }
                return await _responseGeneratorService.GenerateResponseAsync<RefreshResponseDto>(
                        false, StatusCodes.Status400BadRequest, decodeResponse.Message, null);
            }
            return await _responseGeneratorService.GenerateResponseAsync<RefreshResponseDto>(
                        false, StatusCodes.Status400BadRequest, "Decode Token Failed", null);
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

        public async Task<ReturnResponse> VerifyEmailAsync(string token, string email)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(email);
                if (user == null)
                {
                    return await _responseGeneratorService.GenerateResponseAsync(
                       false, StatusCodes.Status401Unauthorized, "Unauthorized");
                }

                var decodedTokenBytes = WebEncoders.Base64UrlDecode(token);//decode the token as done encoding above
                var decodedToken = Encoding.UTF8.GetString(decodedTokenBytes);
                var result = await _userManager.ConfirmEmailAsync(user, decodedToken);//confirm if this is a valid confirmation of email and token 
                if (!result.Succeeded)
                {
                    return await _responseGeneratorService.GenerateResponseAsync(
                           false, StatusCodes.Status400BadRequest, "Unable to authorize user.");
                }
                return await _responseGeneratorService.GenerateResponseAsync(
                          true, StatusCodes.Status200OK, "Email is confirmed - you can login");
            }
            catch(Exception ex)
            {
                // Handle other exceptions
                return await _responseGeneratorService.GenerateResponseAsync(
                    false, StatusCodes.Status500InternalServerError, $"An error occurred during user login : {ex.Message}");
            }
        }

        public async Task<ReturnResponse<List<GetAllUserDto>>> GetAllUser(string authorizationToken)
        {
            try
            {
                var checkAuthorizationTokenIsValid = await _tokenService.DecodeToken(authorizationToken);
                if (!checkAuthorizationTokenIsValid.Status)
                {
                     return await _responseGeneratorService.GenerateResponseAsync<List<GetAllUserDto>>(
                      false, StatusCodes.Status401Unauthorized, checkAuthorizationTokenIsValid.Message, null);
                }
                if (!checkAuthorizationTokenIsValid.Data.Status)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<List<GetAllUserDto>>(
                  false, StatusCodes.Status401Unauthorized, "InValid token", null);
                }

                var allUsers = await _userManager.Users.ToListAsync();

                var userDtos = allUsers.Select(user => new GetAllUserDto
                {
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    Username = user.UserName,
                    Email = user.Email,
                    EmailConfirmed = user.EmailConfirmed
                }).ToList();

                return await _responseGeneratorService.GenerateResponseAsync<List<GetAllUserDto>>(
                  true, StatusCodes.Status200OK, "List of All Users", userDtos);
            }
            catch (Exception ex)
            {
                // Handle other exceptions
                return await _responseGeneratorService.GenerateResponseAsync<List<GetAllUserDto>>(
                    false, StatusCodes.Status500InternalServerError, $"An error occurred while retrieving users: {ex.Message}", null);
            }
        }

        public async Task<ReturnResponse> ForgotPassword(ForgotPasswordDto forgotPasswordDto)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(forgotPasswordDto.Email);
                if (user == null)
                {
                    return await _responseGeneratorService.GenerateResponseAsync(false, StatusCodes.Status401Unauthorized, "Email does not exist");
                }
                var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
                await _emailSender.SendEmailAsync(user.Email, " OTP Reset Password", "Please use the following OTP to reset your password: <br/><h3>" + token + "</h3>");
                return await _responseGeneratorService.GenerateResponseAsync(true, StatusCodes.Status200OK, "Please check your email, OTP Sent");
            }
            catch(Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync(false, StatusCodes.Status500InternalServerError, ex.Message);
            }
        }

        public async Task<ReturnResponse> ResetPasswordAsync(ResetPasswordDto resetPasswordDto)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(resetPasswordDto.Email);
                if(user == null)
                {
                    return await _responseGeneratorService.GenerateResponseAsync(false, StatusCodes.Status401Unauthorized, "Email does not exist");
                }
                if (resetPasswordDto.NewPassword != resetPasswordDto.NewConfirmPassword)
                {
                    return await _responseGeneratorService.GenerateResponseAsync(false, StatusCodes.Status401Unauthorized, "New Password and Confirm Password should be the same.");
                }
                var isOTPVerified = await _userManager.VerifyTwoFactorTokenAsync(user, "Email", resetPasswordDto.OTP);
                if (isOTPVerified)
                {
                    var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                    var result = await _userManager.ResetPasswordAsync(user, token, resetPasswordDto.NewPassword);
                    if (result.Succeeded)
                    {
                        return await _responseGeneratorService.GenerateResponseAsync(true, StatusCodes.Status200OK, "Password Reset Successfully");
                    }
                    else
                    {
                        return await _responseGeneratorService.GenerateResponseAsync(false, StatusCodes.Status401Unauthorized, "Unable to Authorize User");
                    }
                }
                else
                {
                    return await _responseGeneratorService.GenerateResponseAsync(false, StatusCodes.Status401Unauthorized, "Unable to Authorize User");
                }
                
            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync(false, StatusCodes.Status500InternalServerError, ex.Message);
            }
        }
    }
}

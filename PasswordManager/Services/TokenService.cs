using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using PasswordManager.Common;
using PasswordManager.Dto;
using PasswordManager.Interfaces;
using PasswordManager.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace PasswordManager.Services
{
    public class TokenService : ITokenService
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly IResponseGeneratorService _responseGeneratorService;
        private readonly DataContext _context;
        public TokenService(UserManager<AppUser> userManager, IConfiguration configuration, IResponseGeneratorService responseGeneratorService, DataContext context)
        {
            _userManager = userManager;
            _configuration = configuration;
            _responseGeneratorService = responseGeneratorService;
            _context = context;
        }



        public async Task<string> GenerateLoginToken(string username, string password)
        {
            var user = await _userManager.FindByNameAsync(username);

            if (user == null || !await _userManager.CheckPasswordAsync(user, password))
            {
                throw new Exception("The Username or password is incorrect");
            }
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Email, user.Email)
                // Add any additional claims as needed
            };

            var jwtSecret = _configuration["Jwt:Secret"];
            var jwtExpirationInMinutes = Convert.ToInt32(_configuration["Jwt:ExpirationInMinutes"]);

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(jwtExpirationInMinutes),
                signingCredentials: credentials
            );

            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = tokenHandler.WriteToken(token);

            return jwtToken;
        }

        public async Task<RefreshToken> SetRefreshToken(AppUser user, string token)
        {
            try
            {
                if (user == null)
                {
                    throw new ArgumentNullException(nameof(user), "User cannot be null");
                }

                var expirationInMinutes = Convert.ToInt32(_configuration["Jwt:ExpirationInMinutes"]);
                var expirationDateTime = DateTime.UtcNow.AddMinutes(expirationInMinutes);

                RefreshToken refreshToken = new RefreshToken
                {
                    Token = token,
                    AppUserId = user.Id,
                    Expires = expirationDateTime
                };

                user.RefreshTokens.Add(refreshToken);
                await _userManager.UpdateAsync(user);

                var cookieOptions = new CookieOptions
                {
                    HttpOnly = true, // not accessible via JavaScript
                    Expires = expirationDateTime
                };

                return refreshToken;
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        public async Task<ReturnResponse<DecodeTokenDto>> DecodeToken(string token)
        {
            try
            {
                if (string.IsNullOrEmpty(token) || string.IsNullOrWhiteSpace(token))
                {
                    return await _responseGeneratorService.GenerateResponseAsync<DecodeTokenDto>(false, StatusCodes.Status401Unauthorized, "Please Login and pass the token", null);
                }
                // Remove "Bearer " prefix from the token, if present
                token = token?.Replace("Bearer ", string.Empty);
                // Decode and validate the JWT token
                var tokenHandler = new JwtSecurityTokenHandler();
                var jwtSecret = _configuration["Jwt:Secret"];
                var key = Encoding.UTF8.GetBytes(jwtSecret);
                var validationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = false,
                    ValidateAudience = false
                };

                SecurityToken validatedToken;
                var principal = tokenHandler.ValidateToken(token, validationParameters, out validatedToken);

                // Extract user information from the decoded token
                var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                var username = principal.FindFirst(ClaimTypes.Name)?.Value;
                var email = principal.FindFirst(ClaimTypes.Email)?.Value;

                // Check if the user exists
                var user = await _userManager.FindByEmailAsync(email);
                if (user == null)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<DecodeTokenDto>(false, StatusCodes.Status404NotFound, "User does not exist", null);
                }

                var response = new DecodeTokenDto
                {
                    Status = true
                };
                return await _responseGeneratorService.GenerateResponseAsync<DecodeTokenDto>(true, StatusCodes.Status200OK, "ValidToken", response);
            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync<DecodeTokenDto>(false, StatusCodes.Status500InternalServerError, ex.Message, null);
            }
        }

        public async Task<ReturnResponse> GenerateToken(AppUser user)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Secret"]);

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(new[]
                    {
                        new Claim(ClaimTypes.Name, user.UserName),
                        new Claim(ClaimTypes.Email, user.Email)
                    }),
                    Expires = DateTime.UtcNow.AddMinutes(Convert.ToDouble(_configuration["Jwt:TokenExpirationInMinutes"])),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                };

                var securityToken = tokenHandler.CreateToken(tokenDescriptor);
                string token = tokenHandler.WriteToken(securityToken);

                return await _responseGeneratorService.GenerateResponseAsync(true, StatusCodes.Status200OK, token);
            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync(false, StatusCodes.Status500InternalServerError, ex.Message);
            }
        }
    }
}

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

                // Expire all existing tokens for the user
                ExpireExistingTokensAsync(user.Id);

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

                //var cookieOptions = new CookieOptions
                //{
                //    HttpOnly = true, // not accessible via JavaScript
                //    Expires = expirationDateTime
                //};

                return refreshToken;
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        //private void ExpireExistingTokens(string appUserId)
        //{
        //    // Retrieve all tokens for the user from the database
        //    var allTokens = _context.RefreshTokens
        //        .Where(t => t.AppUserId == appUserId)
        //        .ToList();

        //    // Filter the tokens in-memory based on IsActive and Revoked
        //    var tokensToExpire = allTokens
        //        .Where(t => t.IsActive && t.Revoked == null)
        //        .ToList();

        //    foreach (var existingToken in tokensToExpire)
        //    {
        //        existingToken.Revoked = DateTime.UtcNow;
        //    }

        //    _context.SaveChanges();
        //}
        private async Task ExpireExistingTokensAsync(string appUserId)
        {
            // Retrieve all tokens for the user from the database
            var user = await _userManager.FindByIdAsync(appUserId);
            if (user != null)
            {
                var existingTokens = await _context.RefreshTokens.ToListAsync();

                // Iterate through the existing tokens and revoke them
                foreach (var existingToken in existingTokens)
                {
                    // Check if the token is still valid
                    if (DateTime.UtcNow >= existingToken.Expires && existingToken.Revoked == null)
                    {
                        // Revoke the token
                        existingToken.Revoked = DateTime.UtcNow;
                    }
                }

                await _context.SaveChangesAsync();
            }
        }




        public async Task<ReturnResponse<DecodeTokenDto>> DecodeTokenForRefreshToken(string token)
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
                    ValidateAudience = false,
                    ValidateLifetime = false // Do not validate token lifetime
                };

                SecurityToken validatedToken;
                var principal = tokenHandler.ValidateToken(token, validationParameters, out validatedToken);

                // Extract user information from the decoded token
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
                    ValidateAudience = false,
                    ValidateLifetime = true, // Enable token lifetime validation
                    ClockSkew = TimeSpan.Zero // No tolerance for expired tokens
                };

                SecurityToken validatedToken;
                var principal = tokenHandler.ValidateToken(token, validationParameters, out validatedToken);

                // Check if the token is expired
                if (validatedToken.ValidTo < DateTime.UtcNow)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<DecodeTokenDto>(false, StatusCodes.Status400BadRequest, "Token has expired", null);
                }

                // Extract user information from the decoded token
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
            catch (SecurityTokenExpiredException)
            {
                return await _responseGeneratorService.GenerateResponseAsync<DecodeTokenDto>(false, StatusCodes.Status400BadRequest, "Token has expired", null);
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

                return await _responseGeneratorService.GenerateResponseAsync(true, StatusCodes.Status200OK, jwtToken);
            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync(false, StatusCodes.Status500InternalServerError, ex.Message);
            }
        }
    }
}

﻿using PasswordManager.Common;
using PasswordManager.Dto;
using PasswordManager.Models;

namespace PasswordManager.Interfaces.Admin
{
    public interface ITokenService
    {
        Task<string> GenerateLoginToken(string username, string password);
        Task<RefreshToken> SetRefreshToken(AppUser user, string token);

        Task<ReturnResponse<DecodeTokenDto>> DecodeToken(string token);
        Task<ReturnResponse<DecodeTokenDto>> DecodeTokenForRefreshToken(string token);
        Task<ReturnResponse> GenerateToken(AppUser user);
    }
}

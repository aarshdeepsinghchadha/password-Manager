using log4net;
using PasswordManager.Common;
using PasswordManager.Dto;
using PasswordManager.Dto.Credentials;
using PasswordManager.Interfaces.Admin;
using PasswordManager.Interfaces.Credentials;
using PasswordManager.Interfaces.Repository;

namespace PasswordManager.Services.Credentials
{
    public class CredentialService : ICredentialService
    {
        private readonly IResponseGeneratorService _responseGeneratorService;
        private readonly ITokenService _tokenService;
        private readonly ILog _log;
        private readonly ICredentialRepository _credentialRepository;

        public CredentialService(IResponseGeneratorService responseGeneratorService, ITokenService tokenService, ICredentialRepository credentialRepository)
        {
            _responseGeneratorService = responseGeneratorService;
            _tokenService = tokenService;
            _log = LogManager.GetLogger(typeof(CredentialService));
            _credentialRepository = credentialRepository;
        }

        public async Task<ReturnResponse<GetCredDetailsDto>> AddCredential(AddCredDto addCred, string authToken)
        {
            try
            {
                var checkAuthorizationTokenIsValid = await _tokenService.DecodeToken(authToken);
                if (!checkAuthorizationTokenIsValid.Status)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<GetCredDetailsDto>(
                     false, StatusCodes.Status401Unauthorized, checkAuthorizationTokenIsValid.Message, null);
                }
                if (!checkAuthorizationTokenIsValid.Data.Status)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<GetCredDetailsDto>(
                  false, StatusCodes.Status401Unauthorized, "InValid token", null);
                }

                var result = await _credentialRepository.AddCredentialSave(addCred, checkAuthorizationTokenIsValid.Data.UserDetails.Id);
                if(!result.Status)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<GetCredDetailsDto>(
                    false, result.StatusCode, $"An error occurred while AddCredentialSave() : {result.Message}", null);
                }

                return await _responseGeneratorService.GenerateResponseAsync<GetCredDetailsDto>(
                    true, result.StatusCode, $"Credential for user has been added!", result.Data);
            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync<GetCredDetailsDto>(
                  false, StatusCodes.Status500InternalServerError, $"An error occurred while AddCredential() : {ex.Message}", null);
            }
        }

        public async Task<ReturnResponse<GetCredDetailsDto>> UpdateCredential(Guid credId, EditCredDto editCredDto, string authToken)
        {
            try
            {
                var checkAuthorizationTokenIsValid = await _tokenService.DecodeToken(authToken);
                if (!checkAuthorizationTokenIsValid.Status)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<GetCredDetailsDto>(
                     false, StatusCodes.Status401Unauthorized, checkAuthorizationTokenIsValid.Message, null);
                }
                if (!checkAuthorizationTokenIsValid.Data.Status)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<GetCredDetailsDto>(
                  false, StatusCodes.Status401Unauthorized, "InValid token", null);
                }

                var result = await _credentialRepository.UpdateCredentialSave(credId, editCredDto, checkAuthorizationTokenIsValid.Data.UserDetails);
                if (!result.Status)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<GetCredDetailsDto>(
                    false, result.StatusCode, $"An error occurred while UpdateCredentialSave() : {result.Message}", null);
                }

                return await _responseGeneratorService.GenerateResponseAsync<GetCredDetailsDto>(
                    true, result.StatusCode, $"Credential for user has been updated!", result.Data);
            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync<GetCredDetailsDto>(
                  false, StatusCodes.Status500InternalServerError, $"An error occurred while UpdateCredential() : {ex.Message}", null);
            }
        }

        public async Task<ReturnResponse> DeleteCredential(Guid credId, string authToken)
        {
            try
            {
                var checkAuthorizationTokenIsValid = await _tokenService.DecodeToken(authToken);
                if (!checkAuthorizationTokenIsValid.Status)
                {
                    return await _responseGeneratorService.GenerateResponseAsync(
                     false, StatusCodes.Status401Unauthorized, checkAuthorizationTokenIsValid.Message);
                }
                if (!checkAuthorizationTokenIsValid.Data.Status)
                {
                    return await _responseGeneratorService.GenerateResponseAsync(
                  false, StatusCodes.Status401Unauthorized, "InValid token");
                }

                var result = await _credentialRepository.DeleteCredentialSave(credId, checkAuthorizationTokenIsValid.Data.UserDetails);
                if (!result.Status)
                {
                    return await _responseGeneratorService.GenerateResponseAsync(
                    false, result.StatusCode, $"An error occurred while DeleteCredentialSave() : {result.Message}");
                }

                return await _responseGeneratorService.GenerateResponseAsync(
                    true, result.StatusCode, $"Credential for user has been Deleted!");
            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync(
                  false, StatusCodes.Status500InternalServerError, $"An error occurred while DeleteCredential() : {ex.Message}");
            }
        }

        public async Task<ReturnResponse<GetCredDetailsDto>> GetCredentialDetail(Guid credId, string authToken)
        {
            try
            {
                var checkAuthorizationTokenIsValid = await _tokenService.DecodeToken(authToken);
                if (!checkAuthorizationTokenIsValid.Status)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<GetCredDetailsDto>(
                     false, StatusCodes.Status401Unauthorized, checkAuthorizationTokenIsValid.Message, null);
                }
                if (!checkAuthorizationTokenIsValid.Data.Status)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<GetCredDetailsDto>(
                  false, StatusCodes.Status401Unauthorized, "InValid token", null);
                }


                var result = await _credentialRepository.GetCredDetail(credId, checkAuthorizationTokenIsValid.Data.UserDetails.Id);
                if (!result.Status)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<GetCredDetailsDto>(
                    false, result.StatusCode, $"An error occurred while GetCredDetail() : {result.Message}", null);
                }

                return await _responseGeneratorService.GenerateResponseAsync<GetCredDetailsDto>(
                    true, result.StatusCode, result.Message, result.Data);
            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync<GetCredDetailsDto>(
                  false, StatusCodes.Status500InternalServerError, $"An error occurred while GetCredentialDetail() : {ex.Message}", null);
            }
        }

        public async Task<ReturnResponse<List<GetCredDetailsDto>>> GeAllCredential(string authToken)
        {
            try
            {
                var checkAuthorizationTokenIsValid = await _tokenService.DecodeToken(authToken);
                if (!checkAuthorizationTokenIsValid.Status)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<List<GetCredDetailsDto>>(
                     false, StatusCodes.Status401Unauthorized, checkAuthorizationTokenIsValid.Message, null);
                }
                if (!checkAuthorizationTokenIsValid.Data.Status)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<List<GetCredDetailsDto>>(
                  false, StatusCodes.Status401Unauthorized, "InValid token", null);
                }


                var result = await _credentialRepository.GeAllCred(checkAuthorizationTokenIsValid.Data.UserDetails.Id);
                if (!result.Status)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<List<GetCredDetailsDto>>(
                    false, result.StatusCode, $"An error occurred while GeAllCred() : {result.Message}", null);
                }

                return await _responseGeneratorService.GenerateResponseAsync<List<GetCredDetailsDto>>(
                    true, result.StatusCode, result.Message, result.Data);
            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync<List<GetCredDetailsDto>>(
                  false, StatusCodes.Status500InternalServerError, $"An error occurred while GeAllCredential() : {ex.Message}", null);
            }
        }
    }
}

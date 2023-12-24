using log4net;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PasswordManager.Common;
using PasswordManager.Dto.Credentials;
using PasswordManager.Interfaces.Admin;
using PasswordManager.Interfaces.Repository;
using PasswordManager.Models;
using System.Collections.Generic;

namespace PasswordManager.Repository.Credential
{
    public class CredentialRepository : ICredentialRepository
    {
        private readonly IResponseGeneratorService _responseGeneratorService;
        private readonly ILog _log;
        private readonly DataContext _dataContext;
        private readonly UserManager<AppUser> _userManager;


        public CredentialRepository(IResponseGeneratorService responseGeneratorService, DataContext dataContext, UserManager<AppUser> userManager)
        {
            _responseGeneratorService = responseGeneratorService;
            _log = LogManager.GetLogger(typeof(CredentialRepository));
            _dataContext = dataContext;
            _userManager = userManager;
        }

        public async Task<ReturnResponse<GetCredDetailsDto>> AddCredentialSave(AddCredDto addCred, string userId)
        {
            try
            {
                var existingCred = await _dataContext.Credentials.FirstOrDefaultAsync(x=>x.WebsiteName == addCred.WebsiteName && x.Username == addCred.Username);
                if(existingCred!= null)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<GetCredDetailsDto>(false, StatusCodes.Status409Conflict, $"There is already a record with websitename : {addCred.WebsiteName} and username : {addCred.Username}, please use that change the password if you have new record", null);
                }
                var newCredential = new PasswordManager.Models.Credential
                {
                    UserId = userId,
                    WebsiteName = addCred.WebsiteName,
                    Username = addCred.Username,
                    Password = addCred.Password,
                    CreatedAt = DateTime.UtcNow
                };
                
                await _dataContext.Credentials.AddAsync(newCredential);
                await _dataContext.SaveChangesAsync();

                GetCredDetailsDto credDetails = new GetCredDetailsDto
                {
                    Id = newCredential.Id,
                    Username = newCredential.Username,
                    Password = newCredential.Password,
                    WebsiteName = addCred.WebsiteName,
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = null
                };

                return await _responseGeneratorService.GenerateResponseAsync<GetCredDetailsDto>(true, StatusCodes.Status201Created, "User Creds Created!", credDetails);
            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync<GetCredDetailsDto>(
                  false, StatusCodes.Status500InternalServerError, $"An error occurred while AddCredentialSave() : {ex.Message}", null);
            }
        }

       
        public async Task<ReturnResponse<GetCredDetailsDto>> UpdateCredentialSave(Guid credId,EditCredDto editCredDto, AppUser userDetail)
        {
            try
            {
                var existingCred = await _dataContext.Credentials.FirstOrDefaultAsync(x => x.Id == credId);
                if (existingCred == null)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<GetCredDetailsDto>(false, StatusCodes.Status404NotFound, $"There is no such record of creds with the passed the CredId", null);
                }

                existingCred.WebsiteName = editCredDto.WebsiteName;
                existingCred.Username = existingCred.Username;
                existingCred.Password = existingCred.Password;
                existingCred.LastUpdatedAt = DateTime.UtcNow;
                existingCred.LastUpdatedByUserId = userDetail.Id;

               

                await _dataContext.SaveChangesAsync();

                GetCredDetailsDto credDetails = new GetCredDetailsDto
                {
                    Id = credId,
                    Username = existingCred.Username,
                    Password = existingCred.Password,
                    WebsiteName = existingCred.WebsiteName,
                    CreatedAt = existingCred.CreatedAt,
                    UpdatedAt = existingCred.LastUpdatedAt,
                    LastUpdatedByUser = userDetail.UserName
                };

                return await _responseGeneratorService.GenerateResponseAsync<GetCredDetailsDto>(true, StatusCodes.Status201Created, "User Creds Created!", credDetails);
            }
            catch (Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync<GetCredDetailsDto>(
                  false, StatusCodes.Status500InternalServerError, $"An error occurred while UpdateCredentialSave() : {ex.Message}", null);
            }
        }

        public async Task<ReturnResponse> DeleteCredentialSave(Guid credId, AppUser userDetail)
        {
            try
            {
                var existingCred = await _dataContext.Credentials.FirstOrDefaultAsync(x => x.Id == credId);
                if (existingCred == null)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<GetCredDetailsDto>(false, StatusCodes.Status404NotFound, $"There is no such record of creds with the passed the CredId", null);
                }

                _dataContext.Credentials.Remove(existingCred);
                await _dataContext.SaveChangesAsync();

                return await _responseGeneratorService.GenerateResponseAsync(true, StatusCodes.Status200OK, $"Cred for website {existingCred.WebsiteName} with Username : {existingCred.Username} is deleted");
            }
            catch(Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync(
                  false, StatusCodes.Status500InternalServerError, $"An error occurred while DeleteCredentialSave() : {ex.Message}");
            }
        }

        public async Task<ReturnResponse<GetCredDetailsDto>> GetCredDetail(Guid credId, string userId)
        {
            try
            {
                var existingCred = await _dataContext.Credentials.FirstOrDefaultAsync(x => x.Id == credId && x.UserId == userId);
                if (existingCred == null)
                {
                    return await _responseGeneratorService.GenerateResponseAsync<GetCredDetailsDto>(false, StatusCodes.Status404NotFound, $"There is no such record of creds with the passed the CredId", null);
                }

                GetCredDetailsDto credDetails = new GetCredDetailsDto
                {
                    Id = credId,
                    Username = existingCred.Username,
                    Password = existingCred.Password,
                    WebsiteName = existingCred.WebsiteName,
                    CreatedAt = existingCred.CreatedAt,
                    UpdatedAt = existingCred.LastUpdatedAt,
                    LastUpdatedByUser = existingCred.UpdatedByUser?.UserName
                };

                return await _responseGeneratorService.GenerateResponseAsync<GetCredDetailsDto>(true, StatusCodes.Status200OK, "User Creds Found!", credDetails);

            }
            catch(Exception ex)
            {
                return await _responseGeneratorService.GenerateResponseAsync<GetCredDetailsDto>(
                 false, StatusCodes.Status500InternalServerError, $"An error occurred while GetCredDetail() : {ex.Message}", null);
            }
        }

        public async Task<ReturnResponse<List<GetCredDetailsDto>>> GeAllCred(string userId)
        {
            try
            {
                List<GetCredDetailsDto> response = new List<GetCredDetailsDto>();
                var credList = await _dataContext.Credentials.Where(x=>x.UserId == userId).ToListAsync();

                foreach(var cred in credList) 
                {
                    GetCredDetailsDto credDetail = new GetCredDetailsDto
                    {
                        Id = cred.Id,
                        WebsiteName = cred.WebsiteName,
                        Username = cred.Username,
                        Password = cred.Password,
                        CreatedAt= cred.CreatedAt,
                        LastUpdatedByUser = cred.UpdatedByUser?.UserName,
                        UpdatedAt= cred.LastUpdatedAt
                    };

                    response.Add(credDetail);
                };

                return await _responseGeneratorService.GenerateResponseAsync<List<GetCredDetailsDto>>(true, StatusCodes.Status200OK, "All the Credentials", response);
            }
            catch (Exception ex) {
                return await _responseGeneratorService.GenerateResponseAsync<List<GetCredDetailsDto>>(
                     false, StatusCodes.Status500InternalServerError, $"An error occurred while GeAllCred() : {ex.Message}", null);
            }
        }
    }
}

using PasswordManager.Common;
using PasswordManager.Dto.Credentials;
using PasswordManager.Models;

namespace PasswordManager.Interfaces.Repository
{
    public interface ICredentialRepository
    {
        Task<ReturnResponse<GetCredDetailsDto>> AddCredentialSave(AddCredDto addCred, string userId);
        Task<ReturnResponse<GetCredDetailsDto>> UpdateCredentialSave(Guid credId,EditCredDto editCredDto, AppUser userDetail);
        Task<ReturnResponse> DeleteCredentialSave(Guid credId, AppUser userDetail);
        Task<ReturnResponse<GetCredDetailsDto>> GetCredDetail(Guid credId, string userId);
        Task<ReturnResponse<List<GetCredDetailsDto>>> GeAllCred(string userId);
    }
}
